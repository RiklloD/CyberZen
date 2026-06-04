/**
 * WS-100 — Business Impact Assessment: Convex entrypoints (spec §3.5.4)
 *
 * Aggregates findings, blast-radius scores, attack surface, and compliance
 * into a five-dimension business risk picture per repository.
 *
 * Triggered fire-and-forget from events.ts at runAfter(12_000) so the
 * attack-surface snapshot (runAfter(9_000)) is ready.
 *
 * Entrypoints:
 *   recordBusinessImpact                   — internalMutation: compute + persist
 *   triggerBusinessImpactForRepository     — public mutation: on-demand
 *   getLatestBusinessImpact                — query: most recent by repo id
 *   getLatestBusinessImpactBySlug          — query: tenantSlug + repositoryFullName
 *   getBusinessImpactHistory               — query: last 10 lean summaries
 *   getBusinessImpactSummaryByTenant       — query: tenant-wide level distribution
 */

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { computeBusinessImpact, type BusinessImpactInput } from './lib/businessImpact'

const MAX_ROWS_PER_REPO = 10

// ---------------------------------------------------------------------------
// recordBusinessImpact — internalMutation
// ---------------------------------------------------------------------------

export const recordBusinessImpact = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { tenantId, repositoryId }) => {
    const [
      findings,
      blastRadii,
      latestAttackSurface,
      latestCompliance,
      latestRegDrift,
    ] = await Promise.all([
      ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repositoryId))
        .take(500),

      ctx.db
        .query('blastRadiusSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .take(50),

      ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      ctx.db
        .query('complianceAttestationResults')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      ctx.db
        .query('regulatoryDriftSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),
    ])

    // ── Severity counts from open findings ───────────────────────────────

    const openFindings = findings.filter((f) =>
      ['open', 'pr_opened'].includes(f.status),
    )
    const criticalFindings = openFindings.filter((f) => f.severity === 'critical').length
    const highFindings     = openFindings.filter((f) => f.severity === 'high').length
    const mediumFindings   = openFindings.filter((f) => f.severity === 'medium').length
    const lowFindings      = openFindings.filter((f) => f.severity === 'low').length

    // ── Blast radius aggregation ─────────────────────────────────────────

    const blastScores = blastRadii.map((b) => b.businessImpactScore)
    const maxBlastRadiusScore = blastScores.length > 0 ? Math.max(...blastScores) : 0
    const avgBlastRadiusScore =
      blastScores.length > 0
        ? Math.round(blastScores.reduce((s, v) => s + v, 0) / blastScores.length)
        : 0
    const reachableServiceNames = [
      ...new Set(blastRadii.flatMap((b) => b.reachableServices)),
    ]

    // ── Compliance data ──────────────────────────────────────────────────

    let nonCompliantFrameworkCount = 0
    let atRiskFrameworkCount = 0
    if (latestCompliance) {
      for (const fw of latestCompliance.frameworks ?? []) {
        if (fw.status === 'non_compliant') nonCompliantFrameworkCount++
        else if (fw.status === 'at_risk') atRiskFrameworkCount++
      }
    }

    // ── Regulatory drift ─────────────────────────────────────────────────

    const driftLevelMap: Record<string, BusinessImpactInput['regulatoryDriftLevel']> = {
      compliant: 'none', drifting: 'low', at_risk: 'medium', non_compliant: 'high',
    }
    const regulatoryDriftLevel = latestRegDrift
      ? (driftLevelMap[latestRegDrift.overallDriftLevel] ?? null)
      : null

    // ── Run model ────────────────────────────────────────────────────────

    const input: BusinessImpactInput = {
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      maxBlastRadiusScore,
      avgBlastRadiusScore,
      reachableServiceNames,
      attackSurfaceScore: latestAttackSurface?.score ?? null,
      nonCompliantFrameworkCount,
      atRiskFrameworkCount,
      regulatoryDriftLevel,
    }

    const result = computeBusinessImpact(input)

    await ctx.db.insert('businessImpactSnapshots', {
      tenantId,
      repositoryId,
      dataExposureScore:       result.dataExposureScore,
      regulatoryExposureScore: result.regulatoryExposureScore,
      revenueImpactScore:      result.revenueImpactScore,
      reputationScore:         result.reputationScore,
      remediationCostScore:    result.remediationCostScore,
      overallScore:            result.overallScore,
      impactLevel:             result.impactLevel,
      estimatedRecordsAtRisk:      result.estimatedRecordsAtRisk,
      estimatedFineRangeMin:       result.estimatedFineRangeMin,
      estimatedFineRangeMax:       result.estimatedFineRangeMax,
      estimatedRemediationCostMin: result.estimatedRemediationCostMin,
      estimatedRemediationCostMax: result.estimatedRemediationCostMax,
      topExposures: result.topExposures,
      assessedAt:   result.assessedAt,
    })

    // Prune oldest rows beyond cap
    const old = await ctx.db
      .query('businessImpactSnapshots')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('asc')
      .take(MAX_ROWS_PER_REPO + 5)

    if (old.length > MAX_ROWS_PER_REPO) {
      for (const row of old.slice(0, old.length - MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(row._id)
      }
    }

    return { impactLevel: result.impactLevel, overallScore: result.overallScore }
  },
})

// ---------------------------------------------------------------------------
// triggerBusinessImpactForRepository — public mutation
// ---------------------------------------------------------------------------

export const triggerBusinessImpactForRepository = mutation({
  args: {
    tenantSlug:         v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const repo = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repo) throw new Error(`Repository not found: ${repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.businessImpactIntel.recordBusinessImpact,
      { tenantId: tenant._id, repositoryId: repo._id },
    )

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const getLatestBusinessImpact = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('businessImpactSnapshots')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

export const getLatestBusinessImpactBySlug = query({
  args: { tenantSlug: v.string(), repositoryFullName: v.string() },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return null

    const repo = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repo) return null

    return ctx.db
      .query('businessImpactSnapshots')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repo._id))
      .order('desc')
      .first()
  },
})

export const getBusinessImpactHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const rows = await ctx.db
      .query('businessImpactSnapshots')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(10)

    return rows.map((r) => ({
      _id: r._id,
      overallScore: r.overallScore,
      impactLevel: r.impactLevel,
      assessedAt: r.assessedAt,
    }))
  },
})

export const getBusinessImpactSummaryByTenant = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) => q.eq('tenantId', tenantId))
      .take(200)

    const latestByRepo = await Promise.all(
      repos.map((r) =>
        ctx.db
          .query('businessImpactSnapshots')
          .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', r._id))
          .order('desc')
          .first(),
      ),
    )

    const snapshots = latestByRepo.filter(Boolean) as NonNullable<(typeof latestByRepo)[0]>[]

    const levelCounts = { critical: 0, high: 0, medium: 0, low: 0, minimal: 0 }
    let totalScore = 0

    for (const s of snapshots) {
      levelCounts[s.impactLevel]++
      totalScore += s.overallScore
    }

    return {
      totalRepositories: repos.length,
      assessedRepositories: snapshots.length,
      levelDistribution: levelCounts,
      averageScore: snapshots.length === 0 ? 0 : Math.round(totalScore / snapshots.length),
    }
  },
})
