/**
 * WS-44 — Supply Chain Posture Score: Convex entrypoints.
 *
 * Aggregates the outputs of all five supply-chain scanners (EOL, Abandonment,
 * CVE, Malicious Package, Dependency Confusion) plus SBOM attestation status
 * into a single 0–100 posture score and A–F grade per repository.
 *
 * All five sub-scanners are re-run inline from the component list rather than
 * reading from the five separate scan-result tables. This avoids timing races:
 * those scans run fire-and-forget concurrently and may not be persisted yet
 * when the posture scorer executes.
 *
 * Entrypoints:
 *   recordSupplyChainPosture            — internalMutation: scan + persist
 *   triggerSupplyChainPostureForRepository — public mutation: on-demand trigger
 *   getLatestSupplyChainPosture         — public query: most recent result
 *   getSupplyChainPostureHistory        — public query: last 30 lean summaries
 *   getSupplyChainPostureSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeAbandonmentReport } from './lib/abandonmentDetection'
import { computeConfusionReport } from './lib/confusionAttackDetection'
import { computeCveReport } from './lib/cveVersionScanner'
import { computeEolReport } from './lib/eolDetection'
import { computeMaliciousReport } from './lib/maliciousPackageDetection'
import { computeSupplyChainPosture } from './lib/supplyChainPostureScorer'

// ---------------------------------------------------------------------------
// recordSupplyChainPosture — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot, run all five sub-scanners inline, compute
 * the aggregate posture score, and persist the result.
 * Prunes old rows to 30 per repository to bound storage growth.
 */
export const recordSupplyChainPosture = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Load latest SBOM snapshot ─────────────────────────────────────────
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    // ── Load components (cap at 500) ──────────────────────────────────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .take(500)

    const componentInputs = components.map((c) => ({
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
    }))

    // ── Load attestation status (most recent for this repository) ─────────
    const attestation = await ctx.db
      .query('sbomAttestationRecords')
      .withIndex('by_repository_and_attested_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    const attestationStatus = (attestation?.status ?? 'none') as
      | 'valid'
      | 'tampered'
      | 'unverified'
      | 'none'

    // ── Run all five sub-scanners inline ──────────────────────────────────
    const nowMs = Date.now()
    const eolReport = computeEolReport(componentInputs, nowMs)
    const abandonmentReport = computeAbandonmentReport(componentInputs)
    const cveReport = computeCveReport(componentInputs)
    const maliciousReport = computeMaliciousReport(componentInputs)
    const confusionReport = computeConfusionReport(componentInputs)

    // ── Compute posture score ─────────────────────────────────────────────
    const result = computeSupplyChainPosture({
      componentCount: componentInputs.length,
      cve: {
        criticalCount: cveReport.criticalCount,
        highCount: cveReport.highCount,
        mediumCount: cveReport.mediumCount,
        lowCount: cveReport.lowCount,
        overallRisk: cveReport.overallRisk,
      },
      malicious: {
        criticalCount: maliciousReport.criticalCount,
        highCount: maliciousReport.highCount,
        overallRisk: maliciousReport.overallRisk,
      },
      confusion: {
        criticalCount: confusionReport.criticalCount,
        highCount: confusionReport.highCount,
        overallRisk: confusionReport.overallRisk,
      },
      abandonment: {
        criticalCount: abandonmentReport.criticalCount,
        highCount: abandonmentReport.highCount,
        overallRisk: abandonmentReport.overallRisk,
      },
      eol: {
        eolCount: eolReport.eolCount,
        nearEolCount: eolReport.nearEolCount,
        overallStatus: eolReport.overallStatus,
      },
      attestationStatus,
    })

    // ── Persist ───────────────────────────────────────────────────────────
    await ctx.db.insert('supplyChainPostureScores', {
      tenantId,
      repositoryId,
      score: result.score,
      grade: result.grade,
      riskLevel: result.riskLevel,
      componentCount: componentInputs.length,
      breakdown: result.breakdown,
      summary: result.summary,
      cveRisk: result.cveRisk,
      maliciousRisk: result.maliciousRisk,
      confusionRisk: result.confusionRisk,
      abandonmentRisk: result.abandonmentRisk,
      eolRisk: result.eolRisk,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('supplyChainPostureScores')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('asc')
      .take(100)

    if (old.length > 30) {
      for (const row of old.slice(0, old.length - 30)) {
        await ctx.db.delete(row._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerSupplyChainPostureForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand posture re-score trigger. Resolves by slug + full name. */
export const triggerSupplyChainPostureForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), args.repositoryFullName),
        ),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.supplyChainPostureIntel.recordSupplyChainPosture,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestSupplyChainPosture — public query
// ---------------------------------------------------------------------------

/** Return the most recent posture score for a repository. */
export const getLatestSupplyChainPosture = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return null

    return ctx.db
      .query('supplyChainPostureScores')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSupplyChainPostureHistory — lean public query (no breakdown)
// ---------------------------------------------------------------------------

/** Return up to 30 recent posture scores for sparkline / trend display. */
export const getSupplyChainPostureHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return []

    const rows = await ctx.db
      .query('supplyChainPostureScores')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip breakdown to keep response lean.
    return rows.map(({ breakdown: _b, ...lean }) => lean)
  },
})

// ---------------------------------------------------------------------------
// getSupplyChainPostureSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide posture aggregates: repos by grade, average score,
 * and the worst-scoring repository for quick dashboard triage.
 */
export const getSupplyChainPostureSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('supplyChainPostureScores')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent result per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const gradeA = latest.filter((r) => r.grade === 'A').length
    const gradeB = latest.filter((r) => r.grade === 'B').length
    const gradeC = latest.filter((r) => r.grade === 'C').length
    const gradeD = latest.filter((r) => r.grade === 'D').length
    const gradeF = latest.filter((r) => r.grade === 'F').length

    const averageScore =
      latest.length > 0
        ? Math.round(latest.reduce((s, r) => s + r.score, 0) / latest.length)
        : null

    // Worst-scoring repository for triage.
    const worst = latest.reduce<(typeof latest)[0] | null>((acc, r) => {
      if (!acc || r.score < acc.score) return r
      return acc
    }, null)

    return {
      repoCount: latest.length,
      gradeA,
      gradeB,
      gradeC,
      gradeD,
      gradeF,
      averageScore,
      worstRepositoryId: worst?.repositoryId ?? null,
      worstScore: worst?.score ?? null,
      worstGrade: worst?.grade ?? null,
    }
  },
})
