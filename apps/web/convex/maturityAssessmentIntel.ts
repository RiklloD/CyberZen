/**
 * WS-99 — Security Program Maturity Model: Convex entrypoints
 *
 * Reads latest scanner results from 8+ existing tables and runs
 * computeSecurityMaturity to produce a CMMI-style 5-level assessment.
 *
 * Triggered fire-and-forget from events.ts after repositoryHealthIntel
 * (runs ~13 s after push so all sub-scanners have had time to persist).
 *
 * Entrypoints:
 *   recordMaturityAssessment             — internalMutation: compute + persist
 *   triggerMaturityAssessmentForRepository — public mutation: on-demand trigger
 *   getLatestMaturityAssessment          — query: most recent for a repo (by id)
 *   getLatestMaturityAssessmentBySlug    — query: slug-based for dashboard/HTTP
 *   getMaturityAssessmentHistory         — query: last 10 lean summaries
 *   getMaturityAssessmentSummaryByTenant — query: tenant-wide level distribution
 */

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { computeSecurityMaturity, type MaturityInput, type Finding } from './lib/securityMaturityModel'

const MAX_ROWS_PER_REPO = 10

// ---------------------------------------------------------------------------
// recordMaturityAssessment — internalMutation
// ---------------------------------------------------------------------------

export const recordMaturityAssessment = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { tenantId, repositoryId }) => {
    // Fetch all signal sources in parallel
    const [
      findings,
      latestSlaStatus,
      latestSupplyChain,
      latestSbomQuality,
      latestAttestation,
      latestCompliance,
      latestRegulatoryDrift,
      triageEvents,
      latestGate,
      latestAutoRem,
      latestDriftPosture,
      latestRedBlue,
      latestAttackSurface,
      latestEpss,
      latestSecretScan,
      latestHoneypot,
    ] = await Promise.all([
      // findings (up to 500)
      ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repositoryId))
        .take(500),

      // SLA compliance summary (latest)
      ctx.db
        .query('slaBreachEvents')
        .withIndex('by_repository_and_breached_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .take(100),

      // Supply chain posture grade
      ctx.db
        .query('supplyChainPostureScores')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      // SBOM quality grade
      ctx.db
        .query('sbomQualitySnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      // Attestation summary
      ctx.db
        .query('sbomAttestationRecords')
        .withIndex('by_repository_and_attested_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .take(20),

      // Compliance attestation
      ctx.db
        .query('complianceAttestationResults')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      // Regulatory drift
      ctx.db
        .query('regulatoryDriftSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      // Triage events (count proxy)
      ctx.db
        .query('findingTriageEvents')
        .withIndex('by_repository_and_created_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .take(200),

      // CI/CD gate decisions (any = enabled)
      ctx.db
        .query('gateDecisions')
        .withIndex('by_repository_and_stage', (q) => q.eq('repositoryId', repositoryId))
        .first(),

      // Auto-remediation runs (any = enabled)
      ctx.db
        .query('autoRemediationRuns')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .first(),

      // Drift posture (any scan = enabled)
      ctx.db
        .query('driftPostureResults')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .first(),

      // Red/blue rounds
      ctx.db
        .query('redBlueRounds')
        .withIndex('by_repository_and_ran_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .take(50),

      // Attack surface
      ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .order('desc')
        .first(),

      // EPSS snapshot (any = enabled)
      ctx.db
        .query('epssSnapshots')
        .withIndex('by_synced_at', (q) => q)
        .first(),

      // Secret scan results (any = enabled)
      ctx.db
        .query('secretScanResults')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .first(),

      // Honeypot plan (any = configured)
      ctx.db
        .query('honeypotSnapshots')
        .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
        .first(),
    ])

    // ── Build MaturityInput from raw data ─────────────────────────────────

    const mappedFindings: Finding[] = findings.map((f) => ({
      severity: f.severity as Finding['severity'],
      status: f.status as Finding['status'],
      createdAt: f.createdAt,
      resolvedAt: f.resolvedAt ?? undefined,
    }))

    // SLA compliance rate: fraction of findings NOT in slaBreachEvents within their deadline
    const totalFindings = findings.filter((f) =>
      ['open', 'pr_opened', 'resolved', 'merged'].includes(f.status),
    ).length
    const slaBreachers = new Set(latestSlaStatus.map((e) => e.findingId.toString()))
    const compliantCount = totalFindings === 0 ? 0 : totalFindings - slaBreachers.size
    const slaRate = totalFindings === 0 ? 1 : compliantCount / totalFindings

    // MTTR: average resolution time for resolved findings
    const resolvedWithTime = mappedFindings.filter(
      (f) => (f.status === 'resolved' || f.status === 'merged') && f.resolvedAt,
    )
    const mttrMs =
      resolvedWithTime.length === 0
        ? 168 * 3600_000 // default to 1 week if no data
        : resolvedWithTime.reduce(
            (sum, f) => sum + ((f.resolvedAt ?? f.createdAt) - f.createdAt),
            0,
          ) / resolvedWithTime.length
    const mttrHours = mttrMs / 3_600_000

    // Supply chain grade
    const supplyChainGrade = (latestSupplyChain?.grade ?? null) as MaturityInput['supplyChainGrade']
    const sbomQualityGrade  = (latestSbomQuality?.grade ?? null) as MaturityInput['sbomQualityGrade']

    // Attestation
    const attestationData = latestAttestation.length === 0 ? null : {
      total:    latestAttestation.length,
      valid:    latestAttestation.filter((a) => a.status === 'valid').length,
      tampered: latestAttestation.filter((a) => a.status === 'tampered').length,
    }

    // Compliance
    const complianceData = latestCompliance === null ? null : (() => {
      let compliant = 0, atRisk = 0, nonCompliant = 0
      for (const fw of latestCompliance.frameworks ?? []) {
        if (fw.status === 'compliant') compliant++
        else if (fw.status === 'at_risk') atRisk++
        else nonCompliant++
      }
      return { compliantFrameworks: compliant, atRiskFrameworks: atRisk, nonCompliantFrameworks: nonCompliant }
    })()

    // Regulatory drift level — map schema vocabulary → maturity model vocabulary
    const driftLevelMap: Record<string, MaturityInput['regulatoryDriftLevel']> = {
      compliant: 'none', drifting: 'low', at_risk: 'medium', non_compliant: 'high',
    }
    const regDriftLevel = latestRegulatoryDrift
      ? (driftLevelMap[latestRegulatoryDrift.overallDriftLevel] ?? null)
      : null

    // Triage
    const triagedFindingIds = new Set(triageEvents.map((e) => e.findingId.toString()))
    const triagedFindingCount = triagedFindingIds.size
    const fpEvents = triageEvents.filter((e) => e.action === 'mark_false_positive')
    const analystFpRate =
      triageEvents.length === 0 ? null : fpEvents.length / triageEvents.length

    // Automation flags
    const cicdGateEnabled      = latestGate !== null
    const autoRemediationEnabled = latestAutoRem !== null
    const driftDetectionEnabled  = latestDriftPosture !== null

    // Red/Blue
    const redBlueRoundsCompleted = latestRedBlue.length

    // Attack surface
    const attackSurfaceScore = latestAttackSurface?.score ?? null

    // Enrichment / scanning flags
    const epssEnrichmentEnabled    = latestEpss !== null
    const secretsScanningEnabled   = latestSecretScan !== null
    const honeypotConfigured       = latestHoneypot !== null

    // ── Run assessment ────────────────────────────────────────────────────

    const input: MaturityInput = {
      findings: mappedFindings,
      sla: { overallComplianceRate: slaRate, mttrHours },
      supplyChainGrade,
      sbomQualityGrade,
      attestation: attestationData,
      compliance: complianceData,
      regulatoryDriftLevel: regDriftLevel,
      triageEventCount: triageEvents.length,
      triagedFindingCount,
      analystFpRate,
      cicdGateEnabled,
      autoRemediationEnabled,
      driftDetectionEnabled,
      redBlueRoundsCompleted,
      attackSurfaceScore,
      epssEnrichmentEnabled,
      secretsScanningEnabled,
      honeypotConfigured,
    }

    const assessment = computeSecurityMaturity(input)

    await ctx.db.insert('maturityAssessments', {
      tenantId,
      repositoryId,
      overallLevel: assessment.overallLevel,
      overallScore: assessment.overallScore,
      bottleneck: assessment.bottleneck,
      dimensions: assessment.dimensions,
      advancementRoadmap: assessment.advancementRoadmap,
      assessedAt: assessment.assessedAt,
    })

    // Prune
    const old = await ctx.db
      .query('maturityAssessments')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('asc')
      .take(MAX_ROWS_PER_REPO + 5)

    if (old.length > MAX_ROWS_PER_REPO) {
      for (const row of old.slice(0, old.length - MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(row._id)
      }
    }

    return { overallLevel: assessment.overallLevel, overallScore: assessment.overallScore }
  },
})

// ---------------------------------------------------------------------------
// triggerMaturityAssessmentForRepository — public mutation
// ---------------------------------------------------------------------------

export const triggerMaturityAssessmentForRepository = mutation({
  args: {
    repositoryFullName: v.string(),
    tenantSlug:         v.string(),
  },
  handler: async (ctx, { repositoryFullName, tenantSlug }) => {
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
      internal.maturityAssessmentIntel.recordMaturityAssessment,
      { tenantId: tenant._id, repositoryId: repo._id },
    )

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const getLatestMaturityAssessment = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('maturityAssessments')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

export const getLatestMaturityAssessmentBySlug = query({
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
      .query('maturityAssessments')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repo._id))
      .order('desc')
      .first()
  },
})

export const getMaturityAssessmentHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const rows = await ctx.db
      .query('maturityAssessments')
      .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(10)

    return rows.map((r) => ({
      _id: r._id,
      overallLevel: r.overallLevel,
      overallScore: r.overallScore,
      bottleneck: r.bottleneck,
      assessedAt: r.assessedAt,
    }))
  },
})

export const getMaturityAssessmentSummaryByTenant = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) => q.eq('tenantId', tenantId))
      .take(200)

    const latestByRepo = await Promise.all(
      repos.map((r) =>
        ctx.db
          .query('maturityAssessments')
          .withIndex('by_repository_and_assessed_at', (q) => q.eq('repositoryId', r._id))
          .order('desc')
          .first(),
      ),
    )

    const assessments = latestByRepo.filter(Boolean) as NonNullable<(typeof latestByRepo)[0]>[]

    const levelCounts = [0, 0, 0, 0, 0, 0] // index 1–5
    let totalScore = 0

    for (const a of assessments) {
      levelCounts[a.overallLevel]++
      totalScore += a.overallScore
    }

    return {
      totalRepositories: repos.length,
      assessedRepositories: assessments.length,
      levelDistribution: {
        level1: levelCounts[1],
        level2: levelCounts[2],
        level3: levelCounts[3],
        level4: levelCounts[4],
        level5: levelCounts[5],
      },
      averageScore: assessments.length === 0 ? 0 : Math.round(totalScore / assessments.length),
    }
  },
})
