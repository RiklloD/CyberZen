/**
 * WS-49 — Repository Security Health Score: Convex entrypoints.
 *
 * Master synthesis layer that reads the latest persisted results from 8+
 * scanner tables and feeds them into `computeRepositoryHealthScore` to
 * produce a single weighted 0–100 health score with an A–F grade and
 * per-category breakdown.
 *
 * Scheduled with a 9-second delay from sbom.ingestRepositoryInventory so that
 * the entire scanner cascade (WS-48 at 0 s, WS-46 at 5 s, WS-47 at 7 s) has
 * settled before this reads.
 *
 * Entrypoints:
 *   recordRepositoryHealthScore              — internalMutation: gather + compute + persist
 *   triggerRepositoryHealthScoreForRepository — public mutation: on-demand trigger
 *   getLatestRepositoryHealthScore           — public query: most recent result
 *   getRepositoryHealthScoreHistory          — public query: last 30 lean summaries
 *   getRepositoryHealthScoreSummaryByTenant  — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeRepositoryHealthScore } from './lib/repositoryHealthScore'
import type { HealthScannerInputs } from './lib/repositoryHealthScore'

// ---------------------------------------------------------------------------
// recordRepositoryHealthScore — internalMutation
// ---------------------------------------------------------------------------

/**
 * Read the latest result from each scanner table for the given repository,
 * build a `HealthScannerInputs` object, compute the health score, and persist.
 * Prunes old rows to 30 per repository.
 */
export const recordRepositoryHealthScore = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // Helper: fetch the latest row from a scanner result table.
    async function latest<T>(table: string): Promise<T | null> {
      return (await ctx.db
        .query(table as never)
        .withIndex('by_repository_and_computed_at', (q: any) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first()) as T | null
    }

    // ── Gather latest scanner results ────────────────────────────────────
    const [
      supplyChain,
      cve,
      eol,
      abandonment,
      crypto,
      secret,
      iac,
      cicd,
      compliance,
      container,
      licenseScan,
      sbomQuality,
    ] = await Promise.all([
      latest<{ score: number; riskLevel: string }>('supplyChainPostureScores'),
      latest<{ criticalCount: number; highCount: number }>('cveVersionScanResults'),
      latest<{ eolCount: number }>('eolDetectionResults'),
      latest<{ criticalCount: number }>('abandonmentScanResults'),
      latest<{ criticalCount: number; highCount: number }>('cryptoWeaknessResults'),
      latest<{ criticalCount: number; highCount: number }>('secretScanResults'),
      latest<{ criticalCount: number }>('iacScanResults'),
      latest<{ criticalCount: number }>('cicdScanResults'),
      latest<{ overallStatus: string; criticalGapCount: number; highGapCount: number }>(
        'complianceAttestationResults',
      ),
      latest<{ criticalCount: number; highCount: number }>('containerImageScanResults'),
      latest<{ criticalCount: number; highCount: number }>('licenseComplianceScanResults'),
      latest<{ overallScore: number; grade: string }>('sbomQualitySnapshots'),
    ])

    // ── Fetch previous health score for trend detection ──────────────────
    const previousReport = await ctx.db
      .query('repositoryHealthScoreResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    // ── Build scanner inputs ─────────────────────────────────────────────
    const inputs: HealthScannerInputs = {
      // WS-44: Supply Chain Posture
      supplyChainScore: supplyChain?.score ?? null,
      supplyChainRisk: supplyChain?.riskLevel ?? null,

      // WS-43: CVE Scanner
      cveCriticalCount: cve?.criticalCount ?? null,
      cveHighCount: cve?.highCount ?? null,

      // WS-38: EOL Detection
      eolCriticalCount: eol?.eolCount ?? null,

      // WS-39: Abandonment
      abandonmentCriticalCount: abandonment?.criticalCount ?? null,

      // WS-37: Cryptography Weakness
      cryptoCriticalCount: crypto?.criticalCount ?? null,
      cryptoHighCount: crypto?.highCount ?? null,

      // WS-30: Secret Detection
      secretCriticalCount: secret?.criticalCount ?? null,
      secretHighCount: secret?.highCount ?? null,

      // WS-33: IaC Security
      iacCriticalCount: iac?.criticalCount ?? null,

      // WS-35: CI/CD Pipeline Security
      cicdCriticalCount: cicd?.criticalCount ?? null,

      // WS-46: Compliance Attestation
      complianceOverallStatus: compliance?.overallStatus ?? null,
      complianceCriticalGaps: compliance?.criticalGapCount ?? null,
      complianceHighGaps: compliance?.highGapCount ?? null,

      // WS-45: Container Image
      containerCriticalCount: container?.criticalCount ?? null,
      containerHighCount: container?.highCount ?? null,

      // WS-48: License Scan
      licenseCriticalCount: licenseScan?.criticalCount ?? null,
      licenseHighCount: licenseScan?.highCount ?? null,

      // WS-32: SBOM Quality
      sbomQualityScore: sbomQuality?.overallScore ?? null,
      sbomQualityGrade: sbomQuality?.grade ?? null,

      // Previous score for trend
      previousOverallScore: previousReport?.overallScore ?? null,
    }

    // ── Compute ──────────────────────────────────────────────────────────
    const report = computeRepositoryHealthScore(inputs)
    const nowMs = Date.now()

    // ── Persist ──────────────────────────────────────────────────────────
    await ctx.db.insert('repositoryHealthScoreResults', {
      tenantId,
      repositoryId,
      overallScore: report.overallScore,
      overallGrade: report.overallGrade,
      categories: report.categories.map((c) => ({
        category: c.category,
        label: c.label,
        score: c.score,
        weight: c.weight,
        grade: c.grade,
        signals: c.signals,
      })),
      trend: report.trend,
      topRisks: report.topRisks,
      summary: report.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ───────────────────────
    const old = await ctx.db
      .query('repositoryHealthScoreResults')
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
// triggerRepositoryHealthScoreForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand health score trigger. Resolves by tenant slug + repo full name. */
export const triggerRepositoryHealthScoreForRepository = mutation({
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
      internal.repositoryHealthIntel.recordRepositoryHealthScore,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestRepositoryHealthScore — public query
// ---------------------------------------------------------------------------

/** Return the most recent health score for a repository. */
export const getLatestRepositoryHealthScore = query({
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
      .query('repositoryHealthScoreResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getRepositoryHealthScoreHistory — lean public query
// ---------------------------------------------------------------------------

/** Return up to 30 recent health score summaries (signals stripped) for trend display. */
export const getRepositoryHealthScoreHistory = query({
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
      .query('repositoryHealthScoreResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip per-category signals to keep the response lean.
    return rows.map((row) => ({
      ...row,
      categories: row.categories.map(({ signals: _s, ...lean }) => lean),
      topRisks: row.topRisks.slice(0, 3), // just top 3 for history view
    }))
  },
})

// ---------------------------------------------------------------------------
// getRepositoryHealthScoreSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide health aggregates: average score, grade distribution,
 * worst repository, and overall trend.
 */
export const getRepositoryHealthScoreSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('repositoryHealthScoreResults')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent score per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    if (latest.length === 0) return null

    const avgScore = Math.round(
      latest.reduce((sum, r) => sum + r.overallScore, 0) / latest.length,
    )

    // Grade distribution
    const gradeDistribution: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 }
    for (const r of latest) {
      gradeDistribution[r.overallGrade] = (gradeDistribution[r.overallGrade] ?? 0) + 1
    }

    // Worst repository
    const worst = latest.reduce((acc, r) =>
      r.overallScore < acc.overallScore ? r : acc,
    )

    // Trend distribution
    const trendCounts: Record<string, number> = { improving: 0, declining: 0, stable: 0, new: 0 }
    for (const r of latest) {
      trendCounts[r.trend] = (trendCounts[r.trend] ?? 0) + 1
    }

    return {
      repoCount: latest.length,
      avgScore,
      gradeDistribution,
      worstRepositoryId: worst.repositoryId,
      worstScore: worst.overallScore,
      worstGrade: worst.overallGrade,
      trendCounts,
    }
  },
})
