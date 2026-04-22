/**
 * WS-50 — Dependency Update Recommendation Engine: Convex entrypoints.
 *
 * Reads CVE, EOL, and abandonment scanner findings for a repository and
 * produces a deduplicated, prioritised list of concrete dependency update
 * recommendations with urgency, effort classification, and breaking-change
 * risk indicators.
 *
 * Scheduled with an 11-second delay from sbom.ingestRepositoryInventory so
 * that the full scanner cascade (0 s → 5 s → 7 s → 9 s) has settled and
 * all three source scanners have written their results.
 *
 * Entrypoints:
 *   recordDependencyUpdateRecommendations     — internalMutation: gather + compute + persist
 *   triggerDependencyUpdatesForRepository      — public mutation: on-demand trigger
 *   getLatestDependencyUpdateRecommendations   — public query: most recent result
 *   getDependencyUpdateHistory                 — public query: last 30 lean summaries
 *   getDependencyUpdateSummaryByTenant         — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeUpdateRecommendations } from './lib/dependencyUpdateRecommendation'
import type {
  CveFinding,
  EolFinding,
  AbandonmentFinding,
} from './lib/dependencyUpdateRecommendation'

// ---------------------------------------------------------------------------
// recordDependencyUpdateRecommendations — internalMutation
// ---------------------------------------------------------------------------

/**
 * Read latest CVE, EOL, and abandonment scan results for the repository,
 * compute deduplicated update recommendations, and persist.
 * Prunes old rows to 30 per repository.
 */
export const recordDependencyUpdateRecommendations = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Load latest scanner results ──────────────────────────────────────
    const [cveResult, eolResult, abandonmentResult] = await Promise.all([
      ctx.db
        .query('cveVersionScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),
      ctx.db
        .query('eolDetectionResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),
      ctx.db
        .query('abandonmentScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),
    ])

    // Bail if no scanner results exist at all
    if (!cveResult && !eolResult && !abandonmentResult) return null

    // ── Map scanner findings to the input types ──────────────────────────
    const cveFindings: CveFinding[] = (cveResult?.findings ?? []).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      cveId: f.cveId,
      cvss: f.cvss,
      minimumSafeVersion: f.minimumSafeVersion,
      riskLevel: f.riskLevel,
    }))

    const eolFindings: EolFinding[] = (eolResult?.findings ?? []).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      eolStatus: f.eolStatus,
      replacedBy: f.replacedBy,
    }))

    const abandonmentFindings: AbandonmentFinding[] = (abandonmentResult?.findings ?? []).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      reason: f.reason,
      riskLevel: f.riskLevel,
      replacedBy: f.replacedBy,
    }))

    // ── Compute ──────────────────────────────────────────────────────────
    const report = computeUpdateRecommendations({
      cveFindings,
      eolFindings,
      abandonmentFindings,
    })

    const nowMs = Date.now()

    // ── Persist (cap recommendations at 50) ──────────────────────────────
    await ctx.db.insert('dependencyUpdateRecommendations', {
      tenantId,
      repositoryId,
      recommendations: report.recommendations.slice(0, 50),
      criticalCount: report.criticalCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      totalRecommendations: report.totalRecommendations,
      patchCount: report.patchCount,
      breakingCount: report.breakingCount,
      summary: report.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ───────────────────────
    const old = await ctx.db
      .query('dependencyUpdateRecommendations')
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
// triggerDependencyUpdatesForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand update recommendation trigger. Resolves by tenant slug + repo full name. */
export const triggerDependencyUpdatesForRepository = mutation({
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
      internal.dependencyUpdateIntel.recordDependencyUpdateRecommendations,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestDependencyUpdateRecommendations — public query
// ---------------------------------------------------------------------------

/** Return the most recent update recommendations for a repository. */
export const getLatestDependencyUpdateRecommendations = query({
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
      .query('dependencyUpdateRecommendations')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getDependencyUpdateHistory — lean public query
// ---------------------------------------------------------------------------

/** Return up to 30 recent update recommendation summaries (details stripped). */
export const getDependencyUpdateHistory = query({
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
      .query('dependencyUpdateRecommendations')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip per-recommendation details and cveIds to keep the response lean.
    return rows.map((row) => ({
      ...row,
      recommendations: row.recommendations.map(
        ({ details: _d, cveIds: _c, ...lean }) => lean,
      ),
    }))
  },
})

// ---------------------------------------------------------------------------
// getDependencyUpdateSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide update recommendation aggregates: total recommendations,
 * urgency breakdown, patch vs breaking counts, and worst repository.
 */
export const getDependencyUpdateSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('dependencyUpdateRecommendations')
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

    if (latest.length === 0) return null

    const totalRecommendations = latest.reduce((s, r) => s + r.totalRecommendations, 0)
    const totalCritical = latest.reduce((s, r) => s + r.criticalCount, 0)
    const totalHigh = latest.reduce((s, r) => s + r.highCount, 0)
    const totalPatch = latest.reduce((s, r) => s + r.patchCount, 0)
    const totalBreaking = latest.reduce((s, r) => s + r.breakingCount, 0)

    // Repository with the most recommendations
    const worst = latest.reduce((acc, r) =>
      r.totalRecommendations > acc.totalRecommendations ? r : acc,
    )

    return {
      repoCount: latest.length,
      totalRecommendations,
      totalCritical,
      totalHigh,
      totalPatch,
      totalBreaking,
      worstRepositoryId: worst.repositoryId,
      worstRecommendationCount: worst.totalRecommendations,
    }
  },
})
