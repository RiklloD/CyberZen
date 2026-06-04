/**
 * WS-39 — Open-Source Package Abandonment Detector: Convex entrypoints.
 *
 * Persists per-SBOM-ingest abandonment scan results using the pure-library
 * scanner in `lib/abandonmentDetection.ts`. Triggered fire-and-forget from
 * `sbom.ts` whenever a new inventory snapshot is ingested.
 *
 * Entrypoints:
 *   recordAbandonmentScan                — internalMutation: scan all components, persist result
 *   triggerAbandonmentScanForRepository  — public mutation: on-demand re-scan by slug+fullName
 *   getLatestAbandonmentScan             — public query: most recent result for a repository
 *   getAbandonmentScanHistory            — public query: last 30 lean summaries (no findings)
 *   getAbandonmentSummaryByTenant        — public query: tenant-wide aggregate counts
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeAbandonmentReport } from './lib/abandonmentDetection'

// ---------------------------------------------------------------------------
// recordAbandonmentScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot for the repository, run abandonment detection
 * across all components, and persist the result. Prunes old rows to 30 per repo.
 *
 * Triggered fire-and-forget from `sbom.ingestRepositoryInventory` after the
 * EOL scan scheduler call.
 */
export const recordAbandonmentScan = internalMutation({
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

    // ── Run abandonment detection ─────────────────────────────────────────
    const report = computeAbandonmentReport(componentInputs)

    const computedAt = Date.now()

    // Trim findings to 50 entries to keep the stored document size manageable.
    const cappedFindings = report.findings.slice(0, 50).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      reason: f.reason as
        | 'supply_chain_compromised'
        | 'officially_deprecated'
        | 'archived'
        | 'superseded'
        | 'unmaintained',
      riskLevel: f.riskLevel as 'critical' | 'high' | 'medium' | 'low',
      abandonedSince: f.abandonedSince,
      replacedBy: f.replacedBy,
      title: f.title,
      description: f.description,
    }))

    await ctx.db.insert('abandonmentScanResults', {
      tenantId,
      repositoryId,
      criticalCount: report.criticalCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      totalAbandoned: report.totalAbandoned,
      overallRisk: report.overallRisk,
      findings: cappedFindings,
      summary: report.summary,
      computedAt,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('abandonmentScanResults')
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
// triggerAbandonmentScanForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand abandonment re-scan trigger. Resolves tenant + repository by slug
 * and full name, then schedules the internal mutation.
 */
export const triggerAbandonmentScanForRepository = mutation({
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
      internal.abandonmentScanIntel.recordAbandonmentScan,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestAbandonmentScan — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent abandonment scan result for a repository,
 * resolved by tenant slug + repository full name.
 */
export const getLatestAbandonmentScan = query({
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
      .query('abandonmentScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getAbandonmentScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/**
 * Return up to 30 recent abandonment scan summaries for a repository.
 * Findings arrays are stripped to keep the payload small.
 */
export const getAbandonmentScanHistory = query({
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
      .query('abandonmentScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip findings to keep the response lean.
    return rows.map(({ findings: _f, ...lean }) => lean)
  },
})

// ---------------------------------------------------------------------------
// getAbandonmentSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide abandonment aggregates: critical/high/medium/low repo
 * counts and total abandoned package counts across all repositories.
 */
export const getAbandonmentSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('abandonmentScanResults')
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

    const criticalRepos = latest.filter((r) => r.overallRisk === 'critical').length
    const highRepos = latest.filter((r) => r.overallRisk === 'high').length
    const mediumRepos = latest.filter((r) => r.overallRisk === 'medium').length
    const lowRepos = latest.filter((r) => r.overallRisk === 'low').length
    const cleanRepos = latest.filter((r) => r.overallRisk === 'none').length
    const totalCriticalPackages = latest.reduce((s, r) => s + r.criticalCount, 0)
    const totalHighPackages = latest.reduce((s, r) => s + r.highCount, 0)
    const totalAbandonedPackages = latest.reduce((s, r) => s + r.totalAbandoned, 0)

    return {
      criticalRepos,
      highRepos,
      mediumRepos,
      lowRepos,
      cleanRepos,
      totalCriticalPackages,
      totalHighPackages,
      totalAbandonedPackages,
      repoCount: latest.length,
    }
  },
})
