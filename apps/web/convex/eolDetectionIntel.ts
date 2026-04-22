/**
 * WS-38 — Dependency & Runtime End-of-Life (EOL) Detection: Convex entrypoints.
 *
 * Persists per-SBOM-ingest EOL scan results using the pure-library scanner in
 * `lib/eolDetection.ts`. Triggered fire-and-forget from `sbom.ts` whenever a
 * new inventory snapshot is ingested.
 *
 * Entrypoints:
 *   recordEolScan                 — internalMutation: scan all components, persist result
 *   triggerEolScanForRepository   — public mutation: on-demand re-scan by slug+fullName
 *   getLatestEolScan              — public query: most recent result for a repository
 *   getEolScanHistory             — public query: last 30 lean summaries (no findings)
 *   getEolSummaryByTenant         — public query: tenant-wide aggregate counts
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { checkComponentEol, computeEolReport } from './lib/eolDetection'

// ---------------------------------------------------------------------------
// recordEolScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot for the repository, run EOL detection across
 * all components, and persist the result. Prunes old rows to 30 per repo.
 *
 * Triggered fire-and-forget from `sbom.ingestRepositoryInventory` after SBOM
 * quality scoring.
 */
export const recordEolScan = internalMutation({
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

    // ── Run EOL detection ─────────────────────────────────────────────────
    const report = computeEolReport(componentInputs)

    const computedAt = Date.now()

    // Trim findings to 50 entries to keep the stored document size manageable.
    const cappedFindings = report.findings.slice(0, 50).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      eolStatus: f.eolStatus as 'end_of_life' | 'near_eol',
      eolDate: f.eolDate,
      eolDateText: f.eolDateText,
      daysOverdue: f.daysOverdue,
      daysUntilEol: f.daysUntilEol,
      replacedBy: f.replacedBy,
      category: f.category as 'runtime' | 'framework' | 'package',
      title: f.title,
      description: f.description,
    }))

    await ctx.db.insert('eolDetectionResults', {
      tenantId,
      repositoryId,
      eolCount: report.eolCount,
      nearEolCount: report.nearEolCount,
      supportedCount: report.supportedCount,
      unknownCount: report.unknownCount,
      overallStatus: report.overallStatus,
      findings: cappedFindings,
      summary: report.summary,
      computedAt,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('eolDetectionResults')
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
// triggerEolScanForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand EOL re-scan trigger. Resolves tenant + repository by slug and
 * full name, then schedules the internal mutation.
 */
export const triggerEolScanForRepository = mutation({
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

    await ctx.scheduler.runAfter(0, internal.eolDetectionIntel.recordEolScan, {
      tenantId: tenant._id,
      repositoryId: repository._id,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestEolScan — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent EOL scan result for a repository,
 * resolved by tenant slug + repository full name.
 */
export const getLatestEolScan = query({
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
      .query('eolDetectionResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getEolScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/**
 * Return up to 30 recent EOL scan summaries for a repository.
 * Findings arrays are stripped to keep the payload small.
 */
export const getEolScanHistory = query({
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
      .query('eolDetectionResults')
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
// getEolSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide EOL aggregates: critical/warning repo counts, total
 * EOL package count, and per-category breakdowns.
 */
export const getEolSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('eolDetectionResults')
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

    const criticalRepos = latest.filter((r) => r.overallStatus === 'critical').length
    const warningRepos = latest.filter((r) => r.overallStatus === 'warning').length
    const okRepos = latest.filter((r) => r.overallStatus === 'ok').length
    const totalEolPackages = latest.reduce((s, r) => s + r.eolCount, 0)
    const totalNearEolPackages = latest.reduce((s, r) => s + r.nearEolCount, 0)

    return {
      criticalRepos,
      warningRepos,
      okRepos,
      totalEolPackages,
      totalNearEolPackages,
      repoCount: latest.length,
    }
  },
})

// ---------------------------------------------------------------------------
// Re-export checkComponentEol for use in tests / tooling
// ---------------------------------------------------------------------------
export { checkComponentEol }
