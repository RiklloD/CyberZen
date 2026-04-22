/**
 * WS-45 — Container Image Security Analyzer: Convex entrypoints.
 *
 * Detects security risks in container base images declared in SBOM components
 * (ecosystem 'docker', 'container', or 'oci'). Uses a static database of
 * popular base images with version-lifecycle data.
 *
 * Detection signals:
 *   eol_base_image   — past vendor-declared end-of-life (critical)
 *   near_eol         — within 90 days of EOL (high)
 *   outdated_base    — not the recommended LTS/stable version (medium/low)
 *   no_version_tag   — using 'latest' or unpinned tag (medium)
 *   deprecated_image — image name is deprecated/abandoned (high)
 *
 * Entrypoints:
 *   recordContainerImageScan               — internalMutation: scan + persist
 *   triggerContainerImageScanForRepository — public mutation: on-demand trigger
 *   getLatestContainerImageScan            — public query: most recent result
 *   getContainerImageScanHistory           — public query: last 30 lean summaries
 *   getContainerImageScanSummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeContainerImageReport } from './lib/containerImageSecurity'

// ---------------------------------------------------------------------------
// recordContainerImageScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot, run the container image scanner, and persist
 * the result. Prunes old rows to 30 per repository.
 */
export const recordContainerImageScan = internalMutation({
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

    // ── Run the container image scanner ───────────────────────────────────
    const report = computeContainerImageReport(componentInputs)

    const nowMs = Date.now()

    // ── Persist ───────────────────────────────────────────────────────────
    await ctx.db.insert('containerImageScanResults', {
      tenantId,
      repositoryId,
      totalImages: report.totalImages,
      criticalCount: report.criticalCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      overallRisk: report.overallRisk,
      findings: report.findings,
      summary: report.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('containerImageScanResults')
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
// triggerContainerImageScanForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand container image scan trigger. Resolves by slug + full name. */
export const triggerContainerImageScanForRepository = mutation({
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
      internal.containerImageIntel.recordContainerImageScan,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestContainerImageScan — public query
// ---------------------------------------------------------------------------

/** Return the most recent container image scan for a repository. */
export const getLatestContainerImageScan = query({
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
      .query('containerImageScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getContainerImageScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/** Return up to 30 recent scan summaries for trend/sparkline display. */
export const getContainerImageScanHistory = query({
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
      .query('containerImageScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip findings to keep response lean.
    return rows.map(({ findings: _f, ...lean }) => lean)
  },
})

// ---------------------------------------------------------------------------
// getContainerImageScanSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide container image scan aggregates: repos by overall risk,
 * and the most critical repository for quick dashboard triage.
 */
export const getContainerImageScanSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('containerImageScanResults')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent scan per repository.
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

    const RISK_RANK: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      none: 4,
    }
    const worst = latest.reduce<(typeof latest)[0] | null>((acc, r) => {
      if (!acc) return r
      return (RISK_RANK[r.overallRisk] ?? 5) < (RISK_RANK[acc.overallRisk] ?? 5) ? r : acc
    }, null)

    const totalFindings = latest.reduce((s, r) => s + r.criticalCount + r.highCount + r.mediumCount + r.lowCount, 0)

    return {
      repoCount: latest.length,
      criticalRepos,
      highRepos,
      mediumRepos,
      lowRepos,
      cleanRepos,
      totalFindings,
      worstRepositoryId: worst?.repositoryId ?? null,
      worstOverallRisk: worst?.overallRisk ?? null,
    }
  },
})
