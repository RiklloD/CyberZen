/**
 * WS-37 — Cryptography Weakness Detector: Convex entrypoints.
 *
 * Persists per-push cryptographic weakness scan results from the pure-library
 * scanner in `lib/cryptoWeakness.ts`. Triggered fire-and-forget from
 * `events.ts` on every push that touches source files.
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import {
  combineCryptoResults,
  scanFileForCryptoWeakness,
} from './lib/cryptoWeakness'

// ---------------------------------------------------------------------------
// recordCryptoWeaknessScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Scan a batch of source files for cryptographic weaknesses and persist the
 * result.  Prunes old rows to keep at most 50 per repository.
 *
 * The MVP passes file paths as content (same as the IaC / CI/CD scanners).
 * When the GitHub Contents API integration lands, real file bytes will be
 * substituted here without any schema changes.
 */
export const recordCryptoWeaknessScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** Items to scan: { filename, content }. Content defaults to filename if absent. */
    fileItems: v.array(
      v.object({
        filename: v.string(),
        content: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId, branch, commitSha, fileItems } = args

    // Run the pure scanner over each file (cap at 10 findings per file).
    const rawResults = fileItems.map((item) =>
      scanFileForCryptoWeakness(item.filename, item.content),
    )

    // Trim findings to 10 per file to keep the stored row small.
    const cappedResults = rawResults.map((r) => ({
      ...r,
      findings: r.findings.slice(0, 10),
    }))

    const summary = combineCryptoResults(cappedResults)

    const computedAt = Date.now()

    await ctx.db.insert('cryptoWeaknessResults', {
      tenantId,
      repositoryId,
      branch,
      commitSha,
      totalFiles: summary.totalFiles,
      totalFindings: summary.totalFindings,
      criticalCount: summary.criticalCount,
      highCount: summary.highCount,
      mediumCount: summary.mediumCount,
      lowCount: summary.lowCount,
      overallRisk: summary.overallRisk,
      fileResults: cappedResults.map((r) => ({
        filename: r.filename,
        fileType: r.fileType,
        criticalCount: r.criticalCount,
        highCount: r.highCount,
        mediumCount: r.mediumCount,
        lowCount: r.lowCount,
        findings: r.findings,
      })),
      summary: summary.summary,
      computedAt,
    })

    // Prune: keep at most 50 rows per repository (oldest first).
    const old = await ctx.db
      .query('cryptoWeaknessResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('asc')
      .take(200)

    if (old.length > 50) {
      for (const row of old.slice(0, old.length - 50)) {
        await ctx.db.delete(row._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerCryptoWeaknessScanForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand trigger: scan a supplied list of source files for a repository.
 * Useful for manual re-scans from the dashboard or API.
 */
export const triggerCryptoWeaknessScanForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    fileItems: v.array(
      v.object({ filename: v.string(), content: v.string() }),
    ),
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

    await ctx.scheduler.runAfter(0, internal.cryptoWeaknessIntel.recordCryptoWeaknessScan, {
      tenantId: tenant._id,
      repositoryId: repository._id,
      branch: args.branch,
      fileItems: args.fileItems,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestCryptoWeaknessScan — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent crypto-weakness scan result for a repository,
 * resolved by tenant slug + repository full name.
 */
export const getLatestCryptoWeaknessScan = query({
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
      .query('cryptoWeaknessResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getCryptoWeaknessScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/**
 * Return up to 30 recent scan summaries for a repository (no per-file
 * findings arrays, so the payload stays small).
 */
export const getCryptoWeaknessScanHistory = query({
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
      .query('cryptoWeaknessResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip file-level findings to keep the response lean.
    return rows.map(({ fileResults: _fr, ...lean }) => lean)
  },
})

// ---------------------------------------------------------------------------
// getCryptoWeaknessSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide crypto weakness aggregates: critical-risk repo count,
 * total findings, and per-risk-tier repo counts.
 */
export const getCryptoWeaknessSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('cryptoWeaknessResults')
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

    const criticalRiskRepos = latest.filter((r) => r.overallRisk === 'critical').length
    const highRiskRepos = latest.filter((r) => r.overallRisk === 'high').length
    const cleanRepos = latest.filter((r) => r.overallRisk === 'none').length
    const totalFindings = latest.reduce((s, r) => s + r.totalFindings, 0)

    return { criticalRiskRepos, highRiskRepos, cleanRepos, totalFindings, repoCount: latest.length }
  },
})
