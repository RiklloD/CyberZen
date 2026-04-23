/**
 * WS-56 — Git Supply Chain Integrity Scanner: Convex entrypoints.
 *
 * Analyses the list of changed file paths from a push event for supply-chain
 * integrity risks: system-binary PATH-hijacking, submodule manipulation,
 * binary executable smuggling, Git hook tampering, dependency registry
 * overrides, gitconfig modification, large blind pushes, and archive commits.
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordGitIntegrityScan           — internalMutation: run scanner, persist result
 *   triggerGitIntegrityScan          — public mutation: on-demand by slug+fullName
 *   getLatestGitIntegrityScan        — public query: most recent result for a repo
 *   getLatestGitIntegrityScanBySlug  — public query: slug-based (for dashboard/HTTP)
 *   getGitIntegrityScanHistory       — public query: last 30 lean summaries
 *   getGitIntegritySummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanGitIntegrity } from './lib/gitIntegrityScanner'

const MAX_ROWS_PER_REPO = 30
/** Cap on paths stored per scan to keep row size bounded. */
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordGitIntegrityScan — internalMutation
// ---------------------------------------------------------------------------

export const recordGitIntegrityScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha: v.string(),
    branch: v.string(),
    changedFiles: v.array(v.string()),
    totalFileCount: v.number(),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles, totalFileCount }) => {
    const paths = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanGitIntegrity({ changedFiles: paths, totalFileCount })
    const now = Date.now()

    await ctx.db.insert('gitIntegrityResults', {
      tenantId,
      repositoryId,
      commitSha,
      branch,
      scannedPaths: paths,
      totalFileCount,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.mediumCount,
      lowCount: result.lowCount,
      findings: result.findings,
      summary: result.summary,
      scannedAt: now,
    })

    // Prune old rows to keep storage bounded
    const all = await ctx.db
      .query('gitIntegrityResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .collect()
    if (all.length > MAX_ROWS_PER_REPO) {
      for (const old of all.slice(MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(old._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerGitIntegrityScan — public mutation
// ---------------------------------------------------------------------------

export const triggerGitIntegrityScan = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    commitSha: v.string(),
    branch: v.string(),
    changedFiles: v.array(v.string()),
    totalFileCount: v.optional(v.number()),
  },
  handler: async (
    ctx,
    { tenantSlug, repositoryFullName, commitSha, branch, changedFiles, totalFileCount },
  ) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repository) return

    const paths = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const effectiveTotal = totalFileCount ?? changedFiles.length
    const result = scanGitIntegrity({ changedFiles: paths, totalFileCount: effectiveTotal })
    const now = Date.now()

    await ctx.db.insert('gitIntegrityResults', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      commitSha,
      branch,
      scannedPaths: paths,
      totalFileCount: effectiveTotal,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.mediumCount,
      lowCount: result.lowCount,
      findings: result.findings,
      summary: result.summary,
      scannedAt: now,
    })

    // Prune old rows
    const all = await ctx.db
      .query('gitIntegrityResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .collect()
    if (all.length > MAX_ROWS_PER_REPO) {
      for (const old of all.slice(MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(old._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// getLatestGitIntegrityScan — public query
// ---------------------------------------------------------------------------

export const getLatestGitIntegrityScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('gitIntegrityResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestGitIntegrityScanBySlug — public query (slug-based, for dashboard)
// ---------------------------------------------------------------------------

export const getLatestGitIntegrityScanBySlug = query({
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
      .query('gitIntegrityResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getGitIntegrityScanHistory — public query (lean)
// ---------------------------------------------------------------------------

export const getGitIntegrityScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('gitIntegrityResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      _id: r._id,
      commitSha: r.commitSha,
      branch: r.branch,
      riskScore: r.riskScore,
      riskLevel: r.riskLevel,
      totalFindings: r.totalFindings,
      totalFileCount: r.totalFileCount,
      scannedAt: r.scannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getGitIntegritySummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getGitIntegritySummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('gitIntegrityResults')
      .withIndex('by_tenant_and_scanned_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(500)

    // Deduplicate to one per repository (most recent)
    const seenRepos = new Set<string>()
    const latest: typeof allSnapshots = []
    for (const snap of allSnapshots) {
      if (!seenRepos.has(snap.repositoryId)) {
        seenRepos.add(snap.repositoryId)
        latest.push(snap)
      }
    }

    const criticalRepos = latest.filter((s) => s.riskLevel === 'critical').length
    const highRepos = latest.filter((s) => s.riskLevel === 'high').length
    const mediumRepos = latest.filter((s) => s.riskLevel === 'medium').length
    const cleanRepos = latest.filter((s) => s.riskLevel === 'none').length
    const totalFindings = latest.reduce((a, s) => a + s.totalFindings, 0)

    const worstRepo =
      latest.length > 0 ? latest.reduce((a, b) => (a.riskScore > b.riskScore ? a : b)) : null

    return {
      repositoriesScanned: latest.length,
      criticalRepos,
      highRepos,
      mediumRepos,
      cleanRepos,
      totalFindings,
      worstRepositoryId: worstRepo?.riskScore ? worstRepo.repositoryId : null,
      worstRiskScore: worstRepo?.riskScore ?? null,
    }
  },
})
