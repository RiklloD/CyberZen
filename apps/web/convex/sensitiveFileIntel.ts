/**
 * WS-54 — Sensitive File Commit Detector: Convex entrypoints.
 *
 * Analyses the list of changed file paths from a GitHub push event and
 * identifies accidentally committed sensitive files: private keys,
 * certificates, credential configs, .env files, and debug artifacts.
 *
 * Triggered fire-and-forget from events.ts on every push, and exposed as a
 * public mutation for on-demand re-scans.
 *
 * Entrypoints:
 *   recordSensitiveFileScan           — internalMutation: run detector, persist result
 *   triggerSensitiveFileScan          — public mutation: on-demand by slug+fullName
 *   getLatestSensitiveFileScan        — public query: most recent result for a repo
 *   getLatestSensitiveFileScanBySlug  — public query: slug-based (for dashboard/HTTP)
 *   getSensitiveFileScanHistory       — public query: last 30 lean summaries
 *   getSensitiveFileSummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { detectSensitiveFiles } from './lib/sensitiveFileDetector'

const MAX_ROWS_PER_REPO = 30

// ---------------------------------------------------------------------------
// recordSensitiveFileScan — internalMutation
// ---------------------------------------------------------------------------

export const recordSensitiveFileScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha: v.string(),
    branch: v.string(),
    filePaths: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, filePaths }) => {
    const result = detectSensitiveFiles(filePaths)
    const now = Date.now()

    await ctx.db.insert('sensitiveFileResults', {
      tenantId,
      repositoryId,
      commitSha,
      branch,
      scannedPaths: filePaths,
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
      .query('sensitiveFileResults')
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
// triggerSensitiveFileScan — public mutation
// ---------------------------------------------------------------------------

export const triggerSensitiveFileScan = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    commitSha: v.string(),
    branch: v.string(),
    filePaths: v.array(v.string()),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, commitSha, branch, filePaths }) => {
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

    const result = detectSensitiveFiles(filePaths)
    const now = Date.now()

    await ctx.db.insert('sensitiveFileResults', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      commitSha,
      branch,
      scannedPaths: filePaths,
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
      .query('sensitiveFileResults')
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
// getLatestSensitiveFileScan — public query
// ---------------------------------------------------------------------------

export const getLatestSensitiveFileScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('sensitiveFileResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestSensitiveFileScanBySlug — public query (slug-based, for dashboard)
// ---------------------------------------------------------------------------

export const getLatestSensitiveFileScanBySlug = query({
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
      .query('sensitiveFileResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSensitiveFileScanHistory — public query (lean)
// ---------------------------------------------------------------------------

export const getSensitiveFileScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('sensitiveFileResults')
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
      scannedAt: r.scannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getSensitiveFileSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getSensitiveFileSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('sensitiveFileResults')
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
