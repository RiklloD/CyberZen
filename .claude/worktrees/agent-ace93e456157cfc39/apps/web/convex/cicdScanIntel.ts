// WS-35 — CI/CD Pipeline Security Scanner: Convex entrypoints.
//
//   recordCicdScan               — internal mutation: scans a list of
//       {filename, content} items and stores the combined result.
//
//   triggerCicdScanForRepository — public mutation: on-demand / webhook trigger.
//
//   getLatestCicdScan            — public query: latest result for a repo.
//
//   getCicdScanHistory           — public query: lean last-N results for sparklines.
//
//   getCicdScanSummaryByTenant   — public query: tenant-wide aggregate.

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { combineCicdResults, scanCicdFile } from './lib/cicdSecurity'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SCANS_PER_REPO = 50
const MAX_FILE_RESULTS = 10
const MAX_FINDINGS_PER_FILE = 10

// ---------------------------------------------------------------------------
// recordCicdScan (internal mutation)
// ---------------------------------------------------------------------------

export const recordCicdScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** CI/CD file items to scan: filename + full file content. */
    fileItems: v.array(
      v.object({
        filename: v.string(),
        content: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    if (args.fileItems.length === 0) return null

    // ── Scan each file ─────────────────────────────────────────────────────
    const fileResults = args.fileItems
      .slice(0, MAX_FILE_RESULTS)
      .map((item) => scanCicdFile(item.filename, item.content))

    const combined = combineCicdResults(fileResults)

    // Cap findings per file to stay under Convex doc size limit
    const cappedFileResults = combined.fileResults.map((fr) => ({
      filename: fr.filename,
      fileType: fr.fileType,
      criticalCount: fr.criticalCount,
      highCount: fr.highCount,
      mediumCount: fr.mediumCount,
      lowCount: fr.lowCount,
      findings: fr.findings.slice(0, MAX_FINDINGS_PER_FILE).map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        title: f.title,
        remediation: f.remediation,
      })),
    }))

    const now = Date.now()
    await ctx.db.insert('cicdScanResults', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      branch: args.branch,
      commitSha: args.commitSha,
      totalFiles: combined.totalFiles,
      totalFindings: combined.totalFindings,
      criticalCount: combined.criticalCount,
      highCount: combined.highCount,
      mediumCount: combined.mediumCount,
      lowCount: combined.lowCount,
      overallRisk: combined.overallRisk,
      fileResults: cappedFileResults,
      summary: combined.summary,
      computedAt: now,
    })

    // ── Prune old rows ──────────────────────────────────────────────────────
    const allRows = await ctx.db
      .query('cicdScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (allRows.length > MAX_SCANS_PER_REPO) {
      const toDelete = allRows.slice(MAX_SCANS_PER_REPO)
      await Promise.all(toDelete.map((row) => ctx.db.delete(row._id)))
    }

    return {
      totalFiles: combined.totalFiles,
      totalFindings: combined.totalFindings,
      overallRisk: combined.overallRisk,
    }
  },
})

// ---------------------------------------------------------------------------
// triggerCicdScanForRepository (public mutation)
// ---------------------------------------------------------------------------

export const triggerCicdScanForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    fileItems: v.array(
      v.object({
        filename: v.string(),
        content: v.string(),
      }),
    ),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(0, internal.cicdScanIntel.recordCicdScan, {
      tenantId: tenant._id,
      repositoryId: repository._id,
      branch: args.branch,
      fileItems: args.fileItems,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestCicdScan (public query)
// ---------------------------------------------------------------------------

export const getLatestCicdScan = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) return null

    return ctx.db
      .query('cicdScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getCicdScanHistory (public query)
// ---------------------------------------------------------------------------

export const getCicdScanHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 20, 50)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) return []

    const rows = await ctx.db
      .query('cicdScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      totalFiles: r.totalFiles,
      totalFindings: r.totalFindings,
      criticalCount: r.criticalCount,
      highCount: r.highCount,
      overallRisk: r.overallRisk,
      summary: r.summary,
      computedAt: r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getCicdScanSummaryByTenant (public query)
// ---------------------------------------------------------------------------

export const getCicdScanSummaryByTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const rows = await ctx.db
      .query('cicdScanResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Latest per repo
    const latestByRepo = new Map<string, (typeof rows)[0]>()
    for (const row of rows) {
      if (!latestByRepo.has(row.repositoryId)) latestByRepo.set(row.repositoryId, row)
    }

    const latest = [...latestByRepo.values()]
    const criticalRepos = latest.filter((r) => r.overallRisk === 'critical').length
    const highRepos = latest.filter((r) => r.overallRisk === 'high').length
    const totalFindings = latest.reduce((s, r) => s + r.totalFindings, 0)
    const totalCritical = latest.reduce((s, r) => s + r.criticalCount, 0)

    return {
      totalRepositoriesScanned: latest.length,
      criticalRiskRepos: criticalRepos,
      highRiskRepos: highRepos,
      cleanRepos: latest.filter((r) => r.overallRisk === 'none').length,
      totalFindings,
      totalCritical,
    }
  },
})
