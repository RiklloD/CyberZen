// WS-30 — Hardcoded Credential & Secret Detection Engine: Convex entrypoints.
//
//   recordSecretScan        — internal mutation: scans a list of content strings
//       and stores the aggregated result for a repository push event.
//
//   getLatestSecretScan     — public query: latest scan result for a repository
//       resolved via tenantSlug + repositoryFullName.
//
//   getSecretScanHistory    — public query: lean last-N results (findings
//       arrays stripped) for sparklines.
//
//   getSecretScanSummaryByTenant — public query: tenant-wide aggregate counts.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { combineResults, scanForSecrets } from './lib/secretDetection'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SCANS_PER_REPO = 50

// ---------------------------------------------------------------------------
// recordSecretScan (internal mutation)
// ---------------------------------------------------------------------------

export const recordSecretScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /**
     * Array of content items to scan. Each item has the string content and an
     * optional filename that enables test-file-hint tagging.
     */
    contentItems: v.array(
      v.object({
        content: v.string(),
        filename: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, args) => {
    if (args.contentItems.length === 0) return null

    // Run the pure scanner on each content item then combine.
    const results = args.contentItems.map((item) =>
      scanForSecrets(item.content, item.filename),
    )
    const combined = combineResults(results)

    const now = Date.now()
    const id = await ctx.db.insert('secretScanResults', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      branch: args.branch,
      commitSha: args.commitSha,
      scannedItems: args.contentItems.length,
      findings: combined.findings,
      criticalCount: combined.criticalCount,
      highCount: combined.highCount,
      mediumCount: combined.mediumCount,
      totalFound: combined.totalFound,
      summary: combined.summary,
      computedAt: now,
    })

    // Prune old rows
    const allRows = await ctx.db
      .query('secretScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (allRows.length > MAX_SCANS_PER_REPO) {
      const toDelete = allRows.slice(MAX_SCANS_PER_REPO)
      await Promise.all(toDelete.map((row) => ctx.db.delete(row._id)))
    }

    return { id, totalFound: combined.totalFound, criticalCount: combined.criticalCount }
  },
})

// ---------------------------------------------------------------------------
// triggerSecretScanForRepository (public mutation — on-demand/manual trigger)
// ---------------------------------------------------------------------------

export const triggerSecretScanForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    contentItems: v.array(
      v.object({
        content: v.string(),
        filename: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, args) => {
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

    if (args.contentItems.length === 0) return { scanned: 0, totalFound: 0 }

    const results = args.contentItems.map((item) =>
      scanForSecrets(item.content, item.filename),
    )
    const combined = combineResults(results)

    await ctx.db.insert('secretScanResults', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      branch: args.branch,
      scannedItems: args.contentItems.length,
      findings: combined.findings,
      criticalCount: combined.criticalCount,
      highCount: combined.highCount,
      mediumCount: combined.mediumCount,
      totalFound: combined.totalFound,
      summary: combined.summary,
      computedAt: Date.now(),
    })

    return {
      scanned: args.contentItems.length,
      totalFound: combined.totalFound,
      criticalCount: combined.criticalCount,
      summary: combined.summary,
    }
  },
})

// ---------------------------------------------------------------------------
// getLatestSecretScan (public query)
// ---------------------------------------------------------------------------

export const getLatestSecretScan = query({
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
      .query('secretScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSecretScanHistory (public query)
// ---------------------------------------------------------------------------

/** Lean last-N scan results for sparklines — findings arrays stripped. */
export const getSecretScanHistory = query({
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
      .query('secretScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      branch: r.branch,
      commitSha: r.commitSha,
      criticalCount: r.criticalCount,
      highCount: r.highCount,
      mediumCount: r.mediumCount,
      totalFound: r.totalFound,
      summary: r.summary,
      computedAt: r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getSecretScanSummaryByTenant (public query)
// ---------------------------------------------------------------------------

/**
 * Tenant-wide aggregate: how many repositories have at least one finding,
 * and total critical/high/medium counts across the most recent scan per repo.
 */
export const getSecretScanSummaryByTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    // Load the last 200 scans across all repos for this tenant
    const rows = await ctx.db
      .query('secretScanResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Deduplicate: keep only the most recent row per repositoryId
    const latestByRepo = new Map<string, (typeof rows)[0]>()
    for (const row of rows) {
      if (!latestByRepo.has(row.repositoryId)) {
        latestByRepo.set(row.repositoryId, row)
      }
    }

    const latestRows = [...latestByRepo.values()]
    const totalCritical = latestRows.reduce((s, r) => s + r.criticalCount, 0)
    const totalHigh = latestRows.reduce((s, r) => s + r.highCount, 0)
    const totalMedium = latestRows.reduce((s, r) => s + r.mediumCount, 0)
    const affectedRepoCount = latestRows.filter((r) => r.totalFound > 0).length

    return {
      totalRepositoriesScanned: latestRows.length,
      affectedRepoCount,
      totalCritical,
      totalHigh,
      totalMedium,
      totalFindings: totalCritical + totalHigh + totalMedium,
    }
  },
})
