/**
 * WS-63 — Kubernetes & Container Security Hardening Drift Detector: Convex entrypoints.
 *
 * Analyses the changed file paths from a push event to detect modifications to
 * Kubernetes security configuration and container hardening files. Covers 8
 * domains: Kubernetes RBAC, NetworkPolicy, PodSecurityPolicy/Admission,
 * admission controllers, external secrets, Dockerfile hardening, container
 * runtime security profiles, and Helm chart security values.
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordContainerHardeningDriftScan       — internalMutation: run scanner, persist result
 *   triggerContainerHardeningDriftScan      — public mutation: on-demand by slug+fullName
 *   getLatestContainerHardeningDriftScan    — public query: most recent result for a repo
 *   getLatestContainerHardeningDriftBySlug  — public query: slug-based (for dashboard/HTTP)
 *   getContainerHardeningDriftScanHistory   — public query: last 30 lean summaries
 *   getContainerHardeningDriftSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanContainerHardeningDrift } from './lib/containerHardeningDrift'

const MAX_ROWS_PER_REPO = 30
/** Cap on paths passed to the scanner to keep execution time bounded. */
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordContainerHardeningDriftScan — internalMutation
// ---------------------------------------------------------------------------

export const recordContainerHardeningDriftScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha: v.string(),
    branch: v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles }) => {
    const paths = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanContainerHardeningDrift(paths)
    const now = Date.now()

    await ctx.db.insert('containerHardeningDriftResults', {
      tenantId,
      repositoryId,
      commitSha,
      branch,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.mediumCount,
      findings: result.findings,
      summary: result.summary,
      scannedAt: now,
    })

    // Prune old rows to keep storage bounded
    const all = await ctx.db
      .query('containerHardeningDriftResults')
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
// triggerContainerHardeningDriftScan — public mutation
// ---------------------------------------------------------------------------

export const triggerContainerHardeningDriftScan = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    commitSha: v.string(),
    branch: v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, commitSha, branch, changedFiles }) => {
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
    const result = scanContainerHardeningDrift(paths)
    const now = Date.now()

    await ctx.db.insert('containerHardeningDriftResults', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      commitSha,
      branch,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.mediumCount,
      findings: result.findings,
      summary: result.summary,
      scannedAt: now,
    })

    // Prune old rows
    const all = await ctx.db
      .query('containerHardeningDriftResults')
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
// getLatestContainerHardeningDriftScan — public query
// ---------------------------------------------------------------------------

export const getLatestContainerHardeningDriftScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('containerHardeningDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestContainerHardeningDriftBySlug — public query (slug-based, for dashboard)
// ---------------------------------------------------------------------------

export const getLatestContainerHardeningDriftBySlug = query({
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
      .query('containerHardeningDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getContainerHardeningDriftScanHistory — public query (lean summaries)
// ---------------------------------------------------------------------------

export const getContainerHardeningDriftScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('containerHardeningDriftResults')
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
// getContainerHardeningDriftSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getContainerHardeningDriftSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('containerHardeningDriftResults')
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
    const highRepos     = latest.filter((s) => s.riskLevel === 'high').length
    const mediumRepos   = latest.filter((s) => s.riskLevel === 'medium').length
    const lowRepos      = latest.filter((s) => s.riskLevel === 'low').length
    const cleanRepos    = latest.filter((s) => s.riskLevel === 'none').length
    const totalFindings = latest.reduce((a, s) => a + s.totalFindings, 0)

    const worstRepo =
      latest.length > 0 ? latest.reduce((a, b) => (a.riskScore > b.riskScore ? a : b)) : null

    return {
      repositoriesScanned: latest.length,
      criticalRepos,
      highRepos,
      mediumRepos,
      lowRepos,
      cleanRepos,
      totalFindings,
      worstRepositoryId: worstRepo?.riskScore ? worstRepo.repositoryId : null,
      worstRiskScore:    worstRepo?.riskScore ?? null,
    }
  },
})
