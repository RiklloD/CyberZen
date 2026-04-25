/**
 * WS-75 — Web Server & Reverse Proxy Security Configuration Drift Detector:
 * Convex entrypoints.
 *
 * Analyses changed file paths from a push event for modifications to web
 * server and reverse proxy security configuration files. Covers 8 domains:
 * nginx virtualhost and server-block configs, Apache .htaccess and httpd.conf,
 * Traefik static configuration files, Caddy Caddyfile variants, Kubernetes
 * ingress controller security configs, ModSecurity/OWASP CRS WAF rules,
 * SSL/TLS termination parameter files, and web server access control configs
 * (.htpasswd, geo IP allow/deny).
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordWebServerSecurityDriftScan        — internalMutation: run scanner, persist result
 *   triggerWebServerSecurityDriftScan       — public mutation: on-demand by slug+fullName
 *   getLatestWebServerSecurityDriftScan     — public query: most recent result for a repo
 *   getLatestWebServerSecurityDriftBySlug   — public query: slug-based (for dashboard/HTTP)
 *   getWebServerSecurityDriftScanHistory    — public query: last 30 lean summaries
 *   getWebServerSecurityDriftSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanWebServerSecurityDrift } from './lib/webServerSecurityDrift'

const MAX_ROWS_PER_REPO = 30
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordWebServerSecurityDriftScan — internalMutation
// ---------------------------------------------------------------------------

export const recordWebServerSecurityDriftScan = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha:    v.string(),
    branch:       v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles }) => {
    const paths  = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanWebServerSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('webServerSecurityDriftResults', {
      tenantId,
      repositoryId,
      commitSha,
      branch,
      riskScore:     result.riskScore,
      riskLevel:     result.riskLevel,
      totalFindings: result.totalFindings,
      highCount:     result.highCount,
      mediumCount:   result.mediumCount,
      lowCount:      result.lowCount,
      findings:      result.findings,
      summary:       result.summary,
      scannedAt:     now,
    })

    // Prune old rows to keep storage bounded
    const all = await ctx.db
      .query('webServerSecurityDriftResults')
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
// triggerWebServerSecurityDriftScan — public mutation
// ---------------------------------------------------------------------------

export const triggerWebServerSecurityDriftScan = mutation({
  args: {
    tenantSlug:         v.string(),
    repositoryFullName: v.string(),
    commitSha:          v.string(),
    branch:             v.string(),
    changedFiles:       v.array(v.string()),
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

    const paths  = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanWebServerSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('webServerSecurityDriftResults', {
      tenantId:      tenant._id,
      repositoryId:  repository._id,
      commitSha,
      branch,
      riskScore:     result.riskScore,
      riskLevel:     result.riskLevel,
      totalFindings: result.totalFindings,
      highCount:     result.highCount,
      mediumCount:   result.mediumCount,
      lowCount:      result.lowCount,
      findings:      result.findings,
      summary:       result.summary,
      scannedAt:     now,
    })

    // Prune old rows
    const all = await ctx.db
      .query('webServerSecurityDriftResults')
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
// getLatestWebServerSecurityDriftScan — public query
// ---------------------------------------------------------------------------

export const getLatestWebServerSecurityDriftScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('webServerSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestWebServerSecurityDriftBySlug — public query (slug-based)
// ---------------------------------------------------------------------------

export const getLatestWebServerSecurityDriftBySlug = query({
  args: {
    tenantSlug:         v.string(),
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
      .query('webServerSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getWebServerSecurityDriftScanHistory — public query (lean summaries)
// ---------------------------------------------------------------------------

export const getWebServerSecurityDriftScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit:        v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('webServerSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      _id:           r._id,
      commitSha:     r.commitSha,
      branch:        r.branch,
      riskScore:     r.riskScore,
      riskLevel:     r.riskLevel,
      totalFindings: r.totalFindings,
      scannedAt:     r.scannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getWebServerSecurityDriftSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getWebServerSecurityDriftSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('webServerSecurityDriftResults')
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
