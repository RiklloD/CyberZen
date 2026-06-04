/**
 * WS-95 — Endpoint Security & EDR Configuration Drift Detector:
 * Convex entrypoints.
 *
 * Analyses changed file paths from a push event for modifications to endpoint
 * security and EDR configuration: CrowdStrike Falcon EDR agent and prevention
 * policy configuration (falcon.cfg, crowdstrike-policy.json, falcon/ dirs),
 * SentinelOne agent and policy configuration (sentinelone.conf, s1-policy.json),
 * Microsoft Defender for Endpoint managed configuration (mdatp-managed.json,
 * wdav-config.json, defender/ dirs), EDR and antivirus exclusion lists
 * (edr-exclusions.json, av-exclusions.conf — adversary-targeted), MDM and UEM
 * device enrollment and compliance policy configuration (Jamf Pro, Microsoft
 * Intune, SCCM — .mobileconfig profiles, intune-policy.json), Carbon Black and
 * Sophos endpoint security agent configuration (cbagent.cfg, sophos.conf,
 * savdi.conf), vulnerability scanner agent configuration (Nessus, OpenVAS/GVM,
 * Qualys, Tenable, Rapid7), and Tanium and IBM BigFix endpoint management
 * configuration (tanium.conf, bigfix.conf, besclient.conf).
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordEndpointSecurityDriftScan        — internalMutation: run scanner, persist result
 *   triggerEndpointSecurityDriftScan       — public mutation: on-demand by slug+fullName
 *   getLatestEndpointSecurityDriftScan     — public query: most recent result for a repo
 *   getLatestEndpointSecurityDriftBySlug   — public query: slug-based (for dashboard/HTTP)
 *   getEndpointSecurityDriftScanHistory    — public query: last 30 lean summaries
 *   getEndpointSecurityDriftSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanEndpointSecurityDrift } from './lib/endpointSecurityDrift'

const MAX_ROWS_PER_REPO = 30
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordEndpointSecurityDriftScan — internalMutation
// ---------------------------------------------------------------------------

export const recordEndpointSecurityDriftScan = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha:    v.string(),
    branch:       v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles }) => {
    const paths  = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanEndpointSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('endpointSecurityDriftResults', {
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

    const all = await ctx.db
      .query('endpointSecurityDriftResults')
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
// triggerEndpointSecurityDriftScan — public mutation
// ---------------------------------------------------------------------------

export const triggerEndpointSecurityDriftScan = mutation({
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
    const result = scanEndpointSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('endpointSecurityDriftResults', {
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

    const all = await ctx.db
      .query('endpointSecurityDriftResults')
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
// getLatestEndpointSecurityDriftScan — public query
// ---------------------------------------------------------------------------

export const getLatestEndpointSecurityDriftScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('endpointSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestEndpointSecurityDriftBySlug — public query (slug-based)
// ---------------------------------------------------------------------------

export const getLatestEndpointSecurityDriftBySlug = query({
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
      .query('endpointSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getEndpointSecurityDriftScanHistory — public query (lean summaries)
// ---------------------------------------------------------------------------

export const getEndpointSecurityDriftScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit:        v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('endpointSecurityDriftResults')
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
// getEndpointSecurityDriftSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getEndpointSecurityDriftSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('endpointSecurityDriftResults')
      .withIndex('by_tenant_and_scanned_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(500)

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
