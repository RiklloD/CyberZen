/**
 * WS-105 — Secret Management Configuration Drift Detector: Convex entrypoints.
 *
 * Analyses changed file paths from a push event for modifications to secret
 * management infrastructure configuration: HashiCorp Vault server config
 * (vault.hcl), Vault access policies (*.hcl in vault/policies/), AWS Secrets
 * Manager configuration (secrets-manager.json / rotation lambda), Azure Key
 * Vault access policies (keyvault-*.json / azure-key-vault.yaml), SOPS
 * encryption rules (.sops.yaml), Sealed Secrets controller config, External
 * Secrets Operator SecretStore/ClusterSecretStore, and third-party provider
 * integrations (Doppler / 1Password Connect / Infisical).
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordSecretMgmtDriftScan          — internalMutation: run scanner, persist result
 *   triggerSecretMgmtDriftScan         — public mutation: on-demand by slug+fullName
 *   getLatestSecretMgmtDriftScan       — public query: most recent result for a repo
 *   getLatestSecretMgmtDriftBySlug     — public query: slug-based (for dashboard/HTTP)
 *   getSecretMgmtDriftScanHistory      — public query: last 30 lean summaries
 *   getSecretMgmtDriftSummaryByTenant  — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanSecretMgmtDrift } from './lib/secretMgmtDrift'

const MAX_ROWS_PER_REPO = 30
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordSecretMgmtDriftScan — internalMutation
// ---------------------------------------------------------------------------

export const recordSecretMgmtDriftScan = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha:    v.string(),
    branch:       v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles }) => {
    const paths  = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanSecretMgmtDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('secretMgmtDriftResults', {
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
      .query('secretMgmtDriftResults')
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
// triggerSecretMgmtDriftScan — public mutation
// ---------------------------------------------------------------------------

export const triggerSecretMgmtDriftScan = mutation({
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
    const result = scanSecretMgmtDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('secretMgmtDriftResults', {
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
      .query('secretMgmtDriftResults')
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
// getLatestSecretMgmtDriftScan — public query
// ---------------------------------------------------------------------------

export const getLatestSecretMgmtDriftScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('secretMgmtDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestSecretMgmtDriftBySlug — public query (slug-based)
// ---------------------------------------------------------------------------

export const getLatestSecretMgmtDriftBySlug = query({
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
      .query('secretMgmtDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSecretMgmtDriftScanHistory — public query (lean summaries)
// ---------------------------------------------------------------------------

export const getSecretMgmtDriftScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit:        v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('secretMgmtDriftResults')
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
// getSecretMgmtDriftSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getSecretMgmtDriftSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('secretMgmtDriftResults')
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
