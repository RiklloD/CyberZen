/**
 * WS-91 — IoT & Embedded Device Security Configuration Drift Detector:
 * Convex entrypoints.
 *
 * Analyses changed file paths from a push event for modifications to IoT and
 * embedded device security configuration: Balena IoT fleet configuration
 * (balena.yml, balena-compose.yml, fleet-config/), AWS IoT Greengrass
 * configuration (greengrass-config.json, gg-config.json, config.json in
 * greengrass/ dirs), firmware signing and secure-boot configuration (signing_config.json,
 * mcuboot.config.yaml, imgtool-signing.conf, esptool.cfg, bootloader-keys.json),
 * Mender OTA update configuration (mender.conf, mender-artifact.conf, artifact_info),
 * Zigbee/Z-Wave controller configuration (zigbee2mqtt/configuration.yaml,
 * zwavejs2mqtt/settings.json, zwavejs*.json, zigbee-*.yaml), Azure IoT Hub / DPS
 * configuration (iothub-connection.json, dps-config.json, iotedge-config.yaml),
 * IoT device management platforms (thingsboard.yml, hawkbit.yml, edgex-configuration.toml,
 * pelion-config.json), and LoRaWAN / network gateway configuration (chirpstack.toml,
 * the-things-stack.yml, lorawan-server.toml).
 *
 * Triggered fire-and-forget from events.ts on every push.
 *
 * Entrypoints:
 *   recordIotEmbeddedSecurityDriftScan        — internalMutation: run scanner, persist result
 *   triggerIotEmbeddedSecurityDriftScan       — public mutation: on-demand by slug+fullName
 *   getLatestIotEmbeddedSecurityDriftScan     — public query: most recent result for a repo
 *   getLatestIotEmbeddedSecurityDriftBySlug   — public query: slug-based (for dashboard/HTTP)
 *   getIotEmbeddedSecurityDriftScanHistory    — public query: last 30 lean summaries
 *   getIotEmbeddedSecurityDriftSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { scanIotEmbeddedSecurityDrift } from './lib/iotEmbeddedSecurityDrift'

const MAX_ROWS_PER_REPO = 30
const MAX_PATHS_PER_SCAN = 500

// ---------------------------------------------------------------------------
// recordIotEmbeddedSecurityDriftScan — internalMutation
// ---------------------------------------------------------------------------

export const recordIotEmbeddedSecurityDriftScan = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha:    v.string(),
    branch:       v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, { tenantId, repositoryId, commitSha, branch, changedFiles }) => {
    const paths  = changedFiles.slice(0, MAX_PATHS_PER_SCAN)
    const result = scanIotEmbeddedSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('iotEmbeddedSecurityDriftResults', {
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
      .query('iotEmbeddedSecurityDriftResults')
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
// triggerIotEmbeddedSecurityDriftScan — public mutation
// ---------------------------------------------------------------------------

export const triggerIotEmbeddedSecurityDriftScan = mutation({
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
    const result = scanIotEmbeddedSecurityDrift(paths)
    const now    = Date.now()

    await ctx.db.insert('iotEmbeddedSecurityDriftResults', {
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
      .query('iotEmbeddedSecurityDriftResults')
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
// getLatestIotEmbeddedSecurityDriftScan — public query
// ---------------------------------------------------------------------------

export const getLatestIotEmbeddedSecurityDriftScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('iotEmbeddedSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestIotEmbeddedSecurityDriftBySlug — public query (slug-based)
// ---------------------------------------------------------------------------

export const getLatestIotEmbeddedSecurityDriftBySlug = query({
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
      .query('iotEmbeddedSecurityDriftResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getIotEmbeddedSecurityDriftScanHistory — public query (lean summaries)
// ---------------------------------------------------------------------------

export const getIotEmbeddedSecurityDriftScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit:        v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('iotEmbeddedSecurityDriftResults')
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
// getIotEmbeddedSecurityDriftSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getIotEmbeddedSecurityDriftSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('iotEmbeddedSecurityDriftResults')
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
