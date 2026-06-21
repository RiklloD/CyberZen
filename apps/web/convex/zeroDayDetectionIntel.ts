/**
 * WS-98 — Zero-Day Anomaly Detection: Convex entrypoints (spec §3.1.3)
 *
 * Triggered fire-and-forget from semanticFingerprintIntel.analyzeCodeChange when
 * the fingerprint match confidence is below 0.3 (no strong known-vuln-class match).
 *
 * Entrypoints:
 *   recordZeroDayDetection          — internalMutation: run detector + persist
 *   getLatestZeroDayDetection       — query: most recent result for a repo (by id)
 *   getLatestZeroDayDetectionBySlug — query: slug-based for dashboard/HTTP
 *   getZeroDayDetectionHistory      — query: last N detections per repo (by slug)
 *   getZeroDayDetectionSummaryByTenant — query: tenant-wide repo breakdown + totals
 */

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import { detectZeroDayAnomalies, type ZeroDayInput } from './lib/zeroDayDetector'

const MAX_ROWS_PER_REPO = 20

// ---------------------------------------------------------------------------

/** Resolve a tenant row from its slug via the by_slug index. */
async function resolveTenantBySlug(ctx: any, tenantSlug: string) {
  return ctx.db
    .query('tenants')
    .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
    .first()
}

/** Map a zero-day category to a UI severity label. */
function categoryToSeverity(
  category: string,
): 'critical' | 'high' | 'medium' | 'low' {
  switch (category) {
    case 'potential_zero_day':
      return 'critical'
    case 'suspicious_change':
      return 'high'
    case 'novel_pattern':
      return 'medium'
    default:
      return 'low'
  }
}

/** Humanize a snake_case signal type for display. */
function humanizeSignalType(signalType: string): string {
  return signalType
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

// ---------------------------------------------------------------------------
// recordZeroDayDetection — internalMutation
// ---------------------------------------------------------------------------

export const recordZeroDayDetection = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
    ref:          v.string(),
    changedFiles:              v.array(v.string()),
    addedLines:                v.array(v.string()),
    recentBreachTypes:         v.array(v.string()),
    hasTestChanges:            v.boolean(),
    hasLockfileChanges:        v.boolean(),
    fingerprintMatchConfidence: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const {
      tenantId, repositoryId, ref,
      changedFiles, addedLines, recentBreachTypes,
      hasTestChanges, hasLockfileChanges, fingerprintMatchConfidence,
    } = args

    const input: ZeroDayInput = {
      changedFiles,
      addedLines,
      recentBreachTypes,
      hasTestChanges,
      hasLockfileChanges,
      fingerprintMatchConfidence,
    }

    const result = detectZeroDayAnomalies(input)

    await ctx.db.insert('zeroDayDetections', {
      tenantId,
      repositoryId,
      ref,
      signals: result.signals,
      anomalyScore: result.anomalyScore,
      category: result.category,
      recommendation: result.recommendation,
      fingerprintMatchConfidence,
      detectedAt: Date.now(),
    })

    // Prune oldest rows beyond cap
    const old = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repositoryId))
      .order('asc')
      .take(MAX_ROWS_PER_REPO + 10)

    if (old.length > MAX_ROWS_PER_REPO) {
      for (const row of old.slice(0, old.length - MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(row._id)
      }
    }

    return { category: result.category, anomalyScore: result.anomalyScore }
  },
})

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const getLatestZeroDayDetection = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

/**
 * Latest detection for a repo, resolved by tenant slug + repo full name.
 * Returns a Detection-shaped object with a findings[] array derived from
 * the stored signals[].
 */
export const getLatestZeroDayDetectionBySlug = query({
  args: { tenantSlug: v.string(), repositoryFullName: v.string() },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await resolveTenantBySlug(ctx, tenantSlug)
    if (!tenant) return null

    const repo = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q: any) =>
        q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
      )
      .first()
    if (!repo) return null

    const doc = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repo._id))
      .order('desc')
      .first()
    if (!doc) return null

    const severity = categoryToSeverity(doc.category)

    return {
      _id: doc._id,
      ref: doc.ref,
      overallAnomalyScore: doc.anomalyScore,
      analyzedAt: doc.detectedAt,
      summary: doc.recommendation,
      findings: doc.signals.map((s: any, i: number) => ({
        _id: `${doc._id}#${i}`,
        anomalyType: s.signalType,
        severity,
        confidenceScore: Math.round(s.confidence * 100),
        investigated: false,
        title: humanizeSignalType(s.signalType),
        description: s.evidence,
        filePath: s.affectedFiles[0] ?? null,
        lineRange: null,
        packageName: null,
        packageVersion: null,
        detectedAt: doc.detectedAt,
        anomalyFlags: [s.signalType],
      })),
    }
  },
})

/**
 * Detection history for a repo (by slug), newest first.
 * Each entry carries the anomaly score, signal count, and timestamp.
 */
export const getZeroDayDetectionHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, limit }) => {
    const tenant = await resolveTenantBySlug(ctx, tenantSlug)
    if (!tenant) return []

    const repo = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q: any) =>
        q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
      )
      .first()
    if (!repo) return []

    const rows = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repo._id))
      .order('desc')
      .take(limit ?? 20)

    return rows.map((r) => ({
      _id: r._id,
      ref: r.ref,
      anomalyScore: r.anomalyScore,
      analyzedAt: r.detectedAt,
      findingCount: r.signals.length,
      repositoryName: repo.name,
    }))
  },
})

/**
 * Tenant-wide summary: per-repo breakdown of non-benign detections plus
 * aggregate totals for the page header.
 */
export const getZeroDayDetectionSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await resolveTenantBySlug(ctx, tenantSlug)
    if (!tenant) return null

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .collect()

    // Gather recent detections tenant-wide (bounded)
    const allDetections = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_tenant_and_detected_at', (q: any) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Group detections by repository
    const detectionsByRepo = new Map<string, any[]>()
    for (const d of allDetections) {
      const list = detectionsByRepo.get(d.repositoryId) ?? []
      list.push(d)
      detectionsByRepo.set(d.repositoryId, list)
    }

    let totalSignals = 0
    let criticalCount = 0 // potential_zero_day
    let highCount = 0 // suspicious_change
    let uninvestigatedCount = 0 // all non-benign
    let anomalyScoreSum = 0
    let nonBenignCount = 0

    const repoSummaries = repositories.map((repo: any) => {
      const repoDetections = detectionsByRepo.get(repo._id) ?? []
      const nonBenign = repoDetections.filter((d) => d.category !== 'benign')
      const repoCritical = nonBenign.filter(
        (d) => d.category === 'potential_zero_day',
      ).length
      const repoSignals = nonBenign.reduce(
        (sum, d) => sum + d.signals.length,
        0,
      )

      // Roll up tenant totals
      totalSignals += repoSignals
      criticalCount += repoCritical
      highCount += nonBenign.filter((d) => d.category === 'suspicious_change').length
      uninvestigatedCount += nonBenign.length
      for (const d of nonBenign) {
        anomalyScoreSum += d.anomalyScore
        nonBenignCount += 1
      }

      return {
        repositoryId: repo._id,
        repositoryFullName: repo.fullName,
        findingCount: repoSignals,
        criticalCount: repoCritical,
      }
    })

    return {
      repositories: repoSummaries,
      tenantTotals: {
        totalFindings: totalSignals,
        criticalCount,
        highCount,
        uninvestigatedCount,
        avgAnomalyScore: nonBenignCount > 0 ? anomalyScoreSum / nonBenignCount : 0,
      },
    }
  },
})
