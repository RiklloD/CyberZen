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
 *   getZeroDayDetectionHistory      — query: last 20 detections per repo
 *   getZeroDayDetectionSummaryByTenant — query: tenant-wide non-benign counts
 */

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import { detectZeroDayAnomalies, type ZeroDayInput } from './lib/zeroDayDetector'

const MAX_ROWS_PER_REPO = 20

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

export const getLatestZeroDayDetectionBySlug = query({
  args: { tenantSlug: v.string(), repositoryFullName: v.string() },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return null

    const repo = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repo) return null

    return ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repo._id))
      .order('desc')
      .first()
  },
})

export const getZeroDayDetectionHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const rows = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_repository_and_detected_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(20)

    return rows.map((r) => ({
      _id: r._id,
      ref: r.ref,
      category: r.category,
      anomalyScore: r.anomalyScore,
      signalCount: r.signals.length,
      detectedAt: r.detectedAt,
    }))
  },
})

export const getZeroDayDetectionSummaryByTenant = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    const rows = await ctx.db
      .query('zeroDayDetections')
      .withIndex('by_tenant_and_detected_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200)

    let potentialZeroDays = 0
    let suspiciousChanges = 0
    let novelPatterns = 0

    for (const r of rows) {
      if (r.category === 'potential_zero_day') potentialZeroDays++
      else if (r.category === 'suspicious_change') suspiciousChanges++
      else if (r.category === 'novel_pattern') novelPatterns++
    }

    return {
      potentialZeroDays,
      suspiciousChanges,
      novelPatterns,
      total: rows.length,
    }
  },
})
