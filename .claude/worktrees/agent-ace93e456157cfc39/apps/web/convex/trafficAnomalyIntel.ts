// WS-29 — Production Traffic Anomaly Detection (spec §10 Phase 4): Convex
// entrypoints.
//
//   ingestTrafficEvents      — public mutation: accepts a batch of HTTP traffic
//       events, runs computeTrafficAnomaly, stores snapshot, optionally fires
//       finding creation for anomalous/critical results.
//
//   getLatestTrafficAnomaly  — public query: latest snapshot for a repository
//       resolved via tenantSlug + repositoryFullName.
//
//   getTrafficAnomalyHistory — public query: lean last-N snapshots for sparklines.
//
// HTTP endpoint: POST /api/traffic/events?tenantSlug=&repositoryFullName=
// (registered in http.ts — requires SENTINEL_API_KEY)

import { v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { computeTrafficAnomaly, type TrafficEvent } from './lib/trafficAnomaly'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SNAPSHOTS_PER_REPO = 50
const MAX_EVENTS_PER_BATCH = 5_000
const FINDING_CREATION_THRESHOLD = 50 // anomalyScore ≥ this creates a finding

// ---------------------------------------------------------------------------
// ingestTrafficEvents (public mutation)
// ---------------------------------------------------------------------------

export const ingestTrafficEvents = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    events: v.array(
      v.object({
        timestamp: v.number(),
        method: v.string(),
        path: v.string(),
        statusCode: v.number(),
        latencyMs: v.number(),
        userAgent: v.optional(v.string()),
        requestSizeBytes: v.optional(v.number()),
      }),
    ),
  },
  handler: async (ctx, args) => {
    // ── Resolve tenant ────────────────────────────────────────────────────────
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    // ── Resolve repository ────────────────────────────────────────────────────
    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    // ── Clamp event batch to MAX_EVENTS_PER_BATCH ─────────────────────────────
    const events: TrafficEvent[] = args.events.slice(0, MAX_EVENTS_PER_BATCH)

    // ── Compute anomaly ───────────────────────────────────────────────────────
    const result = computeTrafficAnomaly(events)

    // ── Persist snapshot ──────────────────────────────────────────────────────
    await ctx.db.insert('trafficAnomalySnapshots', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      anomalyScore: result.anomalyScore,
      level: result.level,
      patterns: result.patterns,
      findingCandidates: result.findingCandidates,
      stats: result.stats,
      summary: result.summary,
      computedAt: Date.now(),
    })

    // ── Prune old rows ────────────────────────────────────────────────────────
    const allRows = await ctx.db
      .query('trafficAnomalySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .collect()

    if (allRows.length > MAX_SNAPSHOTS_PER_REPO) {
      const toDelete = allRows.slice(MAX_SNAPSHOTS_PER_REPO)
      await Promise.all(toDelete.map((row) => ctx.db.delete(row._id)))
    }

    // ── Optionally create findings for high-confidence candidates ─────────────
    if (result.anomalyScore >= FINDING_CREATION_THRESHOLD && result.findingCandidates.length > 0) {
      const now = Date.now()
      const dedupeKey = `traffic-anomaly-${repository._id}-${now}`

      // Synthetic ingestion event representing the traffic monitor source
      const ingestionEventId = await ctx.db.insert('ingestionEvents', {
        tenantId: tenant._id,
        repositoryId: repository._id,
        dedupeKey,
        kind: 'traffic_anomaly',
        source: 'traffic_monitor',
        workflowType: 'traffic_anomaly_detection',
        status: 'completed',
        summary: result.summary,
        receivedAt: now,
      })

      const workflowRunId = await ctx.db.insert('workflowRuns', {
        tenantId: tenant._id,
        repositoryId: repository._id,
        eventId: ingestionEventId,
        workflowType: 'traffic_anomaly_detection',
        status: 'completed',
        priority: result.level === 'critical' ? 'critical' : result.level === 'anomalous' ? 'high' : 'medium',
        summary: result.summary,
        totalTaskCount: 1,
        completedTaskCount: 1,
        startedAt: now,
        completedAt: now,
      })

      // Create one finding per unique vuln class (cap at 3 per batch)
      const candidates = result.findingCandidates.slice(0, 3)
      for (const candidate of candidates) {
        await ctx.db.insert('findings', {
          tenantId: tenant._id,
          repositoryId: repository._id,
          workflowRunId,
          source: 'traffic_monitor',
          vulnClass: candidate.vulnClass,
          title: `[Traffic] ${candidate.vulnClass.replace(/_/g, ' ')} detected in production traffic`,
          summary: candidate.description,
          confidence: Math.round(candidate.confidence * 100),
          severity: candidate.severity,
          validationStatus: 'likely_exploitable',
          status: 'open',
          businessImpactScore: result.anomalyScore,
          blastRadiusSummary: `Traffic anomaly score ${result.anomalyScore} — ${result.stats.totalRequests} requests analyzed`,
          affectedServices: [],
          affectedFiles: [],
          affectedPackages: [],
          regulatoryImplications: [],
          createdAt: now,
        })
      }
    }

    return {
      anomalyScore: result.anomalyScore,
      level: result.level,
      patternsDetected: result.patterns.length,
      findingCandidates: result.findingCandidates.length,
      summary: result.summary,
    }
  },
})

// ---------------------------------------------------------------------------
// getLatestTrafficAnomaly (public query)
// ---------------------------------------------------------------------------

export const getLatestTrafficAnomaly = query({
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
      .query('trafficAnomalySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getTrafficAnomalyHistory (public query)
// ---------------------------------------------------------------------------

/**
 * Lean history for sparklines — patterns and findingCandidates arrays stripped.
 */
export const getTrafficAnomalyHistory = query({
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
      .query('trafficAnomalySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      anomalyScore: r.anomalyScore,
      level: r.level,
      stats: r.stats,
      summary: r.summary,
      computedAt: r.computedAt,
    }))
  },
})
