// WS-34 — EPSS Score Integration.
//
// The Exploit Prediction Scoring System (EPSS) from FIRST.org provides a
// daily probability score (0.0–1.0) for every CVE indicating the likelihood
// of exploitation in the wild within the next 30 days.  It is the
// forward-looking complement to CISA KEV (which confirms past exploitation).
//
// Actions (network I/O, "use node" required):
//   syncEpssScores     — queries FIRST.org API for CVEs in recent disclosures,
//                        patches epssScore + epssPercentile on matched rows,
//                        persists a sync summary in epssSnapshots.
//
// Mutations (DB helpers):
//   patchDisclosureEpss   — bulk-patch breach disclosures with EPSS data
//   recordEpssSync        — persist epssSnapshots row
//
// Queries:
//   getLatestEpssSnapshot   — most recent sync row (for dashboard)
//   getEpssEnrichedDisclosures — disclosures that have an EPSS score
//   triggerEpssSync         — public on-demand sync trigger (schedules action)

import { v } from 'convex/values'
import { internalAction, internalMutation, internalQuery, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  buildEpssEnrichmentMap,
  buildEpssSummary,
  classifyEpssRisk,
  enrichDisclosureWithEpss,
  extractCveIds,
  parseEpssApiResponse,
  type EpssEnrichedCve,
} from './lib/epssEnrichment'

const EPSS_API_BASE = 'https://api.first.org/data/v1/epss'
const BATCH_SIZE = 100 // FIRST.org supports up to 100 CVEs per request
const MAX_DISCLOSURES = 500 // cap the number of disclosures loaded per sync

// ---------------------------------------------------------------------------
// syncEpssScores — internalAction (network I/O)
// ---------------------------------------------------------------------------

export const syncEpssScores = internalAction({
  args: {},
  handler: async (ctx): Promise<{
    ok: boolean
    queriedCveCount: number
    enrichedCount: number
    criticalRiskCount: number
    error?: string
  }> => {
    // --- load recent breach disclosures ---
    const disclosures = await ctx.runQuery(
      internal.epssIntel.getRecentDisclosuresForEpss,
      {},
    ) as Array<{ _id: string; sourceRef: string; aliases: string[]; packageName?: string }>

    const cveIds = extractCveIds(disclosures)

    if (cveIds.length === 0) {
      await ctx.runMutation(internal.epssIntel.recordEpssSync, {
        syncedAt: Date.now(),
        queriedCveCount: 0,
        enrichedCount: 0,
        criticalRiskCount: 0,
        highRiskCount: 0,
        mediumRiskCount: 0,
        lowRiskCount: 0,
        avgScore: 0,
        topCves: [],
        summary: 'No CVE IDs found in recent breach disclosures — nothing to query.',
      })
      return { ok: true, queriedCveCount: 0, enrichedCount: 0, criticalRiskCount: 0 }
    }

    // --- fetch EPSS scores in batches of BATCH_SIZE ---
    const allEntries = await (async () => {
      const results = []
      for (let i = 0; i < cveIds.length; i += BATCH_SIZE) {
        const batch = cveIds.slice(i, i + BATCH_SIZE)
        const url = `${EPSS_API_BASE}?cve=${encodeURIComponent(batch.join(','))}`
        try {
          const resp = await fetch(url, {
            headers: {
              Accept: 'application/json',
              'User-Agent': 'Sentinel-Security-Agent/1.0',
            },
          })
          if (!resp.ok) continue
          const json = await resp.json()
          const entries = parseEpssApiResponse(json)
          if (entries) results.push(...entries)
        } catch {
          // Isolate per-batch failures — continue with remaining batches
        }
      }
      return results
    })()

    const epssMap = buildEpssEnrichmentMap(allEntries)

    // --- build disclosure→package mapping for topCves enrichment ---
    const packageByDisclosure = new Map<string, string>()
    for (const disc of disclosures) {
      if (disc.packageName) packageByDisclosure.set(disc._id, disc.packageName)
    }

    // --- enrich disclosures and collect results ---
    const enrichedCves: EpssEnrichedCve[] = []
    const patchBatch: Array<{ disclosureId: string; epssScore: number; epssPercentile: number }> = []

    for (const disc of disclosures) {
      const entry = enrichDisclosureWithEpss(disc, epssMap)
      if (!entry) continue

      const epssRiskLevel = classifyEpssRisk(entry.epssScore)
      enrichedCves.push({
        cveId: entry.cveId,
        epssScore: entry.epssScore,
        epssPercentile: entry.epssPercentile,
        epssRiskLevel,
        packageName: disc.packageName,
      })
      patchBatch.push({
        disclosureId: disc._id,
        epssScore: entry.epssScore,
        epssPercentile: entry.epssPercentile,
      })
    }

    // --- patch disclosures in batches to avoid transaction size limits ---
    for (let i = 0; i < patchBatch.length; i += 50) {
      await ctx.runMutation(internal.epssIntel.patchDisclosureEpss, {
        patches: patchBatch.slice(i, i + 50),
      })
    }

    // --- build summary and persist sync record ---
    const summary = buildEpssSummary(enrichedCves, cveIds.length)

    await ctx.runMutation(internal.epssIntel.recordEpssSync, {
      syncedAt: Date.now(),
      queriedCveCount: summary.totalQueried,
      enrichedCount: summary.enrichedCount,
      criticalRiskCount: summary.criticalRiskCount,
      highRiskCount: summary.highRiskCount,
      mediumRiskCount: summary.mediumRiskCount,
      lowRiskCount: summary.lowRiskCount,
      avgScore: summary.avgScore,
      topCves: summary.topCves.map(c => ({
        cveId: c.cveId,
        epssScore: c.epssScore,
        epssPercentile: c.epssPercentile,
        epssRiskLevel: c.epssRiskLevel,
        ...(c.packageName ? { packageName: c.packageName } : {}),
      })),
      summary: summary.summary,
    })

    return {
      ok: true,
      queriedCveCount: summary.totalQueried,
      enrichedCount: summary.enrichedCount,
      criticalRiskCount: summary.criticalRiskCount,
    }
  },
})

// ---------------------------------------------------------------------------
// getRecentDisclosuresForEpss — internalQuery
// ---------------------------------------------------------------------------

export const getRecentDisclosuresForEpss = internalQuery({
  args: {},
  handler: async (ctx) => {
    // Load the most recent breach disclosures across all tenants.
    // Bounded at MAX_DISCLOSURES to keep the query fast.
    const rows = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(MAX_DISCLOSURES)

    return rows.map(r => ({
      _id: r._id as string,
      sourceRef: r.sourceRef,
      aliases: r.aliases,
      packageName: r.packageName,
    }))
  },
})

// ---------------------------------------------------------------------------
// patchDisclosureEpss — internalMutation
// ---------------------------------------------------------------------------

export const patchDisclosureEpss = internalMutation({
  args: {
    patches: v.array(
      v.object({
        disclosureId: v.string(),
        epssScore: v.number(),
        epssPercentile: v.number(),
      }),
    ),
  },
  handler: async (ctx, { patches }) => {
    for (const p of patches) {
      // Use type-cast since the ID comes from a query result serialised as string
      // biome-ignore lint/suspicious/noExplicitAny: cross-boundary ID cast
      await ctx.db.patch(p.disclosureId as any, {
        epssScore: p.epssScore,
        epssPercentile: p.epssPercentile,
      })
    }
  },
})

// ---------------------------------------------------------------------------
// recordEpssSync — internalMutation
// ---------------------------------------------------------------------------

export const recordEpssSync = internalMutation({
  args: {
    syncedAt: v.number(),
    queriedCveCount: v.number(),
    enrichedCount: v.number(),
    criticalRiskCount: v.number(),
    highRiskCount: v.number(),
    mediumRiskCount: v.number(),
    lowRiskCount: v.number(),
    avgScore: v.number(),
    topCves: v.array(
      v.object({
        cveId: v.string(),
        epssScore: v.number(),
        epssPercentile: v.number(),
        epssRiskLevel: v.string(),
        packageName: v.optional(v.string()),
      }),
    ),
    summary: v.string(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('epssSnapshots', args)

    // Prune to 30 most recent rows
    const rows = await ctx.db
      .query('epssSnapshots')
      .withIndex('by_synced_at')
      .order('desc')
      .collect()
    for (const row of rows.slice(30)) {
      await ctx.db.delete(row._id)
    }
  },
})

// ---------------------------------------------------------------------------
// getLatestEpssSnapshot — public query (dashboard)
// ---------------------------------------------------------------------------

export const getLatestEpssSnapshot = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db
      .query('epssSnapshots')
      .withIndex('by_synced_at')
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getEpssEnrichedDisclosures — public query
// Returns breach disclosures that have been scored, ordered by score desc.
// ---------------------------------------------------------------------------

export const getEpssEnrichedDisclosures = query({
  args: {
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { limit }) => {
    const cap = Math.min(limit ?? 50, 200)

    // Load recent disclosures and filter to those with EPSS scores.
    const rows = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(500)

    const enriched = rows
      .filter(r => r.epssScore !== undefined)
      .map(r => ({
        _id: r._id,
        packageName: r.packageName,
        ecosystem: r.ecosystem,
        sourceRef: r.sourceRef,
        severity: r.severity,
        epssScore: r.epssScore!,
        epssPercentile: r.epssPercentile!,
        epssRiskLevel: classifyEpssRisk(r.epssScore!),
        publishedAt: r.publishedAt,
      }))
      .sort((a, b) => b.epssScore - a.epssScore)
      .slice(0, cap)

    return enriched
  },
})

// ---------------------------------------------------------------------------
// triggerEpssSync — public mutation (on-demand)
// ---------------------------------------------------------------------------

export const triggerEpssSync = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, internal.epssIntel.syncEpssScores, {})
  },
})
