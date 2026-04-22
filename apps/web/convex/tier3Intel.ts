'use node'
// Tier 3 Threat Intelligence — CISA KEV + Telegram + dark-web signals.
//
// Actions (network I/O, "use node" required):
//   syncCisaKevCatalog   — fetches CISA KEV JSON, cross-refs breach disclosures,
//                           patches exploitAvailable=true on matched disclosures,
//                           persists sync summary.
//   handleTelegramUpdate — parses a Telegram Bot API Update payload, stores
//                           non-trivial threat signals.
//
// Mutations (DB write helpers):
//   recordCisaKevSync      — persist cisaKevSnapshots row
//   markDisclosuresExploited — bulk-patch breach disclosures that match CISA KEV
//   recordTier3Signal      — persist tier3ThreatSignals row
//
// Queries:
//   getLatestCisaKevSnapshot  — most recent sync row (for dashboard)
//   getRecentTier3Signals     — most recent N threat signals
//   getHighPrioritySignals    — critical/high signals for a time window

import { v } from 'convex/values'
import type { Id } from './_generated/dataModel'
import { internalAction, internalMutation, internalQuery, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  buildCisaKevSummary,
  matchCisaKevToCveList,
  parseCisaKevResponse,
} from './lib/cisaKev'
import { parseTelegramPost, type TelegramChannelPost } from './lib/telegramIntel'

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

// ---------------------------------------------------------------------------
// syncCisaKevCatalog
// ---------------------------------------------------------------------------

export const syncCisaKevCatalog = internalAction({
  args: {},
  handler: async (ctx): Promise<{
    ok: boolean
    totalEntries: number
    matched: number
    error?: string
  }> => {
    // --- fetch catalog ---
    let json: unknown
    try {
      const resp = await fetch(CISA_KEV_URL, {
        headers: { Accept: 'application/json', 'User-Agent': 'Sentinel-Security-Agent/1.0' },
      })
      if (!resp.ok) {
        return { ok: false, totalEntries: 0, matched: 0, error: `HTTP ${resp.status}` }
      }
      json = await resp.json()
    } catch (err) {
      return { ok: false, totalEntries: 0, matched: 0, error: String(err) }
    }

    const catalog = parseCisaKevResponse(json)
    if (!catalog) {
      return { ok: false, totalEntries: 0, matched: 0, error: 'Parse failed' }
    }

    const summary = buildCisaKevSummary(catalog)

    // --- load recent breach disclosures to cross-reference (bounded at 500) ---
    const recentDisclosures = (await ctx.runQuery(
      internal.tier3Intel.getBreachDisclosuresForKevMatch,
      {},
    )) as Array<{ _id: string; sourceRef: string; aliases: string[] }>

    // Build CVE lookup from both sourceRef and aliases
    const disclosureByCve = new Map<string, string>()
    for (const disc of recentDisclosures) {
      const allRefs = [disc.sourceRef, ...disc.aliases]
      for (const ref of allRefs) {
        const upper = ref.trim().toUpperCase()
        if (upper.startsWith('CVE-')) {
          disclosureByCve.set(upper, disc._id)
        }
      }
    }

    const allCves = [...disclosureByCve.keys()]
    const matched = matchCisaKevToCveList(catalog, allCves)
    const matchedCveIds = matched.map((e) => e.cveId)

    // Collect the disclosure IDs that match
    const matchedDisclosureIds = matchedCveIds
      .map((cve) => disclosureByCve.get(cve))
      .filter((id): id is string => id !== undefined)

    // --- persist sync snapshot ---
    await ctx.runMutation(internal.tier3Intel.recordCisaKevSync, {
      catalogVersion: catalog.catalogVersion,
      dateReleased: catalog.dateReleased,
      totalEntries: summary.totalEntries,
      ransomwareRelated: summary.ransomwareRelated,
      recentEntries: summary.recentEntries,
      hasHighPriorityEntries: summary.hasHighPriorityEntries,
      matchedCveIds,
      matchedFindingCount: matchedDisclosureIds.length,
    })

    // --- patch matched disclosures with exploitAvailable=true ---
    if (matchedDisclosureIds.length > 0) {
      await ctx.runMutation(internal.tier3Intel.markDisclosuresExploited, {
        disclosureIds: matchedDisclosureIds,
      })
    }

    return { ok: true, totalEntries: summary.totalEntries, matched: matchedDisclosureIds.length }
  },
})

// ---------------------------------------------------------------------------
// handleTelegramUpdate
// ---------------------------------------------------------------------------

export const handleTelegramUpdate = internalAction({
  args: { updateJson: v.string() },
  handler: async (ctx, args): Promise<{ stored: boolean; threatLevel: string }> => {
    let update: Record<string, unknown>
    try {
      update = JSON.parse(args.updateJson) as Record<string, unknown>
    } catch {
      return { stored: false, threatLevel: 'none' }
    }

    // Accept both message and channel_post
    const post = (update.message ?? update.channel_post) as TelegramChannelPost | undefined
    if (!post) return { stored: false, threatLevel: 'none' }

    const signal = parseTelegramPost(post)

    // Only store signals with a meaningful threat level
    if (signal.threatLevel === 'none') {
      return { stored: false, threatLevel: 'none' }
    }

    await ctx.runMutation(internal.tier3Intel.recordTier3Signal, {
      source: 'telegram' as const,
      channelId: signal.channelId,
      messageId: signal.messageId,
      text: signal.text,
      cveIds: signal.cveIds,
      packageMentions: signal.packageMentions,
      hasCredentialPattern: signal.hasCredentialPattern,
      hasExploitKeywords: signal.hasExploitKeywords,
      hasRansomwareKeywords: signal.hasRansomwareKeywords,
      threatLevel: signal.threatLevel,
      capturedAt: signal.capturedAt,
    })

    return { stored: true, threatLevel: signal.threatLevel }
  },
})

// ---------------------------------------------------------------------------
// Internal mutations
// ---------------------------------------------------------------------------

export const getBreachDisclosuresForKevMatch = internalQuery({
  args: {},
  handler: async (ctx) => {
    // Load recent breach disclosures ordered by published date (bounded to 500)
    return await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(500)
  },
})

export const recordCisaKevSync = internalMutation({
  args: {
    catalogVersion: v.string(),
    dateReleased: v.string(),
    totalEntries: v.number(),
    ransomwareRelated: v.number(),
    recentEntries: v.number(),
    hasHighPriorityEntries: v.boolean(),
    matchedCveIds: v.array(v.string()),
    matchedFindingCount: v.number(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('cisaKevSnapshots', {
      ...args,
      syncedAt: Date.now(),
    })
  },
})

export const markDisclosuresExploited = internalMutation({
  args: { disclosureIds: v.array(v.string()) },
  handler: async (ctx, args) => {
    for (const rawId of args.disclosureIds) {
      const id = rawId as Id<'breachDisclosures'>
      await ctx.db.patch(id, { exploitAvailable: true })
    }
  },
})

export const recordTier3Signal = internalMutation({
  args: {
    source: v.union(
      v.literal('telegram'),
      v.literal('dark_web'),
      v.literal('paste_site'),
    ),
    channelId: v.optional(v.string()),
    messageId: v.optional(v.string()),
    text: v.string(),
    cveIds: v.array(v.string()),
    packageMentions: v.array(v.string()),
    hasCredentialPattern: v.boolean(),
    hasExploitKeywords: v.boolean(),
    hasRansomwareKeywords: v.boolean(),
    threatLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
    ),
    capturedAt: v.number(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('tier3ThreatSignals', args)
  },
})

// ---------------------------------------------------------------------------
// Public queries
// ---------------------------------------------------------------------------

export const getLatestCisaKevSnapshot = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db
      .query('cisaKevSnapshots')
      .withIndex('by_synced_at')
      .order('desc')
      .first()
  },
})

export const getRecentTier3Signals = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const n = Math.min(args.limit ?? 20, 100)
    return await ctx.db
      .query('tier3ThreatSignals')
      .withIndex('by_captured_at')
      .order('desc')
      .take(n)
  },
})

export const getHighPrioritySignals = query({
  args: {},
  handler: async (ctx) => {
    // Return the 10 most recent critical/high signals
    const critical = await ctx.db
      .query('tier3ThreatSignals')
      .withIndex('by_threat_level_and_captured_at', (q) =>
        q.eq('threatLevel', 'critical'),
      )
      .order('desc')
      .take(5)

    const high = await ctx.db
      .query('tier3ThreatSignals')
      .withIndex('by_threat_level_and_captured_at', (q) =>
        q.eq('threatLevel', 'high'),
      )
      .order('desc')
      .take(5)

    return [...critical, ...high].sort((a, b) => b.capturedAt - a.capturedAt)
  },
})

// ---------------------------------------------------------------------------
// Public mutation — trigger CISA KEV sync on demand
// ---------------------------------------------------------------------------

export const triggerCisaKevSync = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, internal.tier3Intel.syncCisaKevCatalog, {})
    return { scheduled: true }
  },
})
