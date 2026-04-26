/**
 * SIEM Intel — Convex entrypoints for Splunk + Elastic push delivery (spec §4.6.5).
 *
 * Pushes Blue Agent detection rules from `detectionRuleSnapshots` to
 * configured SIEM endpoints after each rule generation cycle.
 *
 * Entrypoints:
 *   pushToSiem                  — internalAction: fetches latest snapshot,
 *       builds batched payloads, POSTs to Splunk HEC and/or Elastic _bulk.
 *       Each destination is attempted independently — one failure never
 *       blocks the other. Result is persisted to `siemPushLogs`.
 *
 *   recordSiemPush              — internalMutation: persist push outcome.
 *
 *   triggerSiemPushForRepository — public mutation: manual dashboard trigger.
 *
 *   getLatestSiemPush           — public query: latest push log for dashboard.
 *   getSiemPushHistory          — public query: trend sparkline (last 10).
 *
 * Configuration:
 *   npx convex env set SPLUNK_HEC_URL   https://splunk.internal:8088
 *   npx convex env set SPLUNK_HEC_TOKEN <hec-token>
 *   npx convex env set SPLUNK_HEC_INDEX sentinel_detection_rules   (optional)
 *   npx convex env set ELASTIC_URL      https://elasticsearch.internal:9200
 *   npx convex env set ELASTIC_API_KEY  <base64-id:api_key>
 *   npx convex env set ELASTIC_INDEX    sentinel-detection-rules   (optional)
 *
 * Wiring: fire-and-forget from blueAgentIntel.generateAndStoreDetectionRules
 * after each rule snapshot is stored.
 */

import { v } from 'convex/values'
import { internalAction, internalMutation, internalQuery, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  buildElasticBulkBody,
  buildSplunkHecBody,
  isValidSiemUrl,
} from './lib/siemExport'
import type { Doc } from './_generated/dataModel'

// ---------------------------------------------------------------------------
// pushToSiem (internal action — HTTP calls)
// ---------------------------------------------------------------------------

export const pushToSiem = internalAction({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args): Promise<{
    splunkStatus: 'ok' | 'skipped' | 'error'
    elasticStatus: 'ok' | 'skipped' | 'error'
  }> => {
    // Load the latest detection rule snapshot for this repository
    const snapshot = (await ctx.runQuery(
      internal.siemIntel.getLatestSnapshotForRepo,
      { repositoryId: args.repositoryId },
    )) as Doc<'detectionRuleSnapshots'> | null

    if (!snapshot) {
      console.log(`[siem] no detection rule snapshot for repo ${args.repositoryId}`)
      return { splunkStatus: 'skipped', elasticStatus: 'skipped' }
    }

    const repoName = `repo:${args.repositoryId}` // display label
    let splunkStatus: 'ok' | 'skipped' | 'error' = 'skipped'
    let splunkError: string | undefined
    let elasticStatus: 'ok' | 'skipped' | 'error' = 'skipped'
    let elasticError: string | undefined

    // ── Splunk HEC push ────────────────────────────────────────────────────
    const splunkUrl = process.env.SPLUNK_HEC_URL
    const splunkToken = process.env.SPLUNK_HEC_TOKEN
    const splunkIndex = process.env.SPLUNK_HEC_INDEX

    if (splunkUrl && splunkToken && isValidSiemUrl(splunkUrl)) {
      const splunkRules = snapshot.splunkRules ?? []
      if (splunkRules.length > 0) {
        try {
          const body = buildSplunkHecBody(
            splunkRules,
            repoName,
            snapshot.generatedAt,
            splunkIndex,
          )
          const res = await fetch(
            `${splunkUrl.replace(/\/$/, '')}/services/collector/event`,
            {
              method: 'POST',
              headers: {
                'Authorization': `Splunk ${splunkToken}`,
                'Content-Type': 'application/json',
              },
              body,
            },
          )
          if (res.ok) {
            splunkStatus = 'ok'
            console.log(`[siem] splunk ok — ${splunkRules.length} rules pushed`)
          } else {
            const text = await res.text().catch(() => '')
            splunkError = `HTTP ${res.status}: ${text.slice(0, 200)}`
            splunkStatus = 'error'
            console.warn(`[siem] splunk error: ${splunkError}`)
          }
        } catch (err) {
          splunkError = err instanceof Error ? err.message : 'unknown_error'
          splunkStatus = 'error'
          console.warn(`[siem] splunk fetch failed: ${splunkError}`)
        }
      }
    }

    // ── Elastic _bulk push ─────────────────────────────────────────────────
    const elasticUrl = process.env.ELASTIC_URL
    const elasticApiKey = process.env.ELASTIC_API_KEY
    const elasticIndex = process.env.ELASTIC_INDEX

    if (elasticUrl && elasticApiKey && isValidSiemUrl(elasticUrl)) {
      const elasticRules = snapshot.elasticRules ?? []
      if (elasticRules.length > 0) {
        try {
          const body = buildElasticBulkBody(
            elasticRules,
            repoName,
            snapshot.generatedAt,
            elasticIndex,
          )
          const res = await fetch(
            `${elasticUrl.replace(/\/$/, '')}/_bulk`,
            {
              method: 'POST',
              headers: {
                'Authorization': `ApiKey ${elasticApiKey}`,
                'Content-Type': 'application/x-ndjson',
              },
              body,
            },
          )
          if (res.ok) {
            // Elastic _bulk always returns 200 even on partial failures;
            // check the `errors` field in the JSON response.
            // biome-ignore lint/suspicious/noExplicitAny: Elastic response is untyped
            const json = (await res.json()) as Record<string, any>
            if (json.errors === true) {
              const firstError = json.items
                ?.find((i: Record<string, unknown>) =>
                  (i.index as Record<string, unknown>)?.error,
                )
                ?.index?.error?.reason
              elasticError = firstError ? String(firstError).slice(0, 200) : 'partial_bulk_error'
              elasticStatus = 'error'
              console.warn(`[siem] elastic partial error: ${elasticError}`)
            } else {
              elasticStatus = 'ok'
              console.log(`[siem] elastic ok — ${elasticRules.length} rules pushed`)
            }
          } else {
            const text = await res.text().catch(() => '')
            elasticError = `HTTP ${res.status}: ${text.slice(0, 200)}`
            elasticStatus = 'error'
            console.warn(`[siem] elastic error: ${elasticError}`)
          }
        } catch (err) {
          elasticError = err instanceof Error ? err.message : 'unknown_error'
          elasticStatus = 'error'
          console.warn(`[siem] elastic fetch failed: ${elasticError}`)
        }
      }
    }

    // Persist result
    await ctx.runMutation(internal.siemIntel.recordSiemPush, {
      tenantId: snapshot.tenantId,
      repositoryId: args.repositoryId,
      splunkStatus,
      splunkRuleCount: snapshot.splunkCount,
      splunkError,
      elasticStatus,
      elasticRuleCount: snapshot.elasticCount,
      elasticError,
    })

    return { splunkStatus, elasticStatus }
  },
})

// ---------------------------------------------------------------------------
// getLatestSnapshotForRepo (internal query helper)
// ---------------------------------------------------------------------------

export const getLatestSnapshotForRepo = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('detectionRuleSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// recordSiemPush (internal mutation)
// ---------------------------------------------------------------------------

export const recordSiemPush = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    splunkStatus: v.union(v.literal('ok'), v.literal('skipped'), v.literal('error')),
    splunkRuleCount: v.number(),
    splunkError: v.optional(v.string()),
    elasticStatus: v.union(v.literal('ok'), v.literal('skipped'), v.literal('error')),
    elasticRuleCount: v.number(),
    elasticError: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Keep at most 30 push logs per repository
    const existing = await ctx.db
      .query('siemPushLogs')
      .withIndex('by_repository_and_pushed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (existing.length >= 30) {
      for (const old of existing.slice(29)) {
        await ctx.db.delete(old._id)
      }
    }

    await ctx.db.insert('siemPushLogs', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      splunkStatus: args.splunkStatus,
      splunkRuleCount: args.splunkRuleCount,
      splunkError: args.splunkError,
      elasticStatus: args.elasticStatus,
      elasticRuleCount: args.elasticRuleCount,
      elasticError: args.elasticError,
      pushedAt: Date.now(),
    })
  },
})

// ---------------------------------------------------------------------------
// triggerSiemPushForRepository (public mutation — dashboard / manual)
// ---------------------------------------------------------------------------

export const triggerSiemPushForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error(`Repository ${args.repositoryId} not found`)

    await ctx.scheduler.runAfter(
      0,
      internal.siemIntel.pushToSiem,
      { repositoryId: args.repositoryId },
    )

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// getLatestSiemPush (public query — dashboard)
// ---------------------------------------------------------------------------

export const getLatestSiemPush = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return ctx.db
      .query('siemPushLogs')
      .withIndex('by_repository_and_pushed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSiemPushHistory (public query — sparkline / trend)
// ---------------------------------------------------------------------------

export const getSiemPushHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const rows = await ctx.db
      .query('siemPushLogs')
      .withIndex('by_repository_and_pushed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(10)

    return rows.map((r) => ({
      splunkStatus: r.splunkStatus,
      elasticStatus: r.elasticStatus,
      pushedAt: r.pushedAt,
    }))
  },
})

