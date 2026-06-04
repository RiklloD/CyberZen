import { v } from 'convex/values'
import { internal } from './_generated/api'
import {
  internalAction,
  internalMutation,
  query,
} from './_generated/server'

// ─── §8.3 — Usage Metering ────────────────────────────────────────────────

const KNOWN_METRICS = [
  'repos_connected',
  'scans_run',
  'prs_generated',
  'sandboxes_started',
  'api_calls',
] as const

export const incrementUsage = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    metric: v.string(),
    value: v.optional(v.number()),
  },
  returns: v.id('usageRecords'),
  handler: async (ctx, { tenantId, metric, value }) => {
    return await ctx.db.insert('usageRecords', {
      tenantId,
      metric,
      value: value ?? 1,
      at: Date.now(),
    })
  },
})

export const getUsageForTenant = query({
  args: { tenantId: v.id('tenants') },
  returns: v.array(
    v.object({
      metric: v.string(),
      total: v.number(),
      count: v.number(),
      lastAt: v.number(),
    }),
  ),
  handler: async (ctx, { tenantId }) => {
    const records = await ctx.db
      .query('usageRecords')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .take(2000)

    const agg = new Map<
      string,
      { metric: string; total: number; count: number; lastAt: number }
    >()
    for (const r of records) {
      const existing = agg.get(r.metric)
      if (existing) {
        existing.total += r.value
        existing.count += 1
        if (r.at > existing.lastAt) existing.lastAt = r.at
      } else {
        agg.set(r.metric, {
          metric: r.metric,
          total: r.value,
          count: 1,
          lastAt: r.at,
        })
      }
    }

    return Array.from(agg.values()).sort((a, b) => a.metric.localeCompare(b.metric))
  },
})

export const aggregateTenantUsage = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    periodStart: v.number(),
    periodEnd: v.number(),
  },
  returns: v.number(),
  handler: async (ctx, { tenantId, periodStart, periodEnd }) => {
    let collapsed = 0
    for (const metric of KNOWN_METRICS) {
      const records = await ctx.db
        .query('usageRecords')
        .withIndex('by_tenant_and_metric', (q) =>
          q.eq('tenantId', tenantId).eq('metric', metric),
        )
        .take(5000)

      const inWindow = records.filter(
        (r) => r.at >= periodStart && r.at < periodEnd && !r.periodStart,
      )

      if (inWindow.length === 0) continue

      const total = inWindow.reduce((sum, r) => sum + r.value, 0)
      await ctx.db.insert('usageRecords', {
        tenantId,
        metric,
        value: total,
        at: periodEnd,
        periodStart,
        periodEnd,
        recordedAt: Date.now(),
      })

      for (const r of inWindow) {
        await ctx.db.delete(r._id)
        collapsed += 1
      }
    }
    return collapsed
  },
})

export const listTenantIds = internalMutation({
  args: {},
  returns: v.array(v.id('tenants')),
  handler: async (ctx) => {
    const tenants = await ctx.db.query('tenants').take(500)
    return tenants.map((t) => t._id)
  },
})

export const dailyAggregate = internalAction({
  args: {},
  returns: v.object({
    tenantsProcessed: v.number(),
    recordsCollapsed: v.number(),
  }),
  handler: async (ctx) => {
    const now = Date.now()
    const oneDayMs = 24 * 60 * 60 * 1000
    const periodEnd = now
    const periodStart = now - oneDayMs

    const tenantIds: Array<string> = await ctx.runMutation(
      internal.usage.listTenantIds,
      {},
    )

    let collapsed = 0
    for (const tenantId of tenantIds) {
      const count: number = await ctx.runMutation(
        internal.usage.aggregateTenantUsage,
        {
          tenantId: tenantId as never,
          periodStart,
          periodEnd,
        },
      )
      collapsed += count
    }

    return {
      tenantsProcessed: tenantIds.length,
      recordsCollapsed: collapsed,
    }
  },
})
