// §6.23 — Data Retention Policies
//
//   listPolicies        — public query: list retention policies for a tenant
//   createPolicy        — public mutation: create a new retention policy
//   updatePolicy        — public mutation: update an existing retention policy
//   deletePolicy        — public mutation: remove a retention policy
//   runDailyArchive     — internal action: daily cron that archives/deletes expired data

import { v } from 'convex/values'
import { query, mutation, internalAction, internalMutation } from './_generated/server'
import { internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth'

const DATA_TYPES = v.union(
  v.literal('findings'),
  v.literal('audit_logs'),
  v.literal('sbom_snapshots'),
  v.literal('webhook_deliveries'),
  v.literal('sandbox_environments'),
  v.literal('ingestion_events'),
)

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const listPolicies = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)

    const policies = await ctx.db
      .query('retentionPolicies')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    return policies.sort((a, b) => a.createdAt - b.createdAt)
  },
})

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export const createPolicy = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    name: v.string(),
    dataType: DATA_TYPES,
    retentionDays: v.number(),
    action: v.union(v.literal('archive'), v.literal('delete')),
    enabled: v.boolean(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const now = Date.now()

    return ctx.db.insert('retentionPolicies', {
      tenantId: tenant._id,
      name: args.name,
      dataType: args.dataType,
      retentionDays: args.retentionDays,
      action: args.action,
      enabled: args.enabled,
      createdAt: now,
      updatedAt: now,
    })
  },
})

export const updatePolicy = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    policyId: v.id('retentionPolicies'),
    name: v.optional(v.string()),
    dataType: v.optional(DATA_TYPES),
    retentionDays: v.optional(v.number()),
    action: v.optional(v.union(v.literal('archive'), v.literal('delete'))),
    enabled: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.policyId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('Retention policy not found')
    }

    const patch: Record<string, unknown> = { updatedAt: Date.now() }
    if (args.name !== undefined) patch.name = args.name
    if (args.dataType !== undefined) patch.dataType = args.dataType
    if (args.retentionDays !== undefined) patch.retentionDays = args.retentionDays
    if (args.action !== undefined) patch.action = args.action
    if (args.enabled !== undefined) patch.enabled = args.enabled

    await ctx.db.patch(args.policyId, patch)
  },
})

export const deletePolicy = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    policyId: v.id('retentionPolicies'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.policyId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('Retention policy not found')
    }
    await ctx.db.delete(args.policyId)
  },
})

// ---------------------------------------------------------------------------
// Internal: daily archive cron
// ---------------------------------------------------------------------------

export const runDailyArchive = internalAction({
  args: {},
  handler: async (ctx): Promise<{ processed: number }> => {
    // Schedule internal mutation per tenant with enabled policies
    await ctx.scheduler.runAfter(0, internal.retention._runDailyArchiveForAll, {})
    return { processed: 0 }
  },
})

export const _runDailyArchiveForAll = internalMutation({
  args: {},
  handler: async (ctx) => {
    // This is a placeholder implementation.
    // In production, iterate all tenants, find enabled policies,
    // and archive/delete expired rows based on dataType and retentionDays.
    const allPolicies = await ctx.db
      .query('retentionPolicies')
      .withIndex('by_tenant_and_enabled', (q) => q.eq('enabled', true))
      .collect()

    let processed = 0
    const now = Date.now()

    for (const policy of allPolicies) {
      const cutoff = now - policy.retentionDays * 86_400_000
      if (policy.retentionDays === 0) continue // retain forever

      // Mark policy as applied
      await ctx.db.patch(policy._id, { lastAppliedAt: now, updatedAt: now })
      processed++
    }

    return { processed, policiesChecked: allPolicies.length }
  },
})
