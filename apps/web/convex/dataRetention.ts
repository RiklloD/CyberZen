// §B4 — Data Retention Enforcement
//
//   getRetentionPolicies    — query: per-tenant retention config (with defaults)
//   updateRetentionPolicies — mutation: admin-only; updates retention periods
//   runDailyEnforcement     — internal action: cron entry point
//   _scheduleAllTenants     — internal mutation: fans out to per-tenant enforcement
//   _enforceFindings        — internal mutation: batch-deletes expired closed findings
//   _enforceAuditLogs       — internal mutation: batch-deletes expired audit log entries
//   _enforceApiUsageRecords — internal mutation: batch-deletes expired API usage records
//   _enforceWebhookDeliveries — internal mutation: batch-deletes expired webhook deliveries

import { v } from 'convex/values'
import { query, mutation, internalAction, internalMutation } from './_generated/server'
import { internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth'

const BATCH_SIZE = 50

const DEFAULTS = {
  findingsDays: 365,
  auditLogsDays: 730,
  apiUsageRecordsDays: 90,
  webhookDeliveriesDays: 30,
}

export const RETENTION_MINIMUMS = {
  findingsDays: 90,
  auditLogsDays: 365,
  apiUsageRecordsDays: 30,
  webhookDeliveriesDays: 7,
}

const CLOSED_FINDING_STATUSES = new Set([
  'resolved',
  'false_positive',
  'ignored',
  'merged',
  'accepted_risk',
])

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const getRetentionPolicies = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireSessionAuth(ctx, args.authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership) throw new Error('Not a member of this workspace')

    const config = await ctx.db
      .query('tenantRetentionConfig')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .unique()

    return {
      findingsDays: config?.findingsDays ?? DEFAULTS.findingsDays,
      auditLogsDays: config?.auditLogsDays ?? DEFAULTS.auditLogsDays,
      apiUsageRecordsDays: config?.apiUsageRecordsDays ?? DEFAULTS.apiUsageRecordsDays,
      webhookDeliveriesDays: config?.webhookDeliveriesDays ?? DEFAULTS.webhookDeliveriesDays,
      updatedAt: config?.updatedAt ?? null,
    }
  },
})

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export const updateRetentionPolicies = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    findingsDays: v.number(),
    auditLogsDays: v.number(),
    apiUsageRecordsDays: v.number(),
    webhookDeliveriesDays: v.number(),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireSessionAuth(ctx, args.authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can update retention policies')
    }

    // A6 — enforce retention minimums to prevent destruction of forensic trail
    const mins = RETENTION_MINIMUMS
    if (args.findingsDays < mins.findingsDays) {
      throw new Error(`findingsDays must be at least ${mins.findingsDays} days`)
    }
    if (args.auditLogsDays < mins.auditLogsDays) {
      throw new Error(`auditLogsDays must be at least ${mins.auditLogsDays} days`)
    }
    if (args.apiUsageRecordsDays < mins.apiUsageRecordsDays) {
      throw new Error(`apiUsageRecordsDays must be at least ${mins.apiUsageRecordsDays} days`)
    }
    if (args.webhookDeliveriesDays < mins.webhookDeliveriesDays) {
      throw new Error(`webhookDeliveriesDays must be at least ${mins.webhookDeliveriesDays} days`)
    }

    const now = Date.now()
    const existing = await ctx.db
      .query('tenantRetentionConfig')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .unique()

    if (existing) {
      await ctx.db.patch(existing._id, {
        findingsDays: args.findingsDays,
        auditLogsDays: args.auditLogsDays,
        apiUsageRecordsDays: args.apiUsageRecordsDays,
        webhookDeliveriesDays: args.webhookDeliveriesDays,
        updatedAt: now,
      })
    } else {
      await ctx.db.insert('tenantRetentionConfig', {
        tenantId: tenant._id,
        findingsDays: args.findingsDays,
        auditLogsDays: args.auditLogsDays,
        apiUsageRecordsDays: args.apiUsageRecordsDays,
        webhookDeliveriesDays: args.webhookDeliveriesDays,
        updatedAt: now,
      })
    }

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'retention.policies_updated',
      resourceType: 'retention_config',
      payload: JSON.stringify({
        findingsDays: args.findingsDays,
        auditLogsDays: args.auditLogsDays,
        apiUsageRecordsDays: args.apiUsageRecordsDays,
        webhookDeliveriesDays: args.webhookDeliveriesDays,
      }),
      at: now,
    })
  },
})

// ---------------------------------------------------------------------------
// Internal: cron enforcement
// ---------------------------------------------------------------------------

export const runDailyEnforcement = internalAction({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, internal.dataRetention._scheduleAllTenants, {})
  },
})

export const _scheduleAllTenants = internalMutation({
  args: {},
  handler: async (ctx) => {
    const tenants = await ctx.db.query('tenants').take(200)
    const now = Date.now()

    for (const tenant of tenants) {
      const config = await ctx.db
        .query('tenantRetentionConfig')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
        .unique()

      const findingsDays = config?.findingsDays ?? DEFAULTS.findingsDays
      const auditLogsDays = config?.auditLogsDays ?? DEFAULTS.auditLogsDays
      const apiUsageRecordsDays = config?.apiUsageRecordsDays ?? DEFAULTS.apiUsageRecordsDays
      const webhookDeliveriesDays = config?.webhookDeliveriesDays ?? DEFAULTS.webhookDeliveriesDays

      if (findingsDays > 0) {
        await ctx.scheduler.runAfter(0, internal.dataRetention._enforceFindings, {
          tenantId: tenant._id,
          cutoff: now - findingsDays * 86_400_000,
        })
      }
      if (auditLogsDays > 0) {
        await ctx.scheduler.runAfter(0, internal.dataRetention._enforceAuditLogs, {
          tenantId: tenant._id,
          cutoff: now - auditLogsDays * 86_400_000,
        })
      }
      if (apiUsageRecordsDays > 0) {
        await ctx.scheduler.runAfter(0, internal.dataRetention._enforceApiUsageRecords, {
          tenantId: tenant._id,
          cutoff: now - apiUsageRecordsDays * 86_400_000,
        })
      }
      if (webhookDeliveriesDays > 0) {
        await ctx.scheduler.runAfter(0, internal.dataRetention._enforceWebhookDeliveries, {
          tenantId: tenant._id,
          cutoff: now - webhookDeliveriesDays * 86_400_000,
        })
      }
    }
  },
})

export const _enforceFindings = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    cutoff: v.number(),
    cursorCreatedAt: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const before = args.cursorCreatedAt ?? args.cutoff
    const batch = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', args.tenantId).lt('createdAt', before),
      )
      .order('asc')
      .take(BATCH_SIZE)

    let deleted = 0
    for (const finding of batch) {
      if (CLOSED_FINDING_STATUSES.has(finding.status)) {
        await ctx.db.delete(finding._id)
        deleted++
      }
    }

    if (deleted > 0) {
      await ctx.db.insert('auditLog', {
        tenantId: args.tenantId,
        action: 'retention.findings_deleted',
        resourceType: 'findings',
        payload: JSON.stringify({ deletedCount: deleted, cutoff: args.cutoff }),
        at: Date.now(),
      })
    }

    if (batch.length === BATCH_SIZE) {
      const lastCreatedAt = batch[batch.length - 1].createdAt
      await ctx.scheduler.runAfter(0, internal.dataRetention._enforceFindings, {
        ...args,
        cursorCreatedAt: lastCreatedAt,
      })
    }
  },
})

export const _enforceAuditLogs = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    cutoff: v.number(),
  },
  handler: async (ctx, args) => {
    const batch = await ctx.db
      .query('auditLog')
      .withIndex('by_tenant_and_at', (q) =>
        q.eq('tenantId', args.tenantId).lt('at', args.cutoff),
      )
      .order('asc')
      .take(BATCH_SIZE)

    for (const entry of batch) {
      await ctx.db.delete(entry._id)
    }

    if (batch.length > 0) {
      await ctx.db.insert('auditLog', {
        tenantId: args.tenantId,
        action: 'retention.audit_logs_deleted',
        resourceType: 'audit_log',
        payload: JSON.stringify({ deletedCount: batch.length, cutoff: args.cutoff }),
        at: Date.now(),
      })
    }

    if (batch.length === BATCH_SIZE) {
      await ctx.scheduler.runAfter(0, internal.dataRetention._enforceAuditLogs, args)
    }
  },
})

export const _enforceApiUsageRecords = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    cutoff: v.number(),
  },
  handler: async (ctx, args) => {
    const batch = await ctx.db
      .query('apiUsageRecords')
      .withIndex('by_tenant_and_window_start', (q) =>
        q.eq('tenantId', args.tenantId).lt('windowStart', args.cutoff),
      )
      .order('asc')
      .take(BATCH_SIZE)

    for (const record of batch) {
      await ctx.db.delete(record._id)
    }

    if (batch.length > 0) {
      await ctx.db.insert('auditLog', {
        tenantId: args.tenantId,
        action: 'retention.api_usage_records_deleted',
        resourceType: 'api_usage_records',
        payload: JSON.stringify({ deletedCount: batch.length, cutoff: args.cutoff }),
        at: Date.now(),
      })
    }

    if (batch.length === BATCH_SIZE) {
      await ctx.scheduler.runAfter(0, internal.dataRetention._enforceApiUsageRecords, args)
    }
  },
})

export const _enforceWebhookDeliveries = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    cutoff: v.number(),
  },
  handler: async (ctx, args) => {
    const batch = await ctx.db
      .query('webhookDeliveries')
      .withIndex('by_tenant_and_attempted_at', (q) =>
        q.eq('tenantId', args.tenantId).lt('attemptedAt', args.cutoff),
      )
      .order('asc')
      .take(BATCH_SIZE)

    for (const delivery of batch) {
      await ctx.db.delete(delivery._id)
    }

    if (batch.length > 0) {
      await ctx.db.insert('auditLog', {
        tenantId: args.tenantId,
        action: 'retention.webhook_deliveries_deleted',
        resourceType: 'webhook_deliveries',
        payload: JSON.stringify({ deletedCount: batch.length, cutoff: args.cutoff }),
        at: Date.now(),
      })
    }

    if (batch.length === BATCH_SIZE) {
      await ctx.scheduler.runAfter(0, internal.dataRetention._enforceWebhookDeliveries, args)
    }
  },
})
