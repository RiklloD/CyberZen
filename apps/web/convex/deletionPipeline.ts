import { internalMutation, mutation, query } from './_generated/server'
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth'
import type { Id } from './_generated/dataModel'
import type { MutationCtx } from './_generated/server'

const GRACE_PERIOD_DAYS = 30

const deletionQueueSummary = v.object({
  _id: v.id('deletionQueue'),
  entityType: v.union(v.literal('user'), v.literal('finding'), v.literal('tenant')),
  entityId: v.string(),
  tenantId: v.id('tenants'),
  requestedByUserId: v.id('users'),
  requestedAt: v.number(),
  scheduledAt: v.number(),
  executedAt: v.optional(v.number()),
  status: v.union(
    v.literal('scheduled'),
    v.literal('executing'),
    v.literal('completed'),
    v.literal('failed'),
  ),
  error: v.optional(v.string()),
})

export const scheduleDeletion = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    entityType: v.union(
      v.literal('user'),
      v.literal('finding'),
      v.literal('tenant'),
    ),
    entityId: v.string(),
    delayDays: v.optional(v.number()),
  },
  returns: v.id('deletionQueue'),
  handler: async (ctx, { authToken, tenantSlug, entityType, entityId, delayDays }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership || membership.role !== 'owner') {
      throw new Error('Only workspace owners can schedule deletions')
    }

    const days = Math.max(GRACE_PERIOD_DAYS, delayDays ?? GRACE_PERIOD_DAYS)
    const now = Date.now()
    const scheduledAt = now + days * 24 * 60 * 60 * 1000

    const existing = await ctx.db
      .query('deletionQueue')
      .withIndex('by_entity', (q) =>
        q.eq('entityType', entityType).eq('entityId', entityId),
      )
      .take(10)

    const hasActive = existing.some(
      (e) => e.status === 'scheduled' || e.status === 'executing',
    )
    if (hasActive) throw new Error('A deletion is already scheduled for this entity')

    const queueId = await ctx.db.insert('deletionQueue', {
      entityType,
      entityId,
      tenantId: tenant._id,
      requestedByUserId: userId,
      requestedAt: now,
      scheduledAt,
      status: 'scheduled',
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'deletion.scheduled',
      resourceType: entityType,
      resourceId: entityId,
      payload: JSON.stringify({ queueId, scheduledAt, delayDays: days }),
      at: now,
    })

    return queueId
  },
})

export const cancelDeletion = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    queueId: v.id('deletionQueue'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, queueId }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership || membership.role !== 'owner') {
      throw new Error('Only workspace owners can cancel deletions')
    }

    const entry = await ctx.db.get(queueId)
    if (!entry || entry.tenantId !== tenant._id) throw new Error('Deletion not found')
    if (entry.status !== 'scheduled') {
      throw new Error(`Cannot cancel a deletion with status: ${entry.status}`)
    }

    await ctx.db.delete(queueId)

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'deletion.cancelled',
      resourceType: entry.entityType,
      resourceId: entry.entityId,
      payload: JSON.stringify({ queueId }),
      at: Date.now(),
    })

    return null
  },
})

export const listDeletionQueue = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: v.array(deletionQueueSummary),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can view the deletion queue')
    }

    const entries = await ctx.db
      .query('deletionQueue')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(100)

    return entries.map((e) => ({
      _id: e._id,
      entityType: e.entityType,
      entityId: e.entityId,
      tenantId: e.tenantId,
      requestedByUserId: e.requestedByUserId,
      requestedAt: e.requestedAt,
      scheduledAt: e.scheduledAt,
      executedAt: e.executedAt,
      status: e.status,
      error: e.error,
    }))
  },
})

export const processDeletionQueue = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const now = Date.now()

    const candidates = await ctx.db
      .query('deletionQueue')
      .withIndex('by_status_and_scheduled_at', (q) => q.eq('status', 'scheduled'))
      .take(50)

    const due = candidates.filter((d) => d.scheduledAt <= now).slice(0, 10)

    for (const entry of due) {
      await ctx.db.patch(entry._id, { status: 'executing' })

      try {
        if (entry.entityType === 'user') {
          await executeUserDeletion(ctx, entry.entityId as Id<'users'>, entry.tenantId)
          await ctx.db.patch(entry._id, { status: 'completed', executedAt: Date.now() })
        } else if (entry.entityType === 'finding') {
          await executeFindingDeletion(ctx, entry.entityId as Id<'findings'>)
          await ctx.db.patch(entry._id, { status: 'completed', executedAt: Date.now() })
        } else if (entry.entityType === 'tenant') {
          // Tenant cascade runs as a separate chain of scheduled mutations
          await ctx.scheduler.runAfter(
            0,
            internal.deletionPipeline.executeTenantCascadeDelete,
            { tenantId: entry.entityId as Id<'tenants'>, queueId: entry._id, phase: 'findings' },
          )
          continue
        }

        await ctx.db.insert('auditLog', {
          tenantId: entry.tenantId,
          action: 'deletion.executed',
          resourceType: entry.entityType,
          resourceId: entry.entityId,
          payload: JSON.stringify({ queueId: entry._id }),
          at: Date.now(),
        })
      } catch (err) {
        await ctx.db.patch(entry._id, {
          status: 'failed',
          error: String(err),
          executedAt: Date.now(),
        })
        await ctx.db.insert('auditLog', {
          tenantId: entry.tenantId,
          action: 'deletion.failed',
          resourceType: entry.entityType,
          resourceId: entry.entityId,
          payload: JSON.stringify({ queueId: entry._id, error: String(err) }),
          at: Date.now(),
        })
      }
    }

    // Self-reschedule if there are more due items beyond this batch
    const remaining = candidates.filter((d) => d.scheduledAt <= now).length
    if (remaining > 10) {
      await ctx.scheduler.runAfter(0, internal.deletionPipeline.processDeletionQueue, {})
    }

    return null
  },
})

async function executeUserDeletion(
  ctx: MutationCtx,
  userId: Id<'users'>,
  tenantId: Id<'tenants'>,
) {
  const user = await ctx.db.get(userId)
  if (user) {
    // Anonymize PII fields — keep record intact for audit trail integrity
    await ctx.db.patch(userId, {
      email: '[deleted]@deleted.invalid',
      name: 'Deleted User',
    } as any)
  }

  const memberships = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenantId).eq('userId', userId),
    )
    .take(10)
  for (const m of memberships) {
    await ctx.db.delete(m._id)
  }
}

async function executeFindingDeletion(
  ctx: MutationCtx,
  findingId: Id<'findings'>,
) {
  const finding = await ctx.db.get(findingId)
  if (!finding) return
  // Transfer to tenant-level by removing personal reporter context
  await ctx.db.patch(findingId, { source: '[deleted]' })
}

export const executeTenantCascadeDelete = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    queueId: v.id('deletionQueue'),
    phase: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { tenantId, queueId, phase }) => {
    const BATCH = 50

    const reschedule = async (nextPhase: string) => {
      await ctx.scheduler.runAfter(
        0,
        internal.deletionPipeline.executeTenantCascadeDelete,
        { tenantId, queueId, phase: nextPhase },
      )
    }

    if (phase === 'findings') {
      const batch = await ctx.db
        .query('findings')
        .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      await reschedule(batch.length === BATCH ? 'findings' : 'repositories')
      return null
    }

    if (phase === 'repositories') {
      const batch = await ctx.db
        .query('repositories')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      await reschedule(batch.length === BATCH ? 'repositories' : 'apiKeys')
      return null
    }

    if (phase === 'apiKeys') {
      const batch = await ctx.db
        .query('apiKeys')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      await reschedule(batch.length === BATCH ? 'apiKeys' : 'webhooks')
      return null
    }

    if (phase === 'webhooks') {
      const batch = await ctx.db
        .query('webhookEndpoints')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      await reschedule(batch.length === BATCH ? 'webhooks' : 'roles')
      return null
    }

    if (phase === 'roles') {
      const batch = await ctx.db
        .query('roles')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      await reschedule(batch.length === BATCH ? 'roles' : 'members')
      return null
    }

    if (phase === 'members') {
      const batch = await ctx.db
        .query('tenantMembers')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(BATCH)
      for (const doc of batch) await ctx.db.delete(doc._id)
      if (batch.length === BATCH) {
        await reschedule('members')
        return null
      }

      // Final step: delete the tenant itself and mark queue entry complete
      await ctx.db.delete(tenantId)
      const now = Date.now()
      await ctx.db.patch(queueId, { status: 'completed', executedAt: now })
      return null
    }

    return null
  },
})
