import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import type { Id } from './_generated/dataModel'
import { requireSessionAuth } from './lib/sessionAuth'

async function getTenantAndVerifyAdmin(
  ctx: any,
  authToken: string | undefined,
  tenantSlug: string,
) {
  const { userId } = await requireSessionAuth(ctx, authToken)

  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
    .unique()

  if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q: any) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()

  if (!membership) throw new Error('You do not have access to this workspace')

  if (membership.role !== 'owner' && membership.role !== 'admin') {
    throw new Error('Only owners and admins can manage access reviews')
  }

  return { userId, tenant }
}

export const scheduleAccessReview = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    period: v.string(),
    dueDate: v.number(),
  },
  returns: v.id('accessReviewCycles'),
  handler: async (ctx, { authToken, tenantSlug, period, dueDate }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const now = Date.now()
    const cycleId = await ctx.db.insert('accessReviewCycles', {
      tenantId: tenant._id,
      period,
      status: 'in_progress',
      dueDate,
      createdByUserId: userId,
      createdAt: now,
    })

    const members = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .take(200)

    for (const member of members) {
      await ctx.db.insert('accessReviewItems', {
        cycleId,
        tenantId: tenant._id,
        memberId: member._id,
        role: member.role,
        permissions: member.delegatedPermissions ?? [],
      })
    }

    return cycleId
  },
})

export const listPendingReviews = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    cycleId: v.optional(v.id('accessReviewCycles')),
  },
  handler: async (ctx, { authToken, tenantSlug, cycleId }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    let activeCycleId: Id<'accessReviewCycles'> | undefined = cycleId
    if (!activeCycleId) {
      const activeCycle = await ctx.db
        .query('accessReviewCycles')
        .withIndex('by_tenant_and_status', (q: any) =>
          q.eq('tenantId', tenant._id).eq('status', 'in_progress'),
        )
        .order('desc')
        .first()
      if (!activeCycle) return []
      activeCycleId = activeCycle._id
    }

    const items = await ctx.db
      .query('accessReviewItems')
      .withIndex('by_cycle', (q: any) => q.eq('cycleId', activeCycleId))
      .take(200)

    return await Promise.all(
      items.map(async (item) => {
        const member = await ctx.db.get(item.memberId)
        const user = member ? await ctx.db.get(member.userId) : null
        return {
          ...item,
          userEmail: (user as any)?.email ?? null,
          userName: (user as any)?.name ?? null,
        }
      }),
    )
  },
})

export const approveAccess = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    reviewItemId: v.id('accessReviewItems'),
    justification: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, reviewItemId, justification }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const item = await ctx.db.get(reviewItemId)
    if (!item || item.tenantId !== tenant._id) throw new Error('Review item not found')

    await ctx.db.patch(reviewItemId, {
      decision: 'approved',
      reviewerId: userId,
      justification,
      reviewedAt: Date.now(),
    })

    return null
  },
})

export const flagForRemoval = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    reviewItemId: v.id('accessReviewItems'),
    reason: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, reviewItemId, reason }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const item = await ctx.db.get(reviewItemId)
    if (!item || item.tenantId !== tenant._id) throw new Error('Review item not found')

    await ctx.db.patch(reviewItemId, {
      decision: 'flagged_for_removal',
      reviewerId: userId,
      justification: reason,
      reviewedAt: Date.now(),
    })

    return null
  },
})

export const completeAccessReview = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    cycleId: v.id('accessReviewCycles'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, cycleId }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const cycle = await ctx.db.get(cycleId)
    if (!cycle || cycle.tenantId !== tenant._id) throw new Error('Review cycle not found')

    await ctx.db.patch(cycleId, {
      status: 'completed',
      completedAt: Date.now(),
    })

    return null
  },
})

export const listReviewCycles = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    return await ctx.db
      .query('accessReviewCycles')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(20)
  },
})

export const sendQuarterlyReminder = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const tenants = await ctx.db.query('tenants').take(200)

    for (const tenant of tenants) {
      const existing = await ctx.db
        .query('accessReviewCycles')
        .withIndex('by_tenant_and_status', (q: any) =>
          q.eq('tenantId', tenant._id).eq('status', 'in_progress'),
        )
        .first()

      if (!existing) {
        console.log(
          `[AccessReview] Quarterly reminder: ${tenant.slug} has no active review cycle`,
        )
      }
    }

    return null
  },
})
