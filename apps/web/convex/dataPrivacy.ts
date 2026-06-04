import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

const GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

export const listDataRequests = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.array(
    v.object({
      _id: v.id('dataRequests'),
      type: v.union(
        v.literal('access'),
        v.literal('deletion'),
        v.literal('portability'),
      ),
      status: v.union(
        v.literal('pending'),
        v.literal('processing'),
        v.literal('complete'),
        v.literal('cancelled'),
      ),
      requestDate: v.number(),
      completionDate: v.optional(v.number()),
      downloadUrl: v.optional(v.string()),
      gracePeriodEnd: v.optional(v.number()),
    }),
  ),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const requests = await ctx.db
      .query('dataRequests')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .order('desc')
      .take(50)

    return requests.map((r) => ({
      _id: r._id,
      type: r.type,
      status: r.status,
      requestDate: r.requestDate,
      completionDate: r.completionDate,
      downloadUrl: r.downloadUrl,
      gracePeriodEnd: r.gracePeriodEnd,
    }))
  },
})

export const requestDataAccess = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.id('dataRequests'),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const id = await ctx.db.insert('dataRequests', {
      tenantId: tenant._id,
      userId,
      type: 'access',
      status: 'pending',
      requestDate: Date.now(),
    })

    return id
  },
})

export const requestDataDeletion = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.id('dataRequests'),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const gracePeriodEnd = Date.now() + GRACE_PERIOD_MS

    const id = await ctx.db.insert('dataRequests', {
      tenantId: tenant._id,
      userId,
      type: 'deletion',
      status: 'pending',
      requestDate: Date.now(),
      gracePeriodEnd,
    })

    return id
  },
})

export const requestDataExport = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.id('dataRequests'),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const id = await ctx.db.insert('dataRequests', {
      tenantId: tenant._id,
      userId,
      type: 'portability',
      status: 'pending',
      requestDate: Date.now(),
    })

    return id
  },
})

export const cancelDataRequest = mutation({
  args: {
    authToken: v.string(),
    requestId: v.id('dataRequests'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, requestId }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const request = await ctx.db.get(requestId)
    if (!request || request.userId !== userId) {
      throw new Error('Request not found')
    }
    if (request.status !== 'pending') {
      throw new Error('Only pending requests can be cancelled')
    }

    await ctx.db.patch(requestId, { status: 'cancelled' })

    return null
  },
})

export const processPendingRequests = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const pending = await ctx.db
      .query('dataRequests')
      .withIndex('by_status', (q) => q.eq('status', 'pending'))
      .take(20)

    const now = Date.now()

    for (const request of pending) {
      if (request.type === 'deletion') {
        if (!request.gracePeriodEnd || request.gracePeriodEnd > now) {
          continue
        }
      }

      await ctx.db.patch(request._id, { status: 'processing' })

      if (request.type === 'access' || request.type === 'portability') {
        const user = await ctx.db.get(request.userId)
        const memberships = await ctx.db
          .query('tenantMembers')
          .withIndex('by_user_and_selected_at', (q) =>
            q.eq('userId', request.userId),
          )
          .take(10)

        const auditEntries = await ctx.db
          .query('auditLog')
          .withIndex('by_tenant_and_at', (q) => q.eq('tenantId', request.tenantId))
          .order('desc')
          .take(100)

        const exportData = {
          exportedAt: new Date(now).toISOString(),
          user: user
            ? {
                id: user._id,
                email: 'email' in user ? (user as { email?: string }).email : undefined,
                name: 'name' in user ? (user as { name?: string }).name : undefined,
              }
            : null,
          workspaceMemberships: memberships.map((m) => ({
            tenantId: m.tenantId,
            role: m.role,
            joinedAt: m.joinedAt,
          })),
          auditLogEntries: auditEntries
            .filter((e) => e.actorUserId === request.userId)
            .map((e) => ({
              action: e.action,
              resourceType: e.resourceType,
              at: e.at,
            })),
        }

        await ctx.db.patch(request._id, {
          status: 'complete',
          completionDate: now,
          resultJson: JSON.stringify(exportData),
        })
      } else if (request.type === 'deletion') {
        await ctx.db.patch(request._id, {
          status: 'complete',
          completionDate: now,
        })
      }
    }

    return null
  },
})
