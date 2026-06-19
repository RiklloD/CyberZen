import { v } from 'convex/values'
import { mutation, query } from './_generated/server'

// ── §6.2 — Notification Center ──────────────────────────────────────

const notificationType = v.union(
  v.literal('finding_critical'),
  v.literal('finding_high'),
  v.literal('gate_blocked'),
  v.literal('gate_overridden'),
  v.literal('exploit_validated'),
  v.literal('remediation_dispatched'),
  v.literal('pr_generated'),
  v.literal('scan_completed'),
  v.literal('sla_breach'),
  v.literal('member_invited'),
  v.literal('system'),
)

/**
 * List notifications for the current user in the given tenant.
 * Returns newest first.
 */
export const listForUser = query({
  args: {
    tenantSlug: v.string(),
    authToken: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      _id: v.id('notifications'),
      _creationTime: v.number(),
      userId: v.id('users'),
      tenantId: v.id('tenants'),
      type: v.string(),
      payload: v.string(),
      readAt: v.optional(v.number()),
      createdAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    // Get the current user via auth
    const identity = await ctx.auth.getUserIdentity()
    if (!identity) return []

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', identity.email!))
      .unique()

    if (!user) return []

    const notifications = await ctx.db
      .query('notifications')
      .withIndex('by_user', (q) => q.eq('userId', user._id))
      .order('desc')
      .take(100)

    // Filter to current tenant
    return notifications.filter((n) => n.tenantId === tenant._id)
  },
})

/**
 * Get the count of unread notifications for the bell badge.
 */
export const unreadCount = query({
  args: {
    tenantSlug: v.string(),
    authToken: v.optional(v.string()),
  },
  returns: v.number(),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return 0

    const identity = await ctx.auth.getUserIdentity()
    if (!identity) return 0

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', identity.email!))
      .unique()

    if (!user) return 0

    const unread = await ctx.db
      .query('notifications')
      .withIndex('by_user_unread', (q) => q.eq('userId', user._id).eq('readAt', undefined!))
      .collect()

    return unread.filter((n) => n.tenantId === tenant._id).length
  },
})

/**
 * Mark a single notification as read.
 */
export const markRead = mutation({
  args: {
    notificationId: v.id('notifications'),
    authToken: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const notification = await ctx.db.get(args.notificationId)
    if (!notification) throw new Error('Notification not found')

    await ctx.db.patch(args.notificationId, {
      readAt: Date.now(),
    })
  },
})

/**
 * Mark all notifications for the current user in the tenant as read.
 */
export const markAllRead = mutation({
  args: {
    tenantSlug: v.string(),
    authToken: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return

    const identity = await ctx.auth.getUserIdentity()
    if (!identity) return

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', identity.email!))
      .unique()

    if (!user) return

    const unread = await ctx.db
      .query('notifications')
      .withIndex('by_user', (q) => q.eq('userId', user._id))
      .collect()

    const now = Date.now()
    for (const n of unread) {
      if (!n.readAt && n.tenantId === tenant._id) {
        await ctx.db.patch(n._id, { readAt: now })
      }
    }
  },
})

/**
 * Get notification preferences for the current user.
 */
export const getPreferences = query({
  args: {
    tenantSlug: v.string(),
    authToken: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      _id: v.id('notificationPreferences'),
      _creationTime: v.number(),
      userId: v.id('users'),
      tenantId: v.id('tenants'),
      channel: v.union(
        v.literal('in_app'),
        v.literal('email'),
        v.literal('slack'),
      ),
      type: v.string(),
      enabled: v.boolean(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    const identity = await ctx.auth.getUserIdentity()
    if (!identity) return []

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', identity.email!))
      .unique()

    if (!user) return []

    return await ctx.db
      .query('notificationPreferences')
      .withIndex('by_user_tenant', (q) =>
        q.eq('userId', user._id).eq('tenantId', tenant._id),
      )
      .collect()
  },
})

/**
 * Update (or create) a notification preference.
 */
export const upsertPreference = mutation({
  args: {
    tenantSlug: v.string(),
    authToken: v.optional(v.string()),
    channel: v.union(
      v.literal('in_app'),
      v.literal('email'),
      v.literal('slack'),
    ),
    type: v.string(),
    enabled: v.boolean(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) throw new Error('Tenant not found')

    const identity = await ctx.auth.getUserIdentity()
    if (!identity) throw new Error('Not authenticated')

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', identity.email!))
      .unique()

    if (!user) throw new Error('User not found')

    const existing = await ctx.db
      .query('notificationPreferences')
      .withIndex('by_user_tenant', (q) =>
        q.eq('userId', user._id).eq('tenantId', tenant._id),
      )
      .collect()

    const match = existing.find(
      (p) => p.channel === args.channel && p.type === args.type,
    )

    if (match) {
      await ctx.db.patch(match._id, { enabled: args.enabled })
    } else {
      await ctx.db.insert('notificationPreferences', {
        userId: user._id,
        tenantId: tenant._id,
        channel: args.channel,
        type: args.type,
        enabled: args.enabled,
      })
    }
  },
})
