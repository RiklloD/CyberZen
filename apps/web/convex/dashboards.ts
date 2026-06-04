/**
 * §6.3 Custom Dashboard Builder — CRUD for custom dashboards
 *
 * Each dashboard has a JSON layout describing widget positions and types.
 * Widgets render data from existing backend queries.
 */
import { v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// ---------------------------------------------------------------------------
// listDashboards — query
// ---------------------------------------------------------------------------

export const listDashboards = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

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

    if (!membership) throw new Error('Not a member of this workspace')

    const dashboards = await ctx.db
      .query('dashboards')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .collect()

    // Users see their own dashboards + default dashboards
    return dashboards
      .filter((d) => d.userId === userId || d.isDefault)
      .map((d) => ({
        _id: d._id,
        name: d.name,
        description: d.description,
        isDefault: d.isDefault,
        layout: d.layout,
        createdAt: d.createdAt,
        updatedAt: d.updatedAt,
      }))
  },
})

// ---------------------------------------------------------------------------
// getDashboard — query
// ---------------------------------------------------------------------------

export const getDashboard = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    dashboardId: v.id('dashboards'),
  },
  handler: async (ctx, { authToken, tenantSlug, dashboardId }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const dashboard = await ctx.db.get(dashboardId)
    if (!dashboard) return null
    if (dashboard.tenantId !== tenant._id) throw new Error('Dashboard not found')
    if (!dashboard.isDefault && dashboard.userId !== userId) {
      throw new Error('Not authorized to view this dashboard')
    }

    return {
      _id: dashboard._id,
      name: dashboard.name,
      description: dashboard.description,
      layout: dashboard.layout,
      isDefault: dashboard.isDefault,
      createdAt: dashboard.createdAt,
      updatedAt: dashboard.updatedAt,
    }
  },
})

// ---------------------------------------------------------------------------
// createDashboard — mutation
// ---------------------------------------------------------------------------

export const createDashboard = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    layout: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug, name, description, layout }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const now = Date.now()
    const dashboardId = await ctx.db.insert('dashboards', {
      tenantId: tenant._id,
      userId,
      name,
      description,
      layout,
      isDefault: false,
      createdAt: now,
      updatedAt: now,
    })

    return { dashboardId }
  },
})

// ---------------------------------------------------------------------------
// updateDashboard — mutation
// ---------------------------------------------------------------------------

export const updateDashboard = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    dashboardId: v.id('dashboards'),
    name: v.optional(v.string()),
    description: v.optional(v.string()),
    layout: v.optional(v.string()),
  },
  handler: async (ctx, { authToken, tenantSlug, dashboardId, name, description, layout }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const dashboard = await ctx.db.get(dashboardId)
    if (!dashboard || dashboard.tenantId !== tenant._id) {
      throw new Error('Dashboard not found')
    }

    // Only the owner or admins can edit
    if (dashboard.userId !== userId) {
      const membership = await ctx.db
        .query('tenantMembers')
        .withIndex('by_tenant_and_user', (q: any) =>
          q.eq('tenantId', tenant._id).eq('userId', userId),
        )
        .unique()
      if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
        throw new Error('Not authorized to edit this dashboard')
      }
    }

    const updates: any = { updatedAt: Date.now() }
    if (name !== undefined) updates.name = name
    if (description !== undefined) updates.description = description
    if (layout !== undefined) updates.layout = layout

    await ctx.db.patch(dashboardId, updates)
    return { success: true }
  },
})

// ---------------------------------------------------------------------------
// deleteDashboard — mutation
// ---------------------------------------------------------------------------

export const deleteDashboard = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    dashboardId: v.id('dashboards'),
  },
  handler: async (ctx, { authToken, tenantSlug, dashboardId }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const dashboard = await ctx.db.get(dashboardId)
    if (!dashboard || dashboard.tenantId !== tenant._id) {
      throw new Error('Dashboard not found')
    }

    if (dashboard.isDefault) throw new Error('Cannot delete default dashboards')
    if (dashboard.userId !== userId) throw new Error('Not authorized')

    await ctx.db.delete(dashboardId)
    return { success: true }
  },
})
