// §6.7 — Scan Scheduling & On-Demand Triggers
//
// Mutations:
//   createSchedule   — create a new scan schedule for a scanner
//   updateSchedule   — update schedule config (cron, enabled, repositories)
//   deleteSchedule   — remove a schedule
//   runScanNow       — trigger an immediate scan
//
// Queries:
//   listSchedules    — all schedules for a tenant
//   getSchedule      — single schedule by id

import { v } from 'convex/values'
import { mutation, query } from './_generated/server'

// ── Queries ────────────────────────────────────────────────────────────────

/**
 * List all scan schedules for a tenant.
 */
export const listSchedules = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('scanSchedules'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      scannerSlug: v.string(),
      cronExpression: v.string(),
      enabled: v.boolean(),
      repositoryIds: v.array(v.id('repositories')),
      lastRunAt: v.optional(v.number()),
      description: v.optional(v.string()),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    return await ctx.db
      .query('scanSchedules')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

/**
 * Get a single scan schedule by ID.
 */
export const getSchedule = query({
  args: { scheduleId: v.id('scanSchedules') },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id('scanSchedules'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      scannerSlug: v.string(),
      cronExpression: v.string(),
      enabled: v.boolean(),
      repositoryIds: v.array(v.id('repositories')),
      lastRunAt: v.optional(v.number()),
      description: v.optional(v.string()),
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db.get(args.scheduleId)
  },
})

// ── Mutations ──────────────────────────────────────────────────────────────

/**
 * Create a new scan schedule.
 */
export const createSchedule = mutation({
  args: {
    tenantSlug: v.string(),
    scannerSlug: v.string(),
    cronExpression: v.string(),
    repositoryIds: v.array(v.id('repositories')),
    enabled: v.optional(v.boolean()),
    description: v.optional(v.string()),
  },
  returns: v.id('scanSchedules'),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) throw new Error('Tenant not found')

    return await ctx.db.insert('scanSchedules', {
      tenantId: tenant._id,
      scannerSlug: args.scannerSlug,
      cronExpression: args.cronExpression,
      repositoryIds: args.repositoryIds,
      enabled: args.enabled ?? true,
      lastRunAt: undefined,
      description: args.description,
    })
  },
})

/**
 * Update an existing scan schedule.
 */
export const updateSchedule = mutation({
  args: {
    scheduleId: v.id('scanSchedules'),
    scannerSlug: v.optional(v.string()),
    cronExpression: v.optional(v.string()),
    repositoryIds: v.optional(v.array(v.id('repositories'))),
    enabled: v.optional(v.boolean()),
    description: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { scheduleId, ...updates } = args
    const schedule = await ctx.db.get(scheduleId)
    if (!schedule) throw new Error('Schedule not found')

    const patch: Record<string, unknown> = {}
    if (updates.scannerSlug !== undefined) patch.scannerSlug = updates.scannerSlug
    if (updates.cronExpression !== undefined) patch.cronExpression = updates.cronExpression
    if (updates.repositoryIds !== undefined) patch.repositoryIds = updates.repositoryIds
    if (updates.enabled !== undefined) patch.enabled = updates.enabled
    if (updates.description !== undefined) patch.description = updates.description

    await ctx.db.patch(scheduleId, patch)
  },
})

/**
 * Delete a scan schedule.
 */
export const deleteSchedule = mutation({
  args: { scheduleId: v.id('scanSchedules') },
  returns: v.null(),
  handler: async (ctx, args) => {
    const schedule = await ctx.db.get(args.scheduleId)
    if (!schedule) throw new Error('Schedule not found')
    await ctx.db.delete(args.scheduleId)
  },
})

/**
 * Trigger an immediate scan for a schedule's scanner + repositories.
 * Records the lastRunAt timestamp.
 */
export const runScanNow = mutation({
  args: { scheduleId: v.id('scanSchedules') },
  returns: v.object({ triggered: v.boolean() }),
  handler: async (ctx, args) => {
    const schedule = await ctx.db.get(args.scheduleId)
    if (!schedule) throw new Error('Schedule not found')

    // Update lastRunAt
    await ctx.db.patch(args.scheduleId, {
      lastRunAt: Date.now(),
    })

    // In a production system this would dispatch to a scanner runner.
    // For now we record the trigger and return success.
    return { triggered: true }
  },
})
