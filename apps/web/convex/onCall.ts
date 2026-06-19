// §6.24 — On-Call Rotation & Escalation Policies
//
//   listSchedules          — public query: list on-call schedules for a tenant
//   createSchedule         — public mutation: create a new on-call schedule
//   updateSchedule         — public mutation: update an on-call schedule
//   deleteSchedule         — public mutation: remove an on-call schedule
//   listEscalationPolicies — public query: list escalation policies for a tenant
//   createEscalationPolicy — public mutation: create a new escalation policy
//   updateEscalationPolicy — public mutation: update an escalation policy
//   deleteEscalationPolicy — public mutation: remove an escalation policy

import { v } from 'convex/values'
import { query, mutation } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

const ROTATION_TYPES = v.union(
  v.literal('daily'),
  v.literal('weekly'),
  v.literal('biweekly'),
  v.literal('monthly'),
)

const ESCALATION_TARGET = v.union(
  v.literal('current_on_call'),
  v.literal('schedule_members'),
  v.literal('specific_user'),
)

const CHANNEL = v.union(
  v.literal('email'),
  v.literal('slack'),
  v.literal('sms'),
  v.literal('webhook'),
)

// ---------------------------------------------------------------------------
// On-Call Schedule Queries
// ---------------------------------------------------------------------------

export const listSchedules = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)

    const schedules = await ctx.db
      .query('onCallSchedules')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    // Enrich with member info
    const enriched = await Promise.all(
      schedules.map(async (schedule) => {
        const members = await Promise.all(
          schedule.memberIds.map((id) => ctx.db.get(id)),
        )
        return {
          ...schedule,
          members: members.filter(Boolean).map((m) => ({
            _id: m!._id,
            name: m!.name ?? m!.email ?? 'Unknown',
            email: m!.email ?? '',
          })),
        }
      }),
    )

    return enriched.sort((a, b) => a.createdAt - b.createdAt)
  },
})

// ---------------------------------------------------------------------------
// On-Call Schedule Mutations
// ---------------------------------------------------------------------------

export const createSchedule = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    rotationType: ROTATION_TYPES,
    memberIds: v.array(v.id('users')),
    timezone: v.string(),
    enabled: v.boolean(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const now = Date.now()

    if (args.memberIds.length === 0) {
      throw new Error('At least one member is required')
    }

    return ctx.db.insert('onCallSchedules', {
      tenantId: tenant._id,
      name: args.name,
      description: args.description,
      rotationType: args.rotationType,
      memberIds: args.memberIds,
      currentRotationIndex: 0,
      currentRotationStart: now,
      timezone: args.timezone,
      enabled: args.enabled,
      createdAt: now,
      updatedAt: now,
    })
  },
})

export const updateSchedule = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    scheduleId: v.id('onCallSchedules'),
    name: v.optional(v.string()),
    description: v.optional(v.string()),
    rotationType: v.optional(ROTATION_TYPES),
    memberIds: v.optional(v.array(v.id('users'))),
    timezone: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.scheduleId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('On-call schedule not found')
    }

    const patch: Record<string, unknown> = { updatedAt: Date.now() }
    if (args.name !== undefined) patch.name = args.name
    if (args.description !== undefined) patch.description = args.description
    if (args.rotationType !== undefined) patch.rotationType = args.rotationType
    if (args.memberIds !== undefined) {
      if (args.memberIds.length === 0) throw new Error('At least one member is required')
      patch.memberIds = args.memberIds
    }
    if (args.timezone !== undefined) patch.timezone = args.timezone
    if (args.enabled !== undefined) patch.enabled = args.enabled

    await ctx.db.patch(args.scheduleId, patch)
  },
})

export const deleteSchedule = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    scheduleId: v.id('onCallSchedules'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.scheduleId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('On-call schedule not found')
    }

    // Also delete any escalation policies bound to this schedule
    const escalationPolicies = await ctx.db
      .query('escalationPolicies')
      .withIndex('by_tenant_and_schedule', (q) =>
        q.eq('tenantId', tenant._id).eq('onCallScheduleId', args.scheduleId),
      )
      .collect()

    for (const ep of escalationPolicies) {
      await ctx.db.delete(ep._id)
    }

    await ctx.db.delete(args.scheduleId)
  },
})

// ---------------------------------------------------------------------------
// Escalation Policy Queries
// ---------------------------------------------------------------------------

export const listEscalationPolicies = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)

    const policies = await ctx.db
      .query('escalationPolicies')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    // Enrich with schedule name
    const enriched = await Promise.all(
      policies.map(async (policy) => {
        const schedule = await ctx.db.get(policy.onCallScheduleId)
        return {
          ...policy,
          scheduleName: schedule?.name ?? 'Unknown',
        }
      }),
    )

    return enriched.sort((a, b) => a.createdAt - b.createdAt)
  },
})

// ---------------------------------------------------------------------------
// Escalation Policy Mutations
// ---------------------------------------------------------------------------

export const createEscalationPolicy = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    onCallScheduleId: v.id('onCallSchedules'),
    steps: v.array(
      v.object({
        delayMinutes: v.number(),
        target: ESCALATION_TARGET,
        targetUserId: v.optional(v.id('users')),
        channels: v.array(CHANNEL),
      }),
    ),
    repeatCount: v.number(),
    enabled: v.boolean(),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)

    // Verify the schedule belongs to the tenant
    const schedule = await ctx.db.get(args.onCallScheduleId)
    if (!schedule || schedule.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('On-call schedule not found')
    }

    if (args.steps.length === 0) {
      throw new Error('At least one escalation step is required')
    }

    const now = Date.now()
    return ctx.db.insert('escalationPolicies', {
      tenantId: tenant._id,
      name: args.name,
      description: args.description,
      onCallScheduleId: args.onCallScheduleId,
      steps: args.steps,
      repeatCount: args.repeatCount,
      enabled: args.enabled,
      createdAt: now,
      updatedAt: now,
    })
  },
})

export const updateEscalationPolicy = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    policyId: v.id('escalationPolicies'),
    name: v.optional(v.string()),
    description: v.optional(v.string()),
    onCallScheduleId: v.optional(v.id('onCallSchedules')),
    steps: v.optional(
      v.array(
        v.object({
          delayMinutes: v.number(),
          target: ESCALATION_TARGET,
          targetUserId: v.optional(v.id('users')),
          channels: v.array(CHANNEL),
        }),
      ),
    ),
    repeatCount: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.policyId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('Escalation policy not found')
    }

    const patch: Record<string, unknown> = { updatedAt: Date.now() }
    if (args.name !== undefined) patch.name = args.name
    if (args.description !== undefined) patch.description = args.description
    if (args.onCallScheduleId !== undefined) {
      const schedule = await ctx.db.get(args.onCallScheduleId)
      if (!schedule || schedule.tenantId.toHexString() !== tenant._id.toHexString()) {
        throw new Error('On-call schedule not found')
      }
      patch.onCallScheduleId = args.onCallScheduleId
    }
    if (args.steps !== undefined) {
      if (args.steps.length === 0) throw new Error('At least one step required')
      patch.steps = args.steps
    }
    if (args.repeatCount !== undefined) patch.repeatCount = args.repeatCount
    if (args.enabled !== undefined) patch.enabled = args.enabled

    await ctx.db.patch(args.policyId, patch)
  },
})

export const deleteEscalationPolicy = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    policyId: v.id('escalationPolicies'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await requireSessionAuth(ctx, args.authToken, args.tenantSlug)
    const existing = await ctx.db.get(args.policyId)
    if (!existing || existing.tenantId.toHexString() !== tenant._id.toHexString()) {
      throw new Error('Escalation policy not found')
    }
    await ctx.db.delete(args.policyId)
  },
})
