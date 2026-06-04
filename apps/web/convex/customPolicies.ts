// §6.9 — Custom Policy Builder
//
// Mutations:
//   createPolicy  — create a new custom policy
//   updatePolicy  — update policy config (name, dsl, enabled)
//   deletePolicy  — remove a custom policy
//
// Queries:
//   listPolicies  — all custom policies for a tenant
//   getPolicy     — single policy by id

import { v } from 'convex/values'
import { mutation, query } from './_generated/server'

// ── Queries ────────────────────────────────────────────────────────────────

/**
 * List all custom policies for a tenant.
 */
export const listPolicies = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('customPolicies'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      name: v.string(),
      description: v.optional(v.string()),
      dsl: v.string(),
      enabled: v.boolean(),
      createdAt: v.number(),
      updatedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    return await ctx.db
      .query('customPolicies')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

/**
 * Get a single custom policy by ID.
 */
export const getPolicy = query({
  args: { policyId: v.id('customPolicies') },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id('customPolicies'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      name: v.string(),
      description: v.optional(v.string()),
      dsl: v.string(),
      enabled: v.boolean(),
      createdAt: v.number(),
      updatedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db.get(args.policyId)
  },
})

// ── Mutations ──────────────────────────────────────────────────────────────

/**
 * Create a new custom policy.
 */
export const createPolicy = mutation({
  args: {
    tenantSlug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    dsl: v.string(),
    enabled: v.optional(v.boolean()),
  },
  returns: v.id('customPolicies'),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) throw new Error('Tenant not found')

    const now = Date.now()
    return await ctx.db.insert('customPolicies', {
      tenantId: tenant._id,
      name: args.name,
      description: args.description,
      dsl: args.dsl,
      enabled: args.enabled ?? true,
      createdAt: now,
      updatedAt: now,
    })
  },
})

/**
 * Update an existing custom policy.
 */
export const updatePolicy = mutation({
  args: {
    policyId: v.id('customPolicies'),
    name: v.optional(v.string()),
    description: v.optional(v.string()),
    dsl: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { policyId, ...updates } = args
    const policy = await ctx.db.get(policyId)
    if (!policy) throw new Error('Policy not found')

    const patch: Record<string, unknown> = { updatedAt: Date.now() }
    if (updates.name !== undefined) patch.name = updates.name
    if (updates.description !== undefined) patch.description = updates.description
    if (updates.dsl !== undefined) patch.dsl = updates.dsl
    if (updates.enabled !== undefined) patch.enabled = updates.enabled

    await ctx.db.patch(policyId, patch)
  },
})

/**
 * Delete a custom policy.
 */
export const deletePolicy = mutation({
  args: { policyId: v.id('customPolicies') },
  returns: v.null(),
  handler: async (ctx, args) => {
    const policy = await ctx.db.get(args.policyId)
    if (!policy) throw new Error('Policy not found')
    await ctx.db.delete(args.policyId)
  },
})
