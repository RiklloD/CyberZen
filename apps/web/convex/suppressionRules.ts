// §6.8 — Finding Suppression Rules Engine
//
// Mutations:
//   createRule   — create a new suppression rule
//   updateRule   — update rule config
//   deleteRule   — remove a suppression rule
//
// Queries:
//   listRules    — all suppression rules for a tenant

import { v } from 'convex/values'
import { mutation, query } from './_generated/server'

// ── Queries ────────────────────────────────────────────────────────────────

/**
 * List all suppression rules for a tenant.
 */
export const listRules = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('suppressionRules'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      pattern: v.string(),
      scope: v.union(
        v.literal('all'),
        v.literal('repository'),
        v.literal('severity'),
        v.literal('package'),
        v.literal('vuln_class'),
      ),
      scopeValue: v.optional(v.string()),
      justification: v.string(),
      expiresAt: v.optional(v.number()),
      createdById: v.optional(v.id('users')),
      enabled: v.boolean(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    return await ctx.db
      .query('suppressionRules')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

// ── Mutations ──────────────────────────────────────────────────────────────

/**
 * Create a new suppression rule.
 */
export const createRule = mutation({
  args: {
    tenantSlug: v.string(),
    pattern: v.string(),
    scope: v.union(
      v.literal('all'),
      v.literal('repository'),
      v.literal('severity'),
      v.literal('package'),
      v.literal('vuln_class'),
    ),
    scopeValue: v.optional(v.string()),
    justification: v.string(),
    expiresAt: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
  },
  returns: v.id('suppressionRules'),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) throw new Error('Tenant not found')

    return await ctx.db.insert('suppressionRules', {
      tenantId: tenant._id,
      pattern: args.pattern,
      scope: args.scope,
      scopeValue: args.scopeValue,
      justification: args.justification,
      expiresAt: args.expiresAt,
      createdById: undefined,
      enabled: args.enabled ?? true,
    })
  },
})

/**
 * Update an existing suppression rule.
 */
export const updateRule = mutation({
  args: {
    ruleId: v.id('suppressionRules'),
    pattern: v.optional(v.string()),
    scope: v.optional(
      v.union(
        v.literal('all'),
        v.literal('repository'),
        v.literal('severity'),
        v.literal('package'),
        v.literal('vuln_class'),
      ),
    ),
    scopeValue: v.optional(v.string()),
    justification: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { ruleId, ...updates } = args
    const rule = await ctx.db.get(ruleId)
    if (!rule) throw new Error('Suppression rule not found')

    const patch: Record<string, unknown> = {}
    if (updates.pattern !== undefined) patch.pattern = updates.pattern
    if (updates.scope !== undefined) patch.scope = updates.scope
    if (updates.scopeValue !== undefined) patch.scopeValue = updates.scopeValue
    if (updates.justification !== undefined) patch.justification = updates.justification
    if (updates.expiresAt !== undefined) patch.expiresAt = updates.expiresAt
    if (updates.enabled !== undefined) patch.enabled = updates.enabled

    await ctx.db.patch(ruleId, patch)
  },
})

/**
 * Delete a suppression rule.
 */
export const deleteRule = mutation({
  args: { ruleId: v.id('suppressionRules') },
  returns: v.null(),
  handler: async (ctx, args) => {
    const rule = await ctx.db.get(args.ruleId)
    if (!rule) throw new Error('Suppression rule not found')
    await ctx.db.delete(args.ruleId)
  },
})
