import { v } from 'convex/values'
import { query } from './_generated/server'

// ─── §8.1 — Tiered Pricing Plans ──────────────────────────────────────────

const planFields = {
  _id: v.id('plans'),
  _creationTime: v.number(),
  slug: v.string(),
  name: v.string(),
  monthlyPrice: v.number(),
  repoLimit: v.number(),
  seatLimit: v.number(),
  featureFlags: v.array(v.string()),
}

export const listPlans = query({
  args: {},
  returns: v.array(v.object(planFields)),
  handler: async (ctx) => {
    return await ctx.db.query('plans').collect()
  },
})

export const currentPlanForTenant = query({
  args: { tenantSlug: v.string() },
  returns: v.union(v.null(), v.object(planFields)),
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const subscription = await ctx.db
      .query('subscriptions')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .first()

    const slug = subscription?.planSlug ?? 'free'
    return await ctx.db
      .query('plans')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique()
  },
})

export const getPlanBySlug = query({
  args: { slug: v.string() },
  returns: v.union(v.null(), v.object(planFields)),
  handler: async (ctx, { slug }) => {
    return await ctx.db
      .query('plans')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique()
  },
})
