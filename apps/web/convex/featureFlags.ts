import { v } from 'convex/values'
import { query } from './_generated/server'

// ─── §8.2 — Feature Flags (derived from tenant.plan.featureFlags) ─────────

async function getTenantFlags(
  ctx: { db: any },
  tenantSlug: string,
): Promise<string[]> {
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
    .unique()
  if (!tenant) return []

  const subscription = await ctx.db
    .query('subscriptions')
    .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
    .first()

  const planSlug = subscription?.planSlug ?? 'free'
  const plan = await ctx.db
    .query('plans')
    .withIndex('by_slug', (q: any) => q.eq('slug', planSlug))
    .unique()

  return plan?.featureFlags ?? []
}

export const isEnabledForTenant = query({
  args: {
    tenantSlug: v.string(),
    slug: v.string(),
  },
  returns: v.boolean(),
  handler: async (ctx, { tenantSlug, slug }) => {
    const flags = await getTenantFlags(ctx, tenantSlug)
    return flags.includes(slug)
  },
})

export const listEnabledForTenant = query({
  args: { tenantSlug: v.string() },
  returns: v.array(v.string()),
  handler: async (ctx, { tenantSlug }) => {
    return await getTenantFlags(ctx, tenantSlug)
  },
})
