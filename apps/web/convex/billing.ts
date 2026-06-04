import { query } from './_generated/server'
import { v } from 'convex/values'

// ─── §6.12 — Billing / Subscription Management ──────────────────────────────

/**
 * List all available billing plans, ordered by sortOrder.
 */
export const listPlans = query({
  args: {},
  returns: v.array(
    v.object({
      _id: v.id('billingPlans'),
      slug: v.string(),
      name: v.string(),
      description: v.string(),
      priceCents: v.number(),
      currency: v.string(),
      interval: v.union(v.literal('month'), v.literal('year')),
      maxRepositories: v.number(),
      maxMembers: v.number(),
      features: v.array(v.string()),
      highlighted: v.boolean(),
      sortOrder: v.number(),
    }),
  ),
  handler: async (ctx) => {
    return await ctx.db
      .query('billingPlans')
      .withIndex('by_sort_order')
      .collect()
  },
})

/**
 * Get the current subscription and plan for a tenant.
 */
export const currentPlanForTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      subscription: v.object({
        _id: v.id('subscriptions'),
        planSlug: v.string(),
        status: v.union(
          v.literal('active'),
          v.literal('past_due'),
          v.literal('canceled'),
          v.literal('trialing'),
        ),
        currentPeriodStart: v.number(),
        currentPeriodEnd: v.number(),
        cancelAtPeriodEnd: v.boolean(),
      }),
      plan: v.union(
        v.null(),
        v.object({
          _id: v.id('billingPlans'),
          slug: v.string(),
          name: v.string(),
          description: v.string(),
          priceCents: v.number(),
          currency: v.string(),
          interval: v.union(v.literal('month'), v.literal('year')),
          maxRepositories: v.number(),
          maxMembers: v.number(),
          features: v.array(v.string()),
          highlighted: v.boolean(),
          sortOrder: v.number(),
        }),
      ),
    }),
  ),
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

    if (!subscription) return null

    const plan = await ctx.db
      .query('billingPlans')
      .withIndex('by_slug', (q) => q.eq('slug', subscription.planSlug))
      .unique()

    return {
      subscription: {
        _id: subscription._id,
        planSlug: subscription.planSlug,
        status: subscription.status,
        currentPeriodStart: subscription.currentPeriodStart,
        currentPeriodEnd: subscription.currentPeriodEnd,
        cancelAtPeriodEnd: subscription.cancelAtPeriodEnd,
      },
      plan,
    }
  },
})

/**
 * Get recent invoices for a tenant.
 */
export const listInvoicesForTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.array(
    v.object({
      _id: v.id('invoices'),
      amountCents: v.number(),
      currency: v.string(),
      status: v.union(
        v.literal('draft'),
        v.literal('open'),
        v.literal('paid'),
        v.literal('void'),
        v.literal('uncollectible'),
      ),
      periodStart: v.number(),
      periodEnd: v.number(),
      dueDate: v.number(),
      paidAt: v.optional(v.number()),
      pdfUrl: v.optional(v.string()),
    }),
  ),
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) return []

    return await ctx.db
      .query('invoices')
      .withIndex('by_tenant_and_period', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(24)
  },
})

/**
 * Get current usage metrics for a tenant.
 */
export const currentUsageForTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.array(
    v.object({
      metric: v.string(),
      value: v.number(),
      periodStart: v.number(),
      periodEnd: v.number(),
    }),
  ),
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) return []

    const now = Date.now()
    // Get all usage records for the current billing period
    const records = await ctx.db
      .query('usageRecords')
      .withIndex('by_tenant_and_period', (q) => q.eq('tenantId', tenant._id))
      .collect()

    // Return only the latest record per metric
    const latest = new Map<string, (typeof records)[number]>()
    for (const r of records) {
      if (r.periodEnd >= now) {
        const existing = latest.get(r.metric)
        if (!existing || r.recordedAt > existing.recordedAt) {
          latest.set(r.metric, r)
        }
      }
    }

    return Array.from(latest.values()).map((r) => ({
      metric: r.metric,
      value: r.value,
      periodStart: r.periodStart,
      periodEnd: r.periodEnd,
    }))
  },
})
