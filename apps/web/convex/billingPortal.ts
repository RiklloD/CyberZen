import { v } from 'convex/values'
import { internal } from './_generated/api'
import { action, internalQuery } from './_generated/server'

// ─── §8.4 — Stripe Billing Portal Session ─────────────────────────────────
//
// Returns a Stripe Customer Portal URL for the tenant's billing customer.
// The tenant must have a stripeCustomerId on its subscription row; otherwise
// the action returns a mock URL so local dev does not break.

const STRIPE_API = 'https://api.stripe.com/v1'

function formEncode(params: Record<string, string | undefined>): string {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v as string)}`)
    .join('&')
}

export const getTenantStripeCustomer = internalQuery({
  args: { tenantSlug: v.string() },
  returns: v.union(v.null(), v.string()),
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .first()
    return sub?.stripeCustomerId ?? null
  },
})

export const createPortalSession = action({
  args: { tenantSlug: v.string() },
  returns: v.object({
    url: v.union(v.null(), v.string()),
    mode: v.union(v.literal('live'), v.literal('mock')),
  }),
  handler: async (ctx, { tenantSlug }) => {
    const apiKey = process.env.STRIPE_SECRET_KEY
    const appUrl = process.env.APP_URL ?? 'http://localhost:5173'
    const returnUrl = `${appUrl}/settings/billing`

    const customerId: string | null = await ctx.runQuery(
      internal.billingPortal.getTenantStripeCustomer,
      { tenantSlug },
    )

    if (!apiKey || !customerId) {
      return {
        url: `${appUrl}/settings/billing?portal=mock`,
        mode: 'mock' as const,
      }
    }

    const response = await fetch(`${STRIPE_API}/billing_portal/sessions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formEncode({
        customer: customerId,
        return_url: returnUrl,
      }),
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error(
        `Stripe portal session creation failed (${response.status}): ${text}`,
      )
    }

    const json = (await response.json()) as { url?: string }
    return { url: json.url ?? null, mode: 'live' as const }
  },
})
