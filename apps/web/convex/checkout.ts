import { v } from 'convex/values'
import { api } from './_generated/api'
import { action } from './_generated/server'

// ─── §8.4 — Stripe Checkout Session ───────────────────────────────────────
//
// Creates a Stripe Checkout Session for upgrading a tenant to the given plan.
// The session is configured to redirect back to /settings/billing after
// success or cancellation. The `client_reference_id` is set to the tenant
// slug so the webhook can map the resulting subscription back to the tenant.

const STRIPE_API = 'https://api.stripe.com/v1'

function formEncode(params: Record<string, string | undefined>): string {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v as string)}`)
    .join('&')
}

export const createCheckoutSession = action({
  args: {
    tenantSlug: v.string(),
    planSlug: v.string(),
  },
  returns: v.object({
    url: v.union(v.null(), v.string()),
    sessionId: v.union(v.null(), v.string()),
    mode: v.union(v.literal('live'), v.literal('mock')),
  }),
  handler: async (ctx, { tenantSlug, planSlug }) => {
    const apiKey = process.env.STRIPE_SECRET_KEY
    const appUrl = process.env.APP_URL ?? 'http://localhost:5173'
    const successUrl = `${appUrl}/settings/billing?checkout=success&session_id={CHECKOUT_SESSION_ID}`
    const cancelUrl = `${appUrl}/settings/billing?checkout=canceled`

    const priceLookup = `plan_${planSlug}`
    const priceEnv =
      process.env[`STRIPE_PRICE_${planSlug.toUpperCase()}`] ?? undefined

    if (!apiKey) {
      // Mock path — useful for local development without Stripe credentials.
      return {
        url: `${appUrl}/settings/billing?checkout=mock&plan=${encodeURIComponent(planSlug)}`,
        sessionId: null,
        mode: 'mock' as const,
      }
    }

    // Verify the plan exists before we hit Stripe.
    const plan = await ctx.runQuery(api.plans.getPlanBySlug, { slug: planSlug })
    if (!plan) {
      throw new Error(`Plan "${planSlug}" not found.`)
    }

    const body: Record<string, string | undefined> = {
      mode: 'subscription',
      success_url: successUrl,
      cancel_url: cancelUrl,
      client_reference_id: tenantSlug,
      'metadata[tenantSlug]': tenantSlug,
      'metadata[planSlug]': planSlug,
      'subscription_data[metadata][planSlug]': planSlug,
      'subscription_data[metadata][tenantSlug]': tenantSlug,
      'line_items[0][quantity]': '1',
    }

    if (priceEnv) {
      body['line_items[0][price]'] = priceEnv
    } else {
      body['line_items[0][price_data][currency]'] = 'usd'
      body['line_items[0][price_data][unit_amount]'] = String(
        Math.round(plan.monthlyPrice * 100),
      )
      body['line_items[0][price_data][recurring][interval]'] = 'month'
      body['line_items[0][price_data][product_data][name]'] = plan.name
      body['line_items[0][price_data][product_data][metadata][lookup]'] =
        priceLookup
    }

    const response = await fetch(`${STRIPE_API}/checkout/sessions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formEncode(body),
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error(
        `Stripe checkout session creation failed (${response.status}): ${text}`,
      )
    }

    const json = (await response.json()) as { id?: string; url?: string }
    return {
      url: json.url ?? null,
      sessionId: json.id ?? null,
      mode: 'live' as const,
    }
  },
})
