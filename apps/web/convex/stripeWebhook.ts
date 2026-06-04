import { v } from 'convex/values'
import { internal } from './_generated/api'
import type { Id } from './_generated/dataModel'
import {
  httpAction,
  internalMutation,
} from './_generated/server'

// ─── §8.4 — Stripe Webhook Handler ────────────────────────────────────────
//
// Receives Stripe events at POST /api/stripe/webhook, verifies the
// `Stripe-Signature` header using STRIPE_WEBHOOK_SECRET, and updates the
// `subscriptions` and `invoices` tables in response.
//
// Stripe signs the payload with HMAC-SHA256:
//   signed_payload = `${timestamp}.${rawBody}`
//   expected       = HMAC-SHA256(secret, signed_payload)
// The header has the form `t=<unix>,v1=<hex>,...`.

const SIGNATURE_TOLERANCE_SECONDS = 5 * 60

async function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const parts = signatureHeader.split(',').map((p) => p.trim())
  let timestamp: string | null = null
  const signatures: string[] = []
  for (const part of parts) {
    const [k, vRaw] = part.split('=', 2)
    if (k === 't') timestamp = vRaw
    else if (k === 'v1' && vRaw) signatures.push(vRaw)
  }
  if (!timestamp || signatures.length === 0) {
    return { ok: false, reason: 'malformed Stripe-Signature header' }
  }

  const tsNum = Number(timestamp)
  if (!Number.isFinite(tsNum)) {
    return { ok: false, reason: 'invalid timestamp' }
  }
  const ageSec = Math.abs(Date.now() / 1000 - tsNum)
  if (ageSec > SIGNATURE_TOLERANCE_SECONDS) {
    return { ok: false, reason: 'timestamp outside tolerance window' }
  }

  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const payload = `${timestamp}.${rawBody}`
  const sigBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(payload))
  const expected = [...new Uint8Array(sigBuffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  const matches = signatures.some((sig) => timingSafeEqual(sig, expected))
  return matches ? { ok: true } : { ok: false, reason: 'signature mismatch' }
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

// ── Event payload helpers ─────────────────────────────────────────────────

type StripeEvent = {
  id: string
  type: string
  data: { object: Record<string, unknown> }
}

function stringField(obj: Record<string, unknown>, key: string): string | null {
  const v = obj[key]
  return typeof v === 'string' ? v : null
}

function numberField(obj: Record<string, unknown>, key: string): number | null {
  const v = obj[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

function mapSubscriptionStatus(
  raw: string | null,
): 'active' | 'past_due' | 'canceled' | 'trialing' {
  switch (raw) {
    case 'active':
    case 'past_due':
    case 'canceled':
    case 'trialing':
      return raw
    case 'incomplete':
    case 'incomplete_expired':
    case 'unpaid':
      return 'past_due'
    case 'paused':
      return 'canceled'
    default:
      return 'active'
  }
}

function mapInvoiceStatus(
  raw: string | null,
): 'draft' | 'open' | 'paid' | 'void' | 'uncollectible' {
  switch (raw) {
    case 'draft':
    case 'open':
    case 'paid':
    case 'void':
    case 'uncollectible':
      return raw
    default:
      return 'open'
  }
}

function extractPlanSlug(subscription: Record<string, unknown>): string | null {
  const metadata = subscription.metadata as Record<string, unknown> | undefined
  if (metadata && typeof metadata.planSlug === 'string') return metadata.planSlug
  const items = subscription.items as
    | { data?: Array<Record<string, unknown>> }
    | undefined
  const first = items?.data?.[0]
  if (first) {
    const price = first.price as Record<string, unknown> | undefined
    if (price) {
      const lookup = price.lookup_key
      if (typeof lookup === 'string') return lookup
      const nickname = price.nickname
      if (typeof nickname === 'string') return nickname
    }
  }
  return null
}

// ── Internal mutations applied from the webhook ──────────────────────────

export const applySubscriptionEvent = internalMutation({
  args: {
    stripeCustomerId: v.string(),
    stripeSubscriptionId: v.string(),
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
  },
  returns: v.union(v.null(), v.id('subscriptions')),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('subscriptions')
      .withIndex('by_stripe_customer', (q) =>
        q.eq('stripeCustomerId', args.stripeCustomerId),
      )
      .first()

    if (!existing) return null

    await ctx.db.patch(existing._id, {
      planSlug: args.planSlug,
      status: args.status,
      currentPeriodStart: args.currentPeriodStart,
      currentPeriodEnd: args.currentPeriodEnd,
      cancelAtPeriodEnd: args.cancelAtPeriodEnd,
      stripeSubscriptionId: args.stripeSubscriptionId,
    })
    return existing._id
  },
})

export const markSubscriptionCanceled = internalMutation({
  args: { stripeSubscriptionId: v.string() },
  returns: v.union(v.null(), v.id('subscriptions')),
  handler: async (ctx, { stripeSubscriptionId }) => {
    const all = await ctx.db
      .query('subscriptions')
      .withIndex('by_stripe_customer')
      .take(2000)
    const sub = all.find((s) => s.stripeSubscriptionId === stripeSubscriptionId)
    if (!sub) return null
    await ctx.db.patch(sub._id, {
      status: 'canceled',
      cancelAtPeriodEnd: true,
    })
    return sub._id
  },
})

export const applyInvoicePaid = internalMutation({
  args: {
    stripeCustomerId: v.string(),
    stripeInvoiceId: v.string(),
    amountCents: v.number(),
    currency: v.string(),
    periodStart: v.number(),
    periodEnd: v.number(),
    dueDate: v.number(),
    pdfUrl: v.optional(v.string()),
  },
  returns: v.union(v.null(), v.id('invoices')),
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_stripe_customer', (q) =>
        q.eq('stripeCustomerId', args.stripeCustomerId),
      )
      .first()
    if (!sub) return null

    const existing = await ctx.db
      .query('invoices')
      .withIndex('by_tenant_and_period', (q) =>
        q.eq('tenantId', sub.tenantId).eq('periodStart', args.periodStart),
      )
      .first()

    const fields = {
      tenantId: sub.tenantId as Id<'tenants'>,
      amountCents: args.amountCents,
      currency: args.currency,
      status: 'paid' as const,
      periodStart: args.periodStart,
      periodEnd: args.periodEnd,
      dueDate: args.dueDate,
      paidAt: Date.now(),
      stripeInvoiceId: args.stripeInvoiceId,
      pdfUrl: args.pdfUrl,
    }

    if (existing) {
      await ctx.db.patch(existing._id, fields)
      return existing._id
    }
    return await ctx.db.insert('invoices', fields)
  },
})

// ── HTTP handler ──────────────────────────────────────────────────────────

export const handleStripeWebhook = httpAction(async (ctx, request) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!secret) {
    return new Response(
      JSON.stringify({ error: 'Stripe webhook not configured.' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const signature = request.headers.get('stripe-signature')
  if (!signature) {
    return new Response(
      JSON.stringify({ error: 'Missing Stripe-Signature header.' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const rawBody = await request.text()
  const verified = await verifyStripeSignature(rawBody, signature, secret)
  if (!verified.ok) {
    return new Response(
      JSON.stringify({ error: `Signature verification failed: ${verified.reason}` }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  let event: StripeEvent
  try {
    event = JSON.parse(rawBody) as StripeEvent
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  const obj = event.data?.object ?? {}
  let action = 'ignored'

  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const stripeCustomerId = stringField(obj, 'customer')
      const stripeSubscriptionId = stringField(obj, 'id')
      const status = mapSubscriptionStatus(stringField(obj, 'status'))
      const planSlug = extractPlanSlug(obj) ?? 'free'
      const currentPeriodStart =
        (numberField(obj, 'current_period_start') ?? 0) * 1000
      const currentPeriodEnd =
        (numberField(obj, 'current_period_end') ?? 0) * 1000
      const cancelAtPeriodEnd = Boolean(obj.cancel_at_period_end)
      if (stripeCustomerId && stripeSubscriptionId) {
        await ctx.runMutation(internal.stripeWebhook.applySubscriptionEvent, {
          stripeCustomerId,
          stripeSubscriptionId,
          planSlug,
          status,
          currentPeriodStart,
          currentPeriodEnd,
          cancelAtPeriodEnd,
        })
        action = 'subscription_updated'
      }
      break
    }
    case 'customer.subscription.deleted': {
      const stripeSubscriptionId = stringField(obj, 'id')
      if (stripeSubscriptionId) {
        await ctx.runMutation(internal.stripeWebhook.markSubscriptionCanceled, {
          stripeSubscriptionId,
        })
        action = 'subscription_canceled'
      }
      break
    }
    case 'invoice.paid': {
      const stripeCustomerId = stringField(obj, 'customer')
      const stripeInvoiceId = stringField(obj, 'id')
      const amountCents = numberField(obj, 'amount_paid') ?? 0
      const currency = stringField(obj, 'currency') ?? 'usd'
      const periodStart = (numberField(obj, 'period_start') ?? 0) * 1000
      const periodEnd = (numberField(obj, 'period_end') ?? 0) * 1000
      const dueDate =
        (numberField(obj, 'due_date') ?? numberField(obj, 'period_end') ?? 0) *
        1000
      const pdfUrl = stringField(obj, 'invoice_pdf') ?? undefined
      if (stripeCustomerId && stripeInvoiceId) {
        await ctx.runMutation(internal.stripeWebhook.applyInvoicePaid, {
          stripeCustomerId,
          stripeInvoiceId,
          amountCents,
          currency,
          periodStart,
          periodEnd,
          dueDate,
          pdfUrl,
        })
        action = 'invoice_paid'
      }
      break
    }
    default:
      action = 'ignored'
  }

  return new Response(
    JSON.stringify({ received: true, eventId: event.id, action }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
})
