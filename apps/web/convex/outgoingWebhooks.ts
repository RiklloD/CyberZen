import { v } from 'convex/values'
import { mutation, query, action } from './_generated/server'

// ── §6.6 — Outgoing Webhooks ──────────────────────────────────────

const webhookEventType = v.union(
  v.literal('finding.created'),
  v.literal('finding.critical'),
  v.literal('finding.triaged'),
  v.literal('gate.blocked'),
  v.literal('gate.overridden'),
  v.literal('exploit.validated'),
  v.literal('pr.generated'),
  v.literal('scan.completed'),
  v.literal('sla.breached'),
  v.literal('remediation.dispatched'),
)

/**
 * List all outgoing webhooks for a tenant.
 */
export const list = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('outgoingWebhooks'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      url: v.string(),
      secret: v.string(),
      eventTypes: v.array(v.string()),
      enabled: v.boolean(),
      lastDeliveryAt: v.optional(v.number()),
      failureCount: v.number(),
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
      .query('outgoingWebhooks')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

/**
 * Create a new outgoing webhook.
 */
export const create = mutation({
  args: {
    tenantSlug: v.string(),
    url: v.string(),
    secret: v.string(),
    eventTypes: v.array(v.string()),
    description: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
  },
  returns: v.id('outgoingWebhooks'),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) throw new Error('Tenant not found')

    return await ctx.db.insert('outgoingWebhooks', {
      tenantId: tenant._id,
      url: args.url,
      secret: args.secret,
      eventTypes: args.eventTypes,
      enabled: args.enabled ?? true,
      lastDeliveryAt: undefined,
      failureCount: 0,
      description: args.description,
    })
  },
})

/**
 * Update an existing outgoing webhook.
 */
export const update = mutation({
  args: {
    webhookId: v.id('outgoingWebhooks'),
    url: v.optional(v.string()),
    secret: v.optional(v.string()),
    eventTypes: v.optional(v.array(v.string())),
    enabled: v.optional(v.boolean()),
    description: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { webhookId, ...updates } = args
    const webhook = await ctx.db.get(webhookId)
    if (!webhook) throw new Error('Webhook not found')

    const patch: Record<string, unknown> = {}
    if (updates.url !== undefined) patch.url = updates.url
    if (updates.secret !== undefined) patch.secret = updates.secret
    if (updates.eventTypes !== undefined) patch.eventTypes = updates.eventTypes
    if (updates.enabled !== undefined) patch.enabled = updates.enabled
    if (updates.description !== undefined) patch.description = updates.description

    await ctx.db.patch(webhookId, patch)
  },
})

/**
 * Delete an outgoing webhook.
 */
export const remove = mutation({
  args: { webhookId: v.id('outgoingWebhooks') },
  returns: v.null(),
  handler: async (ctx, args) => {
    const webhook = await ctx.db.get(args.webhookId)
    if (!webhook) throw new Error('Webhook not found')
    await ctx.db.delete(args.webhookId)
  },
})

/**
 * Test-fire a webhook by sending a test payload to its URL.
 * Returns the HTTP status code and a short body preview.
 */
export const testFire = action({
  args: {
    webhookId: v.id('outgoingWebhooks'),
  },
  returns: v.object({
    ok: v.boolean(),
    status: v.number(),
    body: v.string(),
  }),
  handler: async (ctx, args) => {
    // Actions can't read the DB in Convex — run a query first via the internal API.
    const webhook = await ctx.runQuery(
      // We'll use a helper query defined below
      internal.outgoingWebhooks._getWebhook,
      { webhookId: args.webhookId },
    )

    if (!webhook) {
      return { ok: false, status: 0, body: 'Webhook not found' }
    }

    const testPayload = {
      event: 'test',
      timestamp: Date.now(),
      message: 'CyberZen webhook test fire',
    }

    try {
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CyberZen-Signature': webhook.secret,
          'X-CyberZen-Event': 'test',
        },
        body: JSON.stringify(testPayload),
      })

      const body = await response.text()

      return {
        ok: response.ok,
        status: response.status,
        body: body.slice(0, 500),
      }
    } catch (err) {
      return {
        ok: false,
        status: 0,
        body: err instanceof Error ? err.message : 'Unknown error',
      }
    }
  },
})

import { internalQuery } from './_generated/server'
import { internal } from './_generated/api'

/**
 * Internal query used by testFire action to read the webhook.
 */
export const _getWebhook = internalQuery({
  args: { webhookId: v.id('outgoingWebhooks') },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id('outgoingWebhooks'),
      _creationTime: v.number(),
      tenantId: v.id('tenants'),
      url: v.string(),
      secret: v.string(),
      eventTypes: v.array(v.string()),
      enabled: v.boolean(),
      lastDeliveryAt: v.optional(v.number()),
      failureCount: v.number(),
      description: v.optional(v.string()),
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db.get(args.webhookId)
  },
})
