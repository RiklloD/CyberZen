// Outbound webhook system (spec §7.2)
//
//   registerEndpoint       — public mutation: register a new outbound endpoint
//   deleteEndpoint         — public mutation: remove an endpoint
//   listEndpoints          — public query: list endpoints for a tenant (secrets hidden)
//   listRecentDeliveries   — public query: delivery audit log
//   dispatchWebhookEvent   — internalAction: sign + fan-out to all matching endpoints
//   queryActiveEndpoints   — internalQuery: reads live endpoint secrets (never public)
//   recordDelivery         — internalMutation: writes a delivery row + patches lastDeliveryAt

import { ConvexError, v } from 'convex/values'
import {
  internalAction,
  internalMutation,
  internalQuery,
  mutation,
  query,
} from './_generated/server'
import { internal } from './_generated/api'
import {
  buildSignedPayload,
  isSubscribed,
  postWebhookPayload,
  validateEndpointUrl,
  validateSubscribedEvents,
  type WebhookEnvelope,
  type WebhookEventPayload,
} from './lib/webhookDispatcher'

// ---------------------------------------------------------------------------
// registerEndpoint — POST /api/webhooks
// ---------------------------------------------------------------------------

export const registerEndpoint = mutation({
  args: {
    tenantSlug: v.string(),
    url: v.string(),
    secret: v.string(),
    description: v.optional(v.string()),
    /** Leave empty to subscribe to all events. */
    events: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    const urlCheck = validateEndpointUrl(args.url)
    if (!urlCheck.valid) throw new ConvexError(urlCheck.reason)

    const eventsCheck = validateSubscribedEvents(args.events)
    if (!eventsCheck.valid) throw new ConvexError(eventsCheck.reason)

    if (!args.secret || args.secret.length < 8) {
      throw new ConvexError('Secret must be at least 8 characters.')
    }

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new ConvexError(`Tenant not found: ${args.tenantSlug}`)

    // Prevent duplicate active URLs per tenant.
    const existing = await ctx.db
      .query('webhookEndpoints')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(100)
    if (existing.some((e) => e.url === args.url && e.active)) {
      throw new ConvexError(`An active endpoint already exists for URL: ${args.url}`)
    }

    const id = await ctx.db.insert('webhookEndpoints', {
      tenantId: tenant._id,
      url: args.url,
      secret: args.secret,
      description: args.description,
      events: args.events,
      active: true,
      createdAt: Date.now(),
      lastDeliveryAt: undefined,
    })

    return { endpointId: id }
  },
})

// ---------------------------------------------------------------------------
// deleteEndpoint — DELETE /api/webhooks
// ---------------------------------------------------------------------------

export const deleteEndpoint = mutation({
  args: {
    tenantSlug: v.string(),
    endpointId: v.id('webhookEndpoints'),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new ConvexError(`Tenant not found: ${args.tenantSlug}`)

    const endpoint = await ctx.db.get(args.endpointId)
    if (!endpoint || endpoint.tenantId !== tenant._id) {
      throw new ConvexError('Endpoint not found or does not belong to this tenant.')
    }

    await ctx.db.delete(args.endpointId)
    return { deleted: true }
  },
})

// ---------------------------------------------------------------------------
// listEndpoints — GET /api/webhooks
// Secrets are never returned in public list responses.
// ---------------------------------------------------------------------------

export const listEndpoints = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    const endpoints = await ctx.db
      .query('webhookEndpoints')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(100)

    return endpoints.map((ep) => ({
      _id: ep._id,
      url: ep.url,
      description: ep.description ?? null,
      events: ep.events,
      active: ep.active,
      createdAt: ep.createdAt,
      lastDeliveryAt: ep.lastDeliveryAt ?? null,
    }))
  },
})

// ---------------------------------------------------------------------------
// listRecentDeliveries — GET /api/webhooks/deliveries
// ---------------------------------------------------------------------------

export const listRecentDeliveries = query({
  args: {
    tenantSlug: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    const cap = Math.min(args.limit ?? 50, 200)
    return ctx.db
      .query('webhookDeliveries')
      .withIndex('by_tenant_and_attempted_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(cap)
  },
})

// ---------------------------------------------------------------------------
// queryActiveEndpoints — internalQuery
// Returns endpoint secrets — must remain internal.
// ---------------------------------------------------------------------------

export const queryActiveEndpoints = internalQuery({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    const endpoints = await ctx.db
      .query('webhookEndpoints')
      .withIndex('by_tenant_and_active', (q) =>
        q.eq('tenantId', args.tenantId).eq('active', true),
      )
      .take(50)
    return endpoints.map((ep) => ({
      _id: ep._id,
      url: ep.url,
      secret: ep.secret,
      events: ep.events,
    }))
  },
})

// ---------------------------------------------------------------------------
// recordDelivery — internalMutation
// ---------------------------------------------------------------------------

export const recordDelivery = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    endpointId: v.id('webhookEndpoints'),
    deliveryId: v.string(),
    eventType: v.string(),
    repositoryFullName: v.string(),
    success: v.boolean(),
    statusCode: v.optional(v.number()),
    errorMessage: v.optional(v.string()),
    durationMs: v.number(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('webhookDeliveries', {
      tenantId: args.tenantId,
      endpointId: args.endpointId,
      deliveryId: args.deliveryId,
      eventType: args.eventType,
      repositoryFullName: args.repositoryFullName,
      success: args.success,
      statusCode: args.statusCode,
      errorMessage: args.errorMessage,
      durationMs: args.durationMs,
      attemptedAt: Date.now(),
    })
    await ctx.db.patch(args.endpointId, { lastDeliveryAt: Date.now() })
  },
})

// ---------------------------------------------------------------------------
// dispatchWebhookEvent — internalAction
//
// Called fire-and-forget after significant state transitions.
// Fans out to every active, subscribed endpoint for the tenant.
// ---------------------------------------------------------------------------

export const dispatchWebhookEvent = internalAction({
  args: {
    tenantId: v.id('tenants'),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** WebhookEventPayload serialised as a plain object (v.any()). */
    eventPayload: v.any(),
  },
  handler: async (ctx, args) => {
    const endpoints = await ctx.runQuery(
      internal.webhooks.queryActiveEndpoints,
      { tenantId: args.tenantId },
    )

    const payload = args.eventPayload as WebhookEventPayload
    const now = Date.now()

    for (const endpoint of endpoints) {
      if (!isSubscribed(endpoint.events, payload.event)) continue

      const deliveryId = crypto.randomUUID()
      const envelope: WebhookEnvelope = {
        ...payload,
        tenantSlug: args.tenantSlug,
        repositoryFullName: args.repositoryFullName,
        timestamp: now,
        deliveryId,
      }

      const signed = await buildSignedPayload(envelope, endpoint.secret)
      const result = await postWebhookPayload(
        endpoint._id,
        endpoint.url,
        signed,
        deliveryId,
      )

      await ctx.runMutation(internal.webhooks.recordDelivery, {
        tenantId: args.tenantId,
        endpointId: endpoint._id,
        deliveryId,
        eventType: payload.event,
        repositoryFullName: args.repositoryFullName,
        success: result.success,
        statusCode: result.statusCode ?? undefined,
        errorMessage: result.errorMessage ?? undefined,
        durationMs: result.durationMs,
      })
    }
  },
})
