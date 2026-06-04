// Outbound webhook system (spec §7.2)
//
//   registerEndpoint        — public mutation: register a new outbound endpoint
//   updateEndpoint          — public mutation: update URL / events / secret / active
//   deleteEndpoint          — public mutation: remove an endpoint
//   testFireEndpoint        — public action: send a test payload to an endpoint
//   listEndpoints           — public query: list endpoints for a tenant (secrets hidden)
//   listRecentDeliveries    — public query: delivery audit log
//   listDeadLetterQueue     — public query: dead-lettered retry entries
//   listRetryStats          — public query: per-endpoint retry / dead counts
//   retryDeadLetter         — public mutation: re-queue a dead-lettered entry
//   dispatchWebhookEvent    — internalAction: sign + fan-out to all matching endpoints
//   queryActiveEndpoints    — internalQuery: reads live endpoint secrets (never public)
//   queryEndpointById       — internalQuery: reads one endpoint including secret
//   queryDueRetries         — internalQuery: retry entries ready for processing
//   recordDelivery          — internalMutation: writes a delivery row + patches lastDeliveryAt
//   createRetryEntry        — internalMutation: enqueue a failed delivery for retry
//   updateRetryEntry        — internalMutation: update a retry entry after an attempt
//   processWebhookRetries   — internalAction: cron handler — retries due entries

import { ConvexError, v } from 'convex/values'
import {
  internalAction,
  internalMutation,
  internalQuery,
  mutation,
  query,
  action,
} from './_generated/server'
import { internal } from './_generated/api'
import type { Doc, Id } from './_generated/dataModel'

// ---------------------------------------------------------------------------
// Retry schedule — exponential backoff (ms)
// ---------------------------------------------------------------------------

const RETRY_DELAYS_MS = [
  60_000,        // 1 minute
  300_000,       // 5 minutes
  900_000,       // 15 minutes
  3_600_000,     // 1 hour
  21_600_000,    // 6 hours
] as const

const MAX_RETRY_ATTEMPTS = RETRY_DELAYS_MS.length
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
// AES-GCM envelope encryption for webhook secrets at rest.
// The key must be a 64-char hex string (32 bytes) in WEBHOOK_ENCRYPTION_KEY.
// Stored format: "aes-gcm$<12-byte-iv-hex>$<ciphertext-hex>"
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function encryptWebhookSecret(secret: string): Promise<string> {
  const keyHex = process.env.WEBHOOK_ENCRYPTION_KEY
  if (!keyHex || keyHex.length !== 64) {
    throw new ConvexError('WEBHOOK_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)')
  }
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    hexToBytes(keyHex),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const iv = new Uint8Array(12)
  crypto.getRandomValues(iv)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    new TextEncoder().encode(secret),
  )
  return `aes-gcm$${bytesToHex(iv)}$${bytesToHex(new Uint8Array(ciphertext))}`
}

async function decryptWebhookSecret(stored: string): Promise<string> {
  if (!stored.startsWith('aes-gcm$')) {
    // Legacy plaintext secret — reject and force re-registration.
    throw new Error(
      'Endpoint has a legacy plaintext secret. Delete and re-register this endpoint.',
    )
  }
  const keyHex = process.env.WEBHOOK_ENCRYPTION_KEY
  if (!keyHex || keyHex.length !== 64) {
    throw new Error('WEBHOOK_ENCRYPTION_KEY not configured')
  }
  const parts = stored.split('$')
  if (parts.length !== 3) throw new Error('Malformed encrypted secret')
  const [, ivHex, ctHex] = parts
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    hexToBytes(keyHex),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: hexToBytes(ivHex) },
    cryptoKey,
    hexToBytes(ctHex),
  )
  return new TextDecoder().decode(plaintext)
}

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

    const encryptedSecret = await encryptWebhookSecret(args.secret)
    const id = await ctx.db.insert('webhookEndpoints', {
      tenantId: tenant._id,
      url: args.url,
      secret: encryptedSecret,
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
// updateEndpoint — PATCH /api/webhooks/:id
// ---------------------------------------------------------------------------

export const updateEndpoint = mutation({
  args: {
    endpointId: v.id('webhookEndpoints'),
    url: v.optional(v.string()),
    secret: v.optional(v.string()),
    description: v.optional(v.string()),
    events: v.optional(v.array(v.string())),
    active: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const { endpointId, ...updates } = args
    const endpoint = await ctx.db.get(endpointId)
    if (!endpoint) throw new ConvexError('Endpoint not found')

    const patch: Record<string, unknown> = {}
    if (updates.url !== undefined) {
      const urlCheck = validateEndpointUrl(updates.url)
      if (!urlCheck.valid) throw new ConvexError(urlCheck.reason)
      patch.url = updates.url
    }
    if (updates.secret !== undefined && updates.secret.length > 0) {
      if (updates.secret.length < 8) throw new ConvexError('Secret must be at least 8 characters.')
      patch.secret = await encryptWebhookSecret(updates.secret)
    }
    if (updates.events !== undefined) {
      const eventsCheck = validateSubscribedEvents(updates.events)
      if (!eventsCheck.valid) throw new ConvexError(eventsCheck.reason)
      patch.events = updates.events
    }
    if (updates.description !== undefined) patch.description = updates.description
    if (updates.active !== undefined) patch.active = updates.active

    await ctx.db.patch(endpointId, patch)
    return null
  },
})

// ---------------------------------------------------------------------------
// queryEndpointById — internalQuery (declared early so testFireEndpoint can reference it)
// ---------------------------------------------------------------------------

export const queryEndpointById = internalQuery({
  args: { endpointId: v.id('webhookEndpoints') },
  handler: async (ctx, args) => ctx.db.get(args.endpointId),
})

// ---------------------------------------------------------------------------
// testFireEndpoint — sends a test payload to an endpoint URL
// URL is passed directly from the frontend to avoid internal-query circular types.
// ---------------------------------------------------------------------------

export const testFireEndpoint = action({
  args: {
    endpointId: v.id('webhookEndpoints'),
    endpointUrl: v.string(),
  },
  returns: v.object({ ok: v.boolean(), status: v.number(), body: v.string() }),
  handler: async (_ctx, args) => {
    const deliveryId = crypto.randomUUID()
    const testBody = JSON.stringify({
      event: 'test',
      deliveryId,
      timestamp: Date.now(),
      message: 'CyberZen Sentinel webhook test delivery',
    })

    try {
      const response = await fetch(args.endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Sentinel-Delivery': deliveryId,
          'X-Sentinel-Test': 'true',
        },
        body: testBody,
      })
      const body = await response.text()
      return { ok: response.ok, status: response.status, body: body.slice(0, 500) }
    } catch (err) {
      return {
        ok: false,
        status: 0,
        body: err instanceof Error ? err.message : 'Unknown error',
      }
    }
  },
})

// ---------------------------------------------------------------------------
// listDeadLetterQueue — dead-lettered retry entries for a tenant
// ---------------------------------------------------------------------------

export const listDeadLetterQueue = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    return ctx.db
      .query('webhookRetryQueue')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'dead'),
      )
      .order('desc')
      .take(100)
  },
})

// ---------------------------------------------------------------------------
// listRetryStats — per-endpoint counts: pending retries and dead entries
// ---------------------------------------------------------------------------

export const listRetryStats = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      endpointId: v.id('webhookEndpoints'),
      pending: v.number(),
      dead: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    const failed = await ctx.db
      .query('webhookRetryQueue')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'failed'),
      )
      .take(500)
    const dead = await ctx.db
      .query('webhookRetryQueue')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'dead'),
      )
      .take(500)

    const stats = new Map<string, { pending: number; dead: number }>()
    for (const e of failed) {
      const k = e.endpointId
      if (!stats.has(k)) stats.set(k, { pending: 0, dead: 0 })
      stats.get(k)!.pending++
    }
    for (const e of dead) {
      const k = e.endpointId
      if (!stats.has(k)) stats.set(k, { pending: 0, dead: 0 })
      stats.get(k)!.dead++
    }

    return Array.from(stats.entries()).map(([endpointId, counts]) => ({
      endpointId: endpointId as Id<'webhookEndpoints'>,
      ...counts,
    }))
  },
})

// ---------------------------------------------------------------------------
// retryDeadLetter — re-queue a dead-lettered entry for immediate retry
// ---------------------------------------------------------------------------

export const retryDeadLetter = mutation({
  args: { entryId: v.id('webhookRetryQueue') },
  returns: v.null(),
  handler: async (ctx, args) => {
    const entry = await ctx.db.get(args.entryId)
    if (!entry) throw new ConvexError('Retry entry not found')
    if (entry.status !== 'dead') {
      throw new ConvexError('Entry is not in the dead letter queue')
    }

    await ctx.db.patch(args.entryId, {
      status: 'failed',
      attempts: 0,
      nextRetryAt: Date.now(),
      lastAttemptAt: undefined,
      errorMessage: undefined,
    })
    return null
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
// queryEndpointById — internalQuery (returns secret — must stay internal)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// queryDueRetries — internalQuery: entries due for retry processing
// ---------------------------------------------------------------------------

export const queryDueRetries = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, args) => {
    return ctx.db
      .query('webhookRetryQueue')
      .withIndex('by_status_and_next_retry_at', (q) =>
        q.eq('status', 'failed').lte('nextRetryAt', args.now),
      )
      .take(20)
  },
})

// ---------------------------------------------------------------------------
// createRetryEntry — internalMutation: enqueue a failed delivery for retry
// ---------------------------------------------------------------------------

export const createRetryEntry = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    endpointId: v.id('webhookEndpoints'),
    deliveryId: v.string(),
    eventType: v.string(),
    payload: v.string(),
    signature: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert('webhookRetryQueue', {
      tenantId: args.tenantId,
      endpointId: args.endpointId,
      deliveryId: args.deliveryId,
      eventType: args.eventType,
      payload: args.payload,
      signature: args.signature,
      status: 'failed',
      attempts: 0,
      lastAttemptAt: undefined,
      nextRetryAt: Date.now() + RETRY_DELAYS_MS[0],
      createdAt: Date.now(),
    })
    return null
  },
})

// ---------------------------------------------------------------------------
// updateRetryEntry — internalMutation: record result of a retry attempt
// ---------------------------------------------------------------------------

export const updateRetryEntry = internalMutation({
  args: {
    entryId: v.id('webhookRetryQueue'),
    status: v.union(
      v.literal('pending'),
      v.literal('success'),
      v.literal('failed'),
      v.literal('dead'),
    ),
    attempts: v.optional(v.number()),
    nextRetryAt: v.optional(v.number()),
    responseCode: v.optional(v.number()),
    errorMessage: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { entryId, ...updates } = args
    const patch: Record<string, unknown> = {
      status: updates.status,
      lastAttemptAt: Date.now(),
    }
    if (updates.attempts !== undefined) patch.attempts = updates.attempts
    if (updates.nextRetryAt !== undefined) patch.nextRetryAt = updates.nextRetryAt
    if (updates.responseCode !== undefined) patch.responseCode = updates.responseCode
    if (updates.errorMessage !== undefined) patch.errorMessage = updates.errorMessage
    await ctx.db.patch(entryId, patch)
    return null
  },
})

// ---------------------------------------------------------------------------
// processWebhookRetries — internalAction: cron handler
// Processes up to 20 failed entries whose nextRetryAt has passed.
// ---------------------------------------------------------------------------

export const processWebhookRetries = internalAction({
  args: {},
  handler: async (ctx, _args) => {
    const now = Date.now()
    const dueEntries = await ctx.runQuery(internal.webhooks.queryDueRetries, { now })

    for (const entry of dueEntries) {
      const endpoint = await ctx.runQuery(internal.webhooks.queryEndpointById, {
        endpointId: entry.endpointId,
      })

      if (!endpoint || !endpoint.active) {
        await ctx.runMutation(internal.webhooks.updateRetryEntry, {
          entryId: entry._id,
          status: 'dead',
          errorMessage: endpoint ? 'Endpoint disabled' : 'Endpoint not found',
        })
        continue
      }

      const newAttempts = entry.attempts + 1
      const startMs = Date.now()
      let statusCode: number | undefined
      let success = false
      let errorMessage: string | undefined

      try {
        const res = await fetch(endpoint.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Sentinel-Signature-256': entry.signature,
            'X-Sentinel-Delivery': entry.deliveryId,
          },
          body: entry.payload,
        })
        statusCode = res.status
        success = res.status >= 200 && res.status < 300
        if (!success) errorMessage = `HTTP ${res.status}`
      } catch (err) {
        errorMessage = err instanceof Error ? err.message : String(err)
      }

      const durationMs = Date.now() - startMs

      if (success) {
        await ctx.runMutation(internal.webhooks.updateRetryEntry, {
          entryId: entry._id,
          status: 'success',
          attempts: newAttempts,
          responseCode: statusCode,
        })
        await ctx.runMutation(internal.webhooks.recordDelivery, {
          tenantId: entry.tenantId,
          endpointId: entry.endpointId,
          deliveryId: entry.deliveryId,
          eventType: entry.eventType,
          repositoryFullName: '',
          success: true,
          statusCode,
          durationMs,
        })
      } else if (newAttempts >= MAX_RETRY_ATTEMPTS) {
        await ctx.runMutation(internal.webhooks.updateRetryEntry, {
          entryId: entry._id,
          status: 'dead',
          attempts: newAttempts,
          responseCode: statusCode,
          errorMessage: errorMessage ?? 'Max retries exceeded',
        })
      } else {
        await ctx.runMutation(internal.webhooks.updateRetryEntry, {
          entryId: entry._id,
          status: 'failed',
          attempts: newAttempts,
          nextRetryAt: Date.now() + RETRY_DELAYS_MS[newAttempts],
          responseCode: statusCode,
          errorMessage,
        })
      }
    }
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

      const plainSecret = await decryptWebhookSecret(endpoint.secret)
      const signed = await buildSignedPayload(envelope, plainSecret)
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

      // On failure, enqueue for exponential-backoff retry.
      if (!result.success) {
        await ctx.runMutation(internal.webhooks.createRetryEntry, {
          tenantId: args.tenantId,
          endpointId: endpoint._id,
          deliveryId,
          eventType: payload.event,
          payload: signed.body,
          signature: signed.signature,
        })
      }
    }
  },
})
