/**
 * §6.29 Health Check / Status Page
 *
 * Provides service health data for the public status page.
 * Tracks health of core platform services and incident history.
 */
import { v } from 'convex/values'
import { mutation, query } from './_generated/server'

// ---------------------------------------------------------------------------
// Core services to monitor
// ---------------------------------------------------------------------------

const CORE_SERVICES = [
  { slug: 'api', name: 'API Gateway' },
  { slug: 'webhooks', name: 'Webhook Processing' },
  { slug: 'scanners', name: 'Scanner Engine' },
  { slug: 'advisories', name: 'Advisory Database' },
  { slug: 'auth', name: 'Authentication' },
  { slug: 'notifications', name: 'Notification Service' },
  { slug: 'billing', name: 'Billing Service' },
] as const

// ---------------------------------------------------------------------------
// getServiceHealth — public query (no auth required)
// ---------------------------------------------------------------------------

export const getServiceHealth = query({
  args: {},
  handler: async (ctx) => {
    const now = Date.now()

    // Get the latest health check for each service
    const services = await Promise.all(
      CORE_SERVICES.map(async (service) => {
        const latestCheck = await ctx.db
          .query('serviceHealthChecks')
          .withIndex('by_service', (q: any) => q.eq('service', service.slug))
          .order('desc')
          .first()

        return {
          slug: service.slug,
          name: service.name,
          status: latestCheck?.status ?? 'operational',
          latencyMs: latestCheck?.latencyMs ?? null,
          message: latestCheck?.message ?? null,
          lastCheckedAt: latestCheck?.checkedAt ?? null,
        }
      }),
    )

    // Overall status = worst individual status
    const statusPriority = { operational: 0, degraded: 1, maintenance: 2, outage: 3 } as const
    const worstStatus = services.reduce((worst, s) => {
      return (statusPriority[s.status as keyof typeof statusPriority] ?? 0) >
        (statusPriority[worst as keyof typeof statusPriority] ?? 0)
        ? s.status
        : worst
    }, 'operational' as string)

    return {
      overallStatus: worstStatus,
      services,
      checkedAt: now,
    }
  },
})

// ---------------------------------------------------------------------------
// getIncidentHistory — public query
// ---------------------------------------------------------------------------

export const getIncidentHistory = query({
  args: {
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { limit }) => {
    const cap = Math.min(limit ?? 20, 100)

    return ctx.db
      .query('incidentReports')
      .withIndex('by_started_at')
      .order('desc')
      .take(cap)
  },
})

// ---------------------------------------------------------------------------
// getOverallStatus — public query (lightweight, for status badges)
// ---------------------------------------------------------------------------

export const getOverallStatus = query({
  args: {},
  handler: async (ctx) => {
    const health = await ctx.db
      .query('serviceHealthChecks')
      .order('desc')
      .take(50)

    // Get the worst status from recent checks
    const statusPriority = { operational: 0, degraded: 1, maintenance: 2, outage: 3 } as const
    let worst = 'operational' as string

    // Group by service, get latest per service
    const latestByService = new Map<string, string>()
    for (const check of health) {
      if (!latestByService.has(check.service)) {
        latestByService.set(check.service, check.status)
      }
    }

    for (const status of latestByService.values()) {
      if ((statusPriority[status as keyof typeof statusPriority] ?? 0) >
        (statusPriority[worst as keyof typeof statusPriority] ?? 0)) {
        worst = status
      }
    }

    // Get active incidents
    const activeIncidents = await ctx.db
      .query('incidentReports')
      .withIndex('by_started_at')
      .order('desc')
      .take(10)

    const unresolved = activeIncidents.filter((i) => i.status !== 'resolved')

    return {
      status: worst,
      activeIncidents: unresolved.length,
      lastUpdated: health.length > 0 ? health[0].checkedAt : null,
    }
  },
})

// ---------------------------------------------------------------------------
// Internal mutations for recording health checks
// ---------------------------------------------------------------------------

export const recordHealthCheck = mutation({
  args: {
    service: v.string(),
    status: v.union(
      v.literal('operational'),
      v.literal('degraded'),
      v.literal('outage'),
      v.literal('maintenance'),
    ),
    latencyMs: v.optional(v.number()),
    message: v.optional(v.string()),
  },
  handler: async (ctx, { service, status, latencyMs, message }) => {
    return ctx.db.insert('serviceHealthChecks', {
      service,
      status,
      latencyMs,
      message,
      checkedAt: Date.now(),
    })
  },
})

export const createIncident = mutation({
  args: {
    title: v.string(),
    service: v.string(),
    status: v.union(
      v.literal('investigating'),
      v.literal('identified'),
      v.literal('monitoring'),
      v.literal('resolved'),
    ),
    severity: v.union(v.literal('minor'), v.literal('major'), v.literal('critical')),
    message: v.string(),
  },
  handler: async (ctx, { title, service, status, severity, message }) => {
    const now = Date.now()
    return ctx.db.insert('incidentReports', {
      title,
      service,
      status,
      severity,
      message,
      startedAt: now,
      updatedAt: now,
    })
  },
})

export const updateIncident = mutation({
  args: {
    incidentId: v.id('incidentReports'),
    status: v.optional(v.union(
      v.literal('investigating'),
      v.literal('identified'),
      v.literal('monitoring'),
      v.literal('resolved'),
    )),
    message: v.optional(v.string()),
  },
  handler: async (ctx, { incidentId, status, message }) => {
    const incident = await ctx.db.get(incidentId)
    if (!incident) throw new Error('Incident not found')

    const updates: any = { updatedAt: Date.now() }
    if (status !== undefined) {
      updates.status = status
      if (status === 'resolved') {
        updates.resolvedAt = Date.now()
      }
    }
    if (message !== undefined) updates.message = message

    await ctx.db.patch(incidentId, updates)
    return { success: true }
  },
})
