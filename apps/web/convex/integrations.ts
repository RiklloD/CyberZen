import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import type { Doc } from './_generated/dataModel'

// ── §5.3 — Integration catalog queries + status recomputation ──────────

/**
 * Public query returning all catalog entries.
 * The catalog is seeded once by seedBaseline and rarely changes.
 */
export const listIntegrationCatalog = query({
  args: {},
  returns: v.array(
    v.object({
      _id: v.id('integrationCatalog'),
      _creationTime: v.number(),
      slug: v.string(),
      label: v.string(),
      category: v.union(
        v.literal('vcs'),
        v.literal('ci'),
        v.literal('chat'),
        v.literal('paging'),
        v.literal('ticket'),
        v.literal('siem'),
        v.literal('obs'),
      ),
      envVarName: v.string(),
      description: v.string(),
      webhookPathTemplate: v.optional(v.string()),
      docsUrl: v.optional(v.string()),
    }),
  ),
  handler: async (ctx) => {
    return await ctx.db.query('integrationCatalog').collect()
  },
})

/**
 * Workspace-scoped query returning the health status for all integrations
 * belonging to a given tenant.
 */
export const listIntegrationStatusForTenant = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.array(
      v.object({
        _id: v.id('integrationStatus'),
        _creationTime: v.number(),
        tenantId: v.id('tenants'),
        integrationSlug: v.string(),
        configured: v.boolean(),
        lastSuccessAt: v.optional(v.number()),
        lastErrorAt: v.optional(v.number()),
        lastErrorMessage: v.optional(v.string()),
        health: v.union(
          v.literal('healthy'),
          v.literal('degraded'),
          v.literal('offline'),
        ),
      }),
    ),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    return await ctx.db
      .query('integrationStatus')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
  },
})

/**
 * Internal mutation called by the §5.5 cron every 5 minutes.
 *
 * For every tenant × catalog entry, this function:
 *  1. Checks whether the relevant env var is set (via process.env).
 *  2. Looks at the last-success / last-error timestamps.
 *  3. Upserts an `integrationStatus` row with derived `health`.
 *
 * Health derivation rules:
 *  - `configured: false`  → health = "offline"
 *  - `configured: true` and no errors in 24h  → "healthy"
 *  - `configured: true` and last error < 1h ago → "degraded"
 *  - `configured: true` and last error ≥ 1h ago but < 24h → "degraded"
 */
export const recomputeIntegrationStatus = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const now = Date.now()
    const ONE_HOUR = 60 * 60 * 1000
    const ONE_DAY = 24 * ONE_HOUR

    // 1. Fetch all catalog entries (the env-var lookup map).
    const catalog = await ctx.db.query('integrationCatalog').collect()

    // 2. Fetch all tenants.
    const tenants = await ctx.db.query('tenants').collect()

    for (const tenant of tenants) {
      // 3. Pre-load existing status rows for this tenant.
      const existingStatuses = await ctx.db
        .query('integrationStatus')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
        .collect()

      const statusBySlug = new Map<string, Doc<'integrationStatus'>>()
      for (const s of existingStatuses) {
        statusBySlug.set(s.integrationSlug, s)
      }

      for (const entry of catalog) {
        // Check whether the integration's env var is configured.
        // In Convex the environment is accessed via process.env.
        const configured = !!process.env[entry.envVarName]

        const existing = statusBySlug.get(entry.slug)

        // Determine health from configured state + timestamps.
        let health: 'healthy' | 'degraded' | 'offline'
        if (!configured) {
          health = 'offline'
        } else if (
          existing?.lastErrorAt &&
          existing.lastErrorAt > now - ONE_DAY
        ) {
          // Had an error in the last 24h → degraded.
          health = 'degraded'
        } else {
          health = 'healthy'
        }

        if (existing) {
          // Patch existing row — only update fields that may have changed.
          await ctx.db.patch(existing._id, {
            configured,
            health,
          })
        } else {
          // Insert a new status row.
          await ctx.db.insert('integrationStatus', {
            tenantId: tenant._id,
            integrationSlug: entry.slug,
            configured,
            lastSuccessAt: configured ? now : undefined,
            lastErrorAt: undefined,
            lastErrorMessage: undefined,
            health,
          })
        }
      }
    }

    return null
  },
})
