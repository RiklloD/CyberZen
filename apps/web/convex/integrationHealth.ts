import { v } from 'convex/values'
import { internalAction, internalMutation, internalQuery, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth'

const INTEGRATION_TYPES = ['github', 'gitlab', 'slack', 'sso', 'webhook', 'jira'] as const
type IntegrationType = (typeof INTEGRATION_TYPES)[number]

async function getTenantAndVerifyMember(
  ctx: any,
  authToken: string,
  tenantSlug: string,
) {
  const { userId } = await requireSessionAuth(ctx, authToken)

  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
    .unique()

  if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q: any) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()

  if (!membership) throw new Error('You do not have access to this workspace')

  return { userId, tenant }
}

export const getIntegrationHealth = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const healthRecords = await ctx.db
      .query('integrationHealth')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .take(50)

    return healthRecords
  },
})

export const triggerHealthCheck = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    integrationType: v.union(
      v.literal('github'),
      v.literal('gitlab'),
      v.literal('slack'),
      v.literal('sso'),
      v.literal('webhook'),
      v.literal('jira'),
    ),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, integrationType }) => {
    const { tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    await ctx.scheduler.runAfter(
      0,
      internal.integrationHealth.checkIntegrationHealth,
      { tenantId: tenant._id, integrationType },
    )

    return null
  },
})

export const checkIntegrationHealth = internalAction({
  args: {
    tenantId: v.id('tenants'),
    integrationType: v.union(
      v.literal('github'),
      v.literal('gitlab'),
      v.literal('slack'),
      v.literal('sso'),
      v.literal('webhook'),
      v.literal('jira'),
    ),
  },
  returns: v.null(),
  handler: async (ctx, { tenantId, integrationType }) => {
    const status = await ctx.runQuery(
      internal.integrationHealth.deriveIntegrationStatus,
      { tenantId, integrationType },
    )

    await ctx.runMutation(internal.integrationHealth.upsertHealthRecord, {
      tenantId,
      integrationType,
      status: status.status,
      lastSyncAt: status.lastSyncAt,
      lastError: status.lastError,
    })

    return null
  },
})

export const deriveIntegrationStatus = internalQuery({
  args: {
    tenantId: v.id('tenants'),
    integrationType: v.union(
      v.literal('github'),
      v.literal('gitlab'),
      v.literal('slack'),
      v.literal('sso'),
      v.literal('webhook'),
      v.literal('jira'),
    ),
  },
  returns: v.object({
    status: v.union(v.literal('healthy'), v.literal('degraded'), v.literal('down')),
    lastSyncAt: v.optional(v.number()),
    lastError: v.optional(v.string()),
  }),
  handler: async (ctx, { tenantId, integrationType }) => {
    const now = Date.now()
    const oneHour = 60 * 60 * 1000
    const sixHours = 6 * oneHour

    const integStatus = await ctx.db
      .query('integrationStatus')
      .withIndex('by_tenant_slug', (q: any) =>
        q.eq('tenantId', tenantId).eq('integrationSlug', integrationType),
      )
      .unique()

    if (!integStatus || !integStatus.configured) {
      return { status: 'down' as const, lastError: 'Integration not configured' }
    }

    const lastSuccess = integStatus.lastSuccessAt
    const lastError = integStatus.lastErrorAt

    if (lastSuccess && now - lastSuccess < oneHour) {
      return { status: 'healthy' as const, lastSyncAt: lastSuccess }
    }

    if (lastSuccess && now - lastSuccess < sixHours) {
      return {
        status: 'degraded' as const,
        lastSyncAt: lastSuccess,
        lastError: integStatus.lastErrorMessage ?? 'No recent activity',
      }
    }

    return {
      status: 'down' as const,
      lastSyncAt: lastSuccess ?? undefined,
      lastError: integStatus.lastErrorMessage ?? 'Integration not responding',
    }
  },
})

export const upsertHealthRecord = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    integrationType: v.union(
      v.literal('github'),
      v.literal('gitlab'),
      v.literal('slack'),
      v.literal('sso'),
      v.literal('webhook'),
      v.literal('jira'),
    ),
    status: v.union(v.literal('healthy'), v.literal('degraded'), v.literal('down')),
    lastSyncAt: v.optional(v.number()),
    lastError: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { tenantId, integrationType, status, lastSyncAt, lastError }) => {
    const existing = await ctx.db
      .query('integrationHealth')
      .withIndex('by_tenant_and_type', (q: any) =>
        q.eq('tenantId', tenantId).eq('integrationType', integrationType),
      )
      .unique()

    const now = Date.now()
    const isFailure = status === 'down'

    if (existing) {
      const consecutiveFailures = isFailure ? existing.consecutiveFailures + 1 : 0
      await ctx.db.patch(existing._id, {
        status,
        lastSyncAt,
        lastError,
        consecutiveFailures,
        checkedAt: now,
      })

      if (consecutiveFailures >= 3) {
        console.warn(
          `[IntegrationHealth] ${integrationType} for tenant ${tenantId} has failed ${consecutiveFailures} consecutive checks`,
        )
      }
    } else {
      await ctx.db.insert('integrationHealth', {
        tenantId,
        integrationType,
        status,
        lastSyncAt,
        lastError,
        consecutiveFailures: isFailure ? 1 : 0,
        checkedAt: now,
      })
    }

    return null
  },
})

export const runHealthChecks = internalAction({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const tenants = await ctx.runQuery(internal.integrationHealth.listActiveTenants, {})

    for (const tenantId of tenants) {
      for (const integrationType of INTEGRATION_TYPES) {
        await ctx.runAction(internal.integrationHealth.checkIntegrationHealth, {
          tenantId,
          integrationType,
        })
      }
    }

    return null
  },
})

export const listActiveTenants = internalQuery({
  args: {},
  returns: v.array(v.id('tenants')),
  handler: async (ctx) => {
    const tenants = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.gte('slug', ''))
      .take(200)
    return tenants.map((t) => t._id)
  },
})
