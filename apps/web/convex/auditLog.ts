import type { Id } from './_generated/dataModel'
import { internalMutation, query } from './_generated/server'
import { v } from 'convex/values'
import { requireSessionAuth } from './lib/sessionAuth'

const auditLogEntry = v.object({
  _id: v.id('auditLog'),
  actorUserId: v.optional(v.id('users')),
  actorEmail: v.optional(v.string()),
  actorName: v.optional(v.string()),
  action: v.string(),
  resourceType: v.string(),
  resourceId: v.optional(v.string()),
  payload: v.optional(v.string()),
  at: v.number(),
  ip: v.optional(v.string()),
  ua: v.optional(v.string()),
})

export const listForTenant = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    actionFilter: v.optional(v.string()),
    resourceTypeFilter: v.optional(v.string()),
    actorUserIdFilter: v.optional(v.id('users')),
    afterAt: v.optional(v.number()),
    beforeAt: v.optional(v.number()),
    limit: v.optional(v.number()),
  },
  returns: v.array(auditLogEntry),
  handler: async (
    ctx,
    { authToken, tenantSlug, actionFilter, resourceTypeFilter, actorUserIdFilter, afterAt, beforeAt, limit },
  ) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()

    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership) throw new Error('You do not have access to this workspace')
    if (membership.role !== 'owner' && membership.role !== 'admin') {
      throw new Error('Only owners and admins can view the audit log')
    }

    const maxResults = Math.min(limit ?? 200, 500)

    // Use the most selective index based on available filters
    let entries: any[]

    if (actionFilter) {
      entries = await ctx.db
        .query('auditLog')
        .withIndex('by_tenant_and_action', (q) =>
          q.eq('tenantId', tenant._id).eq('action', actionFilter),
        )
        .order('desc')
        .take(maxResults)
    } else {
      entries = await ctx.db
        .query('auditLog')
        .withIndex('by_tenant_and_at', (q) => q.eq('tenantId', tenant._id))
        .order('desc')
        .take(maxResults)
    }

    // Apply remaining filters client-side
    let filtered = entries

    if (resourceTypeFilter) {
      filtered = filtered.filter((e) => e.resourceType === resourceTypeFilter)
    }

    if (actorUserIdFilter) {
      filtered = filtered.filter((e) => e.actorUserId === actorUserIdFilter)
    }

    if (afterAt) {
      filtered = filtered.filter((e) => e.at >= afterAt)
    }

    if (beforeAt) {
      filtered = filtered.filter((e) => e.at <= beforeAt)
    }

    // Enrich with actor info
    const results = await Promise.all(
      filtered.map(async (entry) => {
        let actorEmail: string | undefined
        let actorName: string | undefined

        if (entry.actorUserId) {
          const user = await ctx.db.get(entry.actorUserId)
          if (user && typeof user === 'object') {
            actorEmail = 'email' in user ? (user as any).email : undefined
            actorName = 'name' in user ? (user as any).name : undefined
          }
        }

        return {
          _id: entry._id,
          actorUserId: entry.actorUserId,
          actorEmail,
          actorName,
          action: entry.action,
          resourceType: entry.resourceType,
          resourceId: entry.resourceId,
          payload: entry.payload,
          at: entry.at,
          ip: entry.ip,
          ua: entry.ua,
        }
      }),
    )

    return results
  },
})

async function computeEntryHash(
  previousHash: string,
  action: string,
  resourceType: string,
  at: number,
  payload?: string,
): Promise<string> {
  const input = `${previousHash}|${action}|${resourceType}|${at}|${payload ?? ''}`
  const encoder = new TextEncoder()
  const data = encoder.encode(input)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

export const insertWithHash = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    actorUserId: v.optional(v.id('users')),
    action: v.string(),
    resourceType: v.string(),
    resourceId: v.optional(v.string()),
    payload: v.optional(v.string()),
    at: v.number(),
    ip: v.optional(v.string()),
    ua: v.optional(v.string()),
  },
  returns: v.id('auditLog'),
  handler: async (ctx, args) => {
    const lastEntry = await ctx.db
      .query('auditLog')
      .withIndex('by_tenant_and_at', (q) => q.eq('tenantId', args.tenantId))
      .order('desc')
      .take(1)

    const previousHash =
      lastEntry.length > 0 && lastEntry[0].entryHash
        ? lastEntry[0].entryHash
        : 'GENESIS'

    const entryHash = await computeEntryHash(
      previousHash,
      args.action,
      args.resourceType,
      args.at,
      args.payload,
    )

    return await ctx.db.insert('auditLog', {
      ...args,
      previousHash,
      entryHash,
    })
  },
})

export const verifyAuditIntegrity = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  returns: v.object({
    totalEntries: v.number(),
    verifiedEntries: v.number(),
    brokenAt: v.optional(v.number()),
    isIntact: v.boolean(),
    preHashEraEntries: v.number(),
  }),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()

    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
      throw new Error('Only owners and admins can verify audit integrity')
    }

    const entries = await ctx.db
      .query('auditLog')
      .withIndex('by_tenant_and_at', (q) => q.eq('tenantId', tenant._id))
      .order('asc')
      .take(500)

    const hashedEntries = entries.filter((e) => e.entryHash)
    const preHashEraEntries = entries.length - hashedEntries.length

    if (hashedEntries.length === 0) {
      return {
        totalEntries: entries.length,
        verifiedEntries: 0,
        isIntact: true,
        preHashEraEntries,
      }
    }

    let verified = 0
    let brokenAt: number | undefined
    let previousHash = 'GENESIS'

    for (const entry of hashedEntries) {
      if (!entry.previousHash || !entry.entryHash) continue

      if (entry.previousHash !== previousHash) {
        brokenAt = entry.at
        break
      }

      const expectedHash = await computeEntryHash(
        entry.previousHash,
        entry.action,
        entry.resourceType,
        entry.at,
        entry.payload,
      )

      if (expectedHash !== entry.entryHash) {
        brokenAt = entry.at
        break
      }

      previousHash = entry.entryHash
      verified++
    }

    return {
      totalEntries: entries.length,
      verifiedEntries: verified,
      brokenAt,
      isIntact: brokenAt === undefined,
      preHashEraEntries,
    }
  },
})
