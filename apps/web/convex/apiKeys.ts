import type { Id } from './_generated/dataModel'
import { internalMutation, mutation, query } from './_generated/server'
import { v } from 'convex/values'
import { requireSessionAuth } from './lib/sessionAuth'

const apiKeySummary = v.object({
  _id: v.id('apiKeys'),
  name: v.string(),
  scopes: v.array(v.string()),
  lastUsedAt: v.optional(v.number()),
  expiresAt: v.optional(v.number()),
  revokedAt: v.optional(v.number()),
  createdAt: v.number(),
})

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

  if (membership.role !== 'owner' && membership.role !== 'admin') {
    throw new Error('Only owners and admins can manage API keys')
  }

  return { userId, tenant }
}

async function generateApiKeySecret(): Promise<{ secret: string; prefix: string; hashed: string }> {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  const secret = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  const prefix = `czk_${secret.slice(0, 8)}`

  const saltBytes = new Uint8Array(16)
  crypto.getRandomValues(saltBytes)
  const salt = Array.from(saltBytes, (b) => b.toString(16).padStart(2, '0')).join('')

  const enc = new TextEncoder()
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(salt + secret))
  const hash = Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, '0')).join('')

  return { secret, prefix, hashed: `sha256$${salt}$${hash}` }
}

// Timing-safe string comparison for use during API key verification.
// Verification flow: split hashed on '$', re-derive SHA-256(salt + providedSecret),
// then call timingSafeEqual(storedHash, derivedHash).
// Keys that don't start with 'sha256$' use the legacy format — reject and require rotation.
function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length)
  let diff = a.length ^ b.length
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0)
  }
  return diff === 0
}

export const listApiKeys = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: v.array(apiKeySummary),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const keys = await ctx.db
      .query('apiKeys')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .collect()

    return keys.map((k) => ({
      _id: k._id,
      name: k.name,
      scopes: k.scopes,
      lastUsedAt: k.lastUsedAt,
      expiresAt: k.expiresAt,
      revokedAt: k.revokedAt,
      createdAt: k.createdAt,
    }))
  },
})

export const createApiKey = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    name: v.string(),
    scopes: v.array(v.string()),
    expiresAt: v.optional(v.number()),
  },
  returns: v.object({
    keyId: v.id('apiKeys'),
    name: v.string(),
    secret: v.string(),
    prefix: v.string(),
    scopes: v.array(v.string()),
    expiresAt: v.optional(v.number()),
  }),
  handler: async (ctx, { authToken, tenantSlug, name, scopes, expiresAt }) => {
    const { userId, tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const { secret, prefix, hashed } = await generateApiKeySecret()
    const now = Date.now()

    const keyId = await ctx.db.insert('apiKeys', {
      tenantId: tenant._id,
      name,
      hashedSecret: hashed,
      prefix,
      scopes,
      expiresAt,
      createdById: userId,
      createdAt: now,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'api_key.created',
      resourceType: 'apiKeys',
      resourceId: keyId,
      payload: JSON.stringify({ name, prefix, scopes }),
      at: now,
    })

    return {
      keyId,
      name,
      secret: `${prefix}.${secret}`,
      prefix,
      scopes,
      expiresAt,
    }
  },
})

export const rotateApiKey = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    keyId: v.id('apiKeys'),
  },
  returns: v.object({
    keyId: v.id('apiKeys'),
    name: v.string(),
    secret: v.string(),
    prefix: v.string(),
    scopes: v.array(v.string()),
    expiresAt: v.optional(v.number()),
  }),
  handler: async (ctx, { authToken, tenantSlug, keyId }) => {
    const { userId, tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const key = await ctx.db.get(keyId)
    if (!key || key.tenantId !== tenant._id) {
      throw new Error('API key not found')
    }

    if (key.revokedAt) {
      throw new Error('Cannot rotate a revoked API key')
    }

    const { secret, prefix, hashed } = await generateApiKeySecret()
    const now = Date.now()

    await ctx.db.patch(keyId, {
      hashedSecret: hashed,
      prefix,
      updatedAt: now,
    })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'api_key.rotated',
      resourceType: 'apiKeys',
      resourceId: keyId,
      payload: JSON.stringify({ name: key.name, newPrefix: prefix }),
      at: now,
    })

    return {
      keyId,
      name: key.name,
      secret: `${prefix}.${secret}`,
      prefix,
      scopes: key.scopes,
      expiresAt: key.expiresAt,
    }
  },
})

export const revokeApiKey = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    keyId: v.id('apiKeys'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, keyId }) => {
    const { userId, tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const key = await ctx.db.get(keyId)
    if (!key || key.tenantId !== tenant._id) {
      throw new Error('API key not found')
    }

    if (key.revokedAt) return null // Already revoked

    const now = Date.now()
    await ctx.db.patch(keyId, { revokedAt: now })

    await ctx.db.insert('auditLog', {
      tenantId: tenant._id,
      actorUserId: userId,
      action: 'api_key.revoked',
      resourceType: 'apiKeys',
      resourceId: keyId,
      payload: JSON.stringify({ name: key.name }),
      at: now,
    })

    return null
  },
})

// ---------------------------------------------------------------------------
// §6.28 API Rate Limiting — per-key usage tracking
// ---------------------------------------------------------------------------

const RATE_LIMIT_PER_MINUTE = 100
const RATE_LIMIT_PER_HOUR = 5_000

// ---------------------------------------------------------------------------
// §A7 — Authenticate and rate-limit a tenant API key (czk_ prefix).
// Called from http.ts for every authenticated HTTP action.
// ---------------------------------------------------------------------------

const tenantKeyCheckResult = v.union(
  v.object({ status: v.literal('invalid') }),
  v.object({ status: v.literal('rate_limited'), retryAfterSeconds: v.number() }),
  v.object({ status: v.literal('ok'), keyId: v.id('apiKeys'), tenantId: v.id('tenants') }),
)

export const checkAndRecordTenantKeyUsage = internalMutation({
  args: { rawKey: v.string() },
  returns: tenantKeyCheckResult,
  handler: async (ctx, { rawKey }) => {
    const dotIdx = rawKey.indexOf('.')
    if (dotIdx < 0 || !rawKey.startsWith('czk_')) {
      return { status: 'invalid' as const }
    }

    const prefix = rawKey.slice(0, dotIdx)
    const secret = rawKey.slice(dotIdx + 1)

    const key = await ctx.db
      .query('apiKeys')
      .withIndex('by_prefix', (q) => q.eq('prefix', prefix))
      .unique()

    if (!key || key.revokedAt || (key.expiresAt && key.expiresAt < Date.now())) {
      return { status: 'invalid' as const }
    }

    const parts = key.hashedSecret.split('$')
    if (parts.length !== 3 || parts[0] !== 'sha256') {
      return { status: 'invalid' as const }
    }
    const [, salt, storedHash] = parts

    const enc = new TextEncoder()
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(salt + secret))
    const derivedHash = Array.from(new Uint8Array(hashBuf), (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('')

    if (!timingSafeEqual(derivedHash, storedHash)) {
      return { status: 'invalid' as const }
    }

    const now = Date.now()
    const minuteWindowStart = Math.floor(now / 60_000) * 60_000
    const hourWindowStart = Math.floor(now / 3_600_000) * 3_600_000

    const minuteRecord = await ctx.db
      .query('apiUsageRecords')
      .withIndex('by_api_key_and_window', (q) =>
        q.eq('apiKeyId', key._id).eq('windowStart', minuteWindowStart),
      )
      .unique()

    if ((minuteRecord?.requestCount ?? 0) >= RATE_LIMIT_PER_MINUTE) {
      if (minuteRecord) {
        await ctx.db.patch(minuteRecord._id, { blockedCount: minuteRecord.blockedCount + 1 })
      }
      return {
        status: 'rate_limited' as const,
        retryAfterSeconds: Math.ceil((minuteWindowStart + 60_000 - now) / 1_000),
      }
    }

    const hourRecords = await ctx.db
      .query('apiUsageRecords')
      .withIndex('by_api_key_and_window', (q) =>
        q.eq('apiKeyId', key._id).gte('windowStart', hourWindowStart),
      )
      .take(120)

    const hourCount = hourRecords.reduce((sum, r) => sum + r.requestCount, 0)

    if (hourCount >= RATE_LIMIT_PER_HOUR) {
      if (minuteRecord) {
        await ctx.db.patch(minuteRecord._id, { blockedCount: minuteRecord.blockedCount + 1 })
      }
      return {
        status: 'rate_limited' as const,
        retryAfterSeconds: Math.ceil((hourWindowStart + 3_600_000 - now) / 1_000),
      }
    }

    if (minuteRecord) {
      await ctx.db.patch(minuteRecord._id, { requestCount: minuteRecord.requestCount + 1 })
    } else {
      await ctx.db.insert('apiUsageRecords', {
        apiKeyId: key._id,
        tenantId: key.tenantId,
        windowStart: minuteWindowStart,
        requestCount: 1,
        blockedCount: 0,
        period: 'minute',
      })
    }

    await ctx.db.patch(key._id, { lastUsedAt: now })

    return { status: 'ok' as const, keyId: key._id, tenantId: key.tenantId }
  },
})

export const getApiKeyUsage = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyMember(ctx as any, authToken, tenantSlug)

    const keys = await ctx.db
      .query('apiKeys')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .collect()

    const now = Date.now()
    const oneHourAgo = now - 60 * 60 * 1000
    const oneDayAgo = now - 24 * 60 * 60 * 1000

    // For each key, get recent usage records
    const usageData = await Promise.all(
      keys.map(async (key) => {
        const records = await ctx.db
          .query('apiUsageRecords')
          .withIndex('by_api_key', (q: any) => q.eq('apiKeyId', key._id))
          .order('desc')
          .take(100)

        const hourlyRequests = records
          .filter((r) => r.windowStart >= oneHourAgo)
          .reduce((sum, r) => sum + r.requestCount, 0)

        const dailyRequests = records
          .filter((r) => r.windowStart >= oneDayAgo)
          .reduce((sum, r) => sum + r.requestCount, 0)

        const hourlyBlocked = records
          .filter((r) => r.windowStart >= oneHourAgo)
          .reduce((sum, r) => sum + r.blockedCount, 0)

        return {
          keyId: key._id,
          name: key.name,
          prefix: key.prefix,
          isRevoked: !!key.revokedAt,
          hourlyRequests,
          dailyRequests,
          hourlyBlocked,
          rateLimitPerMinute: 100, // Default rate limit
          rateLimitPerHour: 5000,
          recentRecords: records.slice(0, 10).map((r) => ({
            windowStart: r.windowStart,
            requestCount: r.requestCount,
            blockedCount: r.blockedCount,
            period: r.period,
          })),
        }
      }),
    )

    return usageData
  },
})
