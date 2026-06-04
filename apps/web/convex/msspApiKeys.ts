import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

async function generateMsspKeySecret(): Promise<{
  secret: string
  prefix: string
  hashed: string
}> {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  const secret = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  const prefix = `msk_${secret.slice(0, 8)}`

  const saltBytes = new Uint8Array(16)
  crypto.getRandomValues(saltBytes)
  const salt = Array.from(saltBytes, (b) => b.toString(16).padStart(2, '0')).join('')

  const enc = new TextEncoder()
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(salt + secret))
  const hash = Array.from(new Uint8Array(hashBuffer), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('')

  return { secret, prefix, hashed: `sha256$${salt}$${hash}` }
}

function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length)
  let diff = a.length ^ b.length
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0)
  }
  return diff === 0
}

async function getTenantAndVerifyAdmin(
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
    throw new Error('Only owners and admins can manage MSSP API keys')
  }

  return { userId, tenant }
}

export const createMsspApiKey = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    partnerName: v.string(),
    scopes: v.array(v.string()),
    expiresAt: v.optional(v.number()),
  },
  returns: v.object({
    keyId: v.id('msspApiKeys'),
    partnerName: v.string(),
    secret: v.string(),
    prefix: v.string(),
    scopes: v.array(v.string()),
  }),
  handler: async (ctx, { authToken, tenantSlug, partnerName, scopes, expiresAt }) => {
    const { userId, tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const { secret, prefix, hashed } = await generateMsspKeySecret()
    const now = Date.now()

    const keyId = await ctx.db.insert('msspApiKeys', {
      tenantId: tenant._id,
      partnerName,
      keyPrefix: prefix,
      keyHash: hashed,
      scopes,
      isActive: true,
      createdByUserId: userId,
      createdAt: now,
      expiresAt,
    })

    return {
      keyId,
      partnerName,
      secret: `${prefix}.${secret}`,
      prefix,
      scopes,
    }
  },
})

export const rotateMsspApiKey = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    keyId: v.id('msspApiKeys'),
  },
  returns: v.object({
    keyId: v.id('msspApiKeys'),
    partnerName: v.string(),
    secret: v.string(),
    prefix: v.string(),
  }),
  handler: async (ctx, { authToken, tenantSlug, keyId }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const key = await ctx.db.get(keyId)
    if (!key || key.tenantId !== tenant._id) throw new Error('MSSP API key not found')
    if (key.revokedAt) throw new Error('Cannot rotate a revoked key')

    const { secret, prefix, hashed } = await generateMsspKeySecret()

    await ctx.db.patch(keyId, {
      keyPrefix: prefix,
      keyHash: hashed,
      isActive: true,
    })

    return {
      keyId,
      partnerName: key.partnerName,
      secret: `${prefix}.${secret}`,
      prefix,
    }
  },
})

export const revokeMsspApiKey = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    keyId: v.id('msspApiKeys'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, keyId }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const key = await ctx.db.get(keyId)
    if (!key || key.tenantId !== tenant._id) throw new Error('MSSP API key not found')

    if (!key.revokedAt) {
      await ctx.db.patch(keyId, {
        revokedAt: Date.now(),
        isActive: false,
      })
    }

    return null
  },
})

export const listMsspApiKeys = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const keys = await ctx.db
      .query('msspApiKeys')
      .withIndex('by_tenant', (q: any) => q.eq('tenantId', tenant._id))
      .take(100)

    return keys.map((k) => ({
      _id: k._id,
      partnerName: k.partnerName,
      keyPrefix: k.keyPrefix,
      scopes: k.scopes,
      isActive: k.isActive,
      lastUsedAt: k.lastUsedAt,
      createdAt: k.createdAt,
      expiresAt: k.expiresAt,
      revokedAt: k.revokedAt,
    }))
  },
})

export const validateMsspKey = internalMutation({
  args: { rawKey: v.string() },
  returns: v.union(
    v.object({ valid: v.literal(false) }),
    v.object({
      valid: v.literal(true),
      keyId: v.id('msspApiKeys'),
      tenantId: v.id('tenants'),
      scopes: v.array(v.string()),
    }),
  ),
  handler: async (ctx, { rawKey }) => {
    const dotIdx = rawKey.indexOf('.')
    if (dotIdx < 0 || !rawKey.startsWith('msk_')) {
      return { valid: false as const }
    }

    const prefix = rawKey.slice(0, dotIdx)
    const secret = rawKey.slice(dotIdx + 1)

    const key = await ctx.db
      .query('msspApiKeys')
      .withIndex('by_key_prefix', (q: any) => q.eq('keyPrefix', prefix))
      .unique()

    if (
      !key ||
      !key.isActive ||
      key.revokedAt ||
      (key.expiresAt && key.expiresAt < Date.now())
    ) {
      return { valid: false as const }
    }

    const parts = key.keyHash.split('$')
    if (parts.length !== 3 || parts[0] !== 'sha256') {
      return { valid: false as const }
    }

    const [, salt, storedHash] = parts
    const enc = new TextEncoder()
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(salt + secret))
    const derivedHash = Array.from(new Uint8Array(hashBuf), (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('')

    if (!timingSafeEqual(derivedHash, storedHash)) {
      return { valid: false as const }
    }

    await ctx.db.patch(key._id, { lastUsedAt: Date.now() })

    return {
      valid: true as const,
      keyId: key._id,
      tenantId: key.tenantId,
      scopes: key.scopes,
    }
  },
})
