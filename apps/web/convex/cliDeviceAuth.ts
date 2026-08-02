import { mutation } from './_generated/server'
import { v } from 'convex/values'
import { requireSessionAuth } from './lib/sessionAuth'

const EXPIRES_IN_MS = 10 * 60 * 1000

function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes)
  crypto.getRandomValues(values)
  return Array.from(values, (value) => value.toString(16).padStart(2, '0')).join('')
}

function randomUserCode(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  const chars = Array.from(bytes, (value) => alphabet[value % alphabet.length])
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`
}

async function createTenantApiKey(ctx: any, userId: any, tenant: any): Promise<{ keyId: any; secret: string }> {
  const secret = randomHex(32)
  const prefix = `czk_${secret.slice(0, 8)}`
  const salt = randomHex(16)
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + secret))
  const hash = Array.from(new Uint8Array(hashBuffer), (value) => value.toString(16).padStart(2, '0')).join('')
  const now = Date.now()
  const keyId = await ctx.db.insert('apiKeys', {
    tenantId: tenant._id,
    name: 'CyberZen CLI device login',
    hashedSecret: `sha256$${salt}$${hash}`,
    prefix,
    scopes: ['*'],
    createdById: userId,
    createdAt: now,
  })
  return { keyId, secret: `${prefix}.${secret}` }
}

/** Public mutation called by the CLI before the browser authorization step. */
export const startDeviceAuthorization = mutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now()
    const deviceCode = randomHex(32)
    const userCode = randomUserCode()
    await ctx.db.insert('cliDeviceCodes', {
      deviceCode,
      userCode,
      status: 'pending',
      createdAt: now,
      expiresAt: now + EXPIRES_IN_MS,
    })
    return { deviceCode, userCode, expiresIn: EXPIRES_IN_MS / 1000, interval: 3 }
  },
})

/** Public mutation polled by the CLI. The token is returned once and consumed. */
export const pollDeviceAuthorization = mutation({
  args: { deviceCode: v.string() },
  handler: async (ctx, { deviceCode }) => {
    const row = await ctx.db
      .query('cliDeviceCodes')
      .withIndex('by_device_code', (query) => query.eq('deviceCode', deviceCode))
      .unique()
    if (!row) return { status: 'expired' as const }
    if (row.expiresAt < Date.now()) {
      await ctx.db.delete(row._id)
      return { status: 'expired' as const }
    }
    if (row.status === 'pending') return { status: 'pending' as const }
    if (row.status === 'denied') {
      await ctx.db.delete(row._id)
      return { status: 'denied' as const }
    }
    if (!row.tokenSecret) return { status: 'pending' as const }
    const result = {
      status: 'authorized' as const,
      token: row.tokenSecret,
      tenantSlug: row.tenantId ? (await ctx.db.get(row.tenantId))?.slug : undefined,
    }
    await ctx.db.delete(row._id)
    return result
  },
})

/** Called by the signed-in browser authorization page. */
export const authorizeDevice = mutation({
  args: { userCode: v.string(), tenantSlug: v.string() },
  handler: async (ctx, { userCode, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any)
    const row = await ctx.db
      .query('cliDeviceCodes')
      .withIndex('by_user_code', (query) => query.eq('userCode', userCode))
      .unique()
    if (!row || row.expiresAt < Date.now() || row.status !== 'pending') throw new Error('Device code is invalid or expired')

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (query) => query.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')
    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (query) => query.eq('tenantId', tenant._id).eq('userId', userId))
      .unique()
    if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) throw new Error('Only tenant owners and admins can authorize CLI access')

    const key = await createTenantApiKey(ctx, userId, tenant)
    await ctx.db.patch(row._id, { status: 'authorized', userId, tenantId: tenant._id, apiKeyId: key.keyId, tokenSecret: key.secret })
    return { authorized: true, tenantSlug }
  },
})
