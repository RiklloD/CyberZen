import { v } from 'convex/values'
import { internalQuery, mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

function ipToUint32(ip: string): number {
  const parts = ip.split('.').map(Number)
  return (((parts[0] ?? 0) << 24) | ((parts[1] ?? 0) << 16) | ((parts[2] ?? 0) << 8) | (parts[3] ?? 0)) >>> 0
}

function isValidCidr(cidr: string): boolean {
  const parts = cidr.split('/')
  if (parts.length !== 2) return false
  const [ip, prefixStr] = parts
  const prefix = parseInt(prefixStr ?? '', 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const ipParts = (ip ?? '').split('.')
  if (ipParts.length !== 4) return false
  return ipParts.every((p) => {
    const n = parseInt(p, 10)
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p
  })
}

function isIpInCidr(ip: string, cidr: string): boolean {
  if (!ip.includes('.')) return true // pass through IPv6 (not yet implemented)
  const parts = cidr.split('/')
  const network = parts[0] ?? ''
  const prefix = parseInt(parts[1] ?? '32', 10)
  if (!network.includes('.')) return false
  const ipInt = ipToUint32(ip)
  const networkInt = ipToUint32(network)
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  return (ipInt & mask) === (networkInt & mask)
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
    throw new Error('Only owners and admins can manage IP allowlists')
  }

  return { userId, tenant }
}

export const updateIpAllowlist = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    cidrs: v.array(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, cidrs }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    for (const cidr of cidrs) {
      if (!isValidCidr(cidr)) {
        throw new Error(`Invalid CIDR notation: ${cidr}`)
      }
    }

    await ctx.db.patch(tenant._id, { ipAllowlist: cidrs.length > 0 ? cidrs : undefined })

    return null
  },
})

export const getIpAllowlist = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)
    return tenant.ipAllowlist ?? []
  },
})

export const checkIpAllowlist = internalQuery({
  args: {
    tenantId: v.id('tenants'),
    clientIp: v.string(),
  },
  returns: v.object({
    allowed: v.boolean(),
    reason: v.optional(v.string()),
  }),
  handler: async (ctx, { tenantId, clientIp }) => {
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) return { allowed: false, reason: 'Tenant not found' }

    const allowlist = tenant.ipAllowlist
    if (!allowlist || allowlist.length === 0) {
      return { allowed: true }
    }

    const cleanIp = clientIp.split(',')[0]?.trim() ?? ''
    for (const cidr of allowlist) {
      if (isIpInCidr(cleanIp, cidr)) {
        return { allowed: true }
      }
    }

    return { allowed: false, reason: `IP ${cleanIp} is not in the allowlist` }
  },
})

export const testIpAccess = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    testIp: v.string(),
  },
  returns: v.object({
    allowed: v.boolean(),
    matchedCidr: v.optional(v.string()),
  }),
  handler: async (ctx, { authToken, tenantSlug, testIp }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    const allowlist = tenant.ipAllowlist
    if (!allowlist || allowlist.length === 0) {
      return { allowed: true }
    }

    for (const cidr of allowlist) {
      if (isIpInCidr(testIp, cidr)) {
        return { allowed: true, matchedCidr: cidr }
      }
    }

    return { allowed: false }
  },
})
