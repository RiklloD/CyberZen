import { v } from 'convex/values'
import { internalQuery, mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// A17 — validate each octet is in range 0-255 before bitwise ops
function ipToUint32(ip: string): number {
  const parts = ip.split('.')
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${ip}`)
  const octets = parts.map((p) => {
    const n = Number(p)
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== p.trim()) {
      throw new Error(`Invalid IPv4 octet "${p}" in: ${ip}`)
    }
    return n
  })
  return (((octets[0] ?? 0) << 24) | ((octets[1] ?? 0) << 16) | ((octets[2] ?? 0) << 8) | (octets[3] ?? 0)) >>> 0
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
  // A5 — IPv6 not supported by CIDR matching: fail closed (reject) rather than
  // silently bypassing the entire allowlist
  if (!ip.includes('.')) return false
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
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    cidrs: v.array(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, cidrs }) => {
    const { tenant } = await getTenantAndVerifyAdmin(ctx as any, authToken, tenantSlug)

    // A18 — cap CIDR count to prevent unbounded per-request O(N) cost
    if (cidrs.length > 100) {
      throw new Error('Maximum of 100 CIDR rules allowed')
    }

    for (const cidr of cidrs) {
      if (!isValidCidr(cidr)) {
        throw new Error(`Invalid CIDR notation: ${cidr}`)
      }
    }

    await ctx.db.patch(tenant._id, { ipAllowlist: cidrs })

    return null
  },
})

export const getIpAllowlist = query({
  args: {
    authToken: v.optional(v.string()),
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
  }),
  handler: async (ctx, { tenantId, clientIp }) => {
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) {
      // A26 — do not echo client IP in response; log server-side only
      return { allowed: false }
    }

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

    // A26 — log reason server-side, return only boolean to caller
    console.log(`[ipAllowlist] IP ${cleanIp} rejected for tenant ${tenantId}`)
    return { allowed: false }
  },
})

export const testIpAccess = query({
  args: {
    authToken: v.optional(v.string()),
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
