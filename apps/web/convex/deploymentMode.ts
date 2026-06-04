import { v } from 'convex/values'
import type { Id } from './_generated/dataModel'
import {
  mutation,
  query,
  type QueryCtx,
  type MutationCtx,
} from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// ─── §8.6 — On-Prem Deployment Mode Toggle ────────────────────────────────
//
// The schema persists deployment mode as `cloud_saas | vpc_injection | on_prem`.
// The public API also accepts the friendlier aliases `cloud | hybrid | on-prem`
// so the UI / external callers can stay close to product copy.

const deploymentModeLiteral = v.union(
  v.literal('cloud_saas'),
  v.literal('vpc_injection'),
  v.literal('on_prem'),
)

const deploymentModeInput = v.union(
  v.literal('cloud_saas'),
  v.literal('vpc_injection'),
  v.literal('on_prem'),
  v.literal('cloud'),
  v.literal('hybrid'),
  v.literal('on-prem'),
)

function canonicalize(
  mode: string,
): 'cloud_saas' | 'vpc_injection' | 'on_prem' {
  switch (mode) {
    case 'cloud':
    case 'cloud_saas':
      return 'cloud_saas'
    case 'hybrid':
    case 'vpc_injection':
      return 'vpc_injection'
    case 'on-prem':
    case 'on_prem':
      return 'on_prem'
    default:
      throw new Error(`Invalid deployment mode: ${mode}`)
  }
}

async function loadTenantAndMembership(
  ctx: QueryCtx | MutationCtx,
  tenantId: Id<'tenants'>,
  userId: Id<'users'>,
) {
  const tenant = await ctx.db.get(tenantId)
  if (!tenant) throw new Error('Tenant not found')

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()

  return { tenant, membership }
}

export const getDeploymentMode = query({
  args: { tenantId: v.id('tenants') },
  returns: v.object({
    tenantId: v.id('tenants'),
    mode: deploymentModeLiteral,
    label: v.string(),
    environment: v.object({
      hostingRegion: v.string(),
      egressEnabled: v.boolean(),
      managedUpdates: v.boolean(),
      dataResidency: v.string(),
    }),
  }),
  handler: async (ctx, { tenantId }) => {
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) throw new Error('Tenant not found')

    const labelMap = {
      cloud_saas: 'Cloud SaaS',
      vpc_injection: 'Hybrid (VPC Injection)',
      on_prem: 'On-Prem',
    } as const

    const environmentMap = {
      cloud_saas: {
        hostingRegion: process.env.CLOUD_REGION ?? 'us-east-1',
        egressEnabled: true,
        managedUpdates: true,
        dataResidency: 'Sentinel-managed',
      },
      vpc_injection: {
        hostingRegion: process.env.HYBRID_REGION ?? 'customer-vpc',
        egressEnabled: true,
        managedUpdates: true,
        dataResidency: 'Customer VPC, Sentinel control plane',
      },
      on_prem: {
        hostingRegion: 'customer-datacenter',
        egressEnabled: false,
        managedUpdates: false,
        dataResidency: 'Customer-owned',
      },
    } as const

    return {
      tenantId: tenant._id,
      mode: tenant.deploymentMode,
      label: labelMap[tenant.deploymentMode],
      environment: environmentMap[tenant.deploymentMode],
    }
  },
})

export const switchDeploymentMode = mutation({
  args: {
    authToken: v.string(),
    tenantId: v.id('tenants'),
    mode: deploymentModeInput,
  },
  returns: v.object({
    tenantId: v.id('tenants'),
    previous: deploymentModeLiteral,
    mode: deploymentModeLiteral,
  }),
  handler: async (ctx, { authToken, tenantId, mode }) => {
    const { userId } = await requireSessionAuth(ctx, authToken)
    const { tenant, membership } = await loadTenantAndMembership(
      ctx,
      tenantId,
      userId,
    )

    if (
      !membership ||
      (membership.role !== 'owner' && membership.role !== 'admin')
    ) {
      throw new Error('Only workspace owners or admins can switch deployment mode.')
    }

    const canonical = canonicalize(mode)
    const previous = tenant.deploymentMode
    if (canonical !== previous) {
      await ctx.db.patch(tenant._id, { deploymentMode: canonical })
    }
    return { tenantId: tenant._id, previous, mode: canonical }
  },
})

export const getDeploymentModeForSlug = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
      tenantId: v.id('tenants'),
      mode: deploymentModeLiteral,
      label: v.string(),
      environment: v.object({
        hostingRegion: v.string(),
        egressEnabled: v.boolean(),
        managedUpdates: v.boolean(),
        dataResidency: v.string(),
      }),
    }),
  ),
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const labelMap = {
      cloud_saas: 'Cloud SaaS',
      vpc_injection: 'Hybrid (VPC Injection)',
      on_prem: 'On-Prem',
    } as const

    const environmentMap = {
      cloud_saas: {
        hostingRegion: process.env.CLOUD_REGION ?? 'us-east-1',
        egressEnabled: true,
        managedUpdates: true,
        dataResidency: 'Sentinel-managed',
      },
      vpc_injection: {
        hostingRegion: process.env.HYBRID_REGION ?? 'customer-vpc',
        egressEnabled: true,
        managedUpdates: true,
        dataResidency: 'Customer VPC, Sentinel control plane',
      },
      on_prem: {
        hostingRegion: 'customer-datacenter',
        egressEnabled: false,
        managedUpdates: false,
        dataResidency: 'Customer-owned',
      },
    } as const

    return {
      tenantId: tenant._id,
      mode: tenant.deploymentMode,
      label: labelMap[tenant.deploymentMode],
      environment: environmentMap[tenant.deploymentMode],
    }
  },
})
