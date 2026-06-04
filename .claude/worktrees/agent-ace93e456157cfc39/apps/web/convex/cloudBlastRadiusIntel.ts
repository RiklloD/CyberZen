// Multi-Cloud Blast Radius — Convex entrypoints.
//
//   computeAndStoreCloudBlastRadius — internalMutation: loads latest SBOM
//       snapshot + components for a repository, runs computeCloudBlastRadius,
//       inserts a cloudBlastRadiusSnapshots row.
//
//   getCloudBlastRadius — public query: latest snapshot by repositoryId.
//
//   getCloudBlastRadiusBySlug — public query: resolves tenant + repository by
//       slug then returns the latest snapshot.

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import { computeCloudBlastRadius } from './lib/cloudBlastRadius'

// ---------------------------------------------------------------------------
// computeAndStoreCloudBlastRadius
// ---------------------------------------------------------------------------

export const computeAndStoreCloudBlastRadius = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // --- load repository ---
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // --- load latest SBOM snapshot for this repository ---
    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    // --- load SBOM components for the snapshot ---
    const components = latestSnapshot
      ? await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) =>
            q.eq('snapshotId', latestSnapshot._id),
          )
          .collect()
      : []

    // --- compute cloud blast radius (pure function, no DB) ---
    const result = computeCloudBlastRadius({
      components: components.map((c) => ({
        name: c.name,
        ecosystem: c.ecosystem,
        layer: c.layer,
      })),
      repositoryName: repository.name,
    })

    // --- persist structured snapshot ---
    const now = Date.now()
    await ctx.db.insert('cloudBlastRadiusSnapshots', {
      repositoryId: args.repositoryId,
      tenantId: repository.tenantId,
      providers: result.providers,
      reachableCloudResources: result.reachableCloudResources,
      criticalResourceCount: result.criticalResourceCount,
      iamEscalationRisk: result.iamEscalationRisk,
      dataExfiltrationRisk: result.dataExfiltrationRisk,
      secretsAccessRisk: result.secretsAccessRisk,
      lateralMovementRisk: result.lateralMovementRisk,
      cloudBlastScore: result.cloudBlastScore,
      cloudRiskTier: result.cloudRiskTier,
      cloudSummary: result.cloudSummary,
      computedAt: now,
    })

    return result
  },
})

// ---------------------------------------------------------------------------
// getCloudBlastRadius
// ---------------------------------------------------------------------------

export const getCloudBlastRadius = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('cloudBlastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getCloudBlastRadiusBySlug
// ---------------------------------------------------------------------------

export const getCloudBlastRadiusBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q
          .eq('tenantId', tenant._id)
          .eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return null

    return await ctx.db
      .query('cloudBlastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})
