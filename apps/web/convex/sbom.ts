import { ConvexError, v } from 'convex/values'
import { mutation, query } from './_generated/server'

const inventoryComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  isDirect: v.boolean(),
  sourceFile: v.string(),
  dependents: v.array(v.string()),
  license: v.optional(v.string()),
})

function countByLayer(
  components: Array<{
    layer: string
  }>,
  layer: string,
) {
  return components.filter((component) => component.layer === layer).length
}

export const ingestRepositoryInventory = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    sourceFiles: v.array(v.string()),
    components: v.array(inventoryComponent),
  },
  returns: v.object({
    snapshotId: v.id('sbomSnapshots'),
    componentCount: v.number(),
  }),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new ConvexError('Tenant not found')
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new ConvexError('Repository not found')
    }

    const previousSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_commit', (q) =>
        q.eq('repositoryId', repository._id).eq('commitSha', args.commitSha),
      )
      .unique()

    if (previousSnapshot) {
      return {
        snapshotId: previousSnapshot._id,
        componentCount: previousSnapshot.totalComponents,
      }
    }

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_commit', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()

    const componentCount = args.components.length
    const snapshotId = await ctx.db.insert('sbomSnapshots', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      commitSha: args.commitSha,
      branch: args.branch,
      capturedAt: Date.now(),
      sourceFiles: args.sourceFiles,
      directDependencyCount: countByLayer(args.components, 'direct'),
      transitiveDependencyCount: countByLayer(args.components, 'transitive'),
      buildDependencyCount: countByLayer(args.components, 'build'),
      containerDependencyCount: countByLayer(args.components, 'container'),
      runtimeDependencyCount: countByLayer(args.components, 'runtime'),
      aiModelDependencyCount: countByLayer(args.components, 'ai_model'),
      totalComponents: componentCount,
      riskDelta: latestSnapshot
        ? componentCount - latestSnapshot.totalComponents
        : componentCount,
      exportFormats: ['sentinel_json'],
    })

    for (const component of args.components) {
      await ctx.db.insert('sbomComponents', {
        tenantId: tenant._id,
        repositoryId: repository._id,
        snapshotId,
        name: component.name,
        version: component.version,
        ecosystem: component.ecosystem,
        layer: component.layer,
        isDirect: component.isDirect,
        sourceFile: component.sourceFile,
        trustScore: 50,
        hasKnownVulnerabilities: false,
        license: component.license,
        dependents: component.dependents,
      })
    }

    await ctx.db.patch(repository._id, {
      latestCommitSha: args.commitSha,
      lastScannedAt: Date.now(),
    })

    return { snapshotId, componentCount }
  },
})

export const latestRepositorySnapshot = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      snapshotId: v.id('sbomSnapshots'),
      commitSha: v.string(),
      branch: v.string(),
      capturedAt: v.number(),
      totalComponents: v.number(),
      sourceFiles: v.array(v.string()),
      components: v.array(inventoryComponent),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      return null
    }

    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_commit', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()

    if (!snapshot) {
      return null
    }

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .collect()

    return {
      snapshotId: snapshot._id,
      commitSha: snapshot.commitSha,
      branch: snapshot.branch,
      capturedAt: snapshot.capturedAt,
      totalComponents: snapshot.totalComponents,
      sourceFiles: snapshot.sourceFiles,
      components: components.map((component) => ({
        name: component.name,
        version: component.version,
        ecosystem: component.ecosystem,
        layer: component.layer,
        isDirect: component.isDirect,
        sourceFile: component.sourceFile,
        dependents: component.dependents,
        license: component.license,
      })),
    }
  },
})
