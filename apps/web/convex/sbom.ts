import { ConvexError, v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { normalizePackageName } from './lib/breachMatching'
import { compareSnapshotComponents } from './lib/sbomDiff'
import { buildCycloneDxBom } from './lib/cyclonedx'

const incomingInventoryComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  isDirect: v.boolean(),
  sourceFile: v.string(),
  dependents: v.array(v.string()),
  license: v.optional(v.string()),
})

const inventoryComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  isDirect: v.boolean(),
  sourceFile: v.string(),
  dependents: v.array(v.string()),
  license: v.optional(v.string()),
  hasKnownVulnerabilities: v.boolean(),
})

const diffComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  sourceFile: v.string(),
})

const versionChangeComponent = v.object({
  name: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  sourceFile: v.string(),
  previousVersion: v.string(),
  nextVersion: v.string(),
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
    components: v.array(incomingInventoryComponent),
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
      .withIndex('by_repository_and_captured_at', (q) =>
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
        normalizedName: normalizePackageName(component.name),
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

    await ctx.db.patch('repositories', repository._id, {
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
      comparison: v.union(
        v.null(),
        v.object({
          previousSnapshotId: v.id('sbomSnapshots'),
          previousCommitSha: v.string(),
          previousCapturedAt: v.number(),
          addedCount: v.number(),
          removedCount: v.number(),
          updatedCount: v.number(),
          changedComponentCount: v.number(),
          vulnerableComponentDelta: v.number(),
          added: v.array(diffComponent),
          removed: v.array(diffComponent),
          updated: v.array(versionChangeComponent),
        }),
      ),
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

    const snapshotHistory = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(2)

    const snapshot = snapshotHistory[0]
    const previousSnapshot = snapshotHistory[1] ?? null

    if (!snapshot) {
      return null
    }

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .collect()

    const previousComponents = previousSnapshot
      ? await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) => q.eq('snapshotId', previousSnapshot._id))
          .collect()
      : []
    const comparison = previousSnapshot
      ? compareSnapshotComponents(previousComponents, components)
      : null

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
        hasKnownVulnerabilities: component.hasKnownVulnerabilities,
      })),
      comparison: previousSnapshot && comparison
        ? {
            previousSnapshotId: previousSnapshot._id,
            previousCommitSha: previousSnapshot.commitSha,
            previousCapturedAt: previousSnapshot.capturedAt,
            addedCount: comparison.addedCount,
            removedCount: comparison.removedCount,
            updatedCount: comparison.updatedCount,
            changedComponentCount: comparison.changedComponentCount,
            vulnerableComponentDelta: comparison.vulnerableComponentDelta,
            added: comparison.added,
            removed: comparison.removed,
            updated: comparison.updated,
          }
        : null,
    }
  },
})

// ---------------------------------------------------------------------------
// exportSnapshot — CycloneDX 1.5 BOM export for a given snapshot ID
//
// Returns a CycloneDX JSON document with full component inventory, PURLs,
// and Sentinel-specific property extensions.  The HTTP route at
// /api/sbom/export?snapshotId=<id> wraps this query for direct downloads.
// ---------------------------------------------------------------------------

const cycloneDxProperty = v.object({ name: v.string(), value: v.string() })
const cycloneDxLicense = v.object({
  license: v.object({ id: v.string() }),
})
const cycloneDxComponent = v.object({
  type: v.union(
    v.literal('library'),
    v.literal('container'),
    v.literal('framework'),
    v.literal('application'),
  ),
  name: v.string(),
  version: v.string(),
  purl: v.string(),
  licenses: v.array(cycloneDxLicense),
  properties: v.array(cycloneDxProperty),
})

const cycloneDxBomValidator = v.object({
  bomFormat: v.literal('CycloneDX'),
  specVersion: v.literal('1.5'),
  serialNumber: v.string(),
  version: v.literal(1),
  metadata: v.object({
    timestamp: v.string(),
    tools: v.array(
      v.object({ vendor: v.string(), name: v.string(), version: v.string() }),
    ),
    component: v.object({
      type: v.literal('application'),
      name: v.string(),
      version: v.string(),
    }),
  }),
  components: v.array(cycloneDxComponent),
})

export const exportSnapshot = query({
  args: { snapshotId: v.id('sbomSnapshots') },
  returns: v.union(v.null(), cycloneDxBomValidator),
  handler: async (ctx, args) => {
    const snapshot = await ctx.db.get(args.snapshotId)
    if (!snapshot) return null

    const repository = await ctx.db.get(snapshot.repositoryId)
    if (!repository) return null

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .collect()

    return buildCycloneDxBom({
      repositoryName: repository.name,
      commitSha: snapshot.commitSha,
      branch: snapshot.branch,
      capturedAt: snapshot.capturedAt,
      snapshotId: snapshot._id,
      components: components.map((c) => ({
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        isDirect: c.isDirect,
        sourceFile: c.sourceFile,
        license: c.license,
        trustScore: c.trustScore,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
      })),
    })
  },
})
