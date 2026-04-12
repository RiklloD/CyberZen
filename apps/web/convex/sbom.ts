import { ConvexError, v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { internal } from './_generated/api'
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

    // Fire-and-forget sbom.drift_detected webhook when the component count
    // changes significantly. Removals (riskDelta < -3) are flagged more
    // aggressively than additions because they may indicate substitution attacks.
    const riskDelta = latestSnapshot
      ? componentCount - latestSnapshot.totalComponents
      : 0

    const isDriftSignificant =
      latestSnapshot !== null &&
      (Math.abs(riskDelta) >= 10 || riskDelta < -3)

    if (isDriftSignificant && latestSnapshot) {
      try {
        const tenant = await ctx.db.get(repository.tenantId)
        if (tenant) {
          await ctx.scheduler.runAfter(
            0,
            internal.webhooks.dispatchWebhookEvent,
            {
              tenantId: repository.tenantId,
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              eventPayload: {
                event: 'sbom.drift_detected' as const,
                data: {
                  previousComponentCount: latestSnapshot.totalComponents,
                  newComponentCount: componentCount,
                  riskDelta,
                  branch: args.branch,
                  commitSha: args.commitSha,
                },
              },
            },
          )
        }
      } catch (e) {
        console.error('[webhooks] sbom.drift_detected dispatch failed', e)
      }
    }

    // Fire-and-forget trust score computation. Runs asynchronously after all
    // components are inserted so the mutation never blocks on score patching.
    // This replaces the initial trustScore: 50 placeholder values with real
    // signal-derived scores for every component in the new snapshot.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.trustScoreIntel.refreshComponentTrustScores,
        { snapshotId },
      )
    } catch (e) {
      console.error('[trust-score] failed to schedule refreshComponentTrustScores', e)
    }

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
// snapshotByCommit — look up a specific SBOM snapshot by commit SHA.
//
// Wraps /api/sbom/commit?commitSha=<sha>&tenantSlug=<slug>&repositoryFullName=<repo>
// ---------------------------------------------------------------------------

export const snapshotByCommit = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    commitSha: v.string(),
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
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) return null

    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_commit', (q) =>
        q.eq('repositoryId', repository._id).eq('commitSha', args.commitSha),
      )
      .unique()
    if (!snapshot) return null

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
      components: components.map((c) => ({
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        isDirect: c.isDirect,
        sourceFile: c.sourceFile,
        dependents: c.dependents,
        license: c.license,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
      })),
    }
  },
})

// ---------------------------------------------------------------------------
// snapshotDiff — diff two SBOM snapshots identified by commit SHA.
//
// Wraps /api/sbom/diff?from=<sha>&to=<sha>&tenantSlug=<slug>&repositoryFullName=<repo>
// ---------------------------------------------------------------------------

export const snapshotDiff = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    fromCommitSha: v.string(),
    toCommitSha: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      from: v.object({
        snapshotId: v.id('sbomSnapshots'),
        commitSha: v.string(),
        capturedAt: v.number(),
        totalComponents: v.number(),
      }),
      to: v.object({
        snapshotId: v.id('sbomSnapshots'),
        commitSha: v.string(),
        capturedAt: v.number(),
        totalComponents: v.number(),
      }),
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
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) return null

    const [fromSnapshot, toSnapshot] = await Promise.all([
      ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_commit', (q) =>
          q.eq('repositoryId', repository._id).eq('commitSha', args.fromCommitSha),
        )
        .unique(),
      ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_commit', (q) =>
          q.eq('repositoryId', repository._id).eq('commitSha', args.toCommitSha),
        )
        .unique(),
    ])

    if (!fromSnapshot || !toSnapshot) return null

    const [fromComponents, toComponents] = await Promise.all([
      ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', fromSnapshot._id))
        .collect(),
      ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', toSnapshot._id))
        .collect(),
    ])

    const diff = compareSnapshotComponents(fromComponents, toComponents)

    return {
      from: {
        snapshotId: fromSnapshot._id,
        commitSha: fromSnapshot.commitSha,
        capturedAt: fromSnapshot.capturedAt,
        totalComponents: fromSnapshot.totalComponents,
      },
      to: {
        snapshotId: toSnapshot._id,
        commitSha: toSnapshot.commitSha,
        capturedAt: toSnapshot.capturedAt,
        totalComponents: toSnapshot.totalComponents,
      },
      ...diff,
    }
  },
})

// ---------------------------------------------------------------------------
// packageTrustScore — per-package trust score from the latest SBOM snapshot.
//
// Wraps /api/trust-scores/detail?package=<name>&tenantSlug=<slug>&repositoryFullName=<repo>
// ---------------------------------------------------------------------------

export const packageTrustScore = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packageName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      name: v.string(),
      version: v.string(),
      ecosystem: v.string(),
      layer: v.string(),
      isDirect: v.boolean(),
      trustScore: v.number(),
      hasKnownVulnerabilities: v.boolean(),
      license: v.optional(v.string()),
      snapshotId: v.id('sbomSnapshots'),
      commitSha: v.string(),
      capturedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) return null

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
    if (!latestSnapshot) return null

    const normalizedSearch = normalizePackageName(args.packageName)

    const allComponents = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .collect()

    const match = allComponents.find(
      (c) => c.normalizedName === normalizedSearch || c.name === args.packageName,
    )
    if (!match) return null

    return {
      name: match.name,
      version: match.version,
      ecosystem: match.ecosystem,
      layer: match.layer,
      isDirect: match.isDirect,
      trustScore: match.trustScore,
      hasKnownVulnerabilities: match.hasKnownVulnerabilities,
      license: match.license,
      snapshotId: latestSnapshot._id,
      commitSha: latestSnapshot.commitSha,
      capturedAt: latestSnapshot.capturedAt,
    }
  },
})

// ---------------------------------------------------------------------------
// packageTrustScoreHistory — trust score history for a package across snapshots.
//
// Wraps /api/trust-scores/history?package=<name>&tenantSlug=<slug>&repositoryFullName=<repo>
// Walks the most recent 20 snapshots; returns one data point per snapshot where
// the package appears.
// ---------------------------------------------------------------------------

export const packageTrustScoreHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packageName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      packageName: v.string(),
      history: v.array(
        v.object({
          snapshotId: v.id('sbomSnapshots'),
          commitSha: v.string(),
          capturedAt: v.number(),
          trustScore: v.number(),
          version: v.string(),
          hasKnownVulnerabilities: v.boolean(),
        }),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) return null

    // Walk the 20 most recent snapshots (bounded for transaction safety)
    const snapshots = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(20)

    if (snapshots.length === 0) return null

    const normalizedSearch = normalizePackageName(args.packageName)

    // For each snapshot, find the matching component (in-memory after bounded collect)
    const historyPoints: Array<{
      snapshotId: (typeof snapshots)[number]['_id']
      commitSha: string
      capturedAt: number
      trustScore: number
      version: string
      hasKnownVulnerabilities: boolean
    }> = []

    for (const snapshot of snapshots) {
      const components = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
        .collect()
      const match = components.find(
        (c) => c.normalizedName === normalizedSearch || c.name === args.packageName,
      )
      if (match) {
        historyPoints.push({
          snapshotId: snapshot._id,
          commitSha: snapshot.commitSha,
          capturedAt: snapshot.capturedAt,
          trustScore: match.trustScore,
          version: match.version,
          hasKnownVulnerabilities: match.hasKnownVulnerabilities,
        })
      }
    }

    if (historyPoints.length === 0) return null

    // Return in chronological order (oldest first) for time-series display
    historyPoints.reverse()

    return { packageName: args.packageName, history: historyPoints }
  },
})

// ---------------------------------------------------------------------------
// attackSurfaceComponents — all tracked SBOM components for the latest snapshot,
// sorted by risk (vulnerable first, then by trustScore ascending, then by layer).
//
// Wraps GET /api/attack-surface/components — spec §7.1.
// ---------------------------------------------------------------------------

export const attackSurfaceComponents = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      snapshotId: v.id('sbomSnapshots'),
      commitSha: v.string(),
      capturedAt: v.number(),
      totalComponents: v.number(),
      vulnerableCount: v.number(),
      untrustedCount: v.number(),
      components: v.array(
        v.object({
          name: v.string(),
          version: v.string(),
          ecosystem: v.string(),
          layer: v.string(),
          isDirect: v.boolean(),
          trustScore: v.number(),
          hasKnownVulnerabilities: v.boolean(),
          license: v.optional(v.string()),
          sourceFile: v.string(),
        }),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) return null

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
    if (!latestSnapshot) return null

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .collect()

    // Sort: vulnerable first, then untrusted (trustScore < 40), then by ascending trustScore
    const sorted = [...components].sort((a, b) => {
      if (a.hasKnownVulnerabilities !== b.hasKnownVulnerabilities) {
        return a.hasKnownVulnerabilities ? -1 : 1
      }
      return a.trustScore - b.trustScore
    })

    return {
      snapshotId: latestSnapshot._id,
      commitSha: latestSnapshot.commitSha,
      capturedAt: latestSnapshot.capturedAt,
      totalComponents: latestSnapshot.totalComponents,
      vulnerableCount: components.filter((c) => c.hasKnownVulnerabilities).length,
      untrustedCount: components.filter((c) => c.trustScore < 40).length,
      components: sorted.map((c) => ({
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        isDirect: c.isDirect,
        trustScore: c.trustScore,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
        license: c.license,
        sourceFile: c.sourceFile,
      })),
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
