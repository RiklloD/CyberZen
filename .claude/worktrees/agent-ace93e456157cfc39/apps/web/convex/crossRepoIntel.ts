import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, query } from './_generated/server'
import type { Id } from './_generated/dataModel'
import {
  computeCrossRepoImpact,
  normalizeForCrossRepo,
  type RepositorySnapshot,
} from './lib/crossRepoImpact'

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

/**
 * Runs cross-repository impact detection for a newly created finding.
 *
 * For every other repository in the tenant, loads its latest SBOM snapshot
 * and checks whether the disclosed package is present.  The result is
 * upserted into `crossRepoImpactEvents` keyed by (tenantId, normalizedPackageName)
 * so re-ingesting the same advisory updates the record rather than duplicating it.
 *
 * Called fire-and-forget from `ingestCanonicalDisclosure` in events.ts.
 */
export const computeAndStoreCrossRepoImpact = internalMutation({
  args: {
    sourceFindingId: v.id('findings'),
    sourceRepositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    packageName: v.string(),
    ecosystem: v.string(),
    severity,
    findingTitle: v.string(),
  },
  handler: async (ctx, args) => {
    // Load all repositories for this tenant
    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', args.tenantId))
      .collect()

    // Exclude the source repository — it already has the finding
    const otherRepos = repositories.filter(
      (r) => r._id !== args.sourceRepositoryId,
    )

    // Build SBOM snapshots for each other repository
    const repositorySnapshots: RepositorySnapshot[] = []

    for (const repo of otherRepos) {
      const latestSnapshot = await ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_captured_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      if (!latestSnapshot) {
        // No snapshot yet — include the repo with an empty inventory so the
        // total count is accurate, but it won't match anything
        repositorySnapshots.push({
          repositoryId: repo._id,
          repositoryName: repo.name,
          components: [],
        })
        continue
      }

      const components = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) =>
          q.eq('snapshotId', latestSnapshot._id),
        )
        .collect()

      repositorySnapshots.push({
        repositoryId: repo._id,
        repositoryName: repo.name,
        components: components.map((c) => ({
          name: c.name,
          normalizedName: c.normalizedName,
          ecosystem: c.ecosystem,
          version: c.version,
          isDirect: c.isDirect,
        })),
      })
    }

    const result = computeCrossRepoImpact({
      packageName: args.packageName,
      ecosystem: args.ecosystem,
      severity: args.severity,
      findingTitle: args.findingTitle,
      repositorySnapshots,
    })

    const normalizedPackageName = normalizeForCrossRepo(args.packageName)
    const now = Date.now()

    // Upsert: check for an existing event for this package in this tenant
    const existing = await ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_tenant_and_normalized_package', (q) =>
        q
          .eq('tenantId', args.tenantId)
          .eq('normalizedPackageName', normalizedPackageName),
      )
      .first()

    const affectedRepositoryIds = result.affectedRepositories.map(
      (i) => i.repositoryId as Id<'repositories'>,
    )
    const affectedRepositoryNames = result.affectedRepositories.map(
      (i) => i.repositoryName,
    )
    const impacts = result.affectedRepositories.map((i) => ({
      repositoryId: i.repositoryId as Id<'repositories'>,
      repositoryName: i.repositoryName,
      directMatchCount: i.directMatchCount,
      transitiveMatchCount: i.transitiveMatchCount,
      matchedVersions: i.matchedVersions,
    }))

    if (existing) {
      await ctx.db.patch(existing._id, {
        sourceFindingId: args.sourceFindingId,
        sourceRepositoryId: args.sourceRepositoryId,
        severity: args.severity,
        totalRepositories: result.totalRepositories,
        affectedRepositoryCount: result.affectedRepositoryCount,
        affectedRepositoryIds,
        affectedRepositoryNames,
        impacts,
        summary: result.summary,
        computedAt: now,
      })
    } else {
      await ctx.db.insert('crossRepoImpactEvents', {
        packageName: args.packageName,
        normalizedPackageName,
        ecosystem: args.ecosystem,
        severity: args.severity,
        sourceFindingId: args.sourceFindingId,
        sourceRepositoryId: args.sourceRepositoryId,
        tenantId: args.tenantId,
        totalRepositories: result.totalRepositories,
        affectedRepositoryCount: result.affectedRepositoryCount,
        affectedRepositoryIds,
        affectedRepositoryNames,
        impacts,
        summary: result.summary,
        computedAt: now,
      })
    }

    // fire-and-forget: re-evaluate severity escalation now that cross-repo
    // spread data has been updated (affectedRepositoryCount may have grown).
    await ctx.scheduler.runAfter(
      0,
      internal.escalationIntel.checkAndEscalateFinding,
      { findingId: args.sourceFindingId },
    )

    return {
      totalRepositories: result.totalRepositories,
      affectedRepositoryCount: result.affectedRepositoryCount,
    }
  },
})

/**
 * Returns the cross-repo impact record for the finding that triggered the
 * most recent scan for a given package.
 */
export const getCrossRepoImpact = query({
  args: {
    sourceFindingId: v.id('findings'),
  },
  handler: async (ctx, args) => {
    return ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_source_finding', (q) =>
        q.eq('sourceFindingId', args.sourceFindingId),
      )
      .first()
  },
})

/**
 * Returns the N most recent cross-repo impact events for a tenant.
 * Packages with multi-repo spread are surfaced first (by recency).
 */
export const getTenantCrossRepoSummary = query({
  args: {
    tenantId: v.id('tenants'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = args.limit ?? 20

    const events = await ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', args.tenantId),
      )
      .order('desc')
      .take(limit)

    const totalAffectedRepoSlots = events.reduce(
      (sum, e) => sum + e.affectedRepositoryCount,
      0,
    )

    const packagesWithSpread = events.filter(
      (e) => e.affectedRepositoryCount > 0,
    ).length

    return {
      events,
      totalPackagesTracked: events.length,
      totalAffectedRepoSlots,
      packagesWithSpread,
    }
  },
})

/**
 * Slug-based variant for the HTTP handler — looks up a tenant by slug and
 * returns the cross-repo impact record for the specified package name.
 */
export const getCrossRepoImpactBySlug = query({
  args: {
    tenantSlug: v.string(),
    packageName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const normalizedPackageName = normalizeForCrossRepo(args.packageName)

    return ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_tenant_and_normalized_package', (q) =>
        q
          .eq('tenantId', tenant._id)
          .eq('normalizedPackageName', normalizedPackageName),
      )
      .first()
  },
})

/**
 * Tenant-level summary via slug — used by the global dashboard panel.
 */
export const getTenantCrossRepoSummaryBySlug = query({
  args: {
    tenantSlug: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const limit = args.limit ?? 20

    const events = await ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(limit)

    const totalAffectedRepoSlots = events.reduce(
      (sum, e) => sum + e.affectedRepositoryCount,
      0,
    )

    const packagesWithSpread = events.filter(
      (e) => e.affectedRepositoryCount > 0,
    ).length

    return {
      events,
      totalPackagesTracked: events.length,
      totalAffectedRepoSlots,
      packagesWithSpread,
    }
  },
})
