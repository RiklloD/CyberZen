// WS-32 — SBOM Quality & Completeness Scoring: Convex entrypoints.
//
//   computeAndStoreSbomQuality       — internal mutation: evaluates the latest
//       SBOM snapshot for a repository and stores the quality result.
//
//   getSbomQualityForRepository      — public query: latest result for a repo
//       resolved via tenantSlug + repositoryFullName.
//
//   getSbomQualityHistory            — public query: lean last-N results
//       (just scores + grade + computedAt) for sparklines.
//
//   getSbomQualitySummaryByTenant    — public query: tenant-wide aggregate.

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeSbomQuality } from './lib/sbomQuality'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SNAPSHOTS_PER_REPO = 30

// ---------------------------------------------------------------------------
// computeAndStoreSbomQuality (internal mutation)
// ---------------------------------------------------------------------------

export const computeAndStoreSbomQuality = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    // ── Load latest SBOM snapshot ─────────────────────────────────────────
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    // ── Load components (cap at 500) ──────────────────────────────────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .take(500)

    const componentInputs = components.map((c) => ({
      version: c.version,
      license: c.license ?? null,
      isDirect: c.isDirect,
      ecosystem: c.ecosystem,
      layer: c.layer,
    }))

    const snapshotInput = {
      capturedAt: snapshot.capturedAt,
      directDependencyCount: snapshot.directDependencyCount,
      transitiveDependencyCount: snapshot.transitiveDependencyCount,
      buildDependencyCount: snapshot.buildDependencyCount,
      containerDependencyCount: snapshot.containerDependencyCount,
      runtimeDependencyCount: snapshot.runtimeDependencyCount,
      aiModelDependencyCount: snapshot.aiModelDependencyCount,
      totalComponents: snapshot.totalComponents,
      sourceFiles: snapshot.sourceFiles,
    }

    // ── Compute quality ───────────────────────────────────────────────────
    const result = computeSbomQuality(snapshotInput, componentInputs)

    const now = Date.now()
    await ctx.db.insert('sbomQualitySnapshots', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: snapshot._id,
      overallScore: result.overallScore,
      grade: result.grade,
      completenessScore: result.completenessScore,
      versionPinningScore: result.versionPinningScore,
      licenseResolutionScore: result.licenseResolutionScore,
      freshnessScore: result.freshnessScore,
      layerCoverageScore: result.layerCoverageScore,
      totalComponents: result.totalComponents,
      exactVersionCount: result.exactVersionCount,
      versionPinningRate: result.versionPinningRate,
      licensedCount: result.licensedCount,
      licenseResolutionRate: result.licenseResolutionRate,
      daysSinceCapture: result.daysSinceCapture,
      layersPopulated: result.layersPopulated,
      summary: result.summary,
      computedAt: now,
    })

    // ── Prune old rows ────────────────────────────────────────────────────
    const allRows = await ctx.db
      .query('sbomQualitySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (allRows.length > MAX_SNAPSHOTS_PER_REPO) {
      const toDelete = allRows.slice(MAX_SNAPSHOTS_PER_REPO)
      await Promise.all(toDelete.map((row) => ctx.db.delete(row._id)))
    }

    return {
      overallScore: result.overallScore,
      grade: result.grade,
      totalComponents: result.totalComponents,
    }
  },
})

// ---------------------------------------------------------------------------
// triggerSbomQualityForRepository (public mutation)
// ---------------------------------------------------------------------------

export const triggerSbomQualityForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.sbomQualityIntel.computeAndStoreSbomQuality,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getSbomQualityForRepository (public query)
// ---------------------------------------------------------------------------

export const getSbomQualityForRepository = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) return null

    return ctx.db
      .query('sbomQualitySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSbomQualityHistory (public query)
// ---------------------------------------------------------------------------

export const getSbomQualityHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 20, 30)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()
    if (!repository) return []

    const rows = await ctx.db
      .query('sbomQualitySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      overallScore: r.overallScore,
      grade: r.grade,
      completenessScore: r.completenessScore,
      versionPinningScore: r.versionPinningScore,
      licenseResolutionScore: r.licenseResolutionScore,
      freshnessScore: r.freshnessScore,
      layerCoverageScore: r.layerCoverageScore,
      totalComponents: r.totalComponents,
      summary: r.summary,
      computedAt: r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getSbomQualitySummaryByTenant (public query)
// ---------------------------------------------------------------------------

export const getSbomQualitySummaryByTenant = query({
  args: {
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const rows = await ctx.db
      .query('sbomQualitySnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Latest per repo
    const latestByRepo = new Map<string, (typeof rows)[0]>()
    for (const row of rows) {
      if (!latestByRepo.has(row.repositoryId)) latestByRepo.set(row.repositoryId, row)
    }

    const latest = [...latestByRepo.values()]
    const excellentCount = latest.filter((r) => r.grade === 'excellent').length
    const goodCount = latest.filter((r) => r.grade === 'good').length
    const fairCount = latest.filter((r) => r.grade === 'fair').length
    const poorCount = latest.filter((r) => r.grade === 'poor').length
    const avgScore =
      latest.length > 0
        ? Math.round(latest.reduce((s, r) => s + r.overallScore, 0) / latest.length)
        : 0

    return {
      totalRepositoriesScanned: latest.length,
      excellentCount,
      goodCount,
      fairCount,
      poorCount,
      avgQualityScore: avgScore,
    }
  },
})
