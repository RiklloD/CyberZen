// WS-31 — Dependency License Compliance Engine: Convex entrypoints.
//
//   refreshLicenseCompliance        — internal mutation: evaluates the latest
//       SBOM snapshot for a repository and stores the compliance result.
//
//   refreshLicenseComplianceForRepository — public mutation: on-demand /
//       webhook trigger by tenantSlug + repositoryFullName.
//
//   getLatestLicenseCompliance      — public query: latest result for a repo
//       resolved via tenantSlug + repositoryFullName.
//
//   getLicenseComplianceHistory     — public query: lean last-N results
//       (violations stripped) for sparklines.
//
//   getLicenseComplianceSummaryByTenant — public query: tenant-wide aggregate.

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeLicenseCompliance } from './lib/licenseCompliance'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SNAPSHOTS_PER_REPO = 30

// ---------------------------------------------------------------------------
// refreshLicenseCompliance (internal mutation)
// ---------------------------------------------------------------------------

export const refreshLicenseCompliance = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    // ── Load latest SBOM snapshot ─────────────────────────────────────────
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) => q.eq('repositoryId', args.repositoryId))
      .order('desc')
      .first()

    if (!snapshot) return null

    // ── Load components (cap at 500) ──────────────────────────────────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .take(500)

    const componentInputs = components.map((c) => ({
      name: c.name,
      ecosystem: c.ecosystem,
      knownLicense: c.license ?? undefined,
    }))

    // ── Compute compliance ────────────────────────────────────────────────
    const result = computeLicenseCompliance(componentInputs)

    // Keep only blocked + warned components as violations (cap at 20 for doc size)
    const violations = result.components
      .filter((c) => c.outcome === 'blocked' || c.outcome === 'warn')
      .slice(0, 20)
      .map((c) => ({
        name: c.name,
        ecosystem: c.ecosystem,
        resolvedLicense: c.resolvedLicense,
        category: c.category,
        outcome: c.outcome as 'blocked' | 'warn',
        source: c.source,
      }))

    const now = Date.now()
    await ctx.db.insert('licenseComplianceSnapshots', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: snapshot._id,
      totalComponents: components.length,
      blockedCount: result.blockedCount,
      warnCount: result.warnCount,
      allowedCount: result.allowedCount,
      unknownCount: result.unknownCount,
      complianceScore: result.complianceScore,
      overallLevel: result.overallLevel,
      violations,
      summary: result.summary,
      computedAt: now,
    })

    // ── Prune old rows ────────────────────────────────────────────────────
    const allRows = await ctx.db
      .query('licenseComplianceSnapshots')
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
      complianceScore: result.complianceScore,
      overallLevel: result.overallLevel,
      blockedCount: result.blockedCount,
      totalComponents: components.length,
    }
  },
})

// ---------------------------------------------------------------------------
// refreshLicenseComplianceForRepository (public mutation)
// ---------------------------------------------------------------------------

export const refreshLicenseComplianceForRepository = mutation({
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
      internal.licenseComplianceIntel.refreshLicenseCompliance,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestLicenseCompliance (public query)
// ---------------------------------------------------------------------------

export const getLatestLicenseCompliance = query({
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
      .query('licenseComplianceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLicenseComplianceHistory (public query)
// ---------------------------------------------------------------------------

export const getLicenseComplianceHistory = query({
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
      .query('licenseComplianceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      complianceScore: r.complianceScore,
      overallLevel: r.overallLevel,
      blockedCount: r.blockedCount,
      warnCount: r.warnCount,
      totalComponents: r.totalComponents,
      summary: r.summary,
      computedAt: r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getLicenseComplianceSummaryByTenant (public query)
// ---------------------------------------------------------------------------

export const getLicenseComplianceSummaryByTenant = query({
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
      .query('licenseComplianceSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Latest per repo
    const latestByRepo = new Map<string, (typeof rows)[0]>()
    for (const row of rows) {
      if (!latestByRepo.has(row.repositoryId)) latestByRepo.set(row.repositoryId, row)
    }

    const latest = [...latestByRepo.values()]
    const nonCompliantCount = latest.filter((r) => r.overallLevel === 'non_compliant').length
    const cautionCount = latest.filter((r) => r.overallLevel === 'caution').length
    const totalBlocked = latest.reduce((s, r) => s + r.blockedCount, 0)
    const totalWarn = latest.reduce((s, r) => s + r.warnCount, 0)
    const avgScore =
      latest.length > 0
        ? Math.round(latest.reduce((s, r) => s + r.complianceScore, 0) / latest.length)
        : 100

    return {
      totalRepositoriesScanned: latest.length,
      nonCompliantCount,
      cautionCount,
      compliantCount: latest.length - nonCompliantCount - cautionCount,
      totalBlocked,
      totalWarn,
      avgComplianceScore: avgScore,
    }
  },
})
