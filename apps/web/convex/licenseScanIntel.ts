/**
 * WS-48 — License Compliance & Risk Scanner: Convex entrypoints.
 *
 * Scans SBOM component license declarations for legal and commercial risk
 * using a static 70-entry SPDX database. Complements WS-31's policy-based
 * engine with a more granular risk taxonomy:
 *
 *   strong_copyleft   (GPL-2.0/3.0, AGPL-3.0, SSPL-1.0) → critical
 *   weak_copyleft     (LGPL, MPL-2.0, EPL, CDDL)         → high
 *   proprietary_restricted (BUSL-1.1, Elastic-2.0)        → high
 *   unknown / unrecognised license                         → medium
 *
 * Scheduled with runAfter(0) immediately after SBOM snapshot ingestion
 * so the license breakdown is available in the same dashboard load.
 *
 * Entrypoints:
 *   recordLicenseComplianceScan               — internalMutation: scan + persist
 *   triggerLicenseComplianceScanForRepository — public mutation: on-demand trigger
 *   getLatestLicenseComplianceScan            — public query: most recent result
 *   getLicenseComplianceScanHistory           — public query: last 30 lean summaries
 *   getLicenseComplianceScanSummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeLicenseCompliance } from './lib/licenseComplianceScanner'

// ---------------------------------------------------------------------------
// recordLicenseComplianceScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot for a repository, run the SPDX-based license
 * risk scanner over all components, and persist the result.
 * Prunes old rows to 30 per repository.
 */
export const recordLicenseComplianceScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Load latest SBOM snapshot ─────────────────────────────────────────
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repositoryId),
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
      name: c.name,
      ecosystem: c.ecosystem,
      version: c.version,
      license: c.license ?? null,
    }))

    // ── Run the SPDX-based license risk scanner ───────────────────────────
    const report = computeLicenseCompliance(componentInputs)

    const nowMs = Date.now()

    // ── Persist ───────────────────────────────────────────────────────────
    await ctx.db.insert('licenseComplianceScanResults', {
      tenantId,
      repositoryId,
      findings: report.findings,
      criticalCount: report.criticalCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      totalScanned: report.totalScanned,
      unknownLicenseCount: report.unknownLicenseCount,
      overallRisk: report.overallRisk,
      licenseBreakdown: report.licenseBreakdown,
      summary: report.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('licenseComplianceScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('asc')
      .take(100)

    if (old.length > 30) {
      for (const row of old.slice(0, old.length - 30)) {
        await ctx.db.delete(row._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerLicenseComplianceScanForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand license scan trigger. Resolves by tenant slug + repo full name. */
export const triggerLicenseComplianceScanForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), args.repositoryFullName),
        ),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.licenseScanIntel.recordLicenseComplianceScan,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestLicenseComplianceScan — public query
// ---------------------------------------------------------------------------

/** Return the most recent SPDX-based license scan for a repository. */
export const getLatestLicenseComplianceScan = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return null

    return ctx.db
      .query('licenseComplianceScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLicenseComplianceScanHistory — lean public query
// ---------------------------------------------------------------------------

/** Return up to 30 recent license scan summaries for trend display. */
export const getLicenseComplianceScanHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return []

    const rows = await ctx.db
      .query('licenseComplianceScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip per-finding description to keep the response lean.
    return rows.map((row) => ({
      ...row,
      findings: row.findings.map(({ description: _d, ...lean }) => lean),
    }))
  },
})

// ---------------------------------------------------------------------------
// getLicenseComplianceScanSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide license risk aggregates: total critical/high counts,
 * most common risky SPDX ID, and the repository with the highest risk.
 */
export const getLicenseComplianceScanSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('licenseComplianceScanResults')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent scan per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const totalCritical = latest.reduce((s, r) => s + r.criticalCount, 0)
    const totalHigh = latest.reduce((s, r) => s + r.highCount, 0)
    const totalUnknown = latest.reduce((s, r) => s + r.unknownLicenseCount, 0)

    // Most common risky SPDX ID across all findings.
    const findingCounts: Record<string, number> = {}
    for (const row of latest) {
      for (const f of row.findings) {
        if (f.riskLevel !== 'none') {
          findingCounts[f.spdxId] = (findingCounts[f.spdxId] ?? 0) + 1
        }
      }
    }
    const mostCommonRiskyLicense =
      Object.entries(findingCounts).sort(([, a], [, b]) => b - a)[0]?.[0] ?? null

    // Repository with the highest risk.
    const RISK_RANK: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      none: 0,
    }
    const highestRisk = latest.reduce<(typeof latest)[0] | null>((acc, r) => {
      if (!acc) return r
      const rRank = RISK_RANK[r.overallRisk] ?? 0
      const accRank = RISK_RANK[acc.overallRisk] ?? 0
      if (rRank > accRank) return r
      if (rRank === accRank && r.criticalCount > acc.criticalCount) return r
      return acc
    }, null)

    return {
      repoCount: latest.length,
      totalCritical,
      totalHigh,
      totalUnknown,
      mostCommonRiskyLicense,
      highestRiskRepositoryId: highestRisk?.repositoryId ?? null,
      highestRiskLevel: highestRisk?.overallRisk ?? null,
    }
  },
})
