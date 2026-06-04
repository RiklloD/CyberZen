/**
 * WS-43 — Known CVE Version Range Scanner: Convex entrypoints.
 *
 * Persists per-SBOM-ingest CVE scan results using the pure-library scanner in
 * `lib/cveVersionScanner.ts`. Triggered fire-and-forget from `sbom.ts` after
 * the malicious package scan.
 *
 * Provides offline CVE detection with no network calls, covering the ~30
 * highest-impact vulnerabilities developers are most likely to encounter.
 *
 * Entrypoints:
 *   recordCveScan                  — internalMutation: scan all components, persist result
 *   triggerCveScanForRepository    — public mutation: on-demand re-scan by slug+fullName
 *   getLatestCveScan               — public query: most recent result for a repository
 *   getCveScanHistory              — public query: last 30 lean summaries (no findings)
 *   getCveSummaryByTenant          — public query: tenant-wide aggregate counts
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeCveReport } from './lib/cveVersionScanner'

// ---------------------------------------------------------------------------
// recordCveScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot for the repository, run CVE version-range
 * scanning across all components, and persist the result.
 * Prunes old rows to 30 per repository to bound storage growth.
 *
 * Triggered fire-and-forget from `sbom.ingestRepositoryInventory` after the
 * malicious package scan.
 */
export const recordCveScan = internalMutation({
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
      version: c.version,
      ecosystem: c.ecosystem,
    }))

    // ── Run CVE version-range scanning ───────────────────────────────────
    const report = computeCveReport(componentInputs)

    const computedAt = Date.now()

    // Cap findings at 50 to keep the stored document size manageable.
    const cappedFindings = report.findings.slice(0, 50).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      cveId: f.cveId,
      cvss: f.cvss,
      minimumSafeVersion: f.minimumSafeVersion,
      riskLevel: f.riskLevel as 'critical' | 'high' | 'medium' | 'low',
      description: f.description,
      evidence: f.evidence,
    }))

    await ctx.db.insert('cveVersionScanResults', {
      tenantId,
      repositoryId,
      totalVulnerable: report.totalVulnerable,
      criticalCount: report.criticalCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      overallRisk: report.overallRisk,
      findings: cappedFindings,
      summary: report.summary,
      computedAt,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('cveVersionScanResults')
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
// triggerCveScanForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand CVE re-scan trigger. Resolves tenant + repository by slug and
 * full name, then schedules the internal mutation.
 */
export const triggerCveScanForRepository = mutation({
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

    await ctx.scheduler.runAfter(0, internal.cveVersionScanIntel.recordCveScan, {
      tenantId: tenant._id,
      repositoryId: repository._id,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestCveScan — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent CVE scan result for a repository,
 * resolved by tenant slug + repository full name.
 */
export const getLatestCveScan = query({
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
      .query('cveVersionScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getCveScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/**
 * Return up to 30 recent CVE scan summaries for a repository.
 * Findings arrays are stripped to keep the payload small.
 */
export const getCveScanHistory = query({
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
      .query('cveVersionScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip findings to keep the response lean.
    return rows.map(({ findings: _f, ...lean }) => lean)
  },
})

// ---------------------------------------------------------------------------
// getCveSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide CVE aggregates: repos with critical/high findings,
 * total vulnerable component count, and the highest-CVSS CVE seen for
 * quick dashboard visibility.
 */
export const getCveSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('cveVersionScanResults')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent result per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const criticalRepos = latest.filter((r) => r.overallRisk === 'critical').length
    const highRepos = latest.filter((r) => r.overallRisk === 'high').length
    const mediumRepos = latest.filter((r) => r.overallRisk === 'medium').length
    const cleanRepos = latest.filter((r) => r.overallRisk === 'none').length
    const totalVulnerableComponents = latest.reduce((s, r) => s + r.totalVulnerable, 0)

    // Surface the highest-CVSS CVE across all repos for quick triage.
    let topCveId: string | null = null
    let topCvss = 0
    for (const row of latest) {
      for (const f of row.findings) {
        if (f.cvss > topCvss) {
          topCvss = f.cvss
          topCveId = f.cveId
        }
      }
    }

    return {
      criticalRepos,
      highRepos,
      mediumRepos,
      cleanRepos,
      totalVulnerableComponents,
      topCveId,
      topCvss: topCvss > 0 ? topCvss : null,
      repoCount: latest.length,
    }
  },
})
