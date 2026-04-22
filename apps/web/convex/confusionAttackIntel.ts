/**
 * WS-41 — Dependency Confusion Attack Detector: Convex entrypoints.
 *
 * Persists per-SBOM-ingest confusion attack scan results using the pure-library
 * scanner in `lib/confusionAttackDetection.ts`. Triggered fire-and-forget from
 * `sbom.ts` after the EOL scan.
 *
 * Entrypoints:
 *   recordConfusionScan                 — internalMutation: scan all components, persist result
 *   triggerConfusionScanForRepository   — public mutation: on-demand re-scan by slug+fullName
 *   getLatestConfusionScan              — public query: most recent result for a repository
 *   getConfusionScanHistory             — public query: last 30 lean summaries (no findings)
 *   getConfusionSummaryByTenant         — public query: tenant-wide aggregate counts
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeConfusionReport } from './lib/confusionAttackDetection'

// ---------------------------------------------------------------------------
// recordConfusionScan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest SBOM snapshot for the repository, run dependency confusion
 * detection across all components, and persist the result.
 * Prunes old rows to 30 per repository to bound storage growth.
 *
 * Triggered fire-and-forget from `sbom.ingestRepositoryInventory` after the
 * EOL detection scan.
 */
export const recordConfusionScan = internalMutation({
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

    // ── Run confusion attack detection ───────────────────────────────────
    const report = computeConfusionReport(componentInputs)

    const computedAt = Date.now()

    // Cap findings at 50 to keep the stored document size manageable.
    const cappedFindings = report.findings.slice(0, 50).map((f) => ({
      packageName: f.packageName,
      ecosystem: f.ecosystem,
      version: f.version,
      signals: f.signals as string[],
      riskLevel: f.riskLevel as 'critical' | 'high' | 'medium' | 'low',
      title: f.title,
      description: f.description,
      evidence: f.evidence,
    }))

    await ctx.db.insert('confusionAttackScanResults', {
      tenantId,
      repositoryId,
      totalSuspicious: report.totalSuspicious,
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
      .query('confusionAttackScanResults')
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
// triggerConfusionScanForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand confusion attack re-scan trigger. Resolves tenant + repository by
 * slug and full name, then schedules the internal mutation.
 */
export const triggerConfusionScanForRepository = mutation({
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

    await ctx.scheduler.runAfter(0, internal.confusionAttackIntel.recordConfusionScan, {
      tenantId: tenant._id,
      repositoryId: repository._id,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestConfusionScan — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent confusion attack scan result for a repository,
 * resolved by tenant slug + repository full name.
 */
export const getLatestConfusionScan = query({
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
      .query('confusionAttackScanResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getConfusionScanHistory — lean public query (no findings)
// ---------------------------------------------------------------------------

/**
 * Return up to 30 recent confusion attack scan summaries for a repository.
 * Findings arrays are stripped to keep the payload small.
 */
export const getConfusionScanHistory = query({
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
      .query('confusionAttackScanResults')
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
// getConfusionSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide confusion attack aggregates: critical/high/medium repo
 * counts, total suspicious package count, and most-recently-flagged package.
 */
export const getConfusionSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('confusionAttackScanResults')
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
    const totalSuspiciousPackages = latest.reduce((s, r) => s + r.totalSuspicious, 0)

    // Surface the most recently flagged package name for quick visibility.
    let mostRecentFlag: string | null = null
    for (const row of latest) {
      if (row.findings.length > 0) {
        mostRecentFlag = row.findings[0].packageName
        break
      }
    }

    return {
      criticalRepos,
      highRepos,
      mediumRepos,
      cleanRepos,
      totalSuspiciousPackages,
      mostRecentFlag,
      repoCount: latest.length,
    }
  },
})
