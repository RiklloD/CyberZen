/**
 * WS-52 — Security Debt Velocity Tracker: Convex entrypoints.
 *
 * Computes a point-in-time security debt snapshot for a repository by reading
 * all its findings, then running the pure-library velocity scorer. Triggered
 * fire-and-forget from `events.ts` after each finding is created/updated, and
 * exposed as a public mutation for on-demand recomputation.
 *
 * Entrypoints:
 *   computeAndStoreSecurityDebt         — internalMutation: load findings, compute, persist
 *   triggerSecurityDebtForRepository    — public mutation: on-demand trigger by slug+fullName
 *   getLatestSecurityDebt               — public query: most recent snapshot for a repository
 *   getSecurityDebtHistory              — public query: last 30 lean summaries (no per-finding data)
 *   getSecurityDebtSummaryByTenant      — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeSecurityDebtVelocity, type FindingInput } from './lib/securityDebtVelocity'

const WINDOW_DAYS = 30
const MAX_FINDINGS = 2000  // cap to avoid query timeout on large repos
const MAX_ROWS_PER_REPO = 30

// ---------------------------------------------------------------------------
// computeAndStoreSecurityDebt — internalMutation
// ---------------------------------------------------------------------------

export const computeAndStoreSecurityDebt = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { tenantId, repositoryId }) => {
    // ── Load findings ──────────────────────────────────────────────────────
    const rawFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(MAX_FINDINGS)

    const findings: FindingInput[] = rawFindings.map((f) => ({
      createdAt: f.createdAt,
      resolvedAt: f.resolvedAt,
      severity: f.severity,
      status: f.status,
    }))

    // ── Compute velocity snapshot ──────────────────────────────────────────
    const now = Date.now()
    const result = computeSecurityDebtVelocity(findings, now, WINDOW_DAYS)

    // ── Persist ───────────────────────────────────────────────────────────
    await ctx.db.insert('securityDebtSnapshots', {
      tenantId,
      repositoryId,
      windowDays: result.windowDays,
      newFindingsInWindow: result.newFindingsInWindow,
      resolvedFindingsInWindow: result.resolvedFindingsInWindow,
      netVelocityPerDay: result.netVelocityPerDay,
      newPerDay: result.newPerDay,
      resolvedPerDay: result.resolvedPerDay,
      openFindings: result.openFindings,
      openCritical: result.openCritical,
      openHigh: result.openHigh,
      overdueFindings: result.overdueFindings,
      overdueCritical: result.overdueCritical,
      trend: result.trend,
      projectedClearanceDays: result.projectedClearanceDays,
      debtScore: result.debtScore,
      summary: result.summary,
      computedAt: now,
    })

    // ── Prune old rows ────────────────────────────────────────────────────
    const all = await ctx.db
      .query('securityDebtSnapshots')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .collect()
    if (all.length > MAX_ROWS_PER_REPO) {
      for (const old of all.slice(MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(old._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerSecurityDebtForRepository — public mutation
// ---------------------------------------------------------------------------

export const triggerSecurityDebtForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repository) return

    await ctx.scheduler.runAfter(0, internal.securityDebtIntel.computeAndStoreSecurityDebt, {
      tenantId: tenant._id,
      repositoryId: repository._id,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestSecurityDebt — public query
// ---------------------------------------------------------------------------

export const getLatestSecurityDebt = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('securityDebtSnapshots')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSecurityDebtHistory — public query (lean — no per-finding data)
// ---------------------------------------------------------------------------

export const getSecurityDebtHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('securityDebtSnapshots')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      _id: r._id,
      debtScore: r.debtScore,
      trend: r.trend,
      openFindings: r.openFindings,
      overdueFindings: r.overdueFindings,
      netVelocityPerDay: r.netVelocityPerDay,
      computedAt: r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getLatestSecurityDebtBySlug — public query (slug-based, for dashboard)
// ---------------------------------------------------------------------------

export const getLatestSecurityDebtBySlug = query({
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
      .query('securityDebtSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getSecurityDebtSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getSecurityDebtSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    // Gather one snapshot per repository (the most recent)
    const allSnapshots = await ctx.db
      .query('securityDebtSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(500)

    // Deduplicate to one per repository
    const seenRepos = new Set<string>()
    const latest: typeof allSnapshots = []
    for (const snap of allSnapshots) {
      const key = snap.repositoryId
      if (!seenRepos.has(key)) {
        seenRepos.add(key)
        latest.push(snap)
      }
    }

    const improvingCount = latest.filter((s) => s.trend === 'improving').length
    const stableCount = latest.filter((s) => s.trend === 'stable').length
    const degradingCount = latest.filter((s) => s.trend === 'degrading').length
    const criticalCount = latest.filter((s) => s.trend === 'critical').length
    const totalOverdue = latest.reduce((acc, s) => acc + s.overdueFindings, 0)
    const totalOpenCritical = latest.reduce((acc, s) => acc + s.openCritical, 0)
    const avgDebtScore =
      latest.length > 0
        ? Math.round(latest.reduce((acc, s) => acc + s.debtScore, 0) / latest.length)
        : 100

    // Worst repository by debt score
    const worstRepo = latest.length > 0
      ? latest.reduce((a, b) => (a.debtScore < b.debtScore ? a : b))
      : null

    return {
      repositoriesTracked: latest.length,
      improvingCount,
      stableCount,
      degradingCount,
      criticalCount,
      totalOverdue,
      totalOpenCritical,
      avgDebtScore,
      worstRepositoryId: worstRepo?.repositoryId ?? null,
      worstDebtScore: worstRepo?.debtScore ?? null,
    }
  },
})
