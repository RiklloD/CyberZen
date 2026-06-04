/**
 * WS-47 — Compliance Gap Remediation Planner: Convex entrypoints.
 *
 * Reads the latest persisted WS-46 compliance attestation, flattens all
 * control gaps across every active framework, and maps each gap to a
 * concrete, step-by-step remediation playbook using the REMEDIATION_CATALOG.
 *
 * Effort estimates are root-cause-deduplicated so that the same underlying
 * weakness appearing across multiple frameworks (e.g. CC6.7, Art.32, HIPAA)
 * is counted only once in `estimatedTotalDays`.
 *
 * Scheduled with a 7-second delay from sbom.ingestRepositoryInventory so that
 * WS-46 (scheduled at 5 s) has had time to write before this reads.
 *
 * Entrypoints:
 *   recordComplianceRemediationPlan               — internalMutation: compute + persist
 *   triggerComplianceRemediationPlanForRepository — public mutation: on-demand trigger
 *   getLatestComplianceRemediationPlan            — public query: most recent result
 *   getComplianceRemediationPlanHistory           — public query: last 30 lean summaries
 *   getComplianceRemediationPlanSummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeRemediationPlan } from './lib/complianceRemediationPlanner'
import type { ControlGap } from './lib/complianceAttestationReport'

// ---------------------------------------------------------------------------
// recordComplianceRemediationPlan — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest WS-46 attestation, flatten all control gaps from all
 * frameworks, compute the remediation plan, and persist. Prunes to 30 per repo.
 */
export const recordComplianceRemediationPlan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Load the latest WS-46 attestation ────────────────────────────────────
    const attestation = await ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    // If no attestation exists yet (race condition on first run), bail gracefully.
    if (!attestation) return

    // ── Flatten control gaps from all frameworks ──────────────────────────────
    const allGaps: ControlGap[] = attestation.frameworks.flatMap(
      (fw) => fw.controlGaps,
    )

    // ── Compute the remediation plan ─────────────────────────────────────────
    const plan = computeRemediationPlan(allGaps)

    const nowMs = Date.now()

    // ── Persist ───────────────────────────────────────────────────────────────
    await ctx.db.insert('complianceRemediationSnapshots', {
      tenantId,
      repositoryId,
      actions: plan.actions,
      totalActions: plan.totalActions,
      criticalActions: plan.criticalActions,
      highActions: plan.highActions,
      mediumActions: plan.mediumActions,
      lowActions: plan.lowActions,
      automatableActions: plan.automatableActions,
      requiresPolicyDocCount: plan.requiresPolicyDocCount,
      estimatedTotalDays: plan.estimatedTotalDays,
      summary: plan.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────────
    const old = await ctx.db
      .query('complianceRemediationSnapshots')
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
// triggerComplianceRemediationPlanForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand remediation plan trigger. Resolves by tenant slug + repo full name. */
export const triggerComplianceRemediationPlanForRepository = mutation({
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
      internal.complianceRemediationIntel.recordComplianceRemediationPlan,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestComplianceRemediationPlan — public query
// ---------------------------------------------------------------------------

/** Return the most recent remediation plan snapshot for a repository. */
export const getLatestComplianceRemediationPlan = query({
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
      .query('complianceRemediationSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getComplianceRemediationPlanHistory — lean public query (no step details)
// ---------------------------------------------------------------------------

/** Return up to 30 recent remediation plan summaries for trend/sparkline display. */
export const getComplianceRemediationPlanHistory = query({
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
      .query('complianceRemediationSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip per-action steps to keep the response lean.
    return rows.map((row) => ({
      ...row,
      actions: row.actions.map(({ steps: _s, ...lean }) => lean),
    }))
  },
})

// ---------------------------------------------------------------------------
// getComplianceRemediationPlanSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide remediation effort aggregates: total actions, automated
 * actions, total estimated days, and the repository with the most critical actions.
 */
export const getComplianceRemediationPlanSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('complianceRemediationSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent snapshot per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const totalActions = latest.reduce((s, r) => s + r.totalActions, 0)
    const totalCriticalActions = latest.reduce((s, r) => s + r.criticalActions, 0)
    const totalAutomatableActions = latest.reduce((s, r) => s + r.automatableActions, 0)
    const totalEstimatedDays = latest.reduce((s, r) => s + r.estimatedTotalDays, 0)

    // The most critical repository (most critical actions; tie-break by most total).
    const mostCritical = latest.reduce<(typeof latest)[0] | null>((acc, r) => {
      if (!acc) return r
      if (r.criticalActions > acc.criticalActions) return r
      if (r.criticalActions === acc.criticalActions && r.totalActions > acc.totalActions) return r
      return acc
    }, null)

    return {
      repoCount: latest.length,
      totalActions,
      totalCriticalActions,
      totalAutomatableActions,
      totalEstimatedDays,
      mostCriticalRepositoryId: mostCritical?.repositoryId ?? null,
      mostCriticalActions: mostCritical?.criticalActions ?? 0,
    }
  },
})
