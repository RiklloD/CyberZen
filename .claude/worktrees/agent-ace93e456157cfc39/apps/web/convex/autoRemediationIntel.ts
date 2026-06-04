// WS-23 — Autonomous Remediation Dispatch
//
// Selects findings from the prioritised remediation queue that meet the
// configured policy thresholds and schedules `proposeFix` for each one.
// All PR generation is fire-and-forget via the scheduler so GitHub API calls
// remain outside the mutation's transaction boundary.
//
// Design:
//   • Opt-in    — DEFAULT_AUTO_REMEDIATION_POLICY has enabled=false; no work
//                 is done unless an operator has enabled the policy.
//   • Capped    — maxConcurrentPrs prevents CI flooding; open + draft PRs are
//                 counted against the cap before dispatching new ones.
//   • Audited   — every run (even zero-dispatch ones) inserts an immutable
//                 `autoRemediationRuns` row for observability.
//
// Functions:
//   triggerAutoRemediationForRepository  — internalMutation: per-repo dispatch
//   runAllAutoRemediationDispatches      — internalMutation: cron target, fans out
//   getAutoRemediationHistoryForRepository — query: per-repo audit log
//   getAutoRemediationSummaryBySlug      — query: slug-based variant for HTTP handler

import { v } from 'convex/values'
import { api, internal } from './_generated/api'
import type { Id } from './_generated/dataModel'
import { internalMutation, query } from './_generated/server'
import {
  DEFAULT_AUTO_REMEDIATION_POLICY,
  selectRemediationCandidates,
} from './lib/autoRemediation'
import { prioritizeRemediationQueue, type RemediationCandidate } from './lib/remediationPriority'
import { DEFAULT_SLA_POLICY, assessSlaFinding } from './lib/slaPolicy'

// ─── Internal: per-repository dispatch ───────────────────────────────────────

/**
 * Builds the prioritised queue for a single repository, applies the
 * auto-remediation policy, and schedules `proposeFix` for each eligible
 * finding.  Inserts an `autoRemediationRuns` audit row regardless of whether
 * any PRs were dispatched.
 *
 * Short-circuits immediately when the default policy is disabled (opt-in
 * design — no DB reads required when the feature is off).
 */
export const triggerAutoRemediationForRepository = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const policy = DEFAULT_AUTO_REMEDIATION_POLICY

    // Short-circuit when the feature is disabled — no DB work needed.
    if (!policy.enabled) return

    const repository = await ctx.db.get(repositoryId)
    if (!repository) return

    const now = Date.now()

    // ── Collect active findings (open + pr_opened) ────────────────────────────
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'open'),
      )
      .take(200)

    const prOpenedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'pr_opened'),
      )
      .take(100)

    const allFindings = [...openFindings, ...prOpenedFindings]
    if (allFindings.length === 0) return

    // ── Latest blast radius score per finding (newest snapshot wins) ──────────
    const blastSnapshots = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(300)

    const blastRadiusMap = new Map<string, number>()
    for (const snap of blastSnapshots) {
      const key = snap.findingId as string
      if (!blastRadiusMap.has(key)) blastRadiusMap.set(key, snap.businessImpactScore)
    }

    // ── Assemble prioritisation candidates ────────────────────────────────────
    const candidates: RemediationCandidate[] = []

    for (const finding of allFindings) {
      const fid = finding._id as string

      const slaAssessment = assessSlaFinding({
        findingId: fid,
        severity: finding.severity,
        status: finding.status,
        openedAt: finding.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      })

      let exploitAvailable = false
      if (finding.breachDisclosureId) {
        const disclosure = await ctx.db.get(finding.breachDisclosureId)
        exploitAvailable = disclosure?.exploitAvailable ?? false
      }

      candidates.push({
        findingId: fid,
        title: finding.title,
        severity: finding.severity as RemediationCandidate['severity'],
        slaStatus: slaAssessment.slaStatus as RemediationCandidate['slaStatus'],
        blastRadiusScore: blastRadiusMap.get(fid) ?? -1,
        exploitAvailable,
        validationStatus: finding.validationStatus as RemediationCandidate['validationStatus'],
        createdAt: finding.createdAt,
        repositoryName: repository.name,
        affectedPackages: finding.affectedPackages,
      })
    }

    const priorityQueue = prioritizeRemediationQueue(candidates)

    // ── Count currently open/draft PRs against the concurrency cap ───────────
    const openPrs = await ctx.db
      .query('prProposals')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'open'),
      )
      .take(50)

    const draftPrs = await ctx.db
      .query('prProposals')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'draft'),
      )
      .take(50)

    const currentOpenPrCount = openPrs.length + draftPrs.length

    // Build the set of finding IDs that already have an in-flight PR.
    const existingPrFindingIds = new Set<string>([
      ...openPrs.map((p) => p.findingId as string),
      ...draftPrs.map((p) => p.findingId as string),
    ])

    // ── Run the candidate-selection engine ────────────────────────────────────
    const selection = selectRemediationCandidates(
      priorityQueue.map((f) => ({
        findingId: f.findingId,
        title: f.title,
        severity: f.severity,
        priorityTier: f.priorityTier,
        priorityScore: f.priorityScore,
      })),
      existingPrFindingIds,
      currentOpenPrCount,
      policy,
    )

    // ── Schedule proposeFix for each eligible finding ─────────────────────────
    // Fire-and-forget: each proposeFix action handles GitHub API calls outside
    // this mutation's transaction boundary.
    for (const candidate of selection.eligible) {
      const finding = await ctx.db.get(candidate.findingId as Id<'findings'>)
      if (!finding) continue

      await ctx.scheduler.runAfter(0, api.prGeneration.proposeFix, {
        findingId: finding._id,
        workflowRunId: finding.workflowRunId,
        actorId: 'auto-remediation',
      })
    }

    // ── Aggregate skip counts ─────────────────────────────────────────────────
    let skippedAlreadyHasPr = 0
    let skippedBelowTier = 0
    let skippedBelowSeverity = 0
    let skippedConcurrencyCap = 0

    for (const s of selection.skipped) {
      if (s.reason === 'already_has_pr') skippedAlreadyHasPr++
      else if (s.reason === 'below_tier') skippedBelowTier++
      else if (s.reason === 'below_severity') skippedBelowSeverity++
      else if (s.reason === 'concurrency_cap') skippedConcurrencyCap++
    }

    // ── Insert immutable audit row ────────────────────────────────────────────
    await ctx.db.insert('autoRemediationRuns', {
      repositoryId,
      tenantId: repository.tenantId,
      candidateCount: priorityQueue.length,
      dispatchedCount: selection.eligible.length,
      skippedAlreadyHasPr,
      skippedBelowTier,
      skippedBelowSeverity,
      skippedConcurrencyCap,
      dispatchedFindingIds: selection.eligible.map(
        (e) => e.findingId as Id<'findings'>,
      ),
      computedAt: now,
    })
  },
})

// ─── Internal: global dispatch (cron target) ─────────────────────────────────

/**
 * Fans out `triggerAutoRemediationForRepository` for every repository in the
 * system.  Scheduled once per day by the cron scheduler.
 */
export const runAllAutoRemediationDispatches = internalMutation({
  args: {},
  handler: async (ctx) => {
    const repositories = await ctx.db.query('repositories').take(500)

    for (const repo of repositories) {
      await ctx.scheduler.runAfter(
        0,
        internal.autoRemediationIntel.triggerAutoRemediationForRepository,
        { repositoryId: repo._id },
      )
    }
  },
})

// ─── Public queries ───────────────────────────────────────────────────────────

/**
 * Returns the 50 most recent auto-remediation run records for a repository,
 * newest first.  Each row captures how many PRs were dispatched, how many
 * findings were skipped (and why), and which finding IDs were eligible.
 */
export const getAutoRemediationHistoryForRepository = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return await ctx.db
      .query('autoRemediationRuns')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(50)
  },
})

// ─── Helpers ──────────────────────────────────────────────────────────────────

type AutoRemediationRunRecord = {
  candidateCount: number
  dispatchedCount: number
  skippedAlreadyHasPr: number
  skippedBelowTier: number
  skippedBelowSeverity: number
  skippedConcurrencyCap: number
  dispatchedFindingIds: string[]
  computedAt: number
}

function buildAutoRemediationSummary(runs: AutoRemediationRunRecord[]) {
  const totalDispatched = runs.reduce((sum, r) => sum + r.dispatchedCount, 0)
  const totalCandidates = runs.reduce((sum, r) => sum + r.candidateCount, 0)
  const totalSkippedAlreadyHasPr = runs.reduce((sum, r) => sum + r.skippedAlreadyHasPr, 0)
  const totalSkippedBelowTier = runs.reduce((sum, r) => sum + r.skippedBelowTier, 0)
  const totalSkippedBelowSeverity = runs.reduce((sum, r) => sum + r.skippedBelowSeverity, 0)
  const totalSkippedConcurrencyCap = runs.reduce((sum, r) => sum + r.skippedConcurrencyCap, 0)

  return {
    totalRuns: runs.length,
    totalCandidates,
    totalDispatched,
    totalSkippedAlreadyHasPr,
    totalSkippedBelowTier,
    totalSkippedBelowSeverity,
    totalSkippedConcurrencyCap,
    recentRuns: runs.slice(0, 10),
  }
}

// ─── Query ────────────────────────────────────────────────────────────────────

/**
 * Slug-based variant for the HTTP endpoint.
 * Returns null when the tenant or repository is not found.
 */
export const getAutoRemediationSummaryBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
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

    const runs = await ctx.db
      .query('autoRemediationRuns')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(50)

    return {
      tenantSlug: tenant.slug,
      repositoryFullName: repository.fullName,
      ...buildAutoRemediationSummary(
        runs.map((r) => ({
          candidateCount: r.candidateCount,
          dispatchedCount: r.dispatchedCount,
          skippedAlreadyHasPr: r.skippedAlreadyHasPr,
          skippedBelowTier: r.skippedBelowTier,
          skippedBelowSeverity: r.skippedBelowSeverity,
          skippedConcurrencyCap: r.skippedConcurrencyCap,
          dispatchedFindingIds: r.dispatchedFindingIds as string[],
          computedAt: r.computedAt,
        })),
      ),
    }
  },
})
