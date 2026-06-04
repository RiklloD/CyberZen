// WS-22 — Finding Severity Escalation Engine
//
// Makes finding severity dynamic by synthesizing all previously built
// intelligence layers (blast radius, CISA KEV exploit availability,
// cross-repo spread, SLA breach) into automatic severity upgrades with a
// full audit trail in `severityEscalationEvents`.
//
// Functions:
//   checkAndEscalateFinding        — internalMutation: assess a single finding
//   runEscalationSweepForRepository — internalMutation: fan-out per repository
//   runAllEscalationSweeps         — internalMutation: cron target, fans out to all repos
//   getEscalationHistoryForFinding  — query: audit log for one finding
//   getEscalationSummaryForRepository — query: aggregate stats for a repository
//   getEscalationSummaryBySlug     — query: slug-based variant for the HTTP handler

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, query } from './_generated/server'
import {
  assessEscalation,
  DEFAULT_ESCALATION_POLICY,
  type EscalationSeverity,
  type EscalationTrigger,
} from './lib/escalationPolicy'
import { assessSlaFinding, DEFAULT_SLA_POLICY } from './lib/slaPolicy'

// ─── Internal: per-finding assessment ────────────────────────────────────────

/**
 * Loads all escalation context signals for a single finding, runs
 * `assessEscalation`, and — when `shouldEscalate = true` — atomically patches
 * `finding.severity` and inserts a `severityEscalationEvents` audit row.
 *
 * Idempotent: repeated calls produce at most one escalation per level
 * because informational and critical findings are skipped, and severity
 * is only ever increased (monotone).
 */
export const checkAndEscalateFinding = internalMutation({
  args: { findingId: v.id('findings') },
  handler: async (ctx, { findingId }) => {
    const finding = await ctx.db.get(findingId)
    if (!finding) return

    // Skip boundaries — informational is not a vulnerability; critical is max.
    if (finding.severity === 'informational' || finding.severity === 'critical') return

    // Only assess active findings (inactive statuses are outside the SLA window).
    const activeStatuses = new Set(['open', 'pr_opened', 'merged'])
    if (!activeStatuses.has(finding.status)) return

    // ── Signal: blast radius ──────────────────────────────────────────────────
    const blastSnap = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .order('desc')
      .first()
    const blastRadiusScore = blastSnap?.businessImpactScore ?? -1

    // ── Signal: exploit availability ──────────────────────────────────────────
    let exploitAvailable = false
    if (finding.breachDisclosureId) {
      const disclosure = await ctx.db.get(finding.breachDisclosureId)
      exploitAvailable = disclosure?.exploitAvailable ?? false
    }

    // ── Signal: cross-repo spread ─────────────────────────────────────────────
    const crossRepoEvent = await ctx.db
      .query('crossRepoImpactEvents')
      .withIndex('by_source_finding', (q) => q.eq('sourceFindingId', findingId))
      .first()
    const affectedRepoCount = crossRepoEvent?.affectedRepositoryCount ?? 0

    // ── Signal: SLA status ────────────────────────────────────────────────────
    const slaAssessment = assessSlaFinding({
      findingId: findingId as string,
      severity: finding.severity,
      status: finding.status,
      openedAt: finding.createdAt,
      policy: DEFAULT_SLA_POLICY,
      nowMs: Date.now(),
    })

    // ── Run escalation engine ─────────────────────────────────────────────────
    const assessment = assessEscalation(
      {
        currentSeverity: finding.severity as EscalationSeverity,
        exploitAvailable,
        blastRadiusScore,
        affectedRepoCount,
        slaStatus: slaAssessment.slaStatus as
          | 'within_sla'
          | 'approaching_sla'
          | 'breached_sla'
          | 'not_applicable',
      },
      DEFAULT_ESCALATION_POLICY,
    )

    if (!assessment.shouldEscalate) return

    const now = Date.now()

    // Patch the finding's severity field (monotone — only increases).
    await ctx.db.patch(findingId, { severity: assessment.newSeverity })

    // Insert immutable audit row.
    await ctx.db.insert('severityEscalationEvents', {
      findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      previousSeverity: assessment.currentSeverity,
      newSeverity: assessment.newSeverity,
      triggers: assessment.triggers as EscalationTrigger[],
      rationale: assessment.rationale,
      computedAt: now,
    })
  },
})

// ─── Internal: repository sweep ──────────────────────────────────────────────

/**
 * Fans out `checkAndEscalateFinding` for every active, non-boundary finding
 * in a single repository.  Scheduled once per repository by `runAllEscalationSweeps`.
 */
export const runEscalationSweepForRepository = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'open'),
      )
      .take(200)

    const prFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'pr_opened'),
      )
      .take(100)

    const candidates = [...openFindings, ...prFindings].filter(
      (f) => f.severity !== 'informational' && f.severity !== 'critical',
    )

    for (const finding of candidates) {
      await ctx.scheduler.runAfter(
        0,
        internal.escalationIntel.checkAndEscalateFinding,
        { findingId: finding._id },
      )
    }
  },
})

// ─── Internal: global sweep (cron target) ────────────────────────────────────

/**
 * Fans out `runEscalationSweepForRepository` for every repository in the
 * system.  Run every 4 hours by the cron scheduler.
 */
export const runAllEscalationSweeps = internalMutation({
  args: {},
  handler: async (ctx) => {
    const repositories = await ctx.db.query('repositories').take(500)

    for (const repo of repositories) {
      await ctx.scheduler.runAfter(
        0,
        internal.escalationIntel.runEscalationSweepForRepository,
        { repositoryId: repo._id },
      )
    }
  },
})

// ─── Public queries ───────────────────────────────────────────────────────────

/**
 * Returns the full escalation history for a single finding, newest first.
 * Each row represents one automatic severity upgrade with its trigger set
 * and rationale strings.
 */
export const getEscalationHistoryForFinding = query({
  args: { findingId: v.id('findings') },
  handler: async (ctx, { findingId }) => {
    return await ctx.db
      .query('severityEscalationEvents')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .order('desc')
      .take(50)
  },
})

// ─── Helpers ──────────────────────────────────────────────────────────────────

type EscalationEvent = {
  findingId: string
  previousSeverity: string
  newSeverity: string
  triggers: string[]
  rationale: string[]
  computedAt: number
}

function buildEscalationSummary(events: EscalationEvent[]) {
  const triggerCounts: Record<string, number> = {
    exploit_available: 0,
    blast_radius_critical: 0,
    blast_radius_high: 0,
    cross_repo_spread: 0,
    sla_breach: 0,
  }
  const escalatedFindingIds = new Set<string>()

  for (const ev of events) {
    escalatedFindingIds.add(ev.findingId)
    for (const t of ev.triggers) {
      if (t in triggerCounts) triggerCounts[t]++
    }
  }

  return {
    totalEscalations: events.length,
    uniqueFindingsEscalated: escalatedFindingIds.size,
    triggerCounts,
    recentEvents: events.slice(0, 10),
  }
}

// ─── Queries ──────────────────────────────────────────────────────────────────

/**
 * Returns aggregate escalation statistics for a single repository.
 * Covers the 100 most recent escalation events.
 */
export const getEscalationSummaryForRepository = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const events = await ctx.db
      .query('severityEscalationEvents')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(100)

    return buildEscalationSummary(
      events.map((e) => ({
        findingId: e.findingId as string,
        previousSeverity: e.previousSeverity,
        newSeverity: e.newSeverity,
        triggers: e.triggers as string[],
        rationale: e.rationale,
        computedAt: e.computedAt,
      })),
    )
  },
})

/**
 * Slug-based variant for the HTTP endpoint.
 * Returns null when the tenant or repository is not found.
 */
export const getEscalationSummaryBySlug = query({
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

    const events = await ctx.db
      .query('severityEscalationEvents')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(100)

    return {
      tenantSlug: tenant.slug,
      repositoryFullName: repository.fullName,
      ...buildEscalationSummary(
        events.map((e) => ({
          findingId: e.findingId as string,
          previousSeverity: e.previousSeverity,
          newSeverity: e.newSeverity,
          triggers: e.triggers as string[],
          rationale: e.rationale,
          computedAt: e.computedAt,
        })),
      ),
    }
  },
})
