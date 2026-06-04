/**
 * WS-51 — Security Event Timeline: Convex entrypoints
 *
 * Assembles a chronological audit log of all security lifecycle events across
 * a repository by fanning out to 10+ existing tables and merging the results
 * through `buildSecurityTimeline`.  No new schema table is needed — this is a
 * computed view, not persisted data.
 *
 * Entrypoints:
 *   getSecurityTimelineForRepository   — public query: dashboard (slug-based)
 *   getSecurityTimelineBySlug          — public query: HTTP API alias
 *   getTimelineEventCountsByType       — public query: summary event-type counts
 */

import { v } from 'convex/values'
import { query } from './_generated/server'
import type { QueryCtx } from './_generated/server'
import type { Id } from './_generated/dataModel'
import {
  buildSecurityTimeline,
  countTimelineEventsByType,
} from './lib/securityTimeline'

// ---------------------------------------------------------------------------
// Internal: fan-out data loader
// ---------------------------------------------------------------------------

/**
 * Load raw event records from all 10 timeline source tables for a single
 * repository.  Uses Promise.all to run reads concurrently.
 */
async function loadTimelineData(
  ctx: QueryCtx,
  repositoryId: Id<'repositories'>,
) {
  const [
    findings,
    escalations,
    triageEvents,
    gateDecisions,
    prProposals,
    slaBreaches,
    riskAcceptances,
    redBlueRounds,
    autoRemediationRuns,
    secretScans,
  ] = await Promise.all([
    // findings: by_repository_and_status — first-field equality returns all statuses
    ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repositoryId))
      .take(50),

    // severity escalation events
    ctx.db
      .query('severityEscalationEvents')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(30),

    // analyst triage events
    ctx.db
      .query('findingTriageEvents')
      .withIndex('by_repository_and_created_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(30),

    // CI gate decisions
    ctx.db
      .query('gateDecisions')
      .withIndex('by_repository_and_stage', (q) => q.eq('repositoryId', repositoryId))
      .take(30),

    // Fix PR proposals
    ctx.db
      .query('prProposals')
      .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repositoryId))
      .take(30),

    // SLA breach events
    ctx.db
      .query('slaBreachEvents')
      .withIndex('by_repository_and_breached_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(30),

    // Risk acceptances
    ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(20),

    // Red/Blue adversarial rounds (newest first)
    ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(20),

    // Autonomous remediation dispatch runs
    ctx.db
      .query('autoRemediationRuns')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(20),

    // Push-event secret scans
    ctx.db
      .query('secretScanResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(20),
  ])

  return {
    findings: findings.map((f) => ({
      id: f._id,
      title: f.title,
      severity: f.severity,
      status: f.status,
      createdAt: f.createdAt,
      resolvedAt: f.resolvedAt,
    })),
    escalations: escalations.map((e) => ({
      id: e._id,
      previousSeverity: e.previousSeverity,
      newSeverity: e.newSeverity,
      triggers: e.triggers,
      computedAt: e.computedAt,
    })),
    triageEvents: triageEvents.map((t) => ({
      id: t._id,
      action: t.action,
      note: t.note,
      analyst: t.analyst,
      createdAt: t.createdAt,
    })),
    gateDecisions: gateDecisions.map((g) => ({
      id: g._id,
      stage: g.stage,
      decision: g.decision,
      createdAt: g.createdAt,
    })),
    prProposals: prProposals.map((p) => ({
      id: p._id,
      status: p.status,
      prUrl: p.prUrl,
      prTitle: p.prTitle,
      createdAt: p.createdAt,
      mergedAt: p.mergedAt,
      mergedBy: p.mergedBy,
    })),
    slaBreaches: slaBreaches.map((s) => ({
      id: s._id,
      severity: s.severity,
      title: s.title,
      breachedAt: s.breachedAt,
      slaThresholdHours: s.slaThresholdHours,
    })),
    riskAcceptances: riskAcceptances.map((r) => ({
      id: r._id,
      approver: r.approver,
      level: r.level,
      status: r.status,
      createdAt: r.createdAt,
      revokedAt: r.revokedAt,
    })),
    redBlueRounds: redBlueRounds.map((rb) => ({
      id: rb._id,
      roundOutcome: rb.roundOutcome,
      ranAt: rb.ranAt,
      simulatedFindingsGenerated: rb.simulatedFindingsGenerated,
    })),
    autoRemediationRuns: autoRemediationRuns.map((ar) => ({
      id: ar._id,
      dispatchedCount: ar.dispatchedCount,
      candidateCount: ar.candidateCount,
      computedAt: ar.computedAt,
    })),
    secretScans: secretScans.map((ss) => ({
      id: ss._id,
      criticalCount: ss.criticalCount,
      highCount: ss.highCount,
      scannedAt: ss.computedAt,
    })),
  }
}

// ---------------------------------------------------------------------------
// getSecurityTimelineForRepository — public query (dashboard)
// ---------------------------------------------------------------------------

/**
 * Return a chronological security event timeline for a repository, newest-first.
 *
 * Merges findings, escalations, triage, gate decisions, PR proposals, SLA
 * breaches, risk acceptances, red/blue rounds, auto-remediation runs, and
 * secret scans into a single unified audit log (up to 100 entries).
 */
export const getSecurityTimelineForRepository = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, limit = 50 }) => {
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

    const data = await loadTimelineData(ctx, repository._id)
    return buildSecurityTimeline(data, Math.min(limit, 100))
  },
})

// ---------------------------------------------------------------------------
// getSecurityTimelineBySlug — public query (HTTP API)
// ---------------------------------------------------------------------------

/** Identical to getSecurityTimelineForRepository — exposed for HTTP API callers. */
export const getSecurityTimelineBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, limit = 50 }) => {
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

    const data = await loadTimelineData(ctx, repository._id)
    return buildSecurityTimeline(data, Math.min(limit, 100))
  },
})

// ---------------------------------------------------------------------------
// getTimelineEventCountsByType — public query
// ---------------------------------------------------------------------------

/**
 * Return per-event-type counts for the full timeline of a repository.
 * Useful for summary pills ("12 findings created, 3 gate blocks, …").
 */
export const getTimelineEventCountsByType = query({
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

    const data = await loadTimelineData(ctx, repository._id)
    const timeline = buildSecurityTimeline(data, 100)
    return countTimelineEventsByType(timeline)
  },
})
