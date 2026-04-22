// SLA Enforcement Intelligence — spec §3.13.3
//
// Mutations:
//   checkSlaBreaches         — scan active findings for a repository, record
//                              breach events, schedule Slack notifications
//   checkAllSlaBreaches      — fan-out to all repositories via scheduler
//
// Queries:
//   getSlaStatusForRepository — per-finding SLA assessments + summary + MTTR
//   getSlaBreachHistory       — recent breach events for a repository
//   getSlaComplianceReport    — per-repo SLA summaries for a tenant

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import {
  assessSlaFinding,
  computeSlaSummary,
  DEFAULT_SLA_POLICY,
  getSlaThresholdHours,
} from './lib/slaPolicy'

// ── Internal: breach detection ────────────────────────────────────────────────

// Scan active findings for a single repository, insert breach events for
// newly-expired SLAs, and schedule Slack notifications for first-time breaches.
export const checkSlaBreaches = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const repository = await ctx.db.get(repositoryId)
    if (!repository) return

    const nowMs = Date.now()

    // Load all open + pr_opened findings.  Two index scans required because
    // Convex index equality filters don't support OR conditions.
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
      .take(200)

    const activeFindings = [...openFindings, ...prOpenedFindings]

    for (const finding of activeFindings) {
      const assessment = assessSlaFinding({
        findingId: finding._id,
        severity: finding.severity,
        status: finding.status,
        openedAt: finding.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs,
      })

      if (assessment.slaStatus !== 'breached_sla') continue

      // Idempotency: skip if a breach event already exists for this finding.
      const existing = await ctx.db
        .query('slaBreachEvents')
        .withIndex('by_finding', (q) => q.eq('findingId', finding._id))
        .first()

      if (existing) continue

      const thresholdHours =
        getSlaThresholdHours(finding.severity, DEFAULT_SLA_POLICY) ?? 0

      await ctx.db.insert('slaBreachEvents', {
        findingId: finding._id,
        repositoryId,
        tenantId: finding.tenantId,
        severity: finding.severity,
        title: finding.title,
        slaThresholdHours: thresholdHours,
        openedAt: finding.createdAt,
        breachedAt: nowMs,
        notificationChannels: [],
      })

      // Schedule Slack notification (fire-and-forget, safe to fail).
      const hoursOverdue = Math.max(
        0,
        Math.round(assessment.hoursElapsed - thresholdHours),
      )
      await ctx.scheduler.runAfter(0, internal.slack.sendSlaBreachNotification, {
        findingTitle: finding.title,
        severity: finding.severity,
        repositoryFullName: repository.fullName,
        hoursOverdue,
      })
    }
  },
})

// Schedule checkSlaBreaches for every repository — called by the hourly cron.
export const checkAllSlaBreaches = internalMutation({
  args: {},
  handler: async (ctx) => {
    const repositories = await ctx.db.query('repositories').take(100)
    for (const repo of repositories) {
      await ctx.scheduler.runAfter(
        0,
        internal.slaIntel.checkSlaBreaches,
        { repositoryId: repo._id },
      )
    }
  },
})

// ── Public: per-repository SLA status ────────────────────────────────────────

// Returns per-finding SLA assessments, a rolled-up summary, and MTTR.
export const getSlaStatusForRepository = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const nowMs = Date.now()

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
      .take(200)

    const resolvedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repositoryId).eq('status', 'resolved'),
      )
      .order('desc')
      .take(100)

    const activeFindings = [...openFindings, ...prOpenedFindings]

    const assessments = activeFindings.map((f) =>
      assessSlaFinding({
        findingId: f._id,
        severity: f.severity,
        status: f.status,
        openedAt: f.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs,
      }),
    )

    const resolvedForMttr = resolvedFindings
      .filter((f): f is typeof f & { resolvedAt: number } => f.resolvedAt != null)
      .map((f) => ({ createdAt: f.createdAt, resolvedAt: f.resolvedAt }))

    const summary = computeSlaSummary(assessments, resolvedForMttr)

    return { assessments, summary }
  },
})

// Returns up to 50 recent SLA breach events for a repository.
export const getSlaBreachHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return await ctx.db
      .query('slaBreachEvents')
      .withIndex('by_repository_and_breached_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(50)
  },
})

// Returns per-repository SLA summaries for a tenant (for the executive view).
export const getSlaComplianceReport = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .first()
    if (!tenant) return []

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(50)

    const nowMs = Date.now()
    const results = []

    for (const repo of repositories) {
      const openF = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repo._id).eq('status', 'open'),
        )
        .take(100)

      const prF = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repo._id).eq('status', 'pr_opened'),
        )
        .take(100)

      const resolvedF = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repo._id).eq('status', 'resolved'),
        )
        .order('desc')
        .take(50)

      const assessments = [...openF, ...prF].map((f) =>
        assessSlaFinding({
          findingId: f._id,
          severity: f.severity,
          status: f.status,
          openedAt: f.createdAt,
          policy: DEFAULT_SLA_POLICY,
          nowMs,
        }),
      )

      const resolvedForMttr = resolvedF
        .filter((f): f is typeof f & { resolvedAt: number } => f.resolvedAt != null)
        .map((f) => ({ createdAt: f.createdAt, resolvedAt: f.resolvedAt }))

      results.push({
        repositoryId: repo._id,
        repositoryFullName: repo.fullName,
        summary: computeSlaSummary(assessments, resolvedForMttr),
      })
    }

    return results
  },
})

// Slug-based lookup variant for the HTTP endpoint — accepts tenantSlug +
// repositoryFullName so the HTTP handler doesn't need to do two extra queries.
export const getSlaStatusBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .first()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
      )
      .first()
    if (!repository) return null

    const nowMs = Date.now()

    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'open'),
      )
      .take(200)

    const prOpenedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'pr_opened'),
      )
      .take(200)

    const resolvedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'resolved'),
      )
      .order('desc')
      .take(100)

    const assessments = [...openFindings, ...prOpenedFindings].map((f) =>
      assessSlaFinding({
        findingId: f._id,
        severity: f.severity,
        status: f.status,
        openedAt: f.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs,
      }),
    )

    const resolvedForMttr = resolvedFindings
      .filter((f): f is typeof f & { resolvedAt: number } => f.resolvedAt != null)
      .map((f) => ({ createdAt: f.createdAt, resolvedAt: f.resolvedAt }))

    return {
      repositoryId: repository._id,
      repositoryFullName,
      assessments,
      summary: computeSlaSummary(assessments, resolvedForMttr),
    }
  },
})

// ── Public: on-demand trigger ─────────────────────────────────────────────────

// Manually trigger SLA breach check for a single repository (for testing /
// dashboard "run now" actions).
export const triggerSlaCheckForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    await ctx.scheduler.runAfter(
      0,
      internal.slaIntel.checkSlaBreaches,
      { repositoryId },
    )
    return { scheduled: true }
  },
})
