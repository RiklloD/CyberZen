// Risk Acceptance Intelligence — spec §4.3
//
// Mutations:
//   createRiskAcceptance      — formally accept a risk (temporary or permanent)
//   revokeRiskAcceptance      — explicitly revoke an active acceptance
//   checkExpiredAcceptances   — hourly cron: expire overdue acceptances,
//                               revert findings to open, schedule notifications
//
// Queries:
//   getRiskAcceptancesForRepository  — list acceptances for a repository
//   getExpiringAcceptances           — acceptances expiring within 7 days
//   getAcceptanceSummaryForRepository — aggregate counts (for dashboard)

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import {
  computeAcceptanceSummary,
  computeExpiresAt,
  isExpired,
} from './lib/riskAcceptance'

// ── Public mutations ──────────────────────────────────────────────────────────

// Formally accept a risk for a finding.  Patches the finding status to
// 'accepted_risk'; schedules automatic expiry when durationDays is provided.
export const createRiskAcceptance = mutation({
  args: {
    findingId: v.id('findings'),
    justification: v.string(),
    approver: v.string(),
    /** Omit for a permanent acceptance; provide a positive integer for temporary. */
    durationDays: v.optional(v.number()),
  },
  handler: async (ctx, { findingId, justification, approver, durationDays }) => {
    const finding = await ctx.db.get(findingId)
    if (!finding) throw new Error(`Finding ${findingId} not found`)

    // Revoke any existing active acceptance before creating a new one.
    const existing = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .filter((q) => q.eq(q.field('status'), 'active'))
      .first()

    if (existing) {
      await ctx.db.patch(existing._id, {
        status: 'revoked',
        revokedAt: Date.now(),
        revokedBy: approver,
      })
    }

    const nowMs = Date.now()
    const level = durationDays != null ? 'temporary' : 'permanent'
    const expiresAt =
      durationDays != null ? computeExpiresAt(nowMs, durationDays) : undefined

    const acceptanceId = await ctx.db.insert('riskAcceptances', {
      findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      justification,
      approver,
      level,
      expiresAt,
      status: 'active',
      createdAt: nowMs,
    })

    // Advance the finding to accepted_risk status.
    await ctx.db.patch(findingId, { status: 'accepted_risk' })

    return { acceptanceId, level, expiresAt: expiresAt ?? null }
  },
})

// Explicitly revoke an active acceptance and reopen the finding.
export const revokeRiskAcceptance = mutation({
  args: {
    findingId: v.id('findings'),
    revokedBy: v.optional(v.string()),
  },
  handler: async (ctx, { findingId, revokedBy }) => {
    const acceptance = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .filter((q) => q.eq(q.field('status'), 'active'))
      .first()

    if (!acceptance) throw new Error(`No active acceptance for finding ${findingId}`)

    const nowMs = Date.now()
    await ctx.db.patch(acceptance._id, {
      status: 'revoked',
      revokedAt: nowMs,
      revokedBy: revokedBy ?? 'operator',
    })

    // Reopen the finding.
    await ctx.db.patch(findingId, { status: 'open' })

    return { revoked: true }
  },
})

// ── Internal: expiry cron ─────────────────────────────────────────────────────

// Scans all active acceptances, transitions expired ones, reverts findings
// to open, and schedules Slack notifications.  Called hourly by cron.
export const checkExpiredAcceptances = internalMutation({
  args: {},
  handler: async (ctx) => {
    const nowMs = Date.now()

    // Load all active acceptances — the table stays small in practice.
    const active = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_status', (q) => q.eq('status', 'active'))
      .take(500)

    for (const acceptance of active) {
      if (!isExpired({ expiresAt: acceptance.expiresAt }, nowMs)) continue

      // Transition to expired.
      await ctx.db.patch(acceptance._id, { status: 'expired' })

      // Re-open the finding (only if it's still accepted_risk — it may have
      // been manually changed already).
      const finding = await ctx.db.get(acceptance.findingId)
      if (finding && finding.status === 'accepted_risk') {
        await ctx.db.patch(acceptance.findingId, { status: 'open' })
      }

      // Look up the repository full name for the notification.
      const repository = await ctx.db.get(acceptance.repositoryId)
      if (!repository) continue

      // Schedule Slack notification (fire-and-forget, safe to fail).
      await ctx.scheduler.runAfter(
        0,
        internal.slack.sendAcceptanceExpiryNotification,
        {
          findingId: acceptance.findingId,
          justification: acceptance.justification,
          approver: acceptance.approver,
          repositoryFullName: repository.fullName,
        },
      )
    }

    return { processed: active.length }
  },
})

// ── Public queries ────────────────────────────────────────────────────────────

// Returns all acceptance records for a repository, newest first.
export const getRiskAcceptancesForRepository = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(50)
  },
})

// Returns active acceptances expiring within 7 days for a repository.
export const getExpiringAcceptances = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const nowMs = Date.now()
    const windowMs = 7 * 24 * 3_600_000

    const active = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .filter((q) => q.eq(q.field('status'), 'active'))
      .take(100)

    return active.filter((a) => {
      if (a.expiresAt == null) return false
      const remaining = a.expiresAt - nowMs
      return remaining > 0 && remaining <= windowMs
    })
  },
})

// Returns aggregate summary stats for a repository's acceptances.
export const getAcceptanceSummaryForRepository = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const nowMs = Date.now()

    const records = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .take(200)

    return computeAcceptanceSummary(records, nowMs)
  },
})

// Slug-based lookup for the HTTP list endpoint — avoids two-query round-trips.
export const getRiskAcceptancesBySlug = query({
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

    const records = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(50)

    return {
      repositoryId: repository._id,
      acceptances: records,
      summary: computeAcceptanceSummary(records, nowMs),
    }
  },
})

// Returns active acceptances for a tenant (for executive-level view).
export const getActiveAcceptancesForTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .first()
    if (!tenant) return []

    return await ctx.db
      .query('riskAcceptances')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .filter((q) => q.eq(q.field('status'), 'active'))
      .order('desc')
      .take(100)
  },
})
