// Analyst triage entrypoints — finding feedback loop.
//
// Mutations:
//   applyTriageAction        — unified triage action (FP/accepted_risk/reopen/ignore/note)
//   markFalsePositive        — convenience wrapper: mark finding as false_positive
//   reopenFinding            — re-opens a resolved/FP/ignored finding back to open
//   addTriageNote            — appends an analyst note without changing status
//
// Queries:
//   getTriageHistory         — event log for a single finding (for dashboard/audit)
//   getFalsePositiveSummary  — per-vuln-class FP counts for a repository (for learning loop)
//
// Internal queries:
//   loadTriageEventsForRepository — used by learning loop to compute analyst multipliers

import { ConvexError, v } from 'convex/values'
import { internalQuery, mutation, query } from './_generated/server'
import { api } from './_generated/api'
import {
  computeTriageSummary,
  triageActionToStatus,
  type TriageAction,
  type TriageEvent,
} from './lib/findingTriage'
import { requireSessionAuth } from './lib/sessionAuth'
import type { Id } from './_generated/dataModel'

// FIX: C1 — shared helper that verifies the caller is a member of the finding's tenant
async function verifyTenantMembership(ctx: any, authToken: string | undefined, tenantId: Id<'tenants'>) {
  const { userId } = await requireSessionAuth(ctx, authToken)
  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q: any) =>
      q.eq('tenantId', tenantId).eq('userId', userId),
    )
    .unique()
  if (!membership) throw new ConvexError('Forbidden')
}

// Shared action validator
const triageActionValidator = v.union(
  v.literal('mark_false_positive'),
  v.literal('mark_accepted_risk'),
  v.literal('reopen'),
  v.literal('add_note'),
  v.literal('ignore'),
  v.literal('snooze'),
)

// ---------------------------------------------------------------------------
// applyTriageAction — unified mutation powering all triage workflows
// ---------------------------------------------------------------------------

export const applyTriageAction = mutation({
  args: {
    findingId: v.id('findings'),
    authToken: v.optional(v.string()), // FIX: C1 — required for tenant ownership verification
    action: triageActionValidator,
    note: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({
    findingId: v.id('findings'),
    action: v.string(),
    newStatus: v.optional(v.string()),
    triageEventId: v.id('findingTriageEvents'),
  }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) {
      throw new Error(`Finding not found: ${args.findingId}`)
    }
    await verifyTenantMembership(ctx, args.authToken, finding.tenantId) // FIX: C1 — tenant isolation

    // Determine new finding status (null = no status change for add_note)
    const newStatus = triageActionToStatus(args.action as TriageAction)

    // Persist the triage event
    const triageEventId = await ctx.db.insert('findingTriageEvents', {
      findingId: args.findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      action: args.action as TriageAction,
      note: args.note,
      analyst: args.analyst,
      createdAt: Date.now(),
    })

    // Patch the finding status when the action implies a status change
    if (newStatus !== null) {
      await ctx.db.patch(args.findingId, { status: newStatus as NonNullable<ReturnType<typeof triageActionToStatus>> }) // FIX: W4 — typed cast replaces `as any`
    }

    // Neural Memory: Record triage episode for learning
    try {
      let episodeType: 'finding' | 'false_positive' | 'fix'
      if (args.action === 'mark_false_positive') {
        episodeType = 'false_positive'
      } else if (args.action === 'mark_resolved') {
        episodeType = 'fix'
      } else {
        episodeType = 'finding'
      }

      await ctx.runMutation(api.neuralMemory.recordEpisode, {
        repositoryId: finding.repositoryId,
        episodeType,
        payload: {
          findingId: args.findingId,
          action: args.action,
          severity: finding.severity,
          cwe: finding.cwe,
          filePath: finding.filePath,
          ruleId: finding.ruleId,
          analyst: args.analyst,
          note: args.note,
          newStatus: newStatus,
          timestamp: Date.now(),
        },
        sourceRef: `triage-${triageEventId}`,
      })
    } catch (error) {
      // Don't fail triage if Neural Memory recording fails
      console.error('Neural Memory: Failed to record triage episode:', error)
    }

    return {
      findingId: args.findingId,
      action: args.action,
      newStatus: newStatus ?? undefined,
      triageEventId,
    }
  },
})

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

export const markFalsePositive = mutation({
  args: {
    findingId: v.id('findings'),
    authToken: v.optional(v.string()), // FIX: C1 — required for tenant ownership verification
    note: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)
    await verifyTenantMembership(ctx, args.authToken, finding.tenantId) // FIX: C1 — tenant isolation

    const triageEventId = await ctx.db.insert('findingTriageEvents', {
      findingId: args.findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      action: 'mark_false_positive',
      note: args.note,
      analyst: args.analyst,
      createdAt: Date.now(),
    })
    // biome-ignore lint/suspicious/noExplicitAny: findingStatus union extended
    await ctx.db.patch(args.findingId, { status: 'false_positive' as any })
    return { triageEventId }
  },
})

export const reopenFinding = mutation({
  args: {
    findingId: v.id('findings'),
    authToken: v.optional(v.string()), // FIX: C1 — required for tenant ownership verification
    note: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)
    await verifyTenantMembership(ctx, args.authToken, finding.tenantId) // FIX: C1 — tenant isolation

    const triageEventId = await ctx.db.insert('findingTriageEvents', {
      findingId: args.findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      action: 'reopen',
      note: args.note,
      analyst: args.analyst,
      createdAt: Date.now(),
    })
    await ctx.db.patch(args.findingId, { status: 'open' })
    return { triageEventId }
  },
})

export const addTriageNote = mutation({
  args: {
    findingId: v.id('findings'),
    authToken: v.optional(v.string()), // FIX: C1 — required for tenant ownership verification
    note: v.string(),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)
    await verifyTenantMembership(ctx, args.authToken, finding.tenantId) // FIX: C1 — tenant isolation

    const triageEventId = await ctx.db.insert('findingTriageEvents', {
      findingId: args.findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      action: 'add_note',
      note: args.note,
      analyst: args.analyst,
      createdAt: Date.now(),
    })
    return { triageEventId }
  },
})

// ---------------------------------------------------------------------------
// snoozeFinding — snooze a finding for a fixed duration (1d/7d/30d)
// Sets status to 'snoozed', stores expiry timestamp and optional reason.
// ---------------------------------------------------------------------------

export const snoozeFinding = mutation({
  args: {
    findingId: v.id('findings'),
    authToken: v.optional(v.string()), // FIX: C1 — required for tenant ownership verification
    /** Duration in days (1, 7, or 30). */
    durationDays: v.union(v.literal(1), v.literal(7), v.literal(30)),
    /** Optional free-text reason for snoozing. */
    reason: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)
    await verifyTenantMembership(ctx, args.authToken, finding.tenantId) // FIX: C1 — tenant isolation

    const snoozedUntil = Date.now() + args.durationDays * 24 * 60 * 60 * 1000

    const triageEventId = await ctx.db.insert('findingTriageEvents', {
      findingId: args.findingId,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      action: 'snooze',
      note: args.reason ?? `Snoozed for ${args.durationDays} day(s)`,
      analyst: args.analyst,
      createdAt: Date.now(),
    })

    // biome-ignore lint/suspicious/noExplicitAny: findingStatus union extended
    await ctx.db.patch(args.findingId, {
      status: 'snoozed' as any,
      snoozedUntil,
      snoozeReason: args.reason,
    })

    return { triageEventId }
  },
})

// ---------------------------------------------------------------------------
// getTriageHistory — ordered event log for a finding
// ---------------------------------------------------------------------------

export const getTriageHistory = query({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    const events = await ctx.db
      .query('findingTriageEvents')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .order('asc')
      .take(100)

    const summary = computeTriageSummary(events as TriageEvent[])
    return { events, summary }
  },
})

// ---------------------------------------------------------------------------
// getFalsePositiveSummary — per-vuln-class FP breakdown for a repository
// Used by the learning panel and REST API.
// ---------------------------------------------------------------------------

export const getFalsePositiveSummary = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Load false_positive findings for this repository
    const fpFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'false_positive'),
      )
      .order('desc')
      .take(200)

    // Aggregate by vuln class
    const byVulnClass = new Map<string, number>()
    for (const f of fpFindings) {
      byVulnClass.set(f.vulnClass, (byVulnClass.get(f.vulnClass) ?? 0) + 1)
    }

    const breakdown = [...byVulnClass.entries()]
      .map(([vulnClass, count]) => ({ vulnClass, count }))
      .sort((a, b) => b.count - a.count)

    return {
      totalFalsePositives: fpFindings.length,
      breakdown,
    }
  },
})

// ---------------------------------------------------------------------------
// loadTriageEventsForLearningLoop — internal: load recent triage events
// Called from learningProfileIntel to factor analyst feedback into confidence.
// ---------------------------------------------------------------------------

export const loadTriageEventsForLearningLoop = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Load the most recent 500 triage events for this repository
    return await ctx.db
      .query('findingTriageEvents')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(500)
  },
})
