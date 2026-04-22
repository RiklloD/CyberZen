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

import { v } from 'convex/values'
import { internalQuery, mutation, query } from './_generated/server'
import {
  computeTriageSummary,
  triageActionToStatus,
  type TriageAction,
  type TriageEvent,
} from './lib/findingTriage'

// Shared action validator
const triageActionValidator = v.union(
  v.literal('mark_false_positive'),
  v.literal('mark_accepted_risk'),
  v.literal('reopen'),
  v.literal('add_note'),
  v.literal('ignore'),
)

// ---------------------------------------------------------------------------
// applyTriageAction — unified mutation powering all triage workflows
// ---------------------------------------------------------------------------

export const applyTriageAction = mutation({
  args: {
    findingId: v.id('findings'),
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
      // biome-ignore lint/suspicious/noExplicitAny: findingStatus union extended
      await ctx.db.patch(args.findingId, { status: newStatus as any })
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
    note: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)

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
    note: v.optional(v.string()),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)

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
    note: v.string(),
    analyst: v.optional(v.string()),
  },
  returns: v.object({ triageEventId: v.id('findingTriageEvents') }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error(`Finding not found: ${args.findingId}`)

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
