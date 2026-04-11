// WS-15 Phase 3 — Memory and Learning Loop (spec 3.13): Convex entrypoints.
//
//   refreshLearningProfile              — internalMutation: loads findings,
//       red/blue rounds, and attack surface history for the repository, runs
//       computeLearningProfile, inserts a learningProfile snapshot.
//
//   refreshLearningProfileForRepository — public mutation: dashboard trigger.
//
//   getLatestLearningProfile            — public query: latest snapshot or null.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  computeLearningProfile,
  type AttackSurfacePoint,
  type FindingHistoryEntry,
  type RedBlueRoundEntry,
} from './lib/learningLoop'

// ---------------------------------------------------------------------------
// refreshLearningProfile (internal)
// ---------------------------------------------------------------------------

export const refreshLearningProfile = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // Load up to 500 findings for this repository (all statuses, to capture FP patterns).
    const findingDocs = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .take(500)

    const findingHistory: FindingHistoryEntry[] = findingDocs.map((f) => ({
      vulnClass: f.vulnClass,
      severity: f.severity,
      status: f.status,
      validationStatus: f.validationStatus,
    }))

    // Load up to 100 red/blue rounds, ordered by most recent.
    const roundDocs = await ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(100)

    const redBlueRounds: RedBlueRoundEntry[] = roundDocs.map((r) => ({
      roundOutcome: r.roundOutcome,
      exploitChains: r.exploitChains,
    }))

    // Load attack surface history (most recent 50, then reverse to oldest-first
    // so the trend algorithm sees chronological order).
    const surfaceDocs = await ctx.db
      .query('attackSurfaceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(50)

    const attackSurfaceHistory: AttackSurfacePoint[] = surfaceDocs
      .reverse()
      .map((s) => ({ score: s.score }))

    const result = computeLearningProfile({
      findingHistory,
      redBlueRounds,
      attackSurfaceHistory,
    })

    await ctx.db.insert('learningProfiles', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      vulnClassPatterns: result.vulnClassPatterns,
      recurringCount: result.recurringCount,
      suppressedCount: result.suppressedCount,
      successfulExploitPaths: result.successfulExploitPaths,
      attackSurfaceTrend: result.attackSurfaceTrend,
      adaptedConfidenceScore: result.adaptedConfidenceScore,
      redAgentWinRate: result.redAgentWinRate,
      totalFindingsAnalyzed: result.totalFindingsAnalyzed,
      totalRoundsAnalyzed: result.totalRoundsAnalyzed,
      summary: result.summary,
      computedAt: Date.now(),
    })

    return result
  },
})

// ---------------------------------------------------------------------------
// refreshLearningProfileForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const refreshLearningProfileForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new Error(`Tenant ${args.tenantSlug} not found`)
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new Error(`Repository ${args.repositoryFullName} not found`)
    }

    await ctx.scheduler.runAfter(
      0,
      internal.learningProfileIntel.refreshLearningProfile,
      { repositoryId: repository._id },
    )

    return { scheduled: true, repositoryId: repository._id }
  },
})

// ---------------------------------------------------------------------------
// getLatestLearningProfile (public query)
// ---------------------------------------------------------------------------

export const getLatestLearningProfile = query({
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

    return await ctx.db
      .query('learningProfiles')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})
