// WS-14 Phase 2 — Adversarial Red-Blue Agent Loop (spec 3.3): Convex
// entrypoints.
//
//   runAdversarialRound             — internalMutation: loads memory + blast
//       radius + open finding count, runs the simulation, inserts a round record.
//
//   runAdversarialRoundForRepository — public mutation: dashboard trigger.
//       Resolves the repository and schedules runAdversarialRound via the Convex
//       scheduler (fire-and-forget; useQuery subscriptions update automatically).
//
//   getLatestRound                  — public query: most recent redBlueRound for
//       a repository (or null).
//
//   adversarialSummaryForRepository — public query: aggregate win/loss/draw
//       record + averages + latest round for a repository.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  simulateAdversarialRound,
  type AdversarialRoundResult,
} from './lib/redBlueSimulator'
import {
  EMPTY_MEMORY_RECORD,
  type RepositoryMemoryRecord,
} from './lib/memoryController'

// ---------------------------------------------------------------------------
// runAdversarialRound (internal)
// ---------------------------------------------------------------------------

export const runAdversarialRound = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args): Promise<AdversarialRoundResult> => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // --- latest memory snapshot ---
    const memorySnapshot = await ctx.db
      .query('agentMemorySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    const memory: RepositoryMemoryRecord = memorySnapshot ?? EMPTY_MEMORY_RECORD

    // --- latest blast radius snapshot for this repository ---
    const blastSnapshot = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    // --- open finding count (bounded) ---
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'open'),
      )
      .take(50)

    // --- round number (previous + 1) ---
    const previousRound = await ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    const roundNumber = (previousRound?.roundNumber ?? 0) + 1

    // --- simulate ---
    const result = simulateAdversarialRound({
      repositoryMemory: memory,
      blastRadiusSnapshot: blastSnapshot
        ? {
            reachableServices: blastSnapshot.reachableServices,
            exposedDataLayers: blastSnapshot.exposedDataLayers,
            directExposureCount: blastSnapshot.directExposureCount,
            attackPathDepth: blastSnapshot.attackPathDepth,
            riskTier: blastSnapshot.riskTier,
          }
        : null,
      openFindingCount: openFindings.length,
      roundNumber,
      repositoryName: repository.name,
    })

    // --- persist ---
    await ctx.db.insert('redBlueRounds', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      roundNumber,
      redStrategySummary: result.redStrategySummary,
      attackSurfaceCoverage: result.attackSurfaceCoverage,
      simulatedFindingsGenerated: result.simulatedFindingsGenerated,
      blueDetectionScore: result.blueDetectionScore,
      exploitChains: result.exploitChains,
      roundOutcome: result.roundOutcome,
      confidenceGain: result.confidenceGain,
      summary: result.summary,
      ranAt: Date.now(),
    })

    // --- generate Blue Agent detection rules on red_wins ---
    if (result.roundOutcome === 'red_wins') {
      ctx.scheduler.runAfter(0, internal.blueAgentIntel.generateAndStoreDetectionRules, {
        repositoryId: args.repositoryId,
      })
    }

    // --- escalate on red_wins ---
    // Fire-and-forget: exploit chains become real candidate findings that flow
    // through the full pipeline (blast radius → memory → attack surface).
    // Failures are logged but never surfaced to the caller.
    if (result.roundOutcome === 'red_wins') {
      try {
        await ctx.scheduler.runAfter(
          0,
          internal.redAgentEscalation.escalateRedAgentFindings,
          {
            repositoryId: args.repositoryId,
            roundNumber,
            redStrategySummary: result.redStrategySummary,
            attackSurfaceCoverage: result.attackSurfaceCoverage,
            simulatedFindingsGenerated: result.simulatedFindingsGenerated,
            blueDetectionScore: result.blueDetectionScore,
            exploitChains: result.exploitChains,
            roundOutcome: result.roundOutcome,
            confidenceGain: result.confidenceGain,
            summary: result.summary,
          },
        )
      } catch (e) {
        console.error(
          '[red-agent-escalation] failed to schedule for repository',
          args.repositoryId,
          e,
        )
      }
    }

    return result
  },
})

// ---------------------------------------------------------------------------
// runAdversarialRoundForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const runAdversarialRoundForRepository = mutation({
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

    // Schedule the internal mutation; useQuery subscriptions update automatically.
    await ctx.scheduler.runAfter(
      0,
      internal.redBlueIntel.runAdversarialRound,
      { repositoryId: repository._id },
    )

    return { scheduled: true, repositoryId: repository._id }
  },
})

// ---------------------------------------------------------------------------
// getLatestRound (public query)
// ---------------------------------------------------------------------------

export const getLatestRound = query({
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
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// adversarialSummaryForRepository (public query)
// ---------------------------------------------------------------------------

export const adversarialSummaryForRepository = query({
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

    // Load recent rounds (bounded to 50 to stay within transaction limits)
    const rounds = await ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(50)

    if (rounds.length === 0) return null

    const totalRounds = rounds.length
    const redWins = rounds.filter((r) => r.roundOutcome === 'red_wins').length
    const blueWins = rounds.filter((r) => r.roundOutcome === 'blue_wins').length
    const draws = rounds.filter((r) => r.roundOutcome === 'draw').length

    const avgAttackSurfaceCoverage = Math.round(
      rounds.reduce((sum, r) => sum + r.attackSurfaceCoverage, 0) / totalRounds,
    )
    const avgBlueDetectionScore = Math.round(
      rounds.reduce((sum, r) => sum + r.blueDetectionScore, 0) / totalRounds,
    )

    const latestRound = rounds[0] // ordered desc

    return {
      totalRounds,
      redWins,
      blueWins,
      draws,
      avgAttackSurfaceCoverage,
      avgBlueDetectionScore,
      latestRound,
    }
  },
})
