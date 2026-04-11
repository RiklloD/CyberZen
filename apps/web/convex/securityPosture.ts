// Security Posture Report (spec §7.1 /reports/security-posture)
//
//   getSecurityPostureReport — public query: assembles every intelligence
//       signal for a repository into a single SecurityPostureReport.

import { v } from 'convex/values'
import { query } from './_generated/server'
import {
  computeSecurityPosture,
  type PostureAttackSurface,
  type PostureFindings,
  type PostureLearningProfile,
  type PostureRedBlue,
  type PostureRegulatoryDrift,
} from './lib/securityPosture'

export const getSecurityPostureReport = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    // ── Resolve tenant and repository ────────────────────────────────────
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

    const repoId = repository._id

    // ── Open finding counts by severity ──────────────────────────────────
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repoId).eq('status', 'open'),
      )
      .take(500)

    const findings: PostureFindings = {
      openCritical: openFindings.filter((f) => f.severity === 'critical').length,
      openHigh: openFindings.filter((f) => f.severity === 'high').length,
      openMedium: openFindings.filter((f) => f.severity === 'medium').length,
      openLow: openFindings.filter((f) => f.severity === 'low').length,
    }

    // ── Latest attack surface snapshot ────────────────────────────────────
    const attackSurfaceDoc = await ctx.db
      .query('attackSurfaceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repoId),
      )
      .order('desc')
      .first()

    const attackSurface: PostureAttackSurface | null = attackSurfaceDoc
      ? { score: attackSurfaceDoc.score, trend: attackSurfaceDoc.trend }
      : null

    // ── Latest regulatory drift snapshot ──────────────────────────────────
    const driftDoc = await ctx.db
      .query('regulatoryDriftSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repoId),
      )
      .order('desc')
      .first()

    const regulatoryDrift: PostureRegulatoryDrift | null = driftDoc
      ? {
          overallDriftLevel: driftDoc.overallDriftLevel,
          criticalGapCount: driftDoc.criticalGapCount,
          affectedFrameworks: driftDoc.affectedFrameworks,
        }
      : null

    // ── Red/Blue summary ───────────────────────────────────────────────────
    const latestRound = await ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', repoId),
      )
      .order('desc')
      .first()

    let redBlue: PostureRedBlue | null = null
    if (latestRound) {
      // Sample up to 20 rounds to calculate win rate.
      const recentRounds = await ctx.db
        .query('redBlueRounds')
        .withIndex('by_repository_and_ran_at', (q) =>
          q.eq('repositoryId', repoId),
        )
        .order('desc')
        .take(20)

      const wins = recentRounds.filter((r) => r.roundOutcome === 'red_wins').length
      redBlue = {
        latestOutcome: latestRound.roundOutcome,
        redAgentWinRate: recentRounds.length > 0 ? wins / recentRounds.length : 0,
        totalRounds: recentRounds.length,
      }
    }

    // ── Latest learning profile ────────────────────────────────────────────
    const learningDoc = await ctx.db
      .query('learningProfiles')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repoId),
      )
      .order('desc')
      .first()

    const learningProfile: PostureLearningProfile | null = learningDoc
      ? {
          adaptedConfidenceScore: learningDoc.adaptedConfidenceScore,
          recurringVulnClasses: learningDoc.vulnClassPatterns
            .filter((p) => p.isRecurring)
            .map((p) => p.vulnClass),
          successfulExploitPaths: learningDoc.successfulExploitPaths.length,
        }
      : null

    // ── Latest honeypot plan ───────────────────────────────────────────────
    const honeypotDoc = await ctx.db
      .query('honeypotSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repoId),
      )
      .order('desc')
      .first()

    // ── Run computation ────────────────────────────────────────────────────
    const report = computeSecurityPosture({
      repositoryName: repository.fullName,
      findings,
      attackSurface,
      regulatoryDrift,
      redBlue,
      learningProfile,
      honeypot: honeypotDoc
        ? { totalProposals: honeypotDoc.totalProposals, topAttractiveness: honeypotDoc.topAttractiveness }
        : null,
    })

    // Return the full report alongside a timestamp for display.
    return {
      ...report,
      repositoryFullName: repository.fullName,
      computedAt: Date.now(),
    }
  },
})
