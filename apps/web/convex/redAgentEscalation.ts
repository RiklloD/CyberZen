// WS-14 Phase 4 — Red Agent Finding Escalation (spec 3.1.2): Convex
// entrypoints.
//
//   escalateRedAgentFindings — internalMutation: given a red_wins round,
//       creates a synthetic ingestion event + workflow run, then persists each
//       FindingCandidate as a real finding in the findings table.
//
// The dedupeKey pattern ("red_agent:{repositoryId}:{roundNumber}") ensures
// that a Convex mutation retry never double-inserts findings for the same round.

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import { escalateRedAgentRound } from './lib/redAgentEscalator'

// ---------------------------------------------------------------------------
// escalateRedAgentFindings (internal)
// ---------------------------------------------------------------------------

export const escalateRedAgentFindings = internalMutation({
  args: {
    repositoryId: v.id('repositories'),
    roundNumber: v.number(),
    // AdversarialRoundResult fields — passed through from runAdversarialRound
    // to avoid a redundant DB read of the just-inserted redBlueRound.
    redStrategySummary: v.string(),
    attackSurfaceCoverage: v.number(),
    simulatedFindingsGenerated: v.number(),
    blueDetectionScore: v.number(),
    exploitChains: v.array(v.string()),
    roundOutcome: v.union(
      v.literal('red_wins'),
      v.literal('blue_wins'),
      v.literal('draw'),
    ),
    confidenceGain: v.number(),
    summary: v.string(),
  },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // ── Idempotency guard ───────────────────────────────────────────────────
    const dedupeKey = `red_agent:${args.repositoryId}:${args.roundNumber}`
    const existing = await ctx.db
      .query('ingestionEvents')
      .withIndex('by_dedupe_key', (q) => q.eq('dedupeKey', dedupeKey))
      .unique()

    if (existing) {
      // Already escalated (Convex mutation retry) — no-op.
      return { escalated: 0, deduped: true }
    }

    // ── Compute candidates ──────────────────────────────────────────────────
    const { candidates, escalationSummary } = escalateRedAgentRound({
      round: {
        redStrategySummary: args.redStrategySummary,
        attackSurfaceCoverage: args.attackSurfaceCoverage,
        simulatedFindingsGenerated: args.simulatedFindingsGenerated,
        blueDetectionScore: args.blueDetectionScore,
        exploitChains: args.exploitChains,
        roundOutcome: args.roundOutcome,
        confidenceGain: args.confidenceGain,
        summary: args.summary,
      },
      roundNumber: args.roundNumber,
      repositoryName: repository.name,
    })

    // Shared payload for both the empty-candidate and non-empty paths.
    // Extracted here so a schema field addition only needs one edit site.
    const now = Date.now()
    const ingestionEventBase = {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      dedupeKey,
      kind: 'red_agent_round' as const,
      source: 'red_agent' as const,
      workflowType: 'red_agent_escalation' as const,
      status: 'completed' as const,
      summary: escalationSummary,
      receivedAt: now,
    }

    if (candidates.length === 0) {
      // No parseable chains — still insert the event so the dedupeKey is set,
      // preventing repeated futile attempts on subsequent retries.
      await ctx.db.insert('ingestionEvents', ingestionEventBase)
      return { escalated: 0, deduped: false }
    }

    // ── Synthetic ingestion event ───────────────────────────────────────────
    const eventId = await ctx.db.insert('ingestionEvents', ingestionEventBase)

    // ── Synthetic workflow run ──────────────────────────────────────────────
    const workflowRunId = await ctx.db.insert('workflowRuns', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      eventId,
      workflowType: 'red_agent_escalation',
      status: 'completed',
      // Red Agent wins are treated as high-priority — candidates may include
      // critical findings that need immediate gate evaluation.
      priority: 'high',
      summary: escalationSummary,
      totalTaskCount: candidates.length,
      completedTaskCount: candidates.length,
      startedAt: now,
      completedAt: now,
    })

    // ── Persist findings ────────────────────────────────────────────────────
    for (const candidate of candidates) {
      await ctx.db.insert('findings', {
        tenantId: repository.tenantId,
        repositoryId: args.repositoryId,
        workflowRunId,
        source: 'red_agent',
        vulnClass: candidate.vulnClass,
        title: candidate.title,
        summary: candidate.summary,
        confidence: candidate.confidence,
        severity: candidate.severity,
        // Red Agent wins: likely_exploitable — confirmed by simulation outcome,
        // not yet manually verified.
        validationStatus: 'likely_exploitable',
        status: 'open',
        businessImpactScore: candidate.businessImpactScore,
        blastRadiusSummary: candidate.blastRadiusSummary,
        affectedServices: candidate.affectedServices,
        affectedFiles: [],
        affectedPackages: candidate.affectedPackages,
        regulatoryImplications: [],
        createdAt: now,
      })
    }

    return { escalated: candidates.length, deduped: false }
  },
})

// ---------------------------------------------------------------------------
// getRedAgentFindingCount (public query)
//
// Returns the count of open red_agent findings for a repository.
// Bounded to 50: enough for the dashboard pill; avoids unbounded table scans.
// ---------------------------------------------------------------------------

export const getRedAgentFindingCount = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return 0

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return 0

    // Constrain both index fields to scan open findings only; source is
    // filtered in-process (no compound index needed for a single-digit count).
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'open'),
      )
      .take(50)

    return openFindings.filter((f) => f.source === 'red_agent').length
  },
})
