import { ConvexError, v } from 'convex/values'
import { internalMutation, mutation, query, type MutationCtx } from './_generated/server'
import type { Id } from './_generated/dataModel'
import { internal, api } from './_generated/api'
import {
  assessGateFinding,
  computeWorkflowGatePosture,
  DEFAULT_GATE_POLICY,
  type GatePolicy,
} from './lib/gatePolicy'

// Load the active gate policy for a tenant, falling back to the default if none is configured.
async function loadActivePolicyForTenant(
  ctx: MutationCtx,
  tenantId: Id<'tenants'>,
): Promise<GatePolicy> {
  const policy = await ctx.db
    .query('gatePolicies')
    .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
    .filter((q) => q.eq(q.field('isActive'), true))
    .first()

  if (!policy) {
    return DEFAULT_GATE_POLICY
  }

  return {
    blockOnSeverities: policy.blockOnSeverities,
    blockOnValidationStatuses: policy.blockOnValidationStatuses,
    requireExplicitApprovalForCritical: policy.requireExplicitApprovalForCritical,
  }
}

// Shared helper: run the policy engine on a workflow's findings, write gate
// decision records for each finding, and advance the policy stage task.
// Exported so events.ts can call it directly inside the same mutation transaction.
export async function runGateEvaluationForWorkflow(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
) {
  const workflowRun = await ctx.db.get(workflowRunId)
  if (!workflowRun) throw new ConvexError('Workflow run not found')

  const repository = await ctx.db.get(workflowRun.repositoryId)
  if (!repository) throw new ConvexError('Repository not found')

  const event = await ctx.db.get(workflowRun.eventId)
  if (!event) throw new ConvexError('Ingestion event not found')

  const branch = event.branch ?? repository.defaultBranch

  // Prefix scan on the composite index to get all findings for this workflow run.
  const allFindings = await ctx.db
    .query('findings')
    .withIndex('by_workflow_run_and_source', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const policy = await loadActivePolicyForTenant(ctx, workflowRun.tenantId)

  const assessments = allFindings.map((finding) =>
    assessGateFinding({
      finding: {
        id: finding._id,
        title: finding.title,
        severity: finding.severity,
        validationStatus: finding.validationStatus,
        status: finding.status,
        source: finding.source,
        confidence: finding.confidence,
      },
      policy,
      repositoryName: repository.name,
      branch,
    }),
  )

  const posture = computeWorkflowGatePosture(assessments, repository.name)

  // Deduplicate: skip findings that already have a gate decision in this run.
  const existingDecisions = await ctx.db
    .query('gateDecisions')
    .withIndex('by_workflow_run', (q) => q.eq('workflowRunId', workflowRunId))
    .collect()
  const existingFindingIds = new Set(existingDecisions.map((d) => d.findingId))

  const now = Date.now()
  let newDecisionCount = 0

  for (const assessment of assessments) {
    const findingId = assessment.findingId as Id<'findings'>
    if (existingFindingIds.has(findingId)) continue

    await ctx.db.insert('gateDecisions', {
      tenantId: workflowRun.tenantId,
      repositoryId: repository._id,
      workflowRunId,
      findingId,
      stage: 'policy',
      decision: assessment.decision,
      actorType: 'agent',
      actorId: 'gate_policy_agent',
      justification: assessment.justification,
      expiresAt: undefined,
      createdAt: now,
    })

    newDecisionCount += 1
  }

  // Find and advance the policy stage task if it is still queued.
  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const policyTask = tasks.find((t) => t.stage === 'policy' && t.status === 'queued')

  if (policyTask) {
    // Complete any earlier queued tasks that were skipped.
    for (const task of tasks.filter(
      (t) => t.order < policyTask.order && t.status === 'queued',
    )) {
      await ctx.db.patch('workflowTasks', task._id, {
        status: 'completed',
        startedAt: task.startedAt ?? now,
        completedAt: now,
      })
    }

    await ctx.db.patch('workflowTasks', policyTask._id, {
      status: 'completed',
      startedAt: policyTask.startedAt ?? now,
      completedAt: now,
      detail: posture.summary,
    })
  }

  // Sync workflow run status from updated task state.
  const updatedTasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const completedCount = updatedTasks.filter((t) => t.status === 'completed').length
  const hasIncomplete = updatedTasks.some(
    (t) => t.status === 'queued' || t.status === 'running',
  )
  const nextQueuedTask = updatedTasks.find((t) => t.status === 'queued')
  const lastTask = updatedTasks.at(-1)

  await ctx.db.patch('workflowRuns', workflowRunId, {
    completedTaskCount: completedCount,
    status: hasIncomplete ? 'running' : 'completed',
    currentStage: hasIncomplete
      ? (nextQueuedTask?.stage ?? lastTask?.stage)
      : (policyTask?.stage ?? lastTask?.stage),
    completedAt: hasIncomplete ? undefined : now,
    summary: posture.summary,
  })

  await ctx.db.patch('ingestionEvents', workflowRun.eventId, {
    status: hasIncomplete ? 'running' : 'completed',
  })

  return {
    workflowRunId,
    overallDecision: posture.overallDecision,
    blockCount: posture.blockCount,
    totalEvaluated: posture.totalEvaluated,
    newDecisionCount,
    summary: posture.summary,
  }
}

// Internal mutation wrapper — callable via ctx.runMutation from actions.
export const evaluateGateForWorkflow = internalMutation({
  args: { workflowRunId: v.id('workflowRuns') },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    overallDecision: v.union(v.literal('approved'), v.literal('blocked')),
    blockCount: v.number(),
    totalEvaluated: v.number(),
    newDecisionCount: v.number(),
    summary: v.string(),
  }),
  handler: async (ctx, args) => {
    const result = await runGateEvaluationForWorkflow(ctx, args.workflowRunId)

    // Fire-and-forget outbound webhook for gate.blocked events.
    if (result.overallDecision === 'blocked') {
      try {
        const workflowRun = await ctx.db.get(args.workflowRunId)
        if (workflowRun) {
          const [tenant, repository, event] = await Promise.all([
            ctx.db.get(workflowRun.tenantId),
            ctx.db.get(workflowRun.repositoryId),
            ctx.db.get(workflowRun.eventId),
          ])
          if (tenant && repository && event) {
            const allDecisions = await ctx.db
              .query('gateDecisions')
              .withIndex('by_workflow_run', (q) =>
                q.eq('workflowRunId', args.workflowRunId),
              )
              .take(50)
            const blockedReasons = allDecisions
              .filter((d) => d.decision === 'blocked')
              .map((d) => d.justification)
            await ctx.scheduler.runAfter(
              0,
              internal.webhooks.dispatchWebhookEvent,
              {
                tenantId: tenant._id,
                tenantSlug: tenant.slug,
                repositoryFullName: repository.fullName,
                eventPayload: {
                  event: 'gate.blocked' as const,
                  data: {
                    commitSha: event.commitSha ?? 'unknown',
                    branch: event.branch ?? repository.defaultBranch,
                    blockedReasons,
                    decisionPolicy: 'default',
                  },
                },
              },
            )
            // Slack alert for gate blocked
            ctx.scheduler.runAfter(0, internal.slack.sendSlackAlert, {
              kind: 'gate_blocked',
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              title: `Gate blocked on ${event.branch ?? repository.defaultBranch}`,
              summary: blockedReasons?.filter(Boolean).join('; ') ?? 'Policy violation',
            })

            // Teams alert for gate blocked (parallel to Slack)
            ctx.scheduler.runAfter(0, internal.teams.sendTeamsAlert, {
              kind: 'gate_blocked',
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              title: `Gate blocked on ${event.branch ?? repository.defaultBranch}`,
              summary: blockedReasons?.filter(Boolean).join('; ') ?? 'Policy violation',
            })

            // Opsgenie alert for gate blocked (severity: high by default)
            ctx.scheduler.runAfter(0, internal.opsgenie.sendOpsgenieAlert, {
              kind: 'gate_blocked',
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              severity: 'high',
              title: `Gate blocked on ${event.branch ?? repository.defaultBranch}`,
              summary: blockedReasons?.filter(Boolean).join('; ') ?? 'Policy violation',
            })
          }
        }
      } catch (e) {
        console.error('[webhooks] gate.blocked dispatch failed', e)
      }
    }

    // Neural Memory: Record gate decision episode for learning
    try {
      const workflowRun = await ctx.db.get(args.workflowRunId)
      if (workflowRun) {
        await ctx.runMutation(api.neuralMemory.recordEpisode, {
          repositoryId: workflowRun.repositoryId,
          episodeType: 'gate_block',
          payload: {
            workflowRunId: args.workflowRunId,
            decision: result.overallDecision,
            blockCount: result.blockCount,
            totalEvaluated: result.totalEvaluated,
            summary: result.summary,
            workflowType: workflowRun.workflowType,
            branch: workflowRun.summary, // Workflow summary often contains branch info
            timestamp: Date.now(),
          },
          sourceRef: `gate-${args.workflowRunId}`,
        })
      }
    } catch (error) {
      // Don't fail gate evaluation if Neural Memory recording fails
      console.error('Neural Memory: Failed to record gate episode:', error)
    }

    return result
  },
})

// Public mutation: record a named human override on a specific finding's gate.
// In a live integration this would be triggered by a GitHub PR review or an
// operator action through the API; for the MVP it is wired to the dashboard.
export const recordManualOverride = mutation({
  args: {
    workflowRunId: v.id('workflowRuns'),
    findingId: v.id('findings'),
    actorId: v.string(),
    justification: v.string(),
    expiresInHours: v.optional(v.number()),
  },
  returns: v.object({
    gateDecisionId: v.id('gateDecisions'),
    decision: v.literal('overridden'),
  }),
  handler: async (ctx, args) => {
    const workflowRun = await ctx.db.get(args.workflowRunId)
    if (!workflowRun) throw new ConvexError('Workflow run not found')

    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new ConvexError('Finding not found')

    const now = Date.now()
    const expiresAt = args.expiresInHours
      ? now + args.expiresInHours * 60 * 60 * 1000
      : undefined

    const gateDecisionId = await ctx.db.insert('gateDecisions', {
      tenantId: workflowRun.tenantId,
      repositoryId: workflowRun.repositoryId,
      workflowRunId: args.workflowRunId,
      findingId: args.findingId,
      stage: 'policy',
      decision: 'overridden',
      actorType: 'user',
      actorId: args.actorId,
      justification: args.justification,
      expiresAt,
      createdAt: now,
    })

    // Fire-and-forget outbound webhook for gate.override events.
    try {
      const [tenant, repository, event] = await Promise.all([
        ctx.db.get(workflowRun.tenantId),
        ctx.db.get(workflowRun.repositoryId),
        ctx.db.get(workflowRun.eventId),
      ])
      if (tenant && repository && event) {
        await ctx.scheduler.runAfter(
          0,
          internal.webhooks.dispatchWebhookEvent,
          {
            tenantId: tenant._id,
            tenantSlug: tenant.slug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'gate.override' as const,
              data: {
                commitSha: event.commitSha ?? 'unknown',
                branch: event.branch ?? repository.defaultBranch,
                overriddenBy: args.actorId,
                decisionPolicy: 'default',
              },
            },
          },
        )
      }
    } catch (e) {
      console.error('[webhooks] gate.override dispatch failed', e)
    }

    return { gateDecisionId, decision: 'overridden' as const }
  },
})

// ---------------------------------------------------------------------------
// Queries — used by the §1.17 Gate Enforcement Details panels
// ---------------------------------------------------------------------------

/** List gate decisions for a repository (most recent first). */
export const listGateDecisionsForRepository = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.array(
    v.object({
      _id: v.id('gateDecisions'),
      findingId: v.id('findings'),
      findingTitle: v.string(),
      findingSeverity: v.string(),
      repositoryName: v.string(),
      workflowRunId: v.id('workflowRuns'),
      stage: v.string(),
      decision: v.union(
        v.literal('approved'),
        v.literal('blocked'),
        v.literal('overridden'),
      ),
      actorType: v.string(),
      actorId: v.string(),
      justification: v.optional(v.string()),
      expiresAt: v.optional(v.number()),
      createdAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return []

    const decisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_repository_and_stage', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(50)

    const results = await Promise.all(
      decisions.map(async (d) => {
        const finding = await ctx.db.get(d.findingId)
        return {
          _id: d._id,
          findingId: d.findingId,
          findingTitle: finding?.title ?? 'Unknown finding',
          findingSeverity: finding?.severity ?? 'unknown',
          repositoryName: repository.fullName.split('/').pop() ?? repository.fullName,
          workflowRunId: d.workflowRunId,
          stage: d.stage,
          decision: d.decision,
          actorType: d.actorType,
          actorId: d.actorId,
          justification: d.justification,
          expiresAt: d.expiresAt,
          createdAt: d.createdAt,
        }
      }),
    )

    return results
  },
})

/** Detailed view of a single gate decision — includes the full policy trace
 *  (all decisions for the same finding/workflow run) and override history. */
export const getGateDecisionDetail = query({
  args: {
    gateDecisionId: v.id('gateDecisions'),
  },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id('gateDecisions'),
      findingId: v.id('findings'),
      findingTitle: v.string(),
      findingSeverity: v.string(),
      findingSource: v.string(),
      repositoryName: v.string(),
      repositoryFullName: v.string(),
      workflowRunId: v.id('workflowRuns'),
      stage: v.string(),
      decision: v.union(
        v.literal('approved'),
        v.literal('blocked'),
        v.literal('overridden'),
      ),
      actorType: v.string(),
      actorId: v.string(),
      justification: v.optional(v.string()),
      expiresAt: v.optional(v.number()),
      createdAt: v.number(),
      policyTrace: v.array(
        v.object({
          _id: v.id('gateDecisions'),
          decision: v.union(
            v.literal('approved'),
            v.literal('blocked'),
            v.literal('overridden'),
          ),
          actorType: v.string(),
          actorId: v.string(),
          justification: v.optional(v.string()),
          expiresAt: v.optional(v.number()),
          createdAt: v.number(),
        }),
      ),
      overrideHistory: v.array(
        v.object({
          _id: v.id('gateDecisions'),
          actorType: v.string(),
          actorId: v.string(),
          justification: v.optional(v.string()),
          expiresAt: v.optional(v.number()),
          createdAt: v.number(),
        }),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const decision = await ctx.db.get(args.gateDecisionId)
    if (!decision) return null

    const [finding, repository] = await Promise.all([
      ctx.db.get(decision.findingId),
      ctx.db.get(decision.repositoryId),
    ])

    if (!repository) return null

    // All gate decisions for the same workflow run (policy trace)
    const allRunDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_workflow_run', (q) =>
        q.eq('workflowRunId', decision.workflowRunId),
      )
      .order('desc')
      .collect()

    // Filter to just decisions for this finding
    const policyTrace = allRunDecisions
      .filter((d) => d.findingId === decision.findingId)
      .map((d) => ({
        _id: d._id,
        decision: d.decision,
        actorType: d.actorType,
        actorId: d.actorId,
        justification: d.justification,
        expiresAt: d.expiresAt,
        createdAt: d.createdAt,
      }))

    // Override history = only overridden decisions for this finding
    const overrideHistory = policyTrace
      .filter((d) => d.decision === 'overridden')
      .map((d) => ({
        _id: d._id,
        actorType: d.actorType,
        actorId: d.actorId,
        justification: d.justification,
        expiresAt: d.expiresAt,
        createdAt: d.createdAt,
      }))

    return {
      _id: decision._id,
      findingId: decision.findingId,
      findingTitle: finding?.title ?? 'Unknown finding',
      findingSeverity: finding?.severity ?? 'unknown',
      findingSource: finding?.source ?? 'unknown',
      repositoryName: repository.fullName.split('/').pop() ?? repository.fullName,
      repositoryFullName: repository.fullName,
      workflowRunId: decision.workflowRunId,
      stage: decision.stage,
      decision: decision.decision,
      actorType: decision.actorType,
      actorId: decision.actorId,
      justification: decision.justification,
      expiresAt: decision.expiresAt,
      createdAt: decision.createdAt,
      policyTrace,
      overrideHistory,
    }
  },
})
