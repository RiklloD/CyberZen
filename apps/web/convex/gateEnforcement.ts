import { ConvexError, v } from 'convex/values'
import { internalMutation, mutation, type MutationCtx } from './_generated/server'
import type { Id } from './_generated/dataModel'
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
    return runGateEvaluationForWorkflow(ctx, args.workflowRunId)
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

    return { gateDecisionId, decision: 'overridden' as const }
  },
})
