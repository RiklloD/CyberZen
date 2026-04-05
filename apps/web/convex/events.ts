import { ConvexError, v } from 'convex/values'
import { mutation, type MutationCtx } from './_generated/server'
import type { Doc, Id } from './_generated/dataModel'
import {
  buildBreachDisclosureWorkflow,
  buildGithubPushWorkflow,
  type WorkflowTaskTemplate,
} from './lib/eventRouter'

const lifecycleStatus = v.union(
  v.literal('queued'),
  v.literal('running'),
  v.literal('completed'),
  v.literal('failed'),
)

async function insertWorkflowTasks(
  ctx: MutationCtx,
  tenantId: Id<'tenants'>,
  workflowRunId: Id<'workflowRuns'>,
  tasks: WorkflowTaskTemplate[],
) {
  for (const task of tasks) {
    await ctx.db.insert('workflowTasks', {
      tenantId,
      workflowRunId,
      status: 'queued',
      startedAt: undefined,
      completedAt: undefined,
      ...task,
    })
  }
}

async function updateWorkflowTask(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
  taskOrder: number,
  status: Doc<'workflowTasks'>['status'],
  detail?: string,
) {
  const task = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId).eq('order', taskOrder),
    )
    .unique()

  if (!task) {
    throw new ConvexError('Workflow task not found')
  }

  const now = Date.now()
  await ctx.db.patch(task._id, {
    status,
    detail: detail ?? task.detail,
    startedAt:
      status === 'running' || status === 'completed'
        ? task.startedAt ?? now
        : undefined,
    completedAt: status === 'completed' || status === 'failed' ? now : undefined,
  })

  return task
}

function buildWorkflowSummary(
  workflowType: string,
  nextStatus: Doc<'workflowRuns'>['status'],
  nextTask: Doc<'workflowTasks'> | null,
  failedTask: Doc<'workflowTasks'> | null,
  completedTaskCount: number,
  totalTaskCount: number,
) {
  const workflowLabel = workflowType.replace(/_/g, ' ')

  if (failedTask) {
    return `${failedTask.title} failed during the ${workflowLabel} workflow.`
  }

  if (nextStatus === 'completed') {
    return `Completed ${workflowLabel} with ${completedTaskCount}/${totalTaskCount} stages finished.`
  }

  if (nextTask) {
    return `Stage ${completedTaskCount + 1}/${totalTaskCount}: ${nextTask.title}.`
  }

  return `Queued ${workflowLabel} with ${totalTaskCount} planned stages.`
}

async function syncWorkflowState(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
) {
  const workflowRun = await ctx.db.get(workflowRunId)

  if (!workflowRun) {
    throw new ConvexError('Workflow run not found')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const completedTaskCount = tasks.filter(
    (task) => task.status === 'completed',
  ).length
  const failedTask = tasks.find((task) => task.status === 'failed') ?? null
  const runningTask = tasks.find((task) => task.status === 'running') ?? null
  const nextQueuedTask = tasks.find((task) => task.status === 'queued') ?? null

  const nextStatus: Doc<'workflowRuns'>['status'] = failedTask
    ? 'failed'
    : completedTaskCount === tasks.length
      ? 'completed'
      : Boolean(runningTask) || completedTaskCount > 0
        ? 'running'
        : 'queued'

  const currentStage =
    failedTask?.stage ??
    runningTask?.stage ??
    nextQueuedTask?.stage ??
    tasks.at(-1)?.stage

  await ctx.db.patch(workflowRunId, {
    status: nextStatus,
    currentStage,
    summary: buildWorkflowSummary(
      workflowRun.workflowType,
      nextStatus,
      runningTask ?? nextQueuedTask,
      failedTask,
      completedTaskCount,
      tasks.length,
    ),
    totalTaskCount: tasks.length,
    completedTaskCount,
    completedAt:
      nextStatus === 'completed' || nextStatus === 'failed'
        ? Date.now()
        : undefined,
  })

  await ctx.db.patch(workflowRun.eventId, {
    status: nextStatus,
  })

  return {
    workflowRunId,
    workflowStatus: nextStatus,
    currentStage,
    completedTaskCount,
    totalTaskCount: tasks.length,
  }
}

export const ingestGithubPush = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    changedFiles: v.array(v.string()),
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new ConvexError('Tenant not found')
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new ConvexError('Repository not found')
    }

    const routedWorkflow = buildGithubPushWorkflow(args)
    const existingEvent = await ctx.db
      .query('ingestionEvents')
      .withIndex('by_dedupe_key', (q) =>
        q.eq('dedupeKey', routedWorkflow.dedupeKey),
      )
      .unique()

    if (existingEvent) {
      const existingWorkflowRun = await ctx.db
        .query('workflowRuns')
        .withIndex('by_event', (q) => q.eq('eventId', existingEvent._id))
        .unique()

      if (!existingWorkflowRun) {
        throw new ConvexError('Existing workflow run missing for deduped event')
      }

      return {
        eventId: existingEvent._id,
        workflowRunId: existingWorkflowRun._id,
        deduped: true,
      }
    }

    const now = Date.now()
    const eventId = await ctx.db.insert('ingestionEvents', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      dedupeKey: routedWorkflow.dedupeKey,
      kind: routedWorkflow.kind,
      source: routedWorkflow.source,
      workflowType: routedWorkflow.workflowType,
      status: 'queued',
      externalRef: `${repository.provider}:${args.commitSha}`,
      summary: routedWorkflow.eventSummary,
      receivedAt: now,
    })

    const workflowRunId = await ctx.db.insert('workflowRuns', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      eventId,
      workflowType: routedWorkflow.workflowType,
      status: 'queued',
      priority: routedWorkflow.priority,
      currentStage: routedWorkflow.currentStage,
      summary: routedWorkflow.workflowSummary,
      totalTaskCount: routedWorkflow.tasks.length,
      completedTaskCount: 0,
      startedAt: now,
      completedAt: undefined,
    })

    await insertWorkflowTasks(
      ctx,
      tenant._id,
      workflowRunId,
      routedWorkflow.tasks,
    )

    await ctx.db.patch('repositories', repository._id, {
      latestCommitSha: args.commitSha,
      lastScannedAt: now,
    })

    return { eventId, workflowRunId, deduped: false }
  },
})

export const progressWorkflowTask = mutation({
  args: {
    workflowRunId: v.id('workflowRuns'),
    taskOrder: v.number(),
    status: lifecycleStatus,
    detail: v.optional(v.string()),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
  }),
  handler: async (ctx, args) => {
    await updateWorkflowTask(
      ctx,
      args.workflowRunId,
      args.taskOrder,
      args.status,
      args.detail,
    )

    return syncWorkflowState(ctx, args.workflowRunId)
  },
})

export const simulateLatestWorkflowStep = mutation({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      workflowStatus: lifecycleStatus,
      currentStage: v.optional(v.string()),
      completedTaskCount: v.number(),
      totalTaskCount: v.number(),
      advancedTaskTitle: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const activeWorkflow = (
      await ctx.db
        .query('workflowRuns')
        .withIndex('by_tenant_and_started_at', (q) =>
          q.eq('tenantId', tenant._id),
        )
        .order('desc')
        .collect()
    ).find(
      (workflow) =>
        workflow.status === 'queued' || workflow.status === 'running',
    )

    if (!activeWorkflow) {
      return null
    }

    const tasks = await ctx.db
      .query('workflowTasks')
      .withIndex('by_workflow_run_and_order', (q) =>
        q.eq('workflowRunId', activeWorkflow._id),
      )
      .collect()

    const runningTask = tasks.find((task) => task.status === 'running')
    const queuedTask = tasks.find((task) => task.status === 'queued')
    const taskToAdvance = runningTask ?? queuedTask

    if (!taskToAdvance) {
      const syncedState = await syncWorkflowState(ctx, activeWorkflow._id)
      return {
        ...syncedState,
        advancedTaskTitle: 'No queued tasks remaining',
      }
    }

    const nextStatus = runningTask ? 'completed' : 'running'
    await updateWorkflowTask(
      ctx,
      activeWorkflow._id,
      taskToAdvance.order,
      nextStatus,
      runningTask
        ? `${taskToAdvance.detail} Completed during local workflow simulation.`
        : `${taskToAdvance.detail} Started during local workflow simulation.`,
    )
    const syncedState = await syncWorkflowState(ctx, activeWorkflow._id)

    return {
      ...syncedState,
      advancedTaskTitle: taskToAdvance.title,
    }
  },
})

export const ingestBreachDisclosure = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packageName: v.string(),
    sourceName: v.string(),
    sourceRef: v.string(),
    summary: v.string(),
    severity: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('informational'),
    ),
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new ConvexError('Tenant not found')
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new ConvexError('Repository not found')
    }

    const routedWorkflow = buildBreachDisclosureWorkflow({
      packageName: args.packageName,
      sourceName: args.sourceName,
      sourceRef: args.sourceRef,
      severity: args.severity,
    })

    const existingEvent = await ctx.db
      .query('ingestionEvents')
      .withIndex('by_dedupe_key', (q) =>
        q.eq('dedupeKey', routedWorkflow.dedupeKey),
      )
      .unique()

    if (existingEvent) {
      const existingWorkflowRun = await ctx.db
        .query('workflowRuns')
        .withIndex('by_event', (q) => q.eq('eventId', existingEvent._id))
        .unique()

      if (!existingWorkflowRun) {
        throw new ConvexError('Existing workflow run missing for deduped event')
      }

      const existingDisclosure = await ctx.db
        .query('breachDisclosures')
        .withIndex('by_package_and_published_at', (q) =>
          q.eq('packageName', args.packageName),
        )
        .order('desc')
        .first()

      if (!existingDisclosure) {
        throw new ConvexError('Disclosure record missing for deduped event')
      }

      return {
        eventId: existingEvent._id,
        workflowRunId: existingWorkflowRun._id,
        disclosureId: existingDisclosure._id,
        deduped: true,
      }
    }

    const now = Date.now()
    const disclosureId = await ctx.db.insert('breachDisclosures', {
      packageName: args.packageName,
      ecosystem: 'unknown',
      sourceTier: 'tier_1',
      sourceName: args.sourceName,
      summary: args.summary,
      severity: args.severity,
      affectedVersions: [],
      fixVersion: undefined,
      exploitAvailable: false,
      publishedAt: now,
    })

    const eventId = await ctx.db.insert('ingestionEvents', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      dedupeKey: routedWorkflow.dedupeKey,
      kind: routedWorkflow.kind,
      source: routedWorkflow.source,
      workflowType: routedWorkflow.workflowType,
      status: 'queued',
      externalRef: args.sourceRef,
      summary: routedWorkflow.eventSummary,
      receivedAt: now,
    })

    const workflowRunId = await ctx.db.insert('workflowRuns', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      eventId,
      workflowType: routedWorkflow.workflowType,
      status: 'queued',
      priority: routedWorkflow.priority,
      currentStage: routedWorkflow.currentStage,
      summary: routedWorkflow.workflowSummary,
      totalTaskCount: routedWorkflow.tasks.length,
      completedTaskCount: 0,
      startedAt: now,
      completedAt: undefined,
    })

    await insertWorkflowTasks(
      ctx,
      tenant._id,
      workflowRunId,
      routedWorkflow.tasks,
    )

    return {
      eventId,
      workflowRunId,
      disclosureId,
      deduped: false,
    }
  },
})
