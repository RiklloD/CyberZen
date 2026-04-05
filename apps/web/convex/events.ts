import { ConvexError, v } from 'convex/values'
import { mutation, type MutationCtx } from './_generated/server'
import type { Doc, Id } from './_generated/dataModel'
import {
  buildBreachDisclosureWorkflow,
  buildGithubPushWorkflow,
  type WorkflowTaskTemplate,
} from './lib/eventRouter'
import {
  buildDisclosureMatchSummary,
  businessImpactScoreForSeverity,
  matchDisclosureToInventory,
  normalizeEcosystem,
  normalizePackageName,
  uniqueStrings,
  type BreachMatchStatus,
  type InventoryComponentForBreachMatch,
} from './lib/breachMatching'
import {
  normalizeGithubSecurityAdvisory,
  normalizeOsvAdvisory,
  type NormalizedDisclosure,
} from './lib/breachFeeds'

const lifecycleStatus = v.union(
  v.literal('queued'),
  v.literal('running'),
  v.literal('completed'),
  v.literal('failed'),
)

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

type RepositoryContext = {
  tenant: Doc<'tenants'>
  repository: Doc<'repositories'>
}

type SnapshotInventory = {
  latestSnapshot: Doc<'sbomSnapshots'> | null
  latestComponents: Doc<'sbomComponents'>[]
}

type CanonicalDisclosureInput = NormalizedDisclosure

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
  await ctx.db.patch('workflowTasks', task._id, {
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

async function getRepositoryContext(
  ctx: MutationCtx,
  tenantSlug: string,
  repositoryFullName: string,
): Promise<RepositoryContext> {
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()

  if (!tenant) {
    throw new ConvexError('Tenant not found')
  }

  const repository = await ctx.db
    .query('repositories')
    .withIndex('by_tenant_and_full_name', (q) =>
      q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
    )
    .unique()

  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  return {
    tenant,
    repository,
  }
}

async function loadLatestSnapshotInventory(
  ctx: MutationCtx,
  repositoryId: Id<'repositories'>,
): Promise<SnapshotInventory> {
  const latestSnapshot = await ctx.db
    .query('sbomSnapshots')
    .withIndex('by_repository_and_captured_at', (q) =>
      q.eq('repositoryId', repositoryId),
    )
    .order('desc')
    .first()

  if (!latestSnapshot) {
    return {
      latestSnapshot: null,
      latestComponents: [],
    }
  }

  const latestComponents = await ctx.db
    .query('sbomComponents')
    .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
    .collect()

  return {
    latestSnapshot,
    latestComponents,
  }
}

function disclosureFindingTitle(packageName: string, repositoryName: string) {
  return `${packageName} disclosure matched live inventory in ${repositoryName}`
}

function disclosureFindingSummary(args: {
  packageName: string
  disclosureSummary: string
  repositoryName: string
  matchedVersions: string[]
  matchedSourceFiles: string[]
}) {
  const versionSummary =
    args.matchedVersions.length > 0
      ? ` Observed versions: ${args.matchedVersions.join(', ')}.`
      : ''
  const fileSummary =
    args.matchedSourceFiles.length > 0
      ? ` Source manifests: ${args.matchedSourceFiles.join(', ')}.`
      : ''

  return `${args.disclosureSummary} Sentinel matched ${args.packageName} in the latest SBOM snapshot for ${args.repositoryName}.${versionSummary}${fileSummary}`.trim()
}

function blastRadiusSummary(args: {
  repositoryName: string
  directComponentCount: number
  transitiveComponentCount: number
  containerComponentCount: number
}) {
  const segments: string[] = []

  if (args.directComponentCount > 0) {
    segments.push(`${args.directComponentCount} direct dependency path(s)`)
  }

  if (args.transitiveComponentCount > 0) {
    segments.push(`${args.transitiveComponentCount} transitive path(s)`)
  }

  if (args.containerComponentCount > 0) {
    segments.push(`${args.containerComponentCount} container layer reference(s)`)
  }

  if (segments.length === 0) {
    segments.push('tracked package exposure')
  }

  return `${args.repositoryName} is exposed through ${segments.join(', ')}.`
}

async function ingestCanonicalDisclosure(
  ctx: MutationCtx,
  repositoryContext: RepositoryContext,
  snapshotInventory: SnapshotInventory,
  disclosure: CanonicalDisclosureInput,
) {
  const { tenant, repository } = repositoryContext
  const routedWorkflow = buildBreachDisclosureWorkflow({
    packageName: disclosure.packageName,
    sourceName: disclosure.sourceName,
    sourceRef: disclosure.sourceRef,
    severity: disclosure.severity,
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
      .withIndex('by_repository_and_source_ref', (q) =>
        q.eq('repositoryId', repository._id).eq('sourceRef', disclosure.sourceRef),
      )
      .unique()

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

  const nameAndVersionMatch =
    snapshotInventory.latestSnapshot === null
      ? {
          matchStatus: 'no_snapshot' as BreachMatchStatus,
          versionMatchStatus: 'unknown' as const,
          matchedComponents: [] as InventoryComponentForBreachMatch[],
          affectedComponents: [] as InventoryComponentForBreachMatch[],
          matchedComponentCount: 0,
          affectedComponentCount: 0,
          matchedVersions: [] as string[],
          affectedMatchedVersions: [] as string[],
          matchedSourceFiles: [] as string[],
          directComponentCount: 0,
          transitiveComponentCount: 0,
          containerComponentCount: 0,
        }
      : matchDisclosureToInventory({
          packageName: disclosure.packageName,
          ecosystem: disclosure.ecosystem,
          affectedVersions: disclosure.affectedVersions,
          fixVersion: disclosure.fixVersion,
          components: snapshotInventory.latestComponents,
        })

  const matchSummary = buildDisclosureMatchSummary({
    packageName: disclosure.packageName,
    repositoryName: repository.name,
    matchStatus: nameAndVersionMatch.matchStatus,
    matchedComponentCount: nameAndVersionMatch.matchedComponentCount,
    affectedComponentCount: nameAndVersionMatch.affectedComponentCount,
    matchedVersions: nameAndVersionMatch.matchedVersions,
    affectedMatchedVersions: nameAndVersionMatch.affectedMatchedVersions,
    affectedVersions: disclosure.affectedVersions,
    fixVersion: disclosure.fixVersion,
  })

  const now = Date.now()
  const disclosureId = await ctx.db.insert('breachDisclosures', {
    repositoryId: repository._id,
    workflowRunId: undefined,
    packageName: disclosure.packageName,
    normalizedPackageName: normalizePackageName(disclosure.packageName),
    ecosystem: normalizeEcosystem(disclosure.ecosystem),
    sourceType: disclosure.sourceType,
    sourceTier: disclosure.sourceTier,
    sourceName: disclosure.sourceName,
    sourceRef: disclosure.sourceRef,
    aliases: uniqueStrings(disclosure.aliases),
    summary: disclosure.summary,
    severity: disclosure.severity,
    affectedVersions: disclosure.affectedVersions,
    fixVersion: disclosure.fixVersion,
    exploitAvailable: disclosure.exploitAvailable,
    matchStatus: nameAndVersionMatch.matchStatus,
    versionMatchStatus: nameAndVersionMatch.versionMatchStatus,
    matchedSnapshotId: snapshotInventory.latestSnapshot?._id,
    matchedComponentCount: nameAndVersionMatch.matchedComponentCount,
    affectedComponentCount: nameAndVersionMatch.affectedComponentCount,
    matchedVersions: nameAndVersionMatch.matchedVersions,
    affectedMatchedVersions: nameAndVersionMatch.affectedMatchedVersions,
    matchSummary,
    findingId: undefined,
    publishedAt: disclosure.publishedAt ?? now,
  })

  const eventId = await ctx.db.insert('ingestionEvents', {
    tenantId: tenant._id,
    repositoryId: repository._id,
    dedupeKey: routedWorkflow.dedupeKey,
    kind: routedWorkflow.kind,
    source: routedWorkflow.source,
    workflowType: routedWorkflow.workflowType,
    status: 'queued',
    externalRef: disclosure.sourceRef,
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

  await ctx.db.patch('breachDisclosures', disclosureId, {
    workflowRunId,
  })

  await updateWorkflowTask(
    ctx,
    workflowRunId,
    0,
    'completed',
    `Normalized ${disclosure.packageName} from ${disclosure.sourceName} and linked it to ${repository.name}.`,
  )

  await updateWorkflowTask(ctx, workflowRunId, 1, 'completed', matchSummary)

  if (nameAndVersionMatch.affectedComponents.length > 0) {
    const affectedPackages = uniqueStrings(
      nameAndVersionMatch.affectedComponents.map((component) => component.name),
    )
    const affectedServices = uniqueStrings(
      nameAndVersionMatch.affectedComponents.flatMap(
        (component) => component.dependents,
      ),
    )

    for (const component of nameAndVersionMatch.affectedComponents) {
      if (!component._id) {
        continue
      }

      await ctx.db.patch('sbomComponents', component._id, {
        hasKnownVulnerabilities: true,
      })
    }

    const findingId = await ctx.db.insert('findings', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      workflowRunId,
      breachDisclosureId: disclosureId,
      source: 'breach_intel',
      vulnClass: 'supply_chain_disclosure',
      title: disclosureFindingTitle(disclosure.packageName, repository.name),
      summary: disclosureFindingSummary({
        packageName: disclosure.packageName,
        disclosureSummary: disclosure.summary,
        repositoryName: repository.name,
        matchedVersions: nameAndVersionMatch.affectedMatchedVersions,
        matchedSourceFiles: nameAndVersionMatch.matchedSourceFiles,
      }),
      confidence: 0.92,
      severity: disclosure.severity,
      validationStatus: 'pending',
      status: 'open',
      businessImpactScore: businessImpactScoreForSeverity(
        disclosure.severity,
        nameAndVersionMatch.directComponentCount > 0,
        disclosure.exploitAvailable,
      ),
      blastRadiusSummary: blastRadiusSummary({
        repositoryName: repository.name,
        directComponentCount: nameAndVersionMatch.directComponentCount,
        transitiveComponentCount: nameAndVersionMatch.transitiveComponentCount,
        containerComponentCount: nameAndVersionMatch.containerComponentCount,
      }),
      prUrl: undefined,
      reasoningLogUrl: `artifact://reasoning/${disclosure.sourceRef.toLowerCase()}`,
      pocArtifactUrl: undefined,
      affectedServices:
        affectedServices.length > 0 ? affectedServices : [repository.name],
      affectedFiles: nameAndVersionMatch.matchedSourceFiles,
      affectedPackages,
      regulatoryImplications: [],
      createdAt: now,
      resolvedAt: undefined,
    })

    await ctx.db.patch('breachDisclosures', disclosureId, {
      findingId,
    })

    await updateWorkflowTask(
      ctx,
      workflowRunId,
      2,
      'running',
      `Created finding ${findingId} after confirming ${nameAndVersionMatch.affectedComponentCount} affected tracked component(s); exploit-first validation is now ready to run.`,
    )
  } else {
    const validationDetail =
      nameAndVersionMatch.matchStatus === 'no_snapshot'
        ? 'Skipped exploit-first validation because this repository has no imported SBOM snapshot yet.'
        : nameAndVersionMatch.matchStatus === 'version_unknown'
          ? 'Skipped exploit-first validation because the package is present but advisory version coverage could not be evaluated automatically yet.'
          : nameAndVersionMatch.matchStatus === 'version_unaffected'
            ? 'Skipped exploit-first validation because the tracked package version is outside the disclosed affected range.'
            : 'Skipped exploit-first validation because the disclosure did not match the latest tracked inventory.'
    const decisionDetail =
      nameAndVersionMatch.matchStatus === 'no_snapshot'
        ? 'Gate posture is unchanged until an SBOM snapshot is available for this repository.'
        : nameAndVersionMatch.matchStatus === 'version_unknown'
          ? 'Gate posture stayed unchanged because the advisory package matched by name, but version impact still needs manual confirmation.'
          : nameAndVersionMatch.matchStatus === 'version_unaffected'
            ? 'Gate posture stayed unchanged because the tracked package version is already outside the affected advisory range.'
            : 'Gate posture stayed unchanged because no live package exposure was found.'

    await updateWorkflowTask(
      ctx,
      workflowRunId,
      2,
      'completed',
      validationDetail,
    )
    await updateWorkflowTask(
      ctx,
      workflowRunId,
      3,
      'completed',
      decisionDetail,
    )
  }

  await syncWorkflowState(ctx, workflowRunId)

  return {
    eventId,
    workflowRunId,
    disclosureId,
    deduped: false,
  }
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

  await ctx.db.patch('workflowRuns', workflowRunId, {
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

  await ctx.db.patch('ingestionEvents', workflowRun.eventId, {
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

const githubSecurityAdvisoryValidator = v.object({
  ghsaId: v.string(),
  summary: v.string(),
  description: v.optional(v.string()),
  severity,
  aliases: v.optional(v.array(v.string())),
  exploitAvailable: v.optional(v.boolean()),
  publishedAt: v.optional(v.number()),
  vulnerabilities: v.array(
    v.object({
      packageName: v.string(),
      ecosystem: v.string(),
      vulnerableVersionRange: v.optional(v.string()),
      firstPatchedVersion: v.optional(v.string()),
    }),
  ),
})

const osvAdvisoryValidator = v.object({
  id: v.string(),
  summary: v.string(),
  details: v.optional(v.string()),
  severity: v.optional(severity),
  severityScore: v.optional(v.number()),
  aliases: v.optional(v.array(v.string())),
  exploitAvailable: v.optional(v.boolean()),
  publishedAt: v.optional(v.number()),
  affected: v.array(
    v.object({
      packageName: v.string(),
      ecosystem: v.string(),
      versions: v.optional(v.array(v.string())),
      ranges: v.optional(
        v.array(
          v.object({
            type: v.optional(v.string()),
            events: v.array(
              v.object({
                introduced: v.optional(v.string()),
                fixed: v.optional(v.string()),
                lastAffected: v.optional(v.string()),
                limit: v.optional(v.string()),
              }),
            ),
          }),
        ),
      ),
    }),
  ),
})

export const ingestBreachDisclosure = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packageName: v.string(),
    sourceName: v.string(),
    sourceRef: v.string(),
    summary: v.string(),
    ecosystem: v.optional(v.string()),
    sourceType: v.optional(
      v.union(
        v.literal('manual'),
        v.literal('github_security_advisory'),
        v.literal('osv'),
      ),
    ),
    sourceTier: v.optional(
      v.union(v.literal('tier_1'), v.literal('tier_2'), v.literal('tier_3')),
    ),
    affectedVersions: v.optional(v.array(v.string())),
    fixVersion: v.optional(v.string()),
    exploitAvailable: v.optional(v.boolean()),
    aliases: v.optional(v.array(v.string())),
    publishedAt: v.optional(v.number()),
    severity,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      packageName: args.packageName,
      ecosystem: args.ecosystem ?? 'unknown',
      sourceName: args.sourceName,
      sourceRef: args.sourceRef,
      sourceType: args.sourceType ?? 'manual',
      sourceTier: args.sourceTier ?? 'tier_1',
      summary: args.summary,
      severity: args.severity,
      affectedVersions: args.affectedVersions ?? [],
      fixVersion: args.fixVersion,
      aliases: args.aliases ?? [args.sourceRef],
      exploitAvailable: args.exploitAvailable ?? false,
      publishedAt: args.publishedAt,
    })
  },
})

export const ingestGithubSecurityAdvisory = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    advisory: githubSecurityAdvisoryValidator,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )
    const normalizedDisclosure = normalizeGithubSecurityAdvisory({
      advisory: args.advisory,
      inventoryComponents: snapshotInventory.latestComponents,
    })

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      ...normalizedDisclosure,
    })
  },
})

export const ingestOsvAdvisory = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    advisory: osvAdvisoryValidator,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )
    const normalizedDisclosure = normalizeOsvAdvisory({
      advisory: args.advisory,
      inventoryComponents: snapshotInventory.latestComponents,
    })

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      ...normalizedDisclosure,
    })
  },
})
