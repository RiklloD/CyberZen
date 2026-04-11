import { ConvexError, v } from 'convex/values'
import {
  internalMutation,
  mutation,
  type MutationCtx,
} from './_generated/server'
import type { Doc, Id } from './_generated/dataModel'
import { internal } from './_generated/api'
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
import { assessExploitValidation } from './lib/exploitValidation'
import { matchSemanticFingerprints } from './lib/semanticFingerprint'
import { runGateEvaluationForWorkflow } from './gateEnforcement'

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

const validationOutcome = v.union(
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
)

type RepositoryContext = {
  tenant: Doc<'tenants'>
  repository: Doc<'repositories'>
}

type GithubPushIngestInput = {
  branch: string
  commitSha: string
  changedFiles: string[]
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

async function getRepositoryContextByProviderAndFullName(
  ctx: MutationCtx,
  provider: Doc<'repositories'>['provider'],
  repositoryFullName: string,
): Promise<RepositoryContext> {
  const repository = await ctx.db
    .query('repositories')
    .withIndex('by_provider_and_full_name', (q) =>
      q.eq('provider', provider).eq('fullName', repositoryFullName),
    )
    .unique()

  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  const tenant = await ctx.db.get(repository.tenantId)

  if (!tenant) {
    throw new ConvexError('Tenant not found for repository')
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

async function ingestGithubPushForRepository(
  ctx: MutationCtx,
  repositoryContext: RepositoryContext,
  args: GithubPushIngestInput,
) {
  const { tenant, repository } = repositoryContext
  const routedWorkflow = buildGithubPushWorkflow({
    tenantSlug: tenant.slug,
    repositoryFullName: repository.fullName,
    branch: args.branch,
    commitSha: args.commitSha,
    changedFiles: args.changedFiles,
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
    branch: args.branch,
    commitSha: args.commitSha,
    changedFiles: args.changedFiles,
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
}

function semanticFingerprintSummary(args: {
  repositoryName: string
  changedFiles: string[]
  matchCount: number
  createdFindingCount: number
}) {
  if (args.matchCount === 0) {
    return `Semantic fingerprinting reviewed ${args.changedFiles.length} changed file path(s) for ${args.repositoryName} and found no candidate behavior matches.`
  }

  return `Semantic fingerprinting matched ${args.matchCount} candidate pattern(s) across ${args.changedFiles.length} changed file path(s) in ${args.repositoryName} and created ${args.createdFindingCount} finding(s).`
}

async function runSemanticFingerprintForWorkflowInternal(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
) {
  const workflowRun = await ctx.db.get(workflowRunId)

  if (!workflowRun) {
    throw new ConvexError('Workflow run not found')
  }

  const repository = await ctx.db.get(workflowRun.repositoryId)
  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  const event = await ctx.db.get(workflowRun.eventId)
  if (!event) {
    throw new ConvexError('Ingestion event not found')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const analysisTask = tasks.find((task) => task.stage === 'analysis')
  if (!analysisTask) {
    const syncedState = await syncWorkflowState(ctx, workflowRunId)
    return {
      ...syncedState,
      matchCount: 0,
      createdFindingCount: 0,
    }
  }

  for (const task of tasks.filter(
    (task) => task.order < analysisTask.order && task.status === 'queued',
  )) {
    await updateWorkflowTask(
      ctx,
      workflowRunId,
      task.order,
      'completed',
      task.stage === 'intake'
        ? `Normalized stored push metadata for ${repository.name} on ${event.branch ?? 'unknown branch'}.`
        : task.stage === 'inventory'
          ? `Reused the latest imported SBOM snapshot for ${repository.name} while the live repository scan path is still being staged.`
          : task.detail,
    )
  }

  const snapshotInventory = await loadLatestSnapshotInventory(
    ctx,
    repository._id,
  )
  const changedFiles = event.changedFiles ?? []
  const matches = matchSemanticFingerprints({
    repositoryName: repository.name,
    changedFiles,
    inventoryComponents: snapshotInventory.latestComponents.map((component) => ({
      name: component.name,
      sourceFile: component.sourceFile,
      dependents: component.dependents,
    })),
  })

  const existingFindings = await ctx.db
    .query('findings')
    .withIndex('by_workflow_run_and_source', (q) =>
      q.eq('workflowRunId', workflowRunId).eq('source', 'semantic_fingerprint'),
    )
    .collect()

  const existingClasses = new Set(
    existingFindings.map((finding) => finding.vulnClass),
  )

  let createdFindingCount = 0
  const now = Date.now()

  for (const match of matches) {
    if (existingClasses.has(match.vulnClass)) {
      continue
    }

    await ctx.db.insert('findings', {
      tenantId: workflowRun.tenantId,
      repositoryId: repository._id,
      workflowRunId,
      breachDisclosureId: undefined,
      source: 'semantic_fingerprint',
      vulnClass: match.vulnClass,
      title: match.title,
      summary: match.summary,
      confidence: match.confidence,
      severity: match.severity,
      validationStatus: 'pending',
      status: 'open',
      businessImpactScore: businessImpactScoreForSeverity(
        match.severity,
        true,
        false,
      ),
      blastRadiusSummary: match.blastRadiusSummary,
      prUrl: undefined,
      reasoningLogUrl: `artifact://reasoning/${match.fingerprintId.toLowerCase()}-${workflowRunId}`,
      pocArtifactUrl: undefined,
      affectedServices: match.affectedServices,
      affectedFiles: match.matchedFiles,
      affectedPackages: match.affectedPackages,
      regulatoryImplications: [],
      createdAt: now,
      resolvedAt: undefined,
    })

    existingClasses.add(match.vulnClass)
    createdFindingCount += 1
  }

  await updateWorkflowTask(
    ctx,
    workflowRunId,
    analysisTask.order,
    'completed',
    semanticFingerprintSummary({
      repositoryName: repository.name,
      changedFiles,
      matchCount: matches.length,
      createdFindingCount,
    }),
  )

  const syncedState = await syncWorkflowState(ctx, workflowRunId)

  return {
    ...syncedState,
    matchCount: matches.length,
    createdFindingCount,
  }
}

async function runExploitValidationForFindingInternal(
  ctx: MutationCtx,
  findingId: Id<'findings'>,
) {
  const finding = await ctx.db.get(findingId)

  if (!finding) {
    throw new ConvexError('Finding not found')
  }

  const workflowRun = await ctx.db.get(finding.workflowRunId)
  if (!workflowRun) {
    throw new ConvexError('Workflow run not found for finding')
  }

  const repository = await ctx.db.get(finding.repositoryId)
  if (!repository) {
    throw new ConvexError('Repository not found for finding')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRun._id),
    )
    .collect()

  const validationTask = tasks.find((task) => task.stage === 'validation')

  if (validationTask) {
    for (const task of tasks.filter(
      (task) => task.order < validationTask.order && task.status === 'queued',
    )) {
      await updateWorkflowTask(
        ctx,
        workflowRun._id,
        task.order,
        'completed',
        task.stage === 'analysis'
          ? `Promoted the ${finding.vulnClass.replace(/_/g, ' ')} candidate into exploit-first validation for ${repository.name}.`
          : task.detail,
      )
    }
  }

  const disclosure = finding.breachDisclosureId
    ? await ctx.db.get(finding.breachDisclosureId)
    : null
  const assessment = assessExploitValidation({
    repositoryName: repository.name,
    findingId,
    finding: {
      source: finding.source,
      vulnClass: finding.vulnClass,
      severity: finding.severity,
      confidence: finding.confidence,
      affectedFiles: finding.affectedFiles,
      affectedPackages: finding.affectedPackages,
      affectedServices: finding.affectedServices,
    },
    disclosure: disclosure
      ? {
          sourceRef: disclosure.sourceRef,
          exploitAvailable: disclosure.exploitAvailable,
          matchStatus: disclosure.matchStatus,
          fixVersion: disclosure.fixVersion,
        }
      : undefined,
  })

  const startedAt = Date.now()
  const validationRunId = await ctx.db.insert('exploitValidationRuns', {
    tenantId: finding.tenantId,
    repositoryId: finding.repositoryId,
    workflowRunId: workflowRun._id,
    findingId: finding._id,
    status: 'running',
    outcome: undefined,
    validationConfidence: finding.confidence,
    sandboxSummary: `Preparing local-first validation evidence for ${repository.name}.`,
    evidenceSummary: `Queued exploit-first validation for ${finding.title}.`,
    reproductionHint: `Start with ${finding.affectedFiles[0] ?? 'the affected code path'}.`,
    startedAt,
    completedAt: undefined,
  })

  const completedAt = Date.now()

  await ctx.db.patch('exploitValidationRuns', validationRunId, {
    status: 'completed',
    outcome: assessment.outcome,
    validationConfidence: assessment.validationConfidence,
    sandboxSummary: assessment.sandboxSummary,
    evidenceSummary: assessment.evidenceSummary,
    reproductionHint: assessment.reproductionHint,
    completedAt,
  })

  await ctx.db.patch('findings', finding._id, {
    validationStatus: assessment.outcome,
    status: assessment.outcome === 'unexploitable' ? 'resolved' : finding.status,
    reasoningLogUrl: assessment.reasoningLogUrl,
    pocArtifactUrl: assessment.pocArtifactUrl ?? finding.pocArtifactUrl,
    resolvedAt: assessment.outcome === 'unexploitable' ? completedAt : undefined,
  })

  // Fire-and-forget outbound webhook for finding.validated events.
  if (assessment.outcome !== 'unexploitable') {
    try {
      const tenant = await ctx.db.get(finding.tenantId)
      if (tenant) {
        await ctx.scheduler.runAfter(
          0,
          internal.webhooks.dispatchWebhookEvent,
          {
            tenantId: finding.tenantId,
            tenantSlug: tenant.slug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'finding.validated' as const,
              data: {
                findingId: finding._id as string,
                title: finding.title,
                severity: finding.severity,
                vulnClass: finding.vulnClass,
                validationStatus: assessment.outcome,
                validationConfidence: assessment.validationConfidence,
              },
            },
          },
        )
      }
    } catch (e) {
      console.error('[webhooks] finding.validated dispatch failed', e)
    }
  }

  if (validationTask) {
    await updateWorkflowTask(
      ctx,
      workflowRun._id,
      validationTask.order,
      'completed',
      assessment.evidenceSummary,
    )
  }

  const syncedState = await syncWorkflowState(ctx, workflowRun._id)

  return {
    ...syncedState,
    findingId: finding._id,
    validationRunId,
    outcome: assessment.outcome,
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

    // Fire-and-forget blast radius computation. Runs asynchronously so it
    // never aborts or delays the ingestion path if it fails.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.blastRadiusIntel.computeAndStoreBlastRadius,
        { findingId },
      )
    } catch (e) {
      console.error('[blast-radius] failed to schedule for finding', findingId, e)
    }

    // Fire-and-forget memory aggregation. Refreshes the repository-level
    // learning snapshot after each new finding so adversarial rounds have
    // up-to-date signal.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.agentMemory.refreshRepositoryMemory,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[agent-memory] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget attack surface score refresh. Runs after memory so the
    // new snapshot can benefit from the freshly-updated RepositoryMemoryRecord.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.attackSurfaceIntel.refreshAttackSurface,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[attack-surface] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget regulatory drift refresh. Independent of memory/attack
    // surface — driven purely by the finding set, so it can run in parallel.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.regulatoryDriftIntel.refreshRegulatoryDrift,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[regulatory-drift] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget honeypot plan refresh. Aggregates blast radius snapshots
    // already written by earlier steps, so safe to run after finding creation.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.honeypotIntel.refreshHoneypotPlan,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[honeypot] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget learning profile refresh. Aggregates findings, red/blue
    // rounds, and attack surface history — runs after all prior steps so it
    // sees the most complete picture of the repository's security history.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.learningProfileIntel.refreshLearningProfile,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[learning-profile] failed to schedule for repository', repositoryContext.repository._id, e)
    }

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
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )

    return ingestGithubPushForRepository(ctx, repositoryContext, {
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: args.changedFiles,
    })
  },
})

export const ingestGithubPushFromWebhook = internalMutation({
  args: {
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
    const repositoryContext = await getRepositoryContextByProviderAndFullName(
      ctx,
      'github',
      args.repositoryFullName,
    )

    return ingestGithubPushForRepository(ctx, repositoryContext, {
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: args.changedFiles,
    })
  },
})

export const runSemanticFingerprintForWorkflow = mutation({
  args: {
    workflowRunId: v.id('workflowRuns'),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
    matchCount: v.number(),
    createdFindingCount: v.number(),
  }),
  handler: async (ctx, args) => {
    return await runSemanticFingerprintForWorkflowInternal(
      ctx,
      args.workflowRunId,
    )
  },
})

export const runLatestSemanticFingerprint = mutation({
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
      matchCount: v.number(),
      createdFindingCount: v.number(),
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

    const workflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(10)

    const targetWorkflow = workflows.find(
      (workflow) => workflow.workflowType === 'full_scan',
    )

    if (!targetWorkflow) {
      return null
    }

    return await runSemanticFingerprintForWorkflowInternal(ctx, targetWorkflow._id)
  },
})

export const runExploitValidationForFinding = mutation({
  args: {
    findingId: v.id('findings'),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
    findingId: v.id('findings'),
    validationRunId: v.id('exploitValidationRuns'),
    outcome: validationOutcome,
  }),
  handler: async (ctx, args) => {
    return await runExploitValidationForFindingInternal(ctx, args.findingId)
  },
})

export const runLatestExploitValidation = mutation({
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
      findingId: v.id('findings'),
      validationRunId: v.id('exploitValidationRuns'),
      outcome: validationOutcome,
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

    const candidateFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(25)

    const targetFinding = candidateFindings.find(
      (finding) =>
        finding.validationStatus === 'pending' &&
        (finding.status === 'open' || finding.status === 'pr_opened'),
    )

    if (!targetFinding) {
      return null
    }

    return await runExploitValidationForFindingInternal(ctx, targetFinding._id)
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

export const runGateEvaluationForWorkflowMutation = mutation({
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

export const runLatestGateEvaluation = mutation({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      overallDecision: v.union(v.literal('approved'), v.literal('blocked')),
      blockCount: v.number(),
      totalEvaluated: v.number(),
      newDecisionCount: v.number(),
      summary: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    // Find the most recent workflow run that has a policy stage task.
    const recentWorkflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(10)

    let targetWorkflowId: Id<'workflowRuns'> | null = null

    for (const workflow of recentWorkflows) {
      const tasks = await ctx.db
        .query('workflowTasks')
        .withIndex('by_workflow_run_and_order', (q) =>
          q.eq('workflowRunId', workflow._id),
        )
        .collect()

      const hasPolicyTask = tasks.some((t) => t.stage === 'policy')
      if (hasPolicyTask) {
        targetWorkflowId = workflow._id
        break
      }
    }

    if (!targetWorkflowId) return null

    return runGateEvaluationForWorkflow(ctx, targetWorkflowId)
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
