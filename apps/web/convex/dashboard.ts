import { query } from './_generated/server'
import { v } from 'convex/values'
import { compareSnapshotComponents } from './lib/sbomDiff'

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

const workflowStatus = v.union(
  v.literal('queued'),
  v.literal('running'),
  v.literal('completed'),
  v.literal('failed'),
)

const diffComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  sourceFile: v.string(),
})

const versionChangeComponent = v.object({
  name: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  sourceFile: v.string(),
  previousVersion: v.string(),
  nextVersion: v.string(),
})

const overviewValidator = v.object({
  tenant: v.object({
    name: v.string(),
    slug: v.string(),
    deploymentMode: v.string(),
    currentPhase: v.string(),
  }),
  stats: v.object({
    openFindings: v.number(),
    validatedFindings: v.number(),
    criticalFindings: v.number(),
    activeWorkflows: v.number(),
    sbomComponents: v.number(),
  }),
  repositories: v.array(
    v.object({
      _id: v.id('repositories'),
      name: v.string(),
      provider: v.string(),
      primaryLanguage: v.string(),
      defaultBranch: v.string(),
      latestCommitSha: v.optional(v.string()),
      lastScannedAt: v.optional(v.number()),
      latestSnapshot: v.union(
        v.null(),
        v.object({
          snapshotId: v.id('sbomSnapshots'),
          commitSha: v.string(),
          capturedAt: v.number(),
          totalComponents: v.number(),
          sourceFiles: v.array(v.string()),
          comparison: v.union(
            v.null(),
            v.object({
              previousCommitSha: v.string(),
              previousCapturedAt: v.number(),
              addedCount: v.number(),
              removedCount: v.number(),
              updatedCount: v.number(),
              changedComponentCount: v.number(),
              vulnerableComponentDelta: v.number(),
              addedPreview: v.array(diffComponent),
              removedPreview: v.array(diffComponent),
              updatedPreview: v.array(versionChangeComponent),
            }),
          ),
          previewComponents: v.array(
            v.object({
              name: v.string(),
              version: v.string(),
              ecosystem: v.string(),
              layer: v.string(),
              sourceFile: v.string(),
              hasKnownVulnerabilities: v.boolean(),
            }),
          ),
        }),
      ),
    }),
  ),
  findings: v.array(
    v.object({
      _id: v.id('findings'),
      title: v.string(),
      severity,
      validationStatus: v.string(),
      status: v.string(),
      confidence: v.number(),
      source: v.string(),
      createdAt: v.number(),
    }),
  ),
  workflows: v.array(
    v.object({
      _id: v.id('workflowRuns'),
      workflowType: v.string(),
      status: workflowStatus,
      priority: v.string(),
      currentStage: v.optional(v.string()),
      summary: v.string(),
      totalTaskCount: v.number(),
      completedTaskCount: v.number(),
      startedAt: v.number(),
      completedAt: v.optional(v.number()),
      tasks: v.array(
        v.object({
          _id: v.id('workflowTasks'),
          stage: v.string(),
          title: v.string(),
          status: workflowStatus,
          order: v.number(),
        }),
      ),
    }),
  ),
  disclosures: v.array(
    v.object({
      _id: v.id('breachDisclosures'),
      packageName: v.string(),
      sourceType: v.string(),
      sourceTier: v.string(),
      sourceName: v.string(),
      sourceRef: v.string(),
      aliases: v.array(v.string()),
      repositoryName: v.optional(v.string()),
      severity,
      matchStatus: v.string(),
      versionMatchStatus: v.string(),
      matchedComponentCount: v.number(),
      affectedComponentCount: v.number(),
      matchedVersions: v.array(v.string()),
      affectedMatchedVersions: v.array(v.string()),
      affectedVersions: v.array(v.string()),
      fixVersion: v.optional(v.string()),
      matchSummary: v.string(),
      publishedAt: v.number(),
      exploitAvailable: v.boolean(),
    }),
  ),
  gateDecisions: v.array(
    v.object({
      _id: v.id('gateDecisions'),
      stage: v.string(),
      decision: v.string(),
      actorType: v.string(),
      createdAt: v.number(),
      justification: v.optional(v.string()),
    }),
  ),
  latestSnapshot: v.union(
    v.null(),
    v.object({
      _id: v.id('sbomSnapshots'),
      commitSha: v.string(),
      branch: v.string(),
      capturedAt: v.number(),
      sourceFiles: v.array(v.string()),
      totalComponents: v.number(),
      riskDelta: v.number(),
    }),
  ),
})

export const overview = query({
  args: { tenantSlug: v.string() },
  returns: v.union(v.null(), overviewValidator),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const repositoriesWithSnapshots = await Promise.all(
      repositories.map(async (repository) => {
        const snapshotHistory = await ctx.db
          .query('sbomSnapshots')
          .withIndex('by_repository_and_captured_at', (q) =>
            q.eq('repositoryId', repository._id),
          )
          .order('desc')
          .take(2)

        const snapshot = snapshotHistory[0]
        const previousSnapshot = snapshotHistory[1] ?? null

        if (!snapshot) {
          return {
            repository,
            latestSnapshot: null,
          }
        }

        const latestComponents = await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
          .collect()

        const previousComponents = previousSnapshot
          ? await ctx.db
              .query('sbomComponents')
              .withIndex('by_snapshot', (q) =>
                q.eq('snapshotId', previousSnapshot._id),
              )
              .collect()
          : []
        const comparison = previousSnapshot
          ? compareSnapshotComponents(previousComponents, latestComponents)
          : null

        return {
          repository,
          latestSnapshot: {
            snapshotId: snapshot._id,
            commitSha: snapshot.commitSha,
            capturedAt: snapshot.capturedAt,
            totalComponents: snapshot.totalComponents,
            sourceFiles: snapshot.sourceFiles,
            comparison: previousSnapshot && comparison
              ? {
                  previousCommitSha: previousSnapshot.commitSha,
                  previousCapturedAt: previousSnapshot.capturedAt,
                  addedCount: comparison.addedCount,
                  removedCount: comparison.removedCount,
                  updatedCount: comparison.updatedCount,
                  changedComponentCount: comparison.changedComponentCount,
                  vulnerableComponentDelta: comparison.vulnerableComponentDelta,
                  addedPreview: comparison.added.slice(0, 3),
                  removedPreview: comparison.removed.slice(0, 3),
                  updatedPreview: comparison.updated.slice(0, 3),
                }
              : null,
            previewComponents: latestComponents.slice(0, 4).map((component) => ({
              name: component.name,
              version: component.version,
              ecosystem: component.ecosystem,
              layer: component.layer,
              sourceFile: component.sourceFile,
              hasKnownVulnerabilities: component.hasKnownVulnerabilities,
            })),
          },
        }
      }),
    )

    const workflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(5)

    const workflowTasks = await Promise.all(
      workflows.map(async (workflow) => {
        const tasks = await ctx.db
          .query('workflowTasks')
          .withIndex('by_workflow_run_and_order', (q) =>
            q.eq('workflowRunId', workflow._id),
          )
          .collect()

        return [workflow._id, tasks] as const
      }),
    )

    const workflowTaskMap = new Map(workflowTasks)

    const allFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .collect()

    const gateDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(4)

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_tenant_and_captured_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .first()

    const disclosureRows = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(4)

    const disclosures = await Promise.all(
      disclosureRows.map(async (disclosure) => {
        const repository = disclosure.repositoryId
          ? await ctx.db.get(disclosure.repositoryId)
          : null

        return {
          _id: disclosure._id,
          packageName: disclosure.packageName,
          sourceType: disclosure.sourceType,
          sourceTier: disclosure.sourceTier,
          sourceName: disclosure.sourceName,
          sourceRef: disclosure.sourceRef,
          aliases: disclosure.aliases,
          repositoryName: repository?.name,
          severity: disclosure.severity,
          matchStatus: disclosure.matchStatus,
          versionMatchStatus: disclosure.versionMatchStatus,
          matchedComponentCount: disclosure.matchedComponentCount,
          affectedComponentCount: disclosure.affectedComponentCount,
          matchedVersions: disclosure.matchedVersions,
          affectedMatchedVersions: disclosure.affectedMatchedVersions,
          affectedVersions: disclosure.affectedVersions,
          fixVersion: disclosure.fixVersion,
          matchSummary: disclosure.matchSummary,
          publishedAt: disclosure.publishedAt,
          exploitAvailable: disclosure.exploitAvailable,
        }
      }),
    )

    const activeWorkflows = workflows.filter(
      (workflow) => workflow.status === 'queued' || workflow.status === 'running',
    ).length

    const openFindings = allFindings.filter(
      (finding) => finding.status === 'open' || finding.status === 'pr_opened',
    )

    const validatedFindings = allFindings.filter(
      (finding) => finding.validationStatus === 'validated',
    ).length

    const criticalFindings = openFindings.filter(
      (finding) =>
        finding.severity === 'critical' || finding.severity === 'high',
    ).length

    return {
      tenant: {
        name: tenant.name,
        slug: tenant.slug,
        deploymentMode: tenant.deploymentMode,
        currentPhase: tenant.currentPhase,
      },
      stats: {
        openFindings: openFindings.length,
        validatedFindings,
        criticalFindings,
        activeWorkflows,
        sbomComponents: latestSnapshot?.totalComponents ?? 0,
      },
      repositories: repositoriesWithSnapshots.map(
        ({ repository, latestSnapshot }) => ({
          _id: repository._id,
          name: repository.name,
          provider: repository.provider,
          primaryLanguage: repository.primaryLanguage,
          defaultBranch: repository.defaultBranch,
          latestCommitSha: repository.latestCommitSha,
          lastScannedAt: repository.lastScannedAt,
          latestSnapshot,
        }),
      ),
      findings: openFindings.slice(0, 5).map((finding) => ({
        _id: finding._id,
        title: finding.title,
        severity: finding.severity,
        validationStatus: finding.validationStatus,
        status: finding.status,
        confidence: finding.confidence,
        source: finding.source,
        createdAt: finding.createdAt,
      })),
      workflows: workflows.map((workflow) => ({
        _id: workflow._id,
        workflowType: workflow.workflowType,
        status: workflow.status,
        priority: workflow.priority,
        currentStage: workflow.currentStage,
        summary: workflow.summary,
        totalTaskCount: workflow.totalTaskCount,
        completedTaskCount: workflow.completedTaskCount,
        startedAt: workflow.startedAt,
        completedAt: workflow.completedAt,
        tasks: (workflowTaskMap.get(workflow._id) ?? []).map((task) => ({
          _id: task._id,
          stage: task.stage,
          title: task.title,
          status: task.status,
          order: task.order,
        })),
      })),
      disclosures,
      gateDecisions: gateDecisions.map((decision) => ({
        _id: decision._id,
        stage: decision.stage,
        decision: decision.decision,
        actorType: decision.actorType,
        createdAt: decision.createdAt,
        justification: decision.justification,
      })),
      latestSnapshot: latestSnapshot
        ? {
            _id: latestSnapshot._id,
            commitSha: latestSnapshot.commitSha,
            branch: latestSnapshot.branch,
            capturedAt: latestSnapshot.capturedAt,
            sourceFiles: latestSnapshot.sourceFiles,
            totalComponents: latestSnapshot.totalComponents,
            riskDelta: latestSnapshot.riskDelta,
          }
        : null,
    }
  },
})
