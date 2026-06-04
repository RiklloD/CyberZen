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

const previewInventoryComponent = v.object({
  name: v.string(),
  version: v.string(),
  ecosystem: v.string(),
  layer: v.string(),
  sourceFile: v.string(),
  hasKnownVulnerabilities: v.boolean(),
})

const advisorySyncStatus = v.union(
  v.literal('completed'),
  v.literal('skipped'),
  v.literal('failed'),
)

const validationOutcome = v.union(
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
)

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
  advisoryAggregator: v.object({
    lastCompletedAt: v.optional(v.number()),
    recentImportedDisclosures: v.number(),
    recentMatchedDisclosures: v.number(),
    recentRuns: v.array(
      v.object({
        _id: v.id('advisorySyncRuns'),
        repositoryName: v.string(),
        triggerType: v.string(),
        status: advisorySyncStatus,
        packageCount: v.number(),
        githubFetched: v.number(),
        githubImported: v.number(),
        osvFetched: v.number(),
        osvImported: v.number(),
        startedAt: v.number(),
        completedAt: v.number(),
        reason: v.optional(v.string()),
      }),
    ),
    sourceCoverage: v.array(
      v.object({
        sourceType: v.string(),
        sourceName: v.string(),
        sourceTier: v.string(),
        disclosureCount: v.number(),
        matchedCount: v.number(),
        lastPublishedAt: v.optional(v.number()),
      }),
    ),
  }),
  semanticFingerprint: v.object({
    openCandidateCount: v.number(),
    pendingValidationCount: v.number(),
    recentFindings: v.array(
      v.object({
        _id: v.id('findings'),
        title: v.string(),
        vulnClass: v.string(),
        repositoryName: v.string(),
        severity,
        confidence: v.number(),
        validationStatus: v.string(),
        createdAt: v.number(),
      }),
    ),
  }),
  exploitValidation: v.object({
    pendingCount: v.number(),
    validatedCount: v.number(),
    likelyExploitableCount: v.number(),
    recentRuns: v.array(
      v.object({
        _id: v.id('exploitValidationRuns'),
        repositoryName: v.string(),
        findingTitle: v.string(),
        status: workflowStatus,
        outcome: v.optional(validationOutcome),
        validationConfidence: v.number(),
        startedAt: v.number(),
        completedAt: v.optional(v.number()),
        evidenceSummary: v.string(),
      }),
    ),
  }),
  repositories: v.array(
    v.object({
      _id: v.id('repositories'),
      name: v.string(),
      fullName: v.string(),
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
          directDependencyCount: v.number(),
          transitiveDependencyCount: v.number(),
          buildDependencyCount: v.number(),
          containerDependencyCount: v.number(),
          runtimeDependencyCount: v.number(),
          aiModelDependencyCount: v.number(),
          vulnerableComponentCount: v.number(),
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
          previewComponents: v.array(previewInventoryComponent),
          vulnerablePreview: v.array(previewInventoryComponent),
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
  ciGateEnforcement: v.object({
    blockedCount: v.number(),
    approvedCount: v.number(),
    overrideCount: v.number(),
    recentDecisions: v.array(
      v.object({
        _id: v.id('gateDecisions'),
        repositoryName: v.string(),
        findingTitle: v.string(),
        stage: v.string(),
        decision: v.string(),
        actorType: v.string(),
        actorId: v.string(),
        justification: v.optional(v.string()),
        expiresAt: v.optional(v.number()),
        createdAt: v.number(),
      }),
    ),
  }),
  prGeneration: v.object({
    draftCount: v.number(),
    openCount: v.number(),
    mergedCount: v.number(),
    failedCount: v.number(),
    recentProposals: v.array(
      v.object({
        _id: v.id('prProposals'),
        repositoryName: v.string(),
        findingTitle: v.string(),
        status: v.string(),
        fixType: v.string(),
        fixSummary: v.string(),
        prUrl: v.optional(v.string()),
        prNumber: v.optional(v.number()),
        githubError: v.optional(v.string()),
        createdAt: v.number(),
      }),
    ),
  }),
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
    const repositoryIds = new Set(repositories.map((repository) => repository._id))

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
        const vulnerableComponents = latestComponents.filter(
          (component) => component.hasKnownVulnerabilities,
        )

        return {
          repository,
          latestSnapshot: {
            snapshotId: snapshot._id,
            commitSha: snapshot.commitSha,
            capturedAt: snapshot.capturedAt,
            totalComponents: snapshot.totalComponents,
            directDependencyCount: snapshot.directDependencyCount,
            transitiveDependencyCount: snapshot.transitiveDependencyCount,
            buildDependencyCount: snapshot.buildDependencyCount,
            containerDependencyCount: snapshot.containerDependencyCount,
            runtimeDependencyCount: snapshot.runtimeDependencyCount,
            aiModelDependencyCount: snapshot.aiModelDependencyCount,
            vulnerableComponentCount: vulnerableComponents.length,
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
            vulnerablePreview: vulnerableComponents.slice(0, 3).map((component) => ({
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

    const exploitValidationRuns = await ctx.db
      .query('exploitValidationRuns')
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

    const allGateDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(20)

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_tenant_and_captured_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .first()

    const advisorySyncRuns = await ctx.db
      .query('advisorySyncRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(6)

    const prProposalRows = await ctx.db
      .query('prProposals')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(8)

    const disclosureRows = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(4)

    const recentDisclosureRows = (
      await ctx.db
        .query('breachDisclosures')
        .withIndex('by_published_at')
        .order('desc')
        .take(40)
    ).filter(
      (disclosure) =>
        disclosure.repositoryId && repositoryIds.has(disclosure.repositoryId),
    )

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

    const syncRepositories = await Promise.all(
      advisorySyncRuns.map(async (run) => {
        const repository = await ctx.db.get(run.repositoryId)

        return {
          _id: run._id,
          repositoryName: repository?.name ?? 'Unknown repository',
          triggerType: run.triggerType,
          status: run.status,
          packageCount: run.packageCount,
          githubFetched: run.githubFetched,
          githubImported: run.githubImported,
          osvFetched: run.osvFetched,
          osvImported: run.osvImported,
          startedAt: run.startedAt,
          completedAt: run.completedAt,
          reason: run.reason,
        }
      }),
    )

    const sourceCoverageMap = new Map<
      string,
      {
        sourceType: string
        sourceName: string
        sourceTier: string
        disclosureCount: number
        matchedCount: number
        lastPublishedAt?: number
      }
    >()

    for (const disclosure of recentDisclosureRows) {
      const key = [
        disclosure.sourceType,
        disclosure.sourceName,
        disclosure.sourceTier,
      ].join(':')
      const existing = sourceCoverageMap.get(key) ?? {
        sourceType: disclosure.sourceType,
        sourceName: disclosure.sourceName,
        sourceTier: disclosure.sourceTier,
        disclosureCount: 0,
        matchedCount: 0,
        lastPublishedAt: undefined,
      }

      existing.disclosureCount += 1
      if (disclosure.matchStatus === 'matched') {
        existing.matchedCount += 1
      }
      existing.lastPublishedAt = Math.max(
        existing.lastPublishedAt ?? 0,
        disclosure.publishedAt,
      )

      sourceCoverageMap.set(key, existing)
    }

    const enrichedGateDecisions = await Promise.all(
      allGateDecisions.slice(0, 6).map(async (decision) => {
        const decisionRepository = await ctx.db.get(decision.repositoryId)
        const decisionFinding = await ctx.db.get(decision.findingId)
        return {
          _id: decision._id,
          repositoryName: decisionRepository?.name ?? 'Unknown repository',
          findingTitle: decisionFinding?.title ?? 'Unknown finding',
          stage: decision.stage,
          decision: decision.decision,
          actorType: decision.actorType,
          actorId: decision.actorId,
          justification: decision.justification,
          expiresAt: decision.expiresAt,
          createdAt: decision.createdAt,
        }
      }),
    )

    const blockedCount = allGateDecisions.filter((d) => d.decision === 'blocked').length
    const approvedCount = allGateDecisions.filter((d) => d.decision === 'approved').length
    const overrideCount = allGateDecisions.filter((d) => d.decision === 'overridden').length

    const enrichedPrProposals = await Promise.all(
      prProposalRows.map(async (proposal) => {
        const proposalRepository = await ctx.db.get(proposal.repositoryId)
        const proposalFinding = await ctx.db.get(proposal.findingId)
        return {
          _id: proposal._id,
          repositoryName: proposalRepository?.name ?? 'Unknown repository',
          findingTitle: proposalFinding?.title ?? 'Unknown finding',
          status: proposal.status,
          fixType: proposal.fixType,
          fixSummary: proposal.fixSummary,
          prUrl: proposal.prUrl,
          prNumber: proposal.prNumber,
          githubError: proposal.githubError,
          createdAt: proposal.createdAt,
        }
      }),
    )

    const activeWorkflows = workflows.filter(
      (workflow) => workflow.status === 'queued' || workflow.status === 'running',
    ).length

    const openFindings = allFindings.filter(
      (finding) => finding.status === 'open' || finding.status === 'pr_opened',
    )
    const semanticFindings = allFindings.filter(
      (finding) => finding.source === 'semantic_fingerprint',
    )
    const validationRuns = await Promise.all(
      exploitValidationRuns.map(async (run) => {
        const repository = await ctx.db.get(run.repositoryId)
        const finding = await ctx.db.get(run.findingId)

        return {
          _id: run._id,
          repositoryName: repository?.name ?? 'Unknown repository',
          findingTitle: finding?.title ?? 'Unknown finding',
          status: run.status,
          outcome: run.outcome,
          validationConfidence: run.validationConfidence,
          startedAt: run.startedAt,
          completedAt: run.completedAt,
          evidenceSummary: run.evidenceSummary,
        }
      }),
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
      advisoryAggregator: {
        lastCompletedAt: advisorySyncRuns.find((run) => run.status === 'completed')
          ?.completedAt,
        recentImportedDisclosures: recentDisclosureRows.filter(
          (disclosure) =>
            disclosure.sourceType === 'github_security_advisory' ||
            disclosure.sourceType === 'osv',
        ).length,
        recentMatchedDisclosures: recentDisclosureRows.filter(
          (disclosure) => disclosure.matchStatus === 'matched',
        ).length,
        recentRuns: syncRepositories,
        sourceCoverage: [...sourceCoverageMap.values()].sort((left, right) => {
          return right.disclosureCount - left.disclosureCount
        }),
      },
      semanticFingerprint: {
        openCandidateCount: semanticFindings.filter(
          (finding) =>
            finding.status === 'open' || finding.status === 'pr_opened',
        ).length,
        pendingValidationCount: semanticFindings.filter(
          (finding) => finding.validationStatus === 'pending',
        ).length,
        recentFindings: semanticFindings.slice(0, 4).map((finding) => {
          const repository = repositories.find(
            (repository) => repository._id === finding.repositoryId,
          )

          return {
            _id: finding._id,
            title: finding.title,
            vulnClass: finding.vulnClass,
            repositoryName: repository?.name ?? 'Unknown repository',
            severity: finding.severity,
            confidence: finding.confidence,
            validationStatus: finding.validationStatus,
            createdAt: finding.createdAt,
          }
        }),
      },
      exploitValidation: {
        pendingCount: allFindings.filter(
          (finding) =>
            finding.validationStatus === 'pending' &&
            (finding.status === 'open' || finding.status === 'pr_opened'),
        ).length,
        validatedCount: allFindings.filter(
          (finding) => finding.validationStatus === 'validated',
        ).length,
        likelyExploitableCount: allFindings.filter(
          (finding) => finding.validationStatus === 'likely_exploitable',
        ).length,
        recentRuns: validationRuns,
      },
      repositories: repositoriesWithSnapshots.map(
        ({ repository, latestSnapshot }) => ({
          _id: repository._id,
          name: repository.name,
          fullName: repository.fullName,
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
      ciGateEnforcement: {
        blockedCount,
        approvedCount,
        overrideCount,
        recentDecisions: enrichedGateDecisions,
      },
      prGeneration: {
        draftCount: prProposalRows.filter((p) => p.status === 'draft').length,
        openCount: prProposalRows.filter((p) => p.status === 'open').length,
        mergedCount: prProposalRows.filter((p) => p.status === 'merged').length,
        failedCount: prProposalRows.filter((p) => p.status === 'failed').length,
        recentProposals: enrichedPrProposals,
      },
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
