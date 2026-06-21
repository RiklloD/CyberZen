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

// ---------------------------------------------------------------------------
// Shared helper: resolve a tenant by slug (returns null if not found)
// ---------------------------------------------------------------------------
async function resolveTenant(ctx: any, tenantSlug: string) {
  return ctx.db
    .query('tenants')
    .withIndex('by_slug', (q: any) => q.eq('slug', tenantSlug))
    .unique()
}

// ---------------------------------------------------------------------------
// §7.1 — Split queries (replacing the old mega-query)
// ---------------------------------------------------------------------------

// 1. kpiStats — top-line numbers for the dashboard hero tiles
export const kpiStats = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
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
      exploitValidation: v.object({
        pendingCount: v.number(),
        validatedCount: v.number(),
        likelyExploitableCount: v.number(),
      }),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const allFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .collect()

    const openFindings = allFindings.filter(
      (f: any) => f.status === 'open' || f.status === 'pr_opened',
    )

    const workflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(5)

    const activeWorkflows = workflows.filter(
      (w: any) => w.status === 'queued' || w.status === 'running',
    ).length

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_tenant_and_captured_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .first()

    const validatedFindings = allFindings.filter(
      (f: any) => f.validationStatus === 'validated',
    ).length

    const criticalFindings = openFindings.filter(
      (f: any) => f.severity === 'critical' || f.severity === 'high',
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
      exploitValidation: {
        pendingCount: allFindings.filter(
          (f: any) =>
            f.validationStatus === 'pending' &&
            (f.status === 'open' || f.status === 'pr_opened'),
        ).length,
        validatedCount: validatedFindings,
        likelyExploitableCount: allFindings.filter(
          (f: any) => f.validationStatus === 'likely_exploitable',
        ).length,
      },
    }
  },
})

// 2. recentFindings — latest open findings + semantic fingerprint findings
export const recentFindings = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
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
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
    const allFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .collect()

    const openFindings = allFindings.filter(
      (f: any) => f.status === 'open' || f.status === 'pr_opened',
    )
    const semanticFindings = allFindings.filter(
      (f: any) => f.source === 'semantic_fingerprint',
    )

    const disclosureRows = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(4)

    const disclosures = await Promise.all(
      disclosureRows.map(async (disclosure: any) => {
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

    return {
      findings: openFindings.slice(0, 5).map((f: any) => ({
        _id: f._id,
        title: f.title,
        severity: f.severity,
        validationStatus: f.validationStatus,
        status: f.status,
        confidence: f.confidence,
        source: f.source,
        createdAt: f.createdAt,
      })),
      semanticFingerprint: {
        openCandidateCount: semanticFindings.filter(
          (f: any) => f.status === 'open' || f.status === 'pr_opened',
        ).length,
        pendingValidationCount: semanticFindings.filter(
          (f: any) => f.validationStatus === 'pending',
        ).length,
        recentFindings: semanticFindings.slice(0, 4).map((f: any) => {
          const repo = repositories.find((r: any) => r._id === f.repositoryId)
          return {
            _id: f._id,
            title: f.title,
            vulnClass: f.vulnClass,
            repositoryName: repo?.name ?? 'Unknown repository',
            severity: f.severity,
            confidence: f.confidence,
            validationStatus: f.validationStatus,
            createdAt: f.createdAt,
          }
        }),
      },
      disclosures,
    }
  },
})

// 3. repoSummaries — repository list with SBOM snapshot details
export const repoSummaries = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.array(
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
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const reposWithSnapshots = await Promise.all(
      repositories.map(async (repo: any) => {
        const snapshotHistory = await ctx.db
          .query('sbomSnapshots')
          .withIndex('by_repository_and_captured_at', (q) =>
            q.eq('repositoryId', repo._id),
          )
          .order('desc')
          .take(2)

        const snapshot = snapshotHistory[0]
        const previousSnapshot = snapshotHistory[1] ?? null

        if (!snapshot) {
          return { repository: repo, latestSnapshot: null }
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
          (c: any) => c.hasKnownVulnerabilities,
        )

        return {
          repository: repo,
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
            previewComponents: latestComponents.slice(0, 6).map((c: any) => ({
              name: c.name,
              version: c.version,
              ecosystem: c.ecosystem,
              layer: c.layer,
              sourceFile: c.sourceFile,
              hasKnownVulnerabilities: c.hasKnownVulnerabilities,
            })),
            vulnerablePreview: vulnerableComponents.slice(0, 6).map((c: any) => ({
              name: c.name,
              version: c.version,
              ecosystem: c.ecosystem,
              layer: c.layer,
              sourceFile: c.sourceFile,
              hasKnownVulnerabilities: c.hasKnownVulnerabilities,
            })),
          },
        }
      }),
    )

    return reposWithSnapshots.map(({ repository: repo, latestSnapshot: snap }: any) => ({
      _id: repo._id,
      name: repo.name,
      fullName: repo.fullName,
      provider: repo.provider,
      primaryLanguage: repo.primaryLanguage,
      defaultBranch: repo.defaultBranch,
      latestCommitSha: repo.latestCommitSha,
      lastScannedAt: repo.lastScannedAt,
      latestSnapshot: snap,
    }))
  },
})

// 4. workflowEvents — active workflows with tasks
export const workflowEvents = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.array(
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
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const workflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(5)

    const workflowTasks = await Promise.all(
      workflows.map(async (w: any) => {
        const tasks = await ctx.db
          .query('workflowTasks')
          .withIndex('by_workflow_run_and_order', (q) =>
            q.eq('workflowRunId', w._id),
          )
          .collect()
        return [w._id, tasks] as const
      }),
    )
    const taskMap = new Map(workflowTasks)

    return workflows.map((w: any) => ({
      _id: w._id,
      workflowType: w.workflowType,
      status: w.status,
      priority: w.priority,
      currentStage: w.currentStage,
      summary: w.summary,
      totalTaskCount: w.totalTaskCount,
      completedTaskCount: w.completedTaskCount,
      startedAt: w.startedAt,
      completedAt: w.completedAt,
      tasks: (taskMap.get(w._id) ?? []).map((t: any) => ({
        _id: t._id,
        stage: t.stage,
        title: t.title,
        status: t.status,
        order: t.order,
      })),
    }))
  },
})

// 5. gateDecisions — CI gate enforcement data + PR generation data
export const gateDecisions = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
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
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const allGateDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(6)

    const enrichedGateDecisions = await Promise.all(
      allGateDecisions.slice(0, 6).map(async (decision: any) => {
        const repo = await ctx.db.get(decision.repositoryId)
        const finding = await ctx.db.get(decision.findingId)
        return {
          _id: decision._id,
          repositoryName: repo?.name ?? 'Unknown repository',
          findingTitle: finding?.title ?? 'Unknown finding',
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

    const blockedCount = allGateDecisions.filter((d: any) => d.decision === 'blocked').length
    const approvedCount = allGateDecisions.filter((d: any) => d.decision === 'approved').length
    const overrideCount = allGateDecisions.filter((d: any) => d.decision === 'overridden').length

    const prProposalRows = await ctx.db
      .query('prProposals')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(8)

    const enrichedPrProposals = await Promise.all(
      prProposalRows.map(async (proposal: any) => {
        const repo = await ctx.db.get(proposal.repositoryId)
        const finding = await ctx.db.get(proposal.findingId)
        return {
          _id: proposal._id,
          repositoryName: repo?.name ?? 'Unknown repository',
          findingTitle: finding?.title ?? 'Unknown finding',
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

    return {
      ciGateEnforcement: {
        blockedCount,
        approvedCount,
        overrideCount,
        recentDecisions: enrichedGateDecisions,
      },
      prGeneration: {
        draftCount: prProposalRows.filter((p: any) => p.status === 'draft').length,
        openCount: prProposalRows.filter((p: any) => p.status === 'open').length,
        mergedCount: prProposalRows.filter((p: any) => p.status === 'merged').length,
        failedCount: prProposalRows.filter((p: any) => p.status === 'failed').length,
        recentProposals: enrichedPrProposals,
      },
    }
  },
})

// 6. escalations — advisory aggregator + exploit validation runs
export const escalations = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
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
      exploitValidation: v.object({
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
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
    const repositoryIds = new Set(repositories.map((r: any) => r._id))

    const advisorySyncRuns = await ctx.db
      .query('advisorySyncRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(6)

    const recentDisclosureRows = (
      await ctx.db
        .query('breachDisclosures')
        .withIndex('by_published_at')
        .order('desc')
        .take(40)
    ).filter(
      (d: any) => d.repositoryId && repositoryIds.has(d.repositoryId),
    )

    const syncRepositories = await Promise.all(
      advisorySyncRuns.map(async (run: any) => {
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

    const repoNameById = new Map(repositories.map((r: any) => [r._id, r.name]))
    const disclosures = recentDisclosureRows.map((d: any) => ({
      _id: d._id,
      packageName: d.packageName,
      sourceType: d.sourceType,
      sourceTier: d.sourceTier,
      sourceName: d.sourceName,
      sourceRef: d.sourceRef,
      aliases: d.aliases,
      repositoryName: d.repositoryId ? repoNameById.get(d.repositoryId) : undefined,
      severity: d.severity,
      matchStatus: d.matchStatus,
      versionMatchStatus: d.versionMatchStatus,
      matchedComponentCount: d.matchedComponentCount,
      affectedComponentCount: d.affectedComponentCount,
      matchedVersions: d.matchedVersions,
      affectedMatchedVersions: d.affectedMatchedVersions,
      affectedVersions: d.affectedVersions,
      fixVersion: d.fixVersion,
      matchSummary: d.matchSummary,
      publishedAt: d.publishedAt,
      exploitAvailable: d.exploitAvailable,
    }))

    const exploitValidationRuns = await ctx.db
      .query('exploitValidationRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(5)

    const validationRuns = await Promise.all(
      exploitValidationRuns.map(async (run: any) => {
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

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_tenant_and_captured_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .first()

    return {
      advisoryAggregator: {
        lastCompletedAt: advisorySyncRuns.find((run: any) => run.status === 'completed')
          ?.completedAt,
        recentImportedDisclosures: recentDisclosureRows.filter(
          (d: any) =>
            d.sourceType === 'github_security_advisory' ||
            d.sourceType === 'osv',
        ).length,
        recentMatchedDisclosures: recentDisclosureRows.filter(
          (d: any) => d.matchStatus === 'matched',
        ).length,
        recentRuns: syncRepositories,
        sourceCoverage: [...sourceCoverageMap.values()].sort((a, b) => {
          return b.disclosureCount - a.disclosureCount
        }),
      },
      disclosures,
      exploitValidation: {
        recentRuns: validationRuns,
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

// 8. overview — aggregated data for the main dashboard page.
// Returns tenant, stats, findings, workflows, ciGateEnforcement, and
// repositories in a single query so the SPA avoids a waterfall of
// separate requests.
export const overview = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
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
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await resolveTenant(ctx, args.tenantSlug)
    if (!tenant) return null

    // ── Findings ──────────────────────────────────────────────────────
    const allFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .collect()

    const openFindings = allFindings.filter(
      (f: any) => f.status === 'open' || f.status === 'pr_opened',
    )

    const validatedFindings = allFindings.filter(
      (f: any) => f.validationStatus === 'validated',
    ).length

    const criticalFindings = openFindings.filter(
      (f: any) => f.severity === 'critical' || f.severity === 'high',
    ).length

    // ── Workflows ─────────────────────────────────────────────────────
    const workflowRows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(5)

    const activeWorkflows = workflowRows.filter(
      (w: any) => w.status === 'queued' || w.status === 'running',
    ).length

    const workflowTaskEntries = await Promise.all(
      workflowRows.map(async (w: any) => {
        const tasks = await ctx.db
          .query('workflowTasks')
          .withIndex('by_workflow_run_and_order', (q) =>
            q.eq('workflowRunId', w._id),
          )
          .collect()
        return [w._id, tasks] as const
      }),
    )
    const workflowTaskMap = new Map(workflowTaskEntries)

    // ── SBOM ──────────────────────────────────────────────────────────
    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_tenant_and_captured_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .first()

    // ── Gate decisions ────────────────────────────────────────────────
    const allGateDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(20)

    const enrichedGateDecisions = await Promise.all(
      allGateDecisions.slice(0, 6).map(async (decision: any) => {
        const repo = await ctx.db.get(decision.repositoryId)
        const finding = await ctx.db.get(decision.findingId)
        return {
          _id: decision._id,
          repositoryName: repo?.name ?? 'Unknown repository',
          findingTitle: finding?.title ?? 'Unknown finding',
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

    // ── Repositories ──────────────────────────────────────────────────
    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const reposWithSnapshots = await Promise.all(
      repositories.map(async (repo: any) => {
        const snapshotHistory = await ctx.db
          .query('sbomSnapshots')
          .withIndex('by_repository_and_captured_at', (q) =>
            q.eq('repositoryId', repo._id),
          )
          .order('desc')
          .take(2)

        const snapshot = snapshotHistory[0]
        const previousSnapshot = snapshotHistory[1] ?? null

        if (!snapshot) {
          return {
            _id: repo._id,
            name: repo.name,
            fullName: repo.fullName,
            provider: repo.provider,
            primaryLanguage: repo.primaryLanguage,
            defaultBranch: repo.defaultBranch,
            latestCommitSha: repo.latestCommitSha,
            lastScannedAt: repo.lastScannedAt,
            latestSnapshot: null,
          }
        }

        const latestComponents = await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) =>
            q.eq('snapshotId', snapshot._id),
          )
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
          (c: any) => c.hasKnownVulnerabilities,
        )

        return {
          _id: repo._id,
          name: repo.name,
          fullName: repo.fullName,
          provider: repo.provider,
          primaryLanguage: repo.primaryLanguage,
          defaultBranch: repo.defaultBranch,
          latestCommitSha: repo.latestCommitSha,
          lastScannedAt: repo.lastScannedAt,
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
            comparison,
            previewComponents: latestComponents.slice(0, 6).map((c: any) => ({
              name: c.name,
              version: c.version,
              ecosystem: c.ecosystem,
              layer: c.layer,
              sourceFile: c.sourceFile,
              hasKnownVulnerabilities: c.hasKnownVulnerabilities,
            })),
            vulnerablePreview: vulnerableComponents.slice(0, 6).map((c: any) => ({
              name: c.name,
              version: c.version,
              ecosystem: c.ecosystem,
              layer: c.layer,
              sourceFile: c.sourceFile,
              hasKnownVulnerabilities: c.hasKnownVulnerabilities,
            })),
          },
        }
      }),
    )

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
      findings: openFindings.slice(0, 8).map((f: any) => ({
        _id: f._id,
        title: f.title,
        severity: f.severity,
        validationStatus: f.validationStatus,
        status: f.status,
        confidence: f.confidence,
        source: f.source,
        createdAt: f.createdAt,
      })),
      workflows: workflowRows.map((w: any) => ({
        _id: w._id,
        workflowType: w.workflowType,
        status: w.status,
        priority: w.priority,
        currentStage: w.currentStage,
        summary: w.summary,
        totalTaskCount: w.totalTaskCount,
        completedTaskCount: w.completedTaskCount,
        startedAt: w.startedAt,
        completedAt: w.completedAt,
        tasks: (workflowTaskMap.get(w._id) ?? []).map((t: any) => ({
          _id: t._id,
          stage: t.stage,
          title: t.title,
          status: t.status,
          order: t.order,
        })),
      })),
      ciGateEnforcement: {
        blockedCount: allGateDecisions.filter(
          (d: any) => d.decision === 'blocked',
        ).length,
        approvedCount: allGateDecisions.filter(
          (d: any) => d.decision === 'approved',
        ).length,
        overrideCount: allGateDecisions.filter(
          (d: any) => d.decision === 'overridden',
        ).length,
        recentDecisions: enrichedGateDecisions,
      },
      repositories: reposWithSnapshots,
    }
  },
})
