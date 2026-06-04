import { query } from './_generated/server'
import { v } from 'convex/values'
import { aggregateTrustScore } from './lib/trustScore'

export const listByTenant = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('repositories'),
      name: v.string(),
      fullName: v.string(),
      provider: v.string(),
      primaryLanguage: v.string(),
      defaultBranch: v.string(),
      latestCommitSha: v.optional(v.string()),
      lastScannedAt: v.optional(v.number()),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return []
    }

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    return repositories.map((repository) => ({
      _id: repository._id,
      name: repository.name,
      fullName: repository.fullName,
      provider: repository.provider,
      primaryLanguage: repository.primaryLanguage,
      defaultBranch: repository.defaultBranch,
      latestCommitSha: repository.latestCommitSha,
      lastScannedAt: repository.lastScannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// repositories.drilldown — full operator view of a single repository
// ---------------------------------------------------------------------------

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

const trustScoreBreakdown = v.object({
  repositoryScore: v.number(),
  directDepScore: v.number(),
  transitiveDepScore: v.number(),
  untrustedComponentCount: v.number(),
  vulnerableComponentCount: v.number(),
  breakdown: v.array(
    v.object({ layer: v.string(), count: v.number(), averageScore: v.number() }),
  ),
})

export const drilldown = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      repository: v.object({
        _id: v.id('repositories'),
        name: v.string(),
        fullName: v.string(),
        provider: v.string(),
        primaryLanguage: v.string(),
        defaultBranch: v.string(),
        latestCommitSha: v.optional(v.string()),
        lastScannedAt: v.optional(v.number()),
      }),
      snapshot: v.union(
        v.null(),
        v.object({
          _id: v.id('sbomSnapshots'),
          commitSha: v.string(),
          branch: v.string(),
          capturedAt: v.number(),
          totalComponents: v.number(),
          directDependencyCount: v.number(),
          transitiveDependencyCount: v.number(),
          buildDependencyCount: v.number(),
          containerDependencyCount: v.number(),
          runtimeDependencyCount: v.number(),
          aiModelDependencyCount: v.number(),
          sourceFiles: v.array(v.string()),
          trustScore: trustScoreBreakdown,
          vulnerableComponents: v.array(
            v.object({
              name: v.string(),
              version: v.string(),
              ecosystem: v.string(),
              layer: v.string(),
              trustScore: v.number(),
            }),
          ),
        }),
      ),
      findingSummary: v.object({
        total: v.number(),
        open: v.number(),
        critical: v.number(),
        high: v.number(),
        validated: v.number(),
        likelyExploitable: v.number(),
      }),
      openFindings: v.array(
        v.object({
          _id: v.id('findings'),
          title: v.string(),
          severity,
          validationStatus: v.string(),
          status: v.string(),
          confidence: v.number(),
          source: v.string(),
          createdAt: v.number(),
          prUrl: v.optional(v.string()),
        }),
      ),
      recentGateDecisions: v.array(
        v.object({
          _id: v.id('gateDecisions'),
          stage: v.string(),
          decision: v.union(
            v.literal('approved'),
            v.literal('blocked'),
            v.literal('overridden'),
          ),
          actorId: v.string(),
          justification: v.optional(v.string()),
          createdAt: v.number(),
        }),
      ),
      prProposals: v.array(
        v.object({
          _id: v.id('prProposals'),
          status: v.string(),
          fixType: v.string(),
          fixSummary: v.string(),
          prUrl: v.optional(v.string()),
          prNumber: v.optional(v.number()),
          createdAt: v.number(),
        }),
      ),
      recentValidationRuns: v.array(
        v.object({
          _id: v.id('exploitValidationRuns'),
          status: v.string(),
          outcome: v.optional(
            v.union(
              v.literal('validated'),
              v.literal('likely_exploitable'),
              v.literal('unexploitable'),
            ),
          ),
          validationConfidence: v.number(),
          evidenceSummary: v.string(),
          startedAt: v.number(),
          completedAt: v.optional(v.number()),
        }),
      ),
      advisorySyncHealth: v.array(
        v.object({
          _id: v.id('advisorySyncRuns'),
          status: v.union(
            v.literal('completed'),
            v.literal('skipped'),
            v.literal('failed'),
          ),
          triggerType: v.string(),
          githubImported: v.number(),
          osvImported: v.number(),
          startedAt: v.number(),
          completedAt: v.number(),
        }),
      ),
    }),
  ),
  handler: async (ctx, args) => {
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

    // Parallel fetch: snapshot + findings + gate decisions + PRs + validation runs + sync
    const [
      latestSnapshot,
      allFindings,
      recentGateDecisionsRaw,
      prProposalsRaw,
      recentValidationRunsRaw,
      advisorySyncRunsRaw,
    ] = await Promise.all([
      ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_captured_at', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .first(),
      ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .take(100),
      ctx.db
        .query('gateDecisions')
        .withIndex('by_repository_and_stage', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .take(10),
      ctx.db
        .query('prProposals')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .take(10),
      ctx.db
        .query('exploitValidationRuns')
        .withIndex('by_repository_and_started_at', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .take(5),
      ctx.db
        .query('advisorySyncRuns')
        .withIndex('by_repository_and_started_at', (q) =>
          q.eq('repositoryId', repository._id),
        )
        .order('desc')
        .take(3),
    ])

    // SBOM snapshot with trust score
    let snapshotResult = null
    if (latestSnapshot) {
      const components = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
        .collect()

      const trustScore = aggregateTrustScore(
        components.map((c) => ({
          name: c.name,
          version: c.version,
          ecosystem: c.ecosystem,
          layer: c.layer,
          isDirect: c.isDirect,
          trustScore: c.trustScore,
          hasKnownVulnerabilities: c.hasKnownVulnerabilities,
        })),
      )

      const vulnerableComponents = components
        .filter((c) => c.hasKnownVulnerabilities)
        .slice(0, 10)
        .map((c) => ({
          name: c.name,
          version: c.version,
          ecosystem: c.ecosystem,
          layer: c.layer,
          trustScore: c.trustScore,
        }))

      snapshotResult = {
        _id: latestSnapshot._id,
        commitSha: latestSnapshot.commitSha,
        branch: latestSnapshot.branch,
        capturedAt: latestSnapshot.capturedAt,
        totalComponents: latestSnapshot.totalComponents,
        directDependencyCount: latestSnapshot.directDependencyCount,
        transitiveDependencyCount: latestSnapshot.transitiveDependencyCount,
        buildDependencyCount: latestSnapshot.buildDependencyCount,
        containerDependencyCount: latestSnapshot.containerDependencyCount,
        runtimeDependencyCount: latestSnapshot.runtimeDependencyCount,
        aiModelDependencyCount: latestSnapshot.aiModelDependencyCount,
        sourceFiles: latestSnapshot.sourceFiles,
        trustScore,
        vulnerableComponents,
      }
    }

    // Finding summary + open finding list
    const openFindings = allFindings.filter(
      (f) => f.status === 'open' || f.status === 'pr_opened',
    )

    const findingSummary = {
      total: allFindings.length,
      open: openFindings.length,
      critical: openFindings.filter((f) => f.severity === 'critical').length,
      high: openFindings.filter((f) => f.severity === 'high').length,
      validated: allFindings.filter((f) => f.validationStatus === 'validated').length,
      likelyExploitable: allFindings.filter(
        (f) => f.validationStatus === 'likely_exploitable',
      ).length,
    }

    return {
      repository: {
        _id: repository._id,
        name: repository.name,
        fullName: repository.fullName,
        provider: repository.provider,
        primaryLanguage: repository.primaryLanguage,
        defaultBranch: repository.defaultBranch,
        latestCommitSha: repository.latestCommitSha,
        lastScannedAt: repository.lastScannedAt,
      },
      snapshot: snapshotResult,
      findingSummary,
      openFindings: openFindings.slice(0, 20).map((f) => ({
        _id: f._id,
        title: f.title,
        severity: f.severity,
        validationStatus: f.validationStatus,
        status: f.status,
        confidence: f.confidence,
        source: f.source,
        createdAt: f.createdAt,
        prUrl: f.prUrl,
      })),
      recentGateDecisions: recentGateDecisionsRaw.map((d) => ({
        _id: d._id,
        stage: d.stage,
        decision: d.decision,
        actorId: d.actorId,
        justification: d.justification,
        createdAt: d.createdAt,
      })),
      prProposals: prProposalsRaw.map((p) => ({
        _id: p._id,
        status: p.status,
        fixType: p.fixType,
        fixSummary: p.fixSummary,
        prUrl: p.prUrl,
        prNumber: p.prNumber,
        createdAt: p.createdAt,
      })),
      recentValidationRuns: recentValidationRunsRaw.map((r) => ({
        _id: r._id,
        status: r.status,
        outcome: r.outcome,
        validationConfidence: r.validationConfidence,
        evidenceSummary: r.evidenceSummary,
        startedAt: r.startedAt,
        completedAt: r.completedAt,
      })),
      advisorySyncHealth: advisorySyncRunsRaw.map((run) => ({
        _id: run._id,
        status: run.status,
        triggerType: run.triggerType,
        githubImported: run.githubImported,
        osvImported: run.osvImported,
        startedAt: run.startedAt,
        completedAt: run.completedAt,
      })),
    }
  },
})
