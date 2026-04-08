import { defineSchema, defineTable } from 'convex/server'
import { v } from 'convex/values'

const deploymentMode = v.union(
  v.literal('cloud_saas'),
  v.literal('vpc_injection'),
  v.literal('on_prem'),
)

const lifecycleStatus = v.union(
  v.literal('queued'),
  v.literal('running'),
  v.literal('completed'),
  v.literal('failed'),
)

const workflowPriority = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
)

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

const findingStatus = v.union(
  v.literal('open'),
  v.literal('pr_opened'),
  v.literal('merged'),
  v.literal('resolved'),
  v.literal('accepted_risk'),
)

const validationStatus = v.union(
  v.literal('pending'),
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
  v.literal('dismissed'),
)

const gateDecision = v.union(
  v.literal('approved'),
  v.literal('blocked'),
  v.literal('overridden'),
)

const advisorySyncStatus = v.union(
  v.literal('completed'),
  v.literal('skipped'),
  v.literal('failed'),
)

const exploitValidationOutcome = v.union(
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
)

export default defineSchema({
  tenants: defineTable({
    slug: v.string(),
    name: v.string(),
    status: v.union(v.literal('active'), v.literal('paused')),
    deploymentMode,
    currentPhase: v.union(
      v.literal('phase_0'),
      v.literal('phase_1'),
      v.literal('phase_2'),
      v.literal('phase_3'),
      v.literal('phase_4'),
    ),
    createdAt: v.number(),
  }).index('by_slug', ['slug']),

  repositories: defineTable({
    tenantId: v.id('tenants'),
    provider: v.union(v.literal('github'), v.literal('gitlab')),
    name: v.string(),
    fullName: v.string(),
    defaultBranch: v.string(),
    visibility: v.union(v.literal('private'), v.literal('public')),
    primaryLanguage: v.string(),
    latestCommitSha: v.optional(v.string()),
    lastScannedAt: v.optional(v.number()),
  })
    .index('by_tenant', ['tenantId'])
    .index('by_tenant_and_full_name', ['tenantId', 'fullName'])
    .index('by_provider_and_full_name', ['provider', 'fullName']),

  ingestionEvents: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    dedupeKey: v.string(),
    kind: v.string(),
    source: v.string(),
    workflowType: v.string(),
    status: lifecycleStatus,
    externalRef: v.optional(v.string()),
    branch: v.optional(v.string()),
    commitSha: v.optional(v.string()),
    changedFiles: v.optional(v.array(v.string())),
    summary: v.string(),
    receivedAt: v.number(),
  })
    .index('by_tenant_and_received_at', ['tenantId', 'receivedAt'])
    .index('by_status', ['status'])
    .index('by_dedupe_key', ['dedupeKey']),

  workflowRuns: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    eventId: v.id('ingestionEvents'),
    workflowType: v.string(),
    status: lifecycleStatus,
    priority: workflowPriority,
    currentStage: v.optional(v.string()),
    summary: v.string(),
    totalTaskCount: v.number(),
    completedTaskCount: v.number(),
    startedAt: v.number(),
    completedAt: v.optional(v.number()),
  })
    .index('by_tenant_and_started_at', ['tenantId', 'startedAt'])
    .index('by_tenant_and_status', ['tenantId', 'status'])
    .index('by_event', ['eventId']),

  workflowTasks: defineTable({
    tenantId: v.id('tenants'),
    workflowRunId: v.id('workflowRuns'),
    agent: v.string(),
    stage: v.string(),
    status: lifecycleStatus,
    title: v.string(),
    detail: v.string(),
    order: v.number(),
    startedAt: v.optional(v.number()),
    completedAt: v.optional(v.number()),
  }).index('by_workflow_run_and_order', ['workflowRunId', 'order']),

  sbomSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha: v.string(),
    branch: v.string(),
    capturedAt: v.number(),
    sourceFiles: v.array(v.string()),
    directDependencyCount: v.number(),
    transitiveDependencyCount: v.number(),
    buildDependencyCount: v.number(),
    containerDependencyCount: v.number(),
    runtimeDependencyCount: v.number(),
    aiModelDependencyCount: v.number(),
    totalComponents: v.number(),
    riskDelta: v.number(),
    exportFormats: v.array(v.string()),
  })
    .index('by_tenant_and_captured_at', ['tenantId', 'capturedAt'])
    .index('by_repository_and_commit', ['repositoryId', 'commitSha'])
    .index('by_repository_and_captured_at', ['repositoryId', 'capturedAt']),

  sbomComponents: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    name: v.string(),
    normalizedName: v.string(),
    version: v.string(),
    ecosystem: v.string(),
    layer: v.string(),
    isDirect: v.boolean(),
    sourceFile: v.string(),
    trustScore: v.number(),
    hasKnownVulnerabilities: v.boolean(),
    license: v.optional(v.string()),
    dependents: v.array(v.string()),
  })
    .index('by_snapshot', ['snapshotId'])
    .index('by_snapshot_and_normalized_name', ['snapshotId', 'normalizedName'])
    .index('by_tenant_and_name', ['tenantId', 'name']),

  breachDisclosures: defineTable({
    repositoryId: v.optional(v.id('repositories')),
    workflowRunId: v.optional(v.id('workflowRuns')),
    packageName: v.string(),
    normalizedPackageName: v.string(),
    ecosystem: v.string(),
    sourceType: v.union(
      v.literal('manual'),
      v.literal('github_security_advisory'),
      v.literal('osv'),
    ),
    sourceTier: v.union(
      v.literal('tier_1'),
      v.literal('tier_2'),
      v.literal('tier_3'),
    ),
    sourceName: v.string(),
    sourceRef: v.string(),
    aliases: v.array(v.string()),
    summary: v.string(),
    severity,
    affectedVersions: v.array(v.string()),
    fixVersion: v.optional(v.string()),
    exploitAvailable: v.boolean(),
    matchStatus: v.union(
      v.literal('matched'),
      v.literal('version_unaffected'),
      v.literal('version_unknown'),
      v.literal('unmatched'),
      v.literal('no_snapshot'),
    ),
    versionMatchStatus: v.union(
      v.literal('affected'),
      v.literal('unaffected'),
      v.literal('unknown'),
    ),
    matchedSnapshotId: v.optional(v.id('sbomSnapshots')),
    matchedComponentCount: v.number(),
    affectedComponentCount: v.number(),
    matchedVersions: v.array(v.string()),
    affectedMatchedVersions: v.array(v.string()),
    matchSummary: v.string(),
    findingId: v.optional(v.id('findings')),
    publishedAt: v.number(),
  })
    .index('by_package_and_published_at', ['packageName', 'publishedAt'])
    .index('by_repository_and_source_ref', ['repositoryId', 'sourceRef'])
    .index('by_published_at', ['publishedAt']),

  findings: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    breachDisclosureId: v.optional(v.id('breachDisclosures')),
    source: v.string(),
    vulnClass: v.string(),
    title: v.string(),
    summary: v.string(),
    confidence: v.number(),
    severity,
    validationStatus,
    status: findingStatus,
    businessImpactScore: v.number(),
    blastRadiusSummary: v.string(),
    prUrl: v.optional(v.string()),
    reasoningLogUrl: v.optional(v.string()),
    pocArtifactUrl: v.optional(v.string()),
    affectedServices: v.array(v.string()),
    affectedFiles: v.array(v.string()),
    affectedPackages: v.array(v.string()),
    regulatoryImplications: v.array(v.string()),
    createdAt: v.number(),
    resolvedAt: v.optional(v.number()),
  })
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt'])
    .index('by_tenant_and_status', ['tenantId', 'status'])
    .index('by_repository_and_status', ['repositoryId', 'status'])
    .index('by_workflow_run_and_source', ['workflowRunId', 'source']),

  exploitValidationRuns: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    findingId: v.id('findings'),
    status: lifecycleStatus,
    outcome: v.optional(exploitValidationOutcome),
    validationConfidence: v.number(),
    sandboxSummary: v.string(),
    evidenceSummary: v.string(),
    reproductionHint: v.string(),
    startedAt: v.number(),
    completedAt: v.optional(v.number()),
  })
    .index('by_tenant_and_started_at', ['tenantId', 'startedAt'])
    .index('by_repository_and_started_at', ['repositoryId', 'startedAt'])
    .index('by_finding_and_started_at', ['findingId', 'startedAt']),

  gateDecisions: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    findingId: v.id('findings'),
    stage: v.string(),
    decision: gateDecision,
    actorType: v.union(v.literal('agent'), v.literal('user')),
    actorId: v.string(),
    justification: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
  })
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt'])
    .index('by_repository_and_stage', ['repositoryId', 'stage']),

  advisorySyncRuns: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    triggerType: v.union(v.literal('manual'), v.literal('scheduled')),
    status: advisorySyncStatus,
    packageCount: v.number(),
    lookbackHours: v.number(),
    githubQueried: v.number(),
    githubFetched: v.number(),
    githubImported: v.number(),
    githubDeduped: v.number(),
    osvQueried: v.number(),
    osvFetched: v.number(),
    osvImported: v.number(),
    osvDeduped: v.number(),
    reason: v.optional(v.string()),
    startedAt: v.number(),
    completedAt: v.number(),
  })
    .index('by_tenant_and_started_at', ['tenantId', 'startedAt'])
    .index('by_repository_and_started_at', ['repositoryId', 'startedAt'])
    .index('by_status', ['status']),
})
