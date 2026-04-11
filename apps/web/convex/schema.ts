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
    .index('by_repository_and_stage', ['repositoryId', 'stage'])
    .index('by_workflow_run', ['workflowRunId']),

  gatePolicies: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.optional(v.id('repositories')),
    blockOnSeverities: v.array(
      v.union(
        v.literal('critical'),
        v.literal('high'),
        v.literal('medium'),
        v.literal('low'),
      ),
    ),
    blockOnValidationStatuses: v.array(
      v.union(
        v.literal('validated'),
        v.literal('likely_exploitable'),
        v.literal('pending'),
      ),
    ),
    requireExplicitApprovalForCritical: v.boolean(),
    isActive: v.boolean(),
    createdAt: v.number(),
    updatedAt: v.number(),
  }).index('by_tenant', ['tenantId']),

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

  promptInjectionScans: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.optional(v.id('workflowRuns')),
    /** Human-readable label for what was scanned, e.g. "pr_body", "commit_message", "package_readme". */
    contentRef: v.string(),
    /** djb2 hash of the scanned content — used to skip re-scanning identical inputs. */
    contentHash: v.string(),
    /** Cumulative injection likelihood score (0 = clean, 100 = confirmed). */
    score: v.number(),
    detectedPatterns: v.array(v.string()),
    categories: v.array(v.string()),
    riskLevel: v.union(
      v.literal('clean'),
      v.literal('suspicious'),
      v.literal('likely_injection'),
      v.literal('confirmed_injection'),
    ),
    scannedAt: v.number(),
  })
    .index('by_tenant_and_scanned_at', ['tenantId', 'scannedAt'])
    .index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt']),

  agentMemorySnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    recurringVulnClasses: v.array(
      v.object({
        vulnClass: v.string(),
        count: v.number(),
        avgSeverityWeight: v.number(),
      }),
    ),
    falsePositiveRate: v.number(),
    highConfidenceClasses: v.array(v.string()),
    packageRiskMap: v.record(v.string(), v.number()),
    dominantSeverity: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
    ),
    totalFindingsAnalyzed: v.number(),
    resolvedCount: v.number(),
    openCount: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  redBlueRounds: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    roundNumber: v.number(),
    redStrategySummary: v.string(),
    attackSurfaceCoverage: v.number(),
    simulatedFindingsGenerated: v.number(),
    blueDetectionScore: v.number(),
    exploitChains: v.array(v.string()),
    roundOutcome: v.union(
      v.literal('red_wins'),
      v.literal('blue_wins'),
      v.literal('draw'),
    ),
    confidenceGain: v.number(),
    summary: v.string(),
    ranAt: v.number(),
  }).index('by_repository_and_ran_at', ['repositoryId', 'ranAt']),

  blastRadiusSnapshots: defineTable({
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    reachableServices: v.array(v.string()),
    exposedDataLayers: v.array(v.string()),
    directExposureCount: v.number(),
    transitiveExposureCount: v.number(),
    attackPathDepth: v.number(),
    businessImpactScore: v.number(),
    riskTier: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  attackSurfaceSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** 0–100 composite score — higher means more attack surface has been reduced. */
    score: v.number(),
    /** 0–1 severity-weighted fraction of findings that are resolved or mitigated. */
    remediationRate: v.number(),
    openCriticalCount: v.number(),
    openHighCount: v.number(),
    /** Count of findings currently in 'pr_opened' status (active mitigation). */
    activeMitigationCount: v.number(),
    totalFindings: v.number(),
    resolvedFindings: v.number(),
    trend: v.union(
      v.literal('improving'),
      v.literal('stable'),
      v.literal('degrading'),
    ),
    summary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  regulatoryDriftSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** 0–100 per-framework compliance scores. Higher = more compliant. */
    soc2Score: v.number(),
    gdprScore: v.number(),
    hipaaScore: v.number(),
    pciDssScore: v.number(),
    nis2Score: v.number(),
    overallDriftLevel: v.union(
      v.literal('compliant'),
      v.literal('drifting'),
      v.literal('at_risk'),
      v.literal('non_compliant'),
    ),
    /** Total open findings mapped to at least one regulatory framework. */
    openGapCount: v.number(),
    /** Open critical findings mapped to at least one framework. */
    criticalGapCount: v.number(),
    /** Human-readable labels of frameworks with at least one open gap. */
    affectedFrameworks: v.array(v.string()),
    summary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  honeypotSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    totalProposals: v.number(),
    endpointCount: v.number(),
    fileCount: v.number(),
    databaseFieldCount: v.number(),
    tokenCount: v.number(),
    /** Top attractiveness score across all proposals (0–100). */
    topAttractiveness: v.number(),
    /** Ranked canary proposals — bounded list (max ~11 items). */
    proposals: v.array(
      v.object({
        kind: v.union(
          v.literal('endpoint'),
          v.literal('database_field'),
          v.literal('file'),
          v.literal('token'),
        ),
        path: v.string(),
        description: v.string(),
        rationale: v.string(),
        targetContext: v.optional(v.string()),
        attractivenessScore: v.number(),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  learningProfiles: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Per-class learning signals (bounded: one entry per unique vuln class). */
    vulnClassPatterns: v.array(
      v.object({
        vulnClass: v.string(),
        totalCount: v.number(),
        confirmedCount: v.number(),
        falsePositiveCount: v.number(),
        falsePositiveRate: v.number(),
        isRecurring: v.boolean(),
        isSuppressed: v.boolean(),
        confidenceMultiplier: v.number(),
      }),
    ),
    recurringCount: v.number(),
    suppressedCount: v.number(),
    /** Unique exploit chains retained from red-agent wins. */
    successfulExploitPaths: v.array(v.string()),
    attackSurfaceTrend: v.union(
      v.literal('improving'),
      v.literal('stable'),
      v.literal('degrading'),
      v.literal('unknown'),
    ),
    /** 0–100 learning-maturity score. */
    adaptedConfidenceScore: v.number(),
    /** Fraction of red/blue rounds won by the red agent (0–1). */
    redAgentWinRate: v.number(),
    totalFindingsAnalyzed: v.number(),
    totalRoundsAnalyzed: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  // ── Outbound webhook endpoints (spec §7.2) ─────────────────────────────────
  // Each row represents a customer-registered HTTPS endpoint that Sentinel
  // will POST signed event payloads to. `events` is the subscribed event-type
  // allow-list; an empty array means "subscribe to all events".

  webhookEndpoints: defineTable({
    tenantId: v.id('tenants'),
    /** Target URL for outbound POST requests. */
    url: v.string(),
    /** HMAC-SHA256 signing secret stored server-side only. */
    secret: v.string(),
    description: v.optional(v.string()),
    /** Subscribed event types. Empty = wildcard (all events). */
    events: v.array(v.string()),
    active: v.boolean(),
    createdAt: v.number(),
    lastDeliveryAt: v.optional(v.number()),
  })
    .index('by_tenant', ['tenantId'])
    .index('by_tenant_and_active', ['tenantId', 'active']),

  // Audit log of every outbound webhook delivery attempt.
  webhookDeliveries: defineTable({
    tenantId: v.id('tenants'),
    endpointId: v.id('webhookEndpoints'),
    /** UUID included in the X-Sentinel-Delivery header for idempotency. */
    deliveryId: v.string(),
    eventType: v.string(),
    repositoryFullName: v.string(),
    success: v.boolean(),
    statusCode: v.optional(v.number()),
    errorMessage: v.optional(v.string()),
    durationMs: v.number(),
    attemptedAt: v.number(),
  })
    .index('by_tenant_and_attempted_at', ['tenantId', 'attemptedAt'])
    .index('by_endpoint_and_attempted_at', ['endpointId', 'attemptedAt']),

  prProposals: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    findingId: v.id('findings'),
    status: v.union(
      v.literal('draft'),
      v.literal('open'),
      v.literal('merged'),
      v.literal('closed'),
      v.literal('failed'),
    ),
    fixType: v.union(
      v.literal('version_bump'),
      v.literal('patch'),
      v.literal('config_change'),
      v.literal('manual'),
    ),
    proposedBranch: v.string(),
    prTitle: v.string(),
    prBody: v.string(),
    fixSummary: v.string(),
    targetPackage: v.optional(v.string()),
    targetEcosystem: v.optional(v.string()),
    currentVersion: v.optional(v.string()),
    fixVersion: v.optional(v.string()),
    prUrl: v.optional(v.string()),
    prNumber: v.optional(v.number()),
    githubError: v.optional(v.string()),
    createdAt: v.number(),
    submittedAt: v.optional(v.number()),
    mergedAt: v.optional(v.number()),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_status', ['repositoryId', 'status'])
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt']),
})
