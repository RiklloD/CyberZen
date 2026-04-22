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
  v.literal('false_positive'),
  v.literal('ignored'),
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
      v.literal('nvd'),
      v.literal('npm_advisory'),
      v.literal('pypi_safety'),
      v.literal('rustsec'),
      v.literal('go_vuln'),
      v.literal('github_issues'),
      v.literal('hackerone'),
      v.literal('oss_security'),
      v.literal('packet_storm'),
      v.literal('paste_site'),
      v.literal('credential_dump'),
      v.literal('dark_web_mention'),
      v.literal('cisa_kev'),
      v.literal('telegram'),
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
    /** WS-34 — EPSS exploitation probability score (0.0–1.0), populated by daily sync. */
    epssScore: v.optional(v.number()),
    /** WS-34 — EPSS percentile rank (0.0–1.0) among all scored CVEs. */
    epssPercentile: v.optional(v.number()),
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

  // ── Blue Agent detection rule snapshots (spec §3.3.3) ────────────────────
  // Stores WAF rules, SIEM queries, and log patterns generated from Red Agent wins.
  // One row per repository — upserted after each rule generation run.

  detectionRuleSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    totalRules: v.number(),
    nginxCount: v.number(),
    modsecurityCount: v.number(),
    splunkCount: v.number(),
    elasticCount: v.number(),
    sentinelCount: v.number(),
    logRegexCount: v.number(),
    /** Serialized rule content — bounded arrays of strings */
    nginxRules: v.array(v.string()),
    modsecurityRules: v.array(v.string()),
    splunkRules: v.array(v.string()),
    elasticRules: v.array(v.string()),
    sentinelRules: v.array(v.string()),
    logRegexRules: v.array(v.string()),
    summary: v.string(),
    generatedAt: v.number(),
  }).index('by_repository_and_generated_at', ['repositoryId', 'generatedAt']),

  // ── Supply Chain Social Monitor analyses (spec §3.2) ─────────────────────
  // One row per package analyzed per repository — upserted on each analysis run.

  supplyChainAnalyses: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    packageName: v.string(),
    ecosystem: v.string(),
    githubRepoPath: v.string(),
    signals: v.array(
      v.object({
        kind: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        description: v.string(),
        evidence: v.string(),
        detectedAt: v.number(),
      }),
    ),
    overallRiskLevel: v.union(
      v.literal('trusted'),
      v.literal('monitor'),
      v.literal('at_risk'),
      v.literal('suspicious'),
      v.literal('compromised'),
    ),
    socialTrustScore: v.number(),
    repoMetadata: v.optional(
      v.object({
        stars: v.number(),
        forks: v.number(),
        openIssues: v.number(),
        archived: v.boolean(),
        lastCommitDate: v.union(v.string(), v.null()),
        contributorCount: v.number(),
      }),
    ),
    lastAnalyzedAt: v.number(),
  })
    .index('by_repository_and_analyzed_at', ['repositoryId', 'lastAnalyzedAt'])
    .index('by_repository_and_package', ['repositoryId', 'packageName']),

  // ── Semantic fingerprint embeddings (spec §3.1) ───────────────────────────
  // Stores pre-computed OpenAI embeddings for the vulnerability pattern library.
  // Seeded once via initializePatternLibrary; re-seeded when patterns change.

  vulnerabilityPatternEmbeddings: defineTable({
    patternId: v.string(),
    vulnClass: v.string(),
    severity: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('informational'),
    ),
    description: v.string(),
    /** L2-normalized embedding vector from text-embedding-3-small (1536 dims) */
    vector: v.array(v.number()),
    model: v.string(),
    tokenCount: v.number(),
    embeddedAt: v.number(),
  })
    .index('by_pattern_id', ['patternId'])
    .index('by_vuln_class', ['vulnClass']),

  // Per-repository code context embeddings — one per push event
  // Bounded: only the most recent 50 per repository are kept
  codeContextEmbeddings: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    commitSha: v.string(),
    branch: v.string(),
    /** The text that was embedded */
    contextText: v.string(),
    /** L2-normalized embedding vector */
    vector: v.array(v.number()),
    model: v.string(),
    tokenCount: v.number(),
    /** Top matches from the pattern search — stored for audit */
    topMatches: v.array(
      v.object({
        patternId: v.string(),
        vulnClass: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
          v.literal('informational'),
        ),
        similarity: v.number(),
        confidence: v.number(),
      }),
    ),
    /** Zero-day anomaly detection results */
    anomalyLevel: v.optional(v.union(
      v.literal('normal'),
      v.literal('watch'),
      v.literal('suspicious'),
      v.literal('anomalous'),
    )),
    anomalyScore: v.optional(v.number()),
    anomalySummary: v.optional(v.string()),
    embeddedAt: v.number(),
  })
    .index('by_repository_and_embedded_at', ['repositoryId', 'embeddedAt'])
    .index('by_commit', ['repositoryId', 'commitSha']),

  // ── Sandbox execution environments (spec §3.6 / §4.4) ────────────────────
  // One row per exploit validation run — stores the execution context,
  // HTTP evidence, and PoC artifacts separately from the lightweight
  // exploitValidationRuns row (which stays as the finding's status carrier).

  sandboxEnvironments: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    findingId: v.id('findings'),
    exploitValidationRunId: v.id('exploitValidationRuns'),

    /** http_probe = live HTTP requests fired; dry_run = PoC generated only */
    sandboxMode: v.union(v.literal('http_probe'), v.literal('dry_run')),

    /** Base URL probed — null in dry_run mode */
    targetBaseUrl: v.optional(v.string()),

    status: v.union(
      v.literal('queued'),
      v.literal('running'),
      v.literal('completed'),
      v.literal('failed'),
    ),

    outcome: v.optional(
      v.union(
        v.literal('exploited'),
        v.literal('likely_exploitable'),
        v.literal('not_exploitable'),
        v.literal('error'),
      ),
    ),

    /** 0–1 confidence in the outcome */
    confidence: v.optional(v.number()),

    /** Total exploit attempts generated */
    totalAttempts: v.number(),
    /** Attempts that found matching success indicators */
    successfulAttempts: v.number(),

    /** Label of the first winning payload (e.g. "sqli_error_single_quote_id") */
    winningPayloadLabel: v.optional(v.string()),

    /** Proof-of-concept artifacts — only set on exploited / likely_exploitable */
    pocCurl: v.optional(v.string()),
    pocPython: v.optional(v.string()),

    evidenceSummary: v.string(),
    elapsedMs: v.number(),

    startedAt: v.number(),
    completedAt: v.optional(v.number()),
  })
    .index('by_finding', ['findingId'])
    .index('by_validation_run', ['exploitValidationRunId'])
    .index('by_repository_and_started_at', ['repositoryId', 'startedAt']),

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
    /** GitHub login of the engineer who merged the PR — populated by post-fix
     *  validation webhook on pull_request:closed + merged=true.  Used for the
     *  WS-28 gamification engineer leaderboard. */
    mergedBy: v.optional(v.string()),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_status', ['repositoryId', 'status'])
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt']),

  // ── AI/ML Model Supply Chain scans (spec §3.5) ────────────────────────────
  // One snapshot per repository SBOM scan — tracks ML framework inventory and
  // model-specific supply chain risks (pickle RCE, remote weight downloads,
  // unpinned versions, typosquatted model packages, known CVEs in ML libs).

  modelSupplyChainScans: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    /** 0–100 overall ML supply chain risk score. */
    overallRiskScore: v.number(),
    riskLevel: v.union(
      v.literal('low'),
      v.literal('medium'),
      v.literal('high'),
      v.literal('critical'),
    ),
    mlFrameworkCount: v.number(),
    mlFrameworks: v.array(v.string()),
    /** True when any framework loads pickle-format model files by default. */
    hasPickleRisk: v.boolean(),
    /** True when any ML dependency lacks an exact pinned version. */
    hasUnpinnedFramework: v.boolean(),
    /** Count of ML frameworks with a matching known CVE in the advisory DB. */
    vulnerableFrameworkCount: v.number(),
    flaggedComponentCount: v.number(),
    /** Abbreviated per-component signal summary (bounded). */
    flaggedComponents: v.array(
      v.object({
        name: v.string(),
        version: v.string(),
        riskScore: v.number(),
        riskLevel: v.union(
          v.literal('low'),
          v.literal('medium'),
          v.literal('high'),
          v.literal('critical'),
        ),
        topSignalKind: v.string(),
        summary: v.string(),
      }),
    ),
    summary: v.string(),
    scannedAt: v.number(),
  }).index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt']),

  // ── SOC 2 Automated Evidence Collection (spec §10.1) ──────────────────────
  // Aggregates regulatory evidence artifacts per framework per repository.
  // Each snapshot is a point-in-time audit record that maps:
  //   open findings → specific regulatory control IDs
  //   remediated findings → evidence of timely resolution
  //   gate decisions → evidence of CI enforcement controls

  complianceEvidenceSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    framework: v.union(
      v.literal('soc2'),
      v.literal('gdpr'),
      v.literal('hipaa'),
      v.literal('pci_dss'),
      v.literal('nis2'),
    ),
    /** Overall health score for this framework's evidence completeness (0–100). */
    evidenceScore: v.number(),
    /** Number of controls with at least one evidenced finding. */
    coveredControlCount: v.number(),
    /** Number of controls with open (un-remediated) gaps. */
    openGapControlCount: v.number(),
    /** Total evidence items (finding-to-control mappings). */
    totalEvidenceItems: v.number(),
    /** Bounded list of concrete evidence artifacts for audit export. */
    evidenceItems: v.array(
      v.object({
        controlId: v.string(),
        controlName: v.string(),
        evidenceType: v.union(
          v.literal('finding_log'),
          v.literal('remediation_timeline'),
          v.literal('gate_enforcement'),
          v.literal('risk_acceptance'),
          v.literal('pr_audit_trail'),
        ),
        status: v.union(
          v.literal('compliant'),
          v.literal('gap'),
          v.literal('remediated'),
          v.literal('risk_accepted'),
        ),
        description: v.string(),
        findingCount: v.number(),
        lastUpdatedAt: v.number(),
      }),
    ),
    summary: v.string(),
    generatedAt: v.number(),
  }).index('by_repository_and_generated_at', ['repositoryId', 'generatedAt']),

  // ── AI Model Provenance scans (spec §3.11.2 Layer 6) ─────────────────────
  // Tracks the provenance trustworthiness of AI model dependencies in the SBOM:
  // source registry verification, license compliance, weights hash coverage,
  // version pinning, and training dataset risk flags.
  // One snapshot per SBOM ingest run; bounded at 20 per repository.

  modelProvenanceScans: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    /** Total number of AI model components found in this SBOM snapshot. */
    totalModels: v.number(),
    /** Count of models that pass all provenance checks. */
    verifiedCount: v.number(),
    /** Count of models classified as risky. */
    riskyCount: v.number(),
    /** Aggregate provenance trust score (0–100, higher = more trustworthy). */
    aggregateScore: v.number(),
    overallRiskLevel: v.union(
      v.literal('verified'),
      v.literal('acceptable'),
      v.literal('unverified'),
      v.literal('risky'),
    ),
    /** Abbreviated per-model provenance summaries (bounded to 10). */
    components: v.array(
      v.object({
        name: v.string(),
        resolvedSource: v.string(),
        resolvedLicense: v.string(),
        provenanceScore: v.number(),
        riskLevel: v.union(
          v.literal('verified'),
          v.literal('acceptable'),
          v.literal('unverified'),
          v.literal('risky'),
        ),
        topSignalKind: v.optional(v.string()),
        summary: v.string(),
      }),
    ),
    summary: v.string(),
    scannedAt: v.number(),
  }).index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt']),

  // ── SIEM push logs (spec §4.6.5) ──────────────────────────────────────────
  // One row per push attempt per repository. Tracks Splunk HEC + Elastic _bulk
  // outcomes independently — each destination can succeed or fail on its own.

  siemPushLogs: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Status for the Splunk HEC push ("skipped" when not configured). */
    splunkStatus: v.union(
      v.literal('ok'),
      v.literal('skipped'),
      v.literal('error'),
    ),
    splunkRuleCount: v.number(),
    splunkError: v.optional(v.string()),
    /** Status for the Elastic _bulk push ("skipped" when not configured). */
    elasticStatus: v.union(
      v.literal('ok'),
      v.literal('skipped'),
      v.literal('error'),
    ),
    elasticRuleCount: v.number(),
    elasticError: v.optional(v.string()),
    pushedAt: v.number(),
  })
    .index('by_repository_and_pushed_at', ['repositoryId', 'pushedAt'])
    .index('by_tenant_and_pushed_at', ['tenantId', 'pushedAt']),

  // ── Multi-Cloud Blast Radius snapshots (spec §3.12) ───────────────────────
  // One row per repository per computation run — stores inferred cloud resource
  // exposure derived from SBOM package names alone. No cloud API calls needed.

  // ── CISA KEV catalog cache (global singleton — no tenantId) ──────────────
  // One row per sync run.  We do NOT store all 1 000+ individual KEV entries;
  // just the matched CVE IDs and summary stats, keeping the table small.

  cisaKevSnapshots: defineTable({
    catalogVersion: v.string(),
    dateReleased: v.string(),
    totalEntries: v.number(),
    ransomwareRelated: v.number(),
    recentEntries: v.number(),
    hasHighPriorityEntries: v.boolean(),
    matchedCveIds: v.array(v.string()),   // CVEs that matched open findings
    matchedFindingCount: v.number(),
    syncedAt: v.number(),
  }).index('by_synced_at', ['syncedAt']),

  // ── Tier 3 threat signals (Telegram / dark web / paste sites) ────────────
  // Stores parsed signals above threatLevel='none'.

  tier3ThreatSignals: defineTable({
    source: v.union(
      v.literal('telegram'),
      v.literal('dark_web'),
      v.literal('paste_site'),
    ),
    channelId: v.optional(v.string()),
    messageId: v.optional(v.string()),
    text: v.string(),
    cveIds: v.array(v.string()),
    packageMentions: v.array(v.string()),
    hasCredentialPattern: v.boolean(),
    hasExploitKeywords: v.boolean(),
    hasRansomwareKeywords: v.boolean(),
    threatLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
    ),
    capturedAt: v.number(),
  })
    .index('by_captured_at', ['capturedAt'])
    .index('by_threat_level_and_captured_at', ['threatLevel', 'capturedAt']),

  // ── Multi-Cloud Blast Radius snapshots (spec §3.12) ───────────────────────
  // One row per repository per computation run — stores inferred cloud resource
  // exposure derived from SBOM package names alone. No cloud API calls needed.

  cloudBlastRadiusSnapshots: defineTable({
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    providers: v.array(
      v.union(v.literal('aws'), v.literal('gcp'), v.literal('azure')),
    ),
    reachableCloudResources: v.array(
      v.object({
        provider: v.union(v.literal('aws'), v.literal('gcp'), v.literal('azure')),
        resourceType: v.string(),
        sensitivityScore: v.number(),
        label: v.string(),
      }),
    ),
    criticalResourceCount: v.number(),
    iamEscalationRisk: v.boolean(),
    dataExfiltrationRisk: v.boolean(),
    secretsAccessRisk: v.boolean(),
    lateralMovementRisk: v.boolean(),
    cloudBlastScore: v.number(),
    cloudRiskTier: v.union(
      v.literal('critical'),
      v.literal('severe'),
      v.literal('moderate'),
      v.literal('minimal'),
    ),
    cloudSummary: v.string(),
    computedAt: v.number(),
  }).index('by_repository_and_computed_at', ['repositoryId', 'computedAt']),

  // ── Analyst triage events (finding feedback loop) ────────────────────────
  // One row per triage action: FP marking, accepted-risk override, reopen,
  // note.  Kept as a separate append-only table (not an array field on
  // findings) so the audit log never hits document size limits.
  // The learning loop reads this table to compute analyst-confirmed FP rates
  // per vuln-class and adjust confidence multipliers accordingly.

  findingTriageEvents: defineTable({
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    action: v.union(
      v.literal('mark_false_positive'),
      v.literal('mark_accepted_risk'),
      v.literal('reopen'),
      v.literal('add_note'),
      v.literal('ignore'),
    ),
    note: v.optional(v.string()),
    /** Free-form analyst identifier (email, username, etc). Not auth-linked. */
    analyst: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_created_at', ['repositoryId', 'createdAt'])
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt']),

  // ── SLA Enforcement (spec §3.13.3) ──────────────────────────────────────
  // One row per breach event per finding — inserted once when a finding first
  // crosses its SLA deadline.  Subsequent hourly cron runs skip already-recorded
  // findings via the by_finding index.  notifiedAt is set when the first Slack
  // alert is scheduled; notificationChannels records which integrations fired.

  slaBreachEvents: defineTable({
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    severity,
    /** Display title copied from the finding at breach time. */
    title: v.string(),
    /** The SLA threshold that was exceeded (hours). */
    slaThresholdHours: v.number(),
    /** When the finding was first opened (ms). */
    openedAt: v.number(),
    /** When the breach was detected (ms). */
    breachedAt: v.number(),
    /** When the first notification was sent (ms); null until notified. */
    notifiedAt: v.optional(v.number()),
    /** Which channels have been notified (e.g. ['slack', 'teams']). */
    notificationChannels: v.array(v.string()),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_breached_at', ['repositoryId', 'breachedAt'])
    .index('by_tenant_and_breached_at', ['tenantId', 'breachedAt']),

  // ── Risk Acceptance Lifecycle (spec §4.3) ────────────────────────────────
  // One row per formal risk acceptance decision.  Temporary acceptances carry
  // an `expiresAt` deadline; the hourly cron transitions them to `expired`
  // and re-opens the finding.  Permanent acceptances require explicit revocation.
  //
  // Status transitions:
  //   created → active
  //   active  → expired   (automatic, via checkExpiredAcceptances cron)
  //   active  → revoked   (explicit operator action)

  // ── Cross-Repository Impact Detection (spec §3.2.1) ─────────────────────
  // One row per unique normalized package name per tenant.  Upserted each time
  // a disclosure is ingested for that package — the record reflects the latest
  // cross-repo scan.  `sourceFindingId` points to the most recent finding that
  // triggered a re-scan.
  //
  // Indexes:
  //   by_source_finding           — look up impact event for a specific finding
  //   by_tenant_and_computed_at   — list all events for a tenant, newest first
  //   by_tenant_and_normalized_package — upsert guard + slug-based HTTP queries

  crossRepoImpactEvents: defineTable({
    packageName: v.string(),
    normalizedPackageName: v.string(),
    ecosystem: v.string(),
    severity,
    sourceFindingId: v.id('findings'),
    sourceRepositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    totalRepositories: v.number(),
    affectedRepositoryCount: v.number(),
    /** IDs of repositories (other than the source) that contain this package. */
    affectedRepositoryIds: v.array(v.id('repositories')),
    affectedRepositoryNames: v.array(v.string()),
    /** Per-repo impact detail (bounded by affectedRepositoryCount). */
    impacts: v.array(
      v.object({
        repositoryId: v.id('repositories'),
        repositoryName: v.string(),
        directMatchCount: v.number(),
        transitiveMatchCount: v.number(),
        matchedVersions: v.array(v.string()),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_source_finding', ['sourceFindingId'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt'])
    .index('by_tenant_and_normalized_package', [
      'tenantId',
      'normalizedPackageName',
    ]),

  riskAcceptances: defineTable({
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    /** Human-readable reason why this risk is being accepted. */
    justification: v.string(),
    /** Identity of the approver (email, username, etc — not auth-linked). */
    approver: v.string(),
    level: v.union(v.literal('temporary'), v.literal('permanent')),
    /** Expiry timestamp in ms.  Absent for permanent acceptances. */
    expiresAt: v.optional(v.number()),
    status: v.union(
      v.literal('active'),
      v.literal('expired'),
      v.literal('revoked'),
    ),
    revokedAt: v.optional(v.number()),
    revokedBy: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_created_at', ['repositoryId', 'createdAt'])
    .index('by_tenant_and_created_at', ['tenantId', 'createdAt'])
    .index('by_status', ['status']),

  // ── Severity Escalation Events (WS-22) ───────────────────────────────────
  // Append-only audit log of every automatic severity upgrade.
  // One row is inserted each time assessEscalation decides shouldEscalate=true
  // for a finding.  The finding's severity field is patched in the same
  // internalMutation that inserts this row, keeping the audit trail atomic.
  //
  // Indexes:
  //   by_finding                   — escalation history for a single finding
  //   by_repository_and_computed_at — list all escalations for a repository
  //   by_tenant_and_computed_at     — tenant-wide sweep summary

  // ── Autonomous Remediation Dispatch runs (WS-23) ─────────────────────────
  // One row per automatic dispatch batch per repository.  Each run records
  // which findings were eligible, how many PRs were scheduled, and the per-
  // finding skip reasons for audit visibility.
  // No policy table is needed — the DEFAULT_AUTO_REMEDIATION_POLICY is
  // overridable per-call; a settings table can be added when multi-tenant
  // policy customisation is required.

  autoRemediationRuns: defineTable({
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    /** Findings assessed by the selection engine (queue size at time of run). */
    candidateCount: v.number(),
    /** Findings for which proposeFix was scheduled. */
    dispatchedCount: v.number(),
    skippedAlreadyHasPr: v.number(),
    skippedBelowTier: v.number(),
    skippedBelowSeverity: v.number(),
    skippedConcurrencyCap: v.number(),
    /** IDs of findings dispatched in this run. */
    dispatchedFindingIds: v.array(v.id('findings')),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  severityEscalationEvents: defineTable({
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    previousSeverity: severity,
    newSeverity: severity,
    /** Escalation triggers that fired (non-empty when this row exists). */
    triggers: v.array(
      v.union(
        v.literal('exploit_available'),
        v.literal('blast_radius_critical'),
        v.literal('blast_radius_high'),
        v.literal('cross_repo_spread'),
        v.literal('sla_breach'),
      ),
    ),
    /** Human-readable rationale entries — one per active trigger. */
    rationale: v.array(v.string()),
    /** Unix ms timestamp when the escalation was computed. */
    computedAt: v.number(),
  })
    .index('by_finding', ['findingId'])
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── LLM-Native Application Security Certification (WS-26) ───────────────────
  // One certification report per refresh run per repository.  The report
  // synthesises signals from 7 source tables into a single tier verdict.
  // Bounded at 20 per repository (old rows pruned on each refresh).

  llmCertificationReports: defineTable({
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    tier: v.union(
      v.literal('gold'),
      v.literal('silver'),
      v.literal('bronze'),
      v.literal('uncertified'),
    ),
    passCount: v.number(),
    warnCount: v.number(),
    failCount: v.number(),
    overallScore: v.number(),
    /** Critical domain names that received a 'fail' outcome. */
    criticalFailedDomains: v.array(v.string()),
    /** Per-domain results — exactly 7 entries. */
    domainResults: v.array(v.object({
      domain: v.string(),
      outcome: v.union(v.literal('pass'), v.literal('warn'), v.literal('fail')),
      score: v.number(),
      rationale: v.string(),
    })),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── Connected Vendor Inventory (OAuth / SaaS trust-chain defense) ────────────
  // Tracks third-party SaaS tools, OAuth apps, and service integrations that
  // have been granted access to tenant infrastructure.
  //
  // Stable profile data only — high-churn risk assessments live in
  // vendorRiskSnapshots (separate table, foreign-keyed back here).
  //
  // Motivation: the April 2026 Vercel breach originated at Context AI, a
  // connected OAuth tool. This table answers "what 3rd-party services trust
  // us, and what could they do if compromised?"

  connectedVendors: defineTable({
    tenantId: v.id('tenants'),
    /** Display name, e.g. "Context AI", "Datadog", "Supabase". */
    name: v.string(),
    category: v.union(
      v.literal('ai_tool'),
      v.literal('observability'),
      v.literal('auth_provider'),
      v.literal('database'),
      v.literal('ci_cd'),
      v.literal('communication'),
      v.literal('security'),
      v.literal('other'),
    ),
    authMethod: v.union(
      v.literal('oauth2'),
      v.literal('api_key'),
      v.literal('service_account'),
      v.literal('webhook_secret'),
      v.literal('basic_auth'),
    ),
    /** Broadest privilege level this vendor holds. */
    accessLevel: v.union(
      v.literal('read_only'),
      v.literal('read_write'),
      v.literal('admin'),
      v.literal('unknown'),
    ),
    /** OAuth scopes or equivalent permission strings granted to this vendor. */
    grantedScopes: v.array(v.string()),
    /** Categories of data this vendor can access, e.g. "env_vars", "source_code". */
    dataCategories: v.array(v.string()),
    /** When the integration was first authorised (ms). */
    grantedAt: v.optional(v.number()),
    /** When the integration was last audited / re-verified (ms). */
    lastVerifiedAt: v.optional(v.number()),
    status: v.union(
      v.literal('active'),
      v.literal('revoked'),
      v.literal('suspended'),
    ),
    notes: v.optional(v.string()),
    addedAt: v.number(),
  })
    .index('by_tenant', ['tenantId'])
    .index('by_tenant_and_status', ['tenantId', 'status'])
    .index('by_tenant_and_name', ['tenantId', 'name']),

  // ── Vendor Risk Snapshots ─────────────────────────────────────────────────
  // Append-only audit log of every risk assessment for a connected vendor.
  // Written by the vendorTrust sweep action (daily cron) and on-demand
  // assessVendorRisk calls. One row per vendor per assessment run.
  //
  // `snapshotScopes` captures the full scope list at assessment time so the
  // next run can diff for scope-creep detection without relying on the mutable
  // vendor profile.

  vendorRiskSnapshots: defineTable({
    tenantId: v.id('tenants'),
    vendorId: v.id('connectedVendors'),
    /** 0–100. Higher = riskier. */
    riskScore: v.number(),
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('trusted'),
    ),
    /** True when dark-web mentions or credential dumps reference this vendor. */
    breachDetected: v.boolean(),
    breachSummary: v.optional(v.string()),
    /** True when new OAuth scopes appeared since the previous snapshot. */
    scopeCreepDetected: v.boolean(),
    /** Full scope list at the time of this assessment — used for next-run diffing. */
    snapshotScopes: v.array(v.string()),
    /** Scopes added since the previous snapshot (empty on first run). */
    newScopes: v.array(v.string()),
    darkWebMentions: v.number(),
    credentialDumpMatches: v.number(),
    /** Timestamp of the most recent threat signal that matched this vendor (ms). */
    lastKnownBreachAt: v.optional(v.number()),
    /** Bounded list of the top threat signals that fired (max 10). */
    signals: v.array(
      v.object({
        kind: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        description: v.string(),
        detectedAt: v.number(),
      }),
    ),
    recommendation: v.union(
      v.literal('no_action'),
      v.literal('monitor'),
      v.literal('review_scopes'),
      v.literal('revoke_immediately'),
    ),
    computedAt: v.number(),
  })
    .index('by_vendor_and_computed_at', ['vendorId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  /** One scan result per repository push or on-demand analysis. */
  agenticWorkflowScans: defineTable({
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    /** Number of source files scanned. */
    totalFilesScanned: v.number(),
    /** Frameworks detected (e.g. ["langchain", "crewai"]). */
    frameworksDetected: v.array(v.string()),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    /** Serialised findings array (file, line, vulnClass, severity, evidence, remediation). */
    findings: v.array(v.object({
      file: v.string(),
      line: v.number(),
      framework: v.string(),
      vulnClass: v.string(),
      severity: v.string(),
      evidence: v.string(),
      remediation: v.string(),
    })),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── Community Rule/Fingerprint Marketplace (spec §10 Phase 4) ─────────────
  // Operators contribute vulnerability fingerprints and detection rule templates.
  // Approved contributions are incorporated into the platform's detection library.

  communityContributions: defineTable({
    /** Tenant that submitted this contribution. */
    contributorTenantId: v.id('tenants'),
    /** Kind of security artefact. */
    type: v.union(v.literal('fingerprint'), v.literal('detection_rule')),
    title: v.string(),
    description: v.string(),
    /** Vulnerability class (sql_injection, xss, prompt_injection, …). */
    vulnClass: v.string(),
    severity: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('informational'),
    ),
    /** The actual pattern text — regex, YAML rule, or prose description. */
    patternText: v.string(),
    /** Lifecycle status. */
    status: v.union(
      v.literal('pending'),
      v.literal('under_review'),
      v.literal('approved'),
      v.literal('rejected'),
    ),
    upvoteCount: v.number(),
    downvoteCount: v.number(),
    /** Number of abuse / accuracy reports filed against this contribution. */
    reportCount: v.number(),
    /** Set by an operator when the contribution is approved or rejected. */
    reviewNote: v.optional(v.string()),
    approvedAt: v.optional(v.number()),
    createdAt: v.number(),
  })
    .index('by_status_and_created_at', ['status', 'createdAt'])
    .index('by_type_and_status', ['type', 'status'])
    .index('by_contributor_tenant', ['contributorTenantId']),

  /**
   * One row per (voter, contribution) pair — enforces idempotency so a tenant
   * can only cast one vote per contribution.
   */
  contributionVotes: defineTable({
    contributionId: v.id('communityContributions'),
    voterTenantId: v.id('tenants'),
    voteType: v.union(v.literal('upvote'), v.literal('downvote')),
    createdAt: v.number(),
  })
    .index('by_contribution', ['contributionId'])
    .index('by_voter_and_contribution', ['voterTenantId', 'contributionId']),

  // ── Gamification snapshots (spec §3.7.4) ──────────────────────────────────
  // One snapshot per tenant per refresh — stores the computed sprint leaderboard
  // so the dashboard can render without re-running the full computation on every
  // subscription tick.  Pruned to the last 20 per tenant.
  // ── Production Traffic Anomaly snapshots (spec §10 Phase 4) ─────────────
  // One snapshot per ingest batch — stores computed anomaly assessment from
  // HTTP access log events.  Pruned to the last 50 per repository.
  trafficAnomalySnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** 0–100 composite anomaly score. */
    anomalyScore: v.number(),
    level: v.union(
      v.literal('normal'),
      v.literal('suspicious'),
      v.literal('anomalous'),
      v.literal('critical'),
    ),
    patterns: v.array(
      v.object({
        type: v.string(),
        confidence: v.number(),
        details: v.string(),
        relatedVulnClass: v.string(),
        affectedPaths: v.array(v.string()),
      }),
    ),
    findingCandidates: v.array(
      v.object({
        vulnClass: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        confidence: v.number(),
        description: v.string(),
      }),
    ),
    stats: v.object({
      totalRequests: v.number(),
      errorRate: v.number(),
      avgLatencyMs: v.number(),
      uniquePaths: v.number(),
    }),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-31 — Dependency License Compliance
  licenseComplianceSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    /** Total components evaluated. */
    totalComponents: v.number(),
    blockedCount: v.number(),
    warnCount: v.number(),
    allowedCount: v.number(),
    unknownCount: v.number(),
    /** 0-100 compliance score. */
    complianceScore: v.number(),
    overallLevel: v.union(
      v.literal('compliant'),
      v.literal('caution'),
      v.literal('non_compliant'),
    ),
    /** Top violations: blocked + warned items (cap 20 to stay under 1MB). */
    violations: v.array(
      v.object({
        name: v.string(),
        ecosystem: v.string(),
        resolvedLicense: v.union(v.string(), v.null()),
        category: v.string(),
        outcome: v.union(v.literal('blocked'), v.literal('warn')),
        source: v.string(),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-32 — SBOM Quality & Completeness Scoring
  sbomQualitySnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    /** Weighted 0–100 quality score. */
    overallScore: v.number(),
    grade: v.union(
      v.literal('excellent'),
      v.literal('good'),
      v.literal('fair'),
      v.literal('poor'),
    ),
    // Sub-scores (each 0–100)
    completenessScore: v.number(),
    versionPinningScore: v.number(),
    licenseResolutionScore: v.number(),
    freshnessScore: v.number(),
    layerCoverageScore: v.number(),
    // Raw stats
    totalComponents: v.number(),
    exactVersionCount: v.number(),
    versionPinningRate: v.number(),
    licensedCount: v.number(),
    licenseResolutionRate: v.number(),
    daysSinceCapture: v.number(),
    layersPopulated: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-33 — Infrastructure as Code (IaC) Security Scanner
  iacScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** Total IaC files scanned in this push. */
    totalFiles: v.number(),
    /** Total misconfigurations found. */
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-file findings (cap at 10 files, findings capped at 10 per file). */
    fileResults: v.array(
      v.object({
        filename: v.string(),
        fileType: v.string(),
        criticalCount: v.number(),
        highCount: v.number(),
        mediumCount: v.number(),
        lowCount: v.number(),
        findings: v.array(
          v.object({
            ruleId: v.string(),
            severity: v.string(),
            title: v.string(),
            remediation: v.string(),
          }),
        ),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-30 — Hardcoded Credential & Secret Detection
  secretScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** Number of distinct content strings that were scanned (commit messages + file paths). */
    scannedItems: v.number(),
    findings: v.array(
      v.object({
        category: v.string(),
        severity: v.union(v.literal('critical'), v.literal('high'), v.literal('medium')),
        description: v.string(),
        redactedMatch: v.string(),
        isTestFileHint: v.boolean(),
      }),
    ),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    totalFound: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  gamificationSnapshots: defineTable({
    tenantId: v.id('tenants'),
    /** Sprint window length in days (7 / 14 / 30 / 90). */
    windowDays: v.number(),
    repositoryLeaderboard: v.array(
      v.object({
        repositoryId: v.string(),
        repositoryName: v.string(),
        currentScore: v.number(),
        previousScore: v.union(v.number(), v.null()),
        scoreDelta: v.number(),
        trend: v.union(
          v.literal('improving'),
          v.literal('stable'),
          v.literal('degrading'),
        ),
        mergedPrCount: v.number(),
        rank: v.number(),
        badge: v.union(
          v.literal('gold'),
          v.literal('silver'),
          v.literal('bronze'),
          v.null(),
        ),
      }),
    ),
    engineerLeaderboard: v.array(
      v.object({
        engineerLogin: v.string(),
        mergedPrCount: v.number(),
        repositoriesContributed: v.array(v.string()),
        rank: v.number(),
      }),
    ),
    mostImprovedRepository: v.union(v.string(), v.null()),
    totalScoreDelta: v.number(),
    totalPrsMerged: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-34 — EPSS Score Integration
  // Append-once audit log of every EPSS enrichment sync run.
  // Global (not per-tenant) because the EPSS catalog is shared across all
  // tenants — we query tenant-scoped disclosures but the scores themselves
  // are universal.
  epssSnapshots: defineTable({
    syncedAt: v.number(),
    queriedCveCount: v.number(),
    enrichedCount: v.number(),
    criticalRiskCount: v.number(),
    highRiskCount: v.number(),
    mediumRiskCount: v.number(),
    lowRiskCount: v.number(),
    avgScore: v.number(),
    topCves: v.array(
      v.object({
        cveId: v.string(),
        epssScore: v.number(),
        epssPercentile: v.number(),
        epssRiskLevel: v.string(),
        packageName: v.optional(v.string()),
      }),
    ),
    summary: v.string(),
  }).index('by_synced_at', ['syncedAt']),

  // WS-37 — Cryptography Weakness Detector
  // Append-once scan result per push: detects use of broken/deprecated crypto
  // algorithms, insecure modes, weak randomness, etc. in source files.
  cryptoWeaknessResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** Total source files scanned in this push. */
    totalFiles: v.number(),
    /** Total cryptographic weakness findings. */
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-file results (capped at 10 files, findings capped at 10 per file). */
    fileResults: v.array(
      v.object({
        filename: v.string(),
        fileType: v.string(),
        criticalCount: v.number(),
        highCount: v.number(),
        mediumCount: v.number(),
        lowCount: v.number(),
        findings: v.array(
          v.object({
            ruleId: v.string(),
            severity: v.string(),
            title: v.string(),
            description: v.string(),
            remediation: v.string(),
          }),
        ),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-35 — CI/CD Pipeline Security Scanner
  cicdScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    branch: v.string(),
    commitSha: v.optional(v.string()),
    /** Total CI/CD files scanned in this push. */
    totalFiles: v.number(),
    /** Total misconfigurations found. */
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-file findings (cap at 10 files, findings capped at 10 per file). */
    fileResults: v.array(
      v.object({
        filename: v.string(),
        fileType: v.string(),
        criticalCount: v.number(),
        highCount: v.number(),
        mediumCount: v.number(),
        lowCount: v.number(),
        findings: v.array(
          v.object({
            ruleId: v.string(),
            severity: v.string(),
            title: v.string(),
            remediation: v.string(),
          }),
        ),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-39 — Open-Source Package Abandonment Detector
  // Append-once scan result per SBOM ingest: detects components that are known
  // to be abandoned, archived, officially deprecated, or supply-chain-compromised.
  // Orthogonal to EOL — abandonment is about maintainer activity, not official EOL dates.
  // Triggered fire-and-forget from sbom.ingestRepositoryInventory.
  abandonmentScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Number of supply-chain-compromised packages (highest risk). */
    criticalCount: v.number(),
    /** Number of archived/unmaintained packages with security implications. */
    highCount: v.number(),
    /** Number of officially deprecated packages. */
    mediumCount: v.number(),
    /** Number of superseded or low-risk unmaintained packages. */
    lowCount: v.number(),
    /** Total abandoned packages across all risk levels. */
    totalAbandoned: v.number(),
    /** Worst risk level seen, or 'none' when no abandoned packages found. */
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-finding detail rows (capped at 50). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        reason: v.union(
          v.literal('supply_chain_compromised'),
          v.literal('officially_deprecated'),
          v.literal('archived'),
          v.literal('superseded'),
          v.literal('unmaintained'),
        ),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        abandonedSince: v.union(v.string(), v.null()),
        replacedBy: v.union(v.string(), v.null()),
        title: v.string(),
        description: v.string(),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-40 — SBOM Attestation
  // One attestation record per SBOM snapshot — created immediately after ingest.
  // The contentHash fingerprints the component list; the attestationHash binds
  // it to the specific tenant + snapshot so cross-tenant hash reuse is impossible.
  // The status starts as 'unverified' and is updated to 'valid' or 'tampered'
  // whenever a re-verification job runs.
  sbomAttestationRecords: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    /** SHA-256 of the canonical component list alone (tenant-independent). */
    contentHash: v.string(),
    /** SHA-256 of (contentHash + ':' + tenantSlug + ':' + snapshotId + ':' + capturedAt). */
    attestationHash: v.string(),
    /** Number of unique components that were attested. */
    componentCount: v.number(),
    /** Milliseconds timestamp when the SBOM snapshot was captured. */
    capturedAt: v.number(),
    /** Milliseconds timestamp when this attestation was generated. */
    attestedAt: v.number(),
    /** Library algorithm version — bump when canonicalization changes. */
    attestationVersion: v.number(),
    /** Current verification status. */
    status: v.union(
      v.literal('valid'),
      v.literal('tampered'),
      v.literal('unverified'),
    ),
    /** Milliseconds timestamp of the last verification run, if any. */
    lastVerifiedAt: v.optional(v.number()),
  })
    .index('by_snapshot', ['snapshotId'])
    .index('by_repository_and_attested_at', ['repositoryId', 'attestedAt'])
    .index('by_tenant_and_attested_at', ['tenantId', 'attestedAt']),

  // WS-38 — Dependency & Runtime End-of-Life (EOL) Detection
  // Append-once scan result per SBOM ingest: detects components whose versions
  // have passed vendor-declared end-of-life dates and are no longer receiving
  // security patches. Triggered fire-and-forget from sbom.ingestRepositoryInventory.
  eolDetectionResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Number of components that are past end-of-life. */
    eolCount: v.number(),
    /** Number of components within 90 days of end-of-life. */
    nearEolCount: v.number(),
    /** Number of components confirmed supported. */
    supportedCount: v.number(),
    /** Number of components not found in the EOL database (unknown status). */
    unknownCount: v.number(),
    /** Worst-case status: 'critical' when eolCount>0, 'warning' nearEolCount>0, else 'ok'. */
    overallStatus: v.union(
      v.literal('critical'),
      v.literal('warning'),
      v.literal('ok'),
    ),
    /** Per-finding detail rows (capped at 50). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        eolStatus: v.union(v.literal('end_of_life'), v.literal('near_eol')),
        eolDate: v.number(),
        eolDateText: v.string(),
        daysOverdue: v.union(v.number(), v.null()),
        daysUntilEol: v.union(v.number(), v.null()),
        replacedBy: v.union(v.string(), v.null()),
        category: v.union(
          v.literal('runtime'),
          v.literal('framework'),
          v.literal('package'),
        ),
        title: v.string(),
        description: v.string(),
      }),
    ),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-41 — Dependency Confusion Attack Detector
  // Append-once scan result per SBOM ingest: examines version numbers and
  // package name patterns to detect classic "Alex Birsan" dependency confusion
  // attacks — where a public package at an inflated version hijacks a private
  // registry package. Purely static analysis, no network calls required.
  confusionAttackScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Total number of suspicious packages identified. */
    totalSuspicious: v.number(),
    /** Number of critical findings (extreme version numbers ≥ 9000). */
    criticalCount: v.number(),
    /** Number of high findings (e.g. unknown npm scope + major ≥ 500). */
    highCount: v.number(),
    /** Number of medium findings (e.g. internal-name pattern + major ≥ 49). */
    mediumCount: v.number(),
    /** Number of low findings. */
    lowCount: v.number(),
    /** Highest severity seen: 'critical' | 'high' | 'medium' | 'low' | 'none'. */
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-finding detail rows (capped at 50). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        signals: v.array(v.string()),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        title: v.string(),
        description: v.string(),
        evidence: v.string(),
      }),
    ),
    /** Human-readable summary of the scan result. */
    summary: v.string(),
    /** Milliseconds timestamp when this scan was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-42 — Malicious Package Detection
  // Append-once scan result per SBOM ingest: detects typosquatting and other
  // malicious package indicators using three static heuristic layers:
  // (1) known-malicious curated DB, (2) Levenshtein typosquat proximity,
  // (3) beyond-edit-distance patterns (homoglyphs, numeric suffix, scope squat).
  maliciousPackageScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Total number of suspicious packages identified. */
    totalSuspicious: v.number(),
    /** Number of critical findings (confirmed malicious packages). */
    criticalCount: v.number(),
    /** Number of high findings (probable typosquats). */
    highCount: v.number(),
    /** Number of medium findings (suspicious name patterns). */
    mediumCount: v.number(),
    /** Number of low findings. */
    lowCount: v.number(),
    /** Highest severity seen across all findings. */
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-finding detail rows (capped at 50). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        signals: v.array(v.string()),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        /** Popular package this name most closely resembles, or null. */
        similarTo: v.union(v.string(), v.null()),
        title: v.string(),
        description: v.string(),
        evidence: v.string(),
      }),
    ),
    /** Human-readable summary of the scan result. */
    summary: v.string(),
    /** Milliseconds timestamp when this scan was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-43 — Known CVE Version Range Scanner
  // Append-once scan result per SBOM ingest: checks installed component versions
  // against a curated offline database of ~30 high-impact CVEs (Log4Shell,
  // Spring4Shell, Text4Shell, minimist, lodash, vm2, werkzeug, etc.) using
  // pure semver comparison. No network calls required.
  cveVersionScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Total number of CVE matches found. */
    totalVulnerable: v.number(),
    /** Number of critical findings (CVSS ≥ 9.0). */
    criticalCount: v.number(),
    /** Number of high findings (CVSS 7.0–8.9). */
    highCount: v.number(),
    /** Number of medium findings (CVSS 4.0–6.9). */
    mediumCount: v.number(),
    /** Number of low findings (CVSS < 4.0). */
    lowCount: v.number(),
    /** Highest severity seen across all findings. */
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Per-finding detail rows (capped at 50). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        cveId: v.string(),
        cvss: v.number(),
        minimumSafeVersion: v.string(),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        description: v.string(),
        evidence: v.string(),
      }),
    ),
    /** Human-readable summary of the scan result. */
    summary: v.string(),
    /** Milliseconds timestamp when this scan was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-44: Supply Chain Posture Score
  // Aggregates all five supply-chain scanner outputs (EOL, Abandonment, CVE,
  // Malicious Package, Dependency Confusion) plus SBOM attestation status
  // into a single 0–100 posture score and A–F grade per repository.
  supplyChainPostureScores: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** 0–100 composite posture score. Higher = healthier. */
    score: v.number(),
    /** Letter grade derived from score thresholds (A≥90 B≥75 C≥55 D≥35 F<35). */
    grade: v.union(
      v.literal('A'),
      v.literal('B'),
      v.literal('C'),
      v.literal('D'),
      v.literal('F'),
    ),
    /** Severity classification for dashboard colouring. */
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('clean'),
    ),
    /** Total number of SBOM components analysed. */
    componentCount: v.number(),
    /** Per-category penalty breakdown (only categories with non-zero penalty). */
    breakdown: v.array(
      v.object({
        category: v.union(
          v.literal('cve'),
          v.literal('malicious'),
          v.literal('confusion'),
          v.literal('abandonment'),
          v.literal('eol'),
          v.literal('attestation'),
        ),
        label: v.string(),
        penalty: v.number(),
        detail: v.string(),
      }),
    ),
    /** Human-readable one-line summary. */
    summary: v.string(),
    /** Pass-through risk strings from each sub-scanner for secondary display. */
    cveRisk: v.string(),
    maliciousRisk: v.string(),
    confusionRisk: v.string(),
    abandonmentRisk: v.string(),
    eolRisk: v.string(),
    /** Milliseconds timestamp when this score was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-45: Container Image Security Analyzer ─────────────────────────────
  containerImageScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Total container-ecosystem components found in the SBOM. */
    totalImages: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    /** Highest risk level across all findings, or 'none' if no issues. */
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** Full list of per-image findings. */
    findings: v.array(
      v.object({
        imageName: v.string(),
        imageVersion: v.string(),
        signal: v.union(
          v.literal('eol_base_image'),
          v.literal('near_eol'),
          v.literal('outdated_base'),
          v.literal('no_version_tag'),
          v.literal('deprecated_image'),
        ),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        eolDateText: v.union(v.string(), v.null()),
        recommendedVersion: v.string(),
        detail: v.string(),
        evidence: v.string(),
      }),
    ),
    /** Human-readable one-line summary. */
    summary: v.string(),
    /** Milliseconds timestamp when this scan was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-46: Compliance Attestation Report ────────────────────────────────────
  complianceAttestationResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Per-framework attestation details (SOC2, GDPR, PCI-DSS, HIPAA, NIS2). */
    frameworks: v.array(
      v.object({
        framework: v.union(
          v.literal('soc2'),
          v.literal('gdpr'),
          v.literal('pci_dss'),
          v.literal('hipaa'),
          v.literal('nis2'),
        ),
        label: v.string(),
        status: v.union(
          v.literal('compliant'),
          v.literal('at_risk'),
          v.literal('non_compliant'),
        ),
        score: v.number(),
        criticalGaps: v.number(),
        highGaps: v.number(),
        controlGaps: v.array(
          v.object({
            controlId: v.string(),
            controlName: v.string(),
            gapSeverity: v.union(
              v.literal('critical'),
              v.literal('high'),
              v.literal('medium'),
              v.literal('low'),
            ),
            description: v.string(),
          }),
        ),
        summary: v.string(),
      }),
    ),
    /** Worst status across all 5 frameworks. */
    overallStatus: v.union(
      v.literal('compliant'),
      v.literal('at_risk'),
      v.literal('non_compliant'),
    ),
    /** Total critical gaps across all frameworks. */
    criticalGapCount: v.number(),
    /** Total high gaps across all frameworks. */
    highGapCount: v.number(),
    /** Number of frameworks with 'compliant' status. */
    fullyCompliantCount: v.number(),
    /** Human-readable one-line summary. */
    summary: v.string(),
    /** Milliseconds timestamp when this attestation was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-47: Compliance Gap Remediation Planner ───────────────────────────────
  complianceRemediationSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Ordered remediation actions (critical → high → medium → low). */
    actions: v.array(
      v.object({
        controlId: v.string(),
        controlName: v.string(),
        framework: v.union(
          v.literal('soc2'),
          v.literal('gdpr'),
          v.literal('pci_dss'),
          v.literal('hipaa'),
          v.literal('nis2'),
        ),
        gapSeverity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        title: v.string(),
        steps: v.array(
          v.object({
            order: v.number(),
            instruction: v.string(),
            category: v.union(
              v.literal('code_fix'),
              v.literal('config_change'),
              v.literal('policy_doc'),
              v.literal('tool_setup'),
              v.literal('process_change'),
            ),
            automatable: v.boolean(),
          }),
        ),
        effort: v.union(v.literal('low'), v.literal('medium'), v.literal('high')),
        estimatedDays: v.number(),
        automatable: v.boolean(),
        requiresPolicyDoc: v.boolean(),
        evidenceNeeded: v.array(v.string()),
      }),
    ),
    totalActions: v.number(),
    criticalActions: v.number(),
    highActions: v.number(),
    mediumActions: v.number(),
    lowActions: v.number(),
    automatableActions: v.number(),
    requiresPolicyDocCount: v.number(),
    /** Root-cause-deduplicated effort estimate in business days. */
    estimatedTotalDays: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-48: License Compliance & Risk Scanner ─────────────────────────────
  licenseComplianceScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Per-package findings with riskLevel ≥ low (permissive packages excluded). */
    findings: v.array(
      v.object({
        packageName: v.string(),
        ecosystem: v.string(),
        version: v.string(),
        spdxId: v.string(),
        licenseType: v.union(
          v.literal('permissive'),
          v.literal('weak_copyleft'),
          v.literal('strong_copyleft'),
          v.literal('proprietary'),
          v.literal('unknown'),
        ),
        riskLevel: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
          v.literal('none'),
        ),
        riskSignal: v.union(
          v.literal('strong_copyleft'),
          v.literal('weak_copyleft'),
          v.literal('proprietary_restricted'),
          v.literal('unrecognized_license'),
          v.literal('unknown_license'),
        ),
        description: v.string(),
      }),
    ),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    totalScanned: v.number(),
    unknownLicenseCount: v.number(),
    overallRisk: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    /** SPDX identifier → component count (includes permissive packages). */
    licenseBreakdown: v.record(v.string(), v.number()),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-49: Repository Security Health Score ─────────────────────────────────
  // Master synthesis layer that reads from all major scanner result tables and
  // produces a single weighted 0–100 health score with an A–F grade plus
  // per-category breakdown. This is the executive-level "how secure is this
  // repository?" answer.
  repositoryHealthScoreResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Weighted 0–100 overall security health score. */
    overallScore: v.number(),
    /** Letter grade: A≥90, B≥75, C≥60, D≥40, F<40. */
    overallGrade: v.union(
      v.literal('A'),
      v.literal('B'),
      v.literal('C'),
      v.literal('D'),
      v.literal('F'),
    ),
    /** Per-category score breakdown (always 7 entries). */
    categories: v.array(
      v.object({
        category: v.string(),
        label: v.string(),
        score: v.number(),
        weight: v.number(),
        grade: v.union(
          v.literal('A'),
          v.literal('B'),
          v.literal('C'),
          v.literal('D'),
          v.literal('F'),
        ),
        signals: v.array(v.string()),
      }),
    ),
    /** Score trend compared to previous result. */
    trend: v.union(
      v.literal('improving'),
      v.literal('declining'),
      v.literal('stable'),
      v.literal('new'),
    ),
    /** Top 5 risk signals across all categories (lowest-scoring first). */
    topRisks: v.array(v.string()),
    /** Human-readable one-line summary. */
    summary: v.string(),
    /** Milliseconds timestamp when this score was computed. */
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // ── WS-50: Dependency Update Recommendation Engine ──────────────────────────
  // Reads CVE, EOL, and abandonment scanner findings to produce a deduplicated,
  // prioritised list of concrete "upgrade X from v1.2.3 → v1.4.0" recommendations.
  // Each recommendation includes urgency, effort classification (patch/minor/major/
  // replacement), breaking change risk, and combined reasons from all scanners.
  dependencyUpdateRecommendations: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Prioritised update recommendations (capped at 50). */
    recommendations: v.array(
      v.object({
        ecosystem: v.string(),
        packageName: v.string(),
        currentVersion: v.string(),
        recommendedVersion: v.string(),
        urgency: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        effort: v.union(
          v.literal('patch'),
          v.literal('minor'),
          v.literal('major'),
          v.literal('replacement'),
        ),
        breakingChangeRisk: v.boolean(),
        reasons: v.array(v.string()),
        details: v.array(v.string()),
        cveIds: v.array(v.string()),
        replacementPackage: v.union(v.string(), v.null()),
      }),
    ),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    totalRecommendations: v.number(),
    patchCount: v.number(),
    breakingCount: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-52 — Security Debt Velocity Tracker
  // Point-in-time snapshot of how quickly security findings are accumulating
  // versus being resolved. Drives the debt velocity panel and executive digest.
  securityDebtSnapshots: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Analysis window in days used for velocity metrics. */
    windowDays: v.number(),
    /** Findings created within the window. */
    newFindingsInWindow: v.number(),
    /** Findings resolved/closed within the window. */
    resolvedFindingsInWindow: v.number(),
    /** net = new/day − resolved/day (positive = accumulating). */
    netVelocityPerDay: v.number(),
    /** Raw creation rate within the window (findings/day). */
    newPerDay: v.number(),
    /** Raw resolution rate within the window (findings/day). */
    resolvedPerDay: v.number(),
    /** Total open findings at time of snapshot. */
    openFindings: v.number(),
    /** Open findings with severity 'critical'. */
    openCritical: v.number(),
    /** Open findings with severity 'high'. */
    openHigh: v.number(),
    /** Open findings past their SLA deadline. */
    overdueFindings: v.number(),
    /** Open critical findings past the 24-hour SLA. */
    overdueCritical: v.number(),
    /** Trend classification based on net velocity. */
    trend: v.union(
      v.literal('improving'),
      v.literal('stable'),
      v.literal('degrading'),
      v.literal('critical'),
    ),
    /** Projected days to clear all open findings at current resolution rate (null if no resolution). */
    projectedClearanceDays: v.union(v.number(), v.null()),
    /** 0–100 debt score (100 = no debt, 0 = worst). */
    debtScore: v.number(),
    summary: v.string(),
    computedAt: v.number(),
  })
    .index('by_repository_and_computed_at', ['repositoryId', 'computedAt'])
    .index('by_tenant_and_computed_at', ['tenantId', 'computedAt']),

  // WS-53 — GitHub Branch Protection Analyzer
  branchProtectionResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Default branch name that was evaluated (e.g. "main"). */
    defaultBranch: v.string(),
    /** 0–100 composite risk score (0=safe, 100=critical). */
    riskScore: v.number(),
    /** Human-readable risk level. */
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    /** Per-rule findings with recommendation text. */
    findings: v.array(
      v.object({
        ruleId: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        title: v.string(),
        detail: v.string(),
        recommendation: v.string(),
      }),
    ),
    summary: v.string(),
    /** Whether the GitHub API was reachable and returned real data. */
    dataSource: v.union(v.literal('github_api'), v.literal('simulated')),
    scannedAt: v.number(),
  })
    .index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt'])
    .index('by_tenant_and_scanned_at', ['tenantId', 'scannedAt']),

  // WS-54 — Sensitive File Commit Detector
  sensitiveFileResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Git commit SHA that triggered this scan. */
    commitSha: v.string(),
    /** Branch where the push occurred. */
    branch: v.string(),
    /** All file paths in the push payload that were scanned. */
    scannedPaths: v.array(v.string()),
    /** 0–100 composite risk score (0=clean, 100=critical). */
    riskScore: v.number(),
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    /** Per-path findings with category, severity, and remediation advice. */
    findings: v.array(
      v.object({
        ruleId: v.string(),
        category: v.union(
          v.literal('private_key'),
          v.literal('credentials'),
          v.literal('app_config'),
          v.literal('debug'),
        ),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        matchedPath: v.string(),
        description: v.string(),
        recommendation: v.string(),
      }),
    ),
    summary: v.string(),
    scannedAt: v.number(),
  })
    .index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt'])
    .index('by_tenant_and_scanned_at', ['tenantId', 'scannedAt']),

  // WS-55 — Commit Message Security Analyzer
  commitMessageScanResults: defineTable({
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    /** Git commit SHA of the HEAD commit in the push. */
    commitSha: v.string(),
    /** Branch where the push occurred. */
    branch: v.string(),
    /** All commit messages analysed in this push (capped at 50). */
    analyzedMessages: v.array(v.string()),
    /** 0–100 composite risk score (0=clean, 100=critical). */
    riskScore: v.number(),
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('none'),
    ),
    totalFindings: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    /** Per-message findings with rule, severity, and remediation advice. */
    findings: v.array(
      v.object({
        ruleId: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        matchedMessage: v.string(),
        description: v.string(),
        recommendation: v.string(),
      }),
    ),
    summary: v.string(),
    scannedAt: v.number(),
  })
    .index('by_repository_and_scanned_at', ['repositoryId', 'scannedAt'])
    .index('by_tenant_and_scanned_at', ['tenantId', 'scannedAt']),
})
