import { mutation } from './_generated/server'
import { v } from 'convex/values'
import {
  buildBreachDisclosureWorkflow,
  buildGithubPushWorkflow,
} from './lib/eventRouter'
import {
  buildDisclosureMatchSummary,
  normalizePackageName,
} from './lib/breachMatching'

export const seedBaseline = mutation({
  args: {},
  returns: v.object({
    tenantId: v.id('tenants'),
    repositoryIds: v.array(v.id('repositories')),
    created: v.boolean(),
  }),
  handler: async (ctx) => {
    const existingTenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', 'atlas-fintech'))
      .unique()

    if (existingTenant) {
      const repositories = await ctx.db
        .query('repositories')
        .withIndex('by_tenant', (q) => q.eq('tenantId', existingTenant._id))
        .collect()

      return {
        tenantId: existingTenant._id,
        repositoryIds: repositories.map((repository) => repository._id),
        created: false,
      }
    }

    const now = Date.now()
    const hour = 60 * 60 * 1000
    const seededPush = buildGithubPushWorkflow({
      tenantSlug: 'atlas-fintech',
      repositoryFullName: 'atlas-fintech/payments-api',
      branch: 'main',
      commitSha: '9e24a44',
      changedFiles: [
        'services/auth/jwt.py',
        'requirements.txt',
        'infra/github/workflows/scan.yml',
      ],
    })
    const seededDisclosure = buildBreachDisclosureWorkflow({
      packageName: 'pyjwt',
      sourceName: 'GitHub Security Advisories',
      sourceRef: 'GHSA-77m4-fm8m-6h7p',
      severity: 'high',
    })

    const tenantId = await ctx.db.insert('tenants', {
      slug: 'atlas-fintech',
      name: 'Atlas Fintech',
      status: 'active',
      deploymentMode: 'cloud_saas',
      currentPhase: 'phase_0',
      createdAt: now - 30 * 24 * hour,
    })

    const paymentsApiId = await ctx.db.insert('repositories', {
      tenantId,
      provider: 'github',
      name: 'payments-api',
      fullName: 'atlas-fintech/payments-api',
      defaultBranch: 'main',
      visibility: 'private',
      primaryLanguage: 'Python',
      latestCommitSha: '9e24a44',
      lastScannedAt: now - 18 * 60 * 1000,
    })

    const operatorConsoleId = await ctx.db.insert('repositories', {
      tenantId,
      provider: 'github',
      name: 'operator-console',
      fullName: 'atlas-fintech/operator-console',
      defaultBranch: 'main',
      visibility: 'private',
      primaryLanguage: 'TypeScript',
      latestCommitSha: '2fb311a',
      lastScannedAt: now - 52 * 60 * 1000,
    })

    const pushEventId = await ctx.db.insert('ingestionEvents', {
      tenantId,
      repositoryId: paymentsApiId,
      dedupeKey: seededPush.dedupeKey,
      kind: seededPush.kind,
      source: seededPush.source,
      workflowType: seededPush.workflowType,
      status: 'completed',
      externalRef: 'gh-delivery-44391',
      branch: 'main',
      commitSha: '9e24a44',
      changedFiles: [
        'services/auth/jwt.py',
        'requirements.txt',
        'infra/github/workflows/scan.yml',
      ],
      summary: seededPush.eventSummary,
      receivedAt: now - 85 * 60 * 1000,
    })

    const breachEventId = await ctx.db.insert('ingestionEvents', {
      tenantId,
      repositoryId: paymentsApiId,
      dedupeKey: seededDisclosure.dedupeKey,
      kind: seededDisclosure.kind,
      source: seededDisclosure.source,
      workflowType: seededDisclosure.workflowType,
      status: 'running',
      externalRef: 'GHSA-77m4-fm8m-6h7p',
      summary: seededDisclosure.eventSummary,
      receivedAt: now - 26 * 60 * 1000,
    })

    const scanWorkflowId = await ctx.db.insert('workflowRuns', {
      tenantId,
      repositoryId: paymentsApiId,
      eventId: pushEventId,
      workflowType: seededPush.workflowType,
      status: 'completed',
      priority: seededPush.priority,
      currentStage: 'policy',
      summary:
        'Semantic fingerprinting escalated auth-sensitive drift into exploit-first validation and refreshed gate posture on the main branch.',
      totalTaskCount: seededPush.tasks.length,
      completedTaskCount: seededPush.tasks.length,
      startedAt: now - 82 * 60 * 1000,
      completedAt: now - 70 * 60 * 1000,
    })

    const breachWorkflowId = await ctx.db.insert('workflowRuns', {
      tenantId,
      repositoryId: paymentsApiId,
      eventId: breachEventId,
      workflowType: seededDisclosure.workflowType,
      status: 'running',
      priority: seededDisclosure.priority,
      currentStage: 'decision',
      summary:
        'Exploit validation confirmed upstream breach exposure and handed the workflow to gate recalculation.',
      totalTaskCount: seededDisclosure.tasks.length,
      completedTaskCount: 3,
      startedAt: now - 24 * 60 * 1000,
    })

    const tasks = [
      ...seededPush.tasks.map((task, index) => ({
        workflowRunId: scanWorkflowId,
        tenantId,
        ...task,
        status: 'completed' as const,
        detail:
          index === 1
            ? 'Detected dependency drift in lockfiles and rebuilt the repository inventory.'
            : index === 2
              ? 'Semantic fingerprinting matched auth-sensitive drift in JWT handling paths and queued a candidate finding.'
              : index === 3
                ? 'Exploit validation staged a reproducible auth-path replay plan and marked the candidate likely exploitable.'
            : task.detail,
        startedAt: now - (82 - index * 2) * 60 * 1000,
        completedAt: now - (81 - index * 2) * 60 * 1000,
      })),
      ...seededDisclosure.tasks.map((task, index) => ({
        workflowRunId: breachWorkflowId,
        tenantId,
        ...task,
        status:
          index < 3 ? ('completed' as const) : ('queued' as const),
        detail:
          index === 2
            ? 'Local exploit validation confirmed a reproducible path from the matched dependency disclosure.'
            : task.detail,
        startedAt:
          index < 3 ? now - (24 - index * 5) * 60 * 1000 : undefined,
        completedAt: index < 3 ? now - (19 - index * 4) * 60 * 1000 : undefined,
      })),
    ]

    for (const task of tasks) {
      await ctx.db.insert('workflowTasks', task)
    }

    const snapshotId = await ctx.db.insert('sbomSnapshots', {
      tenantId,
      repositoryId: paymentsApiId,
      commitSha: '9e24a44',
      branch: 'main',
      capturedAt: now - 77 * 60 * 1000,
      sourceFiles: ['requirements.txt', 'pyproject.toml', 'Dockerfile'],
      directDependencyCount: 14,
      transitiveDependencyCount: 61,
      buildDependencyCount: 9,
      containerDependencyCount: 21,
      runtimeDependencyCount: 6,
      aiModelDependencyCount: 1,
      totalComponents: 112,
      riskDelta: 18,
      exportFormats: ['cyclonedx', 'spdx', 'sentinel_json'],
    })

    const components = [
      {
        tenantId,
        repositoryId: paymentsApiId,
        snapshotId,
        name: 'fastapi',
        normalizedName: normalizePackageName('fastapi'),
        version: '0.117.1',
        ecosystem: 'pypi',
        layer: 'direct',
        isDirect: true,
        sourceFile: 'pyproject.toml',
        trustScore: 92,
        hasKnownVulnerabilities: false,
        license: 'MIT',
        dependents: [],
      },
      {
        tenantId,
        repositoryId: paymentsApiId,
        snapshotId,
        name: 'httpx',
        normalizedName: normalizePackageName('httpx'),
        version: '0.28.1',
        ecosystem: 'pypi',
        layer: 'direct',
        isDirect: true,
        sourceFile: 'requirements.txt',
        trustScore: 89,
        hasKnownVulnerabilities: false,
        license: 'BSD-3-Clause',
        dependents: [],
      },
      {
        tenantId,
        repositoryId: paymentsApiId,
        snapshotId,
        name: 'pyjwt',
        normalizedName: normalizePackageName('pyjwt'),
        version: '2.10.1',
        ecosystem: 'pypi',
        layer: 'transitive',
        isDirect: false,
        sourceFile: 'requirements.txt',
        trustScore: 71,
        hasKnownVulnerabilities: true,
        license: 'MIT',
        dependents: ['auth-core'],
      },
      {
        tenantId,
        repositoryId: paymentsApiId,
        snapshotId,
        name: 'ghcr.io/atlas/payments-api-base',
        normalizedName: normalizePackageName('ghcr.io/atlas/payments-api-base'),
        version: '2026.04.03',
        ecosystem: 'container',
        layer: 'container',
        isDirect: true,
        sourceFile: 'Dockerfile',
        trustScore: 84,
        hasKnownVulnerabilities: false,
        license: 'proprietary',
        dependents: [],
      },
    ]

    for (const component of components) {
      await ctx.db.insert('sbomComponents', component)
    }

    const disclosureId = await ctx.db.insert('breachDisclosures', {
      repositoryId: paymentsApiId,
      workflowRunId: breachWorkflowId,
      packageName: 'pyjwt',
      normalizedPackageName: normalizePackageName('pyjwt'),
      ecosystem: 'pypi',
      sourceType: 'github_security_advisory',
      sourceTier: 'tier_1',
      sourceName: 'GitHub Security Advisories',
      sourceRef: 'GHSA-77m4-fm8m-6h7p',
      aliases: ['GHSA-77m4-fm8m-6h7p'],
      summary:
        'Authentication bypass conditions may exist when token audience checks are omitted in custom wrappers.',
      severity: 'high',
      affectedVersions: ['>=2.8.0', '<2.10.2'],
      fixVersion: '2.10.2',
      exploitAvailable: true,
      matchStatus: 'matched',
      versionMatchStatus: 'affected',
      matchedSnapshotId: snapshotId,
      matchedComponentCount: 1,
      affectedComponentCount: 1,
      matchedVersions: ['2.10.1'],
      affectedMatchedVersions: ['2.10.1'],
      matchSummary: buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'matched',
        matchedComponentCount: 1,
        affectedComponentCount: 1,
        matchedVersions: ['2.10.1'],
        affectedMatchedVersions: ['2.10.1'],
        affectedVersions: ['>=2.8.0', '<2.10.2'],
        fixVersion: '2.10.2',
      }),
      findingId: undefined,
      publishedAt: now - 30 * 60 * 1000,
    })

    const findingId = await ctx.db.insert('findings', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: breachWorkflowId,
      breachDisclosureId: disclosureId,
      source: 'breach_intel',
      vulnClass: 'jwt_validation_bypass',
      title: 'PyJWT audience validation wrapper needs exploit confirmation',
      summary:
        'The current auth gateway uses a wrapper around token validation that may bypass the newly disclosed audience-check hardening path.',
      confidence: 0.88,
      severity: 'high',
      validationStatus: 'validated',
      status: 'open',
      businessImpactScore: 84,
      blastRadiusSummary:
        'A bypass would affect API token acceptance in the public payments entrypoint and downstream settlement jobs.',
      prUrl: undefined,
      reasoningLogUrl: 'artifact://reasoning/breach-ghsa-77m4',
      pocArtifactUrl: 'artifact://poc/breach-ghsa-77m4',
      affectedServices: ['payments-api', 'auth-gateway'],
      affectedFiles: [
        'services/auth/jwt.py',
        'services/auth/token_router.py',
      ],
      affectedPackages: ['pyjwt'],
      regulatoryImplications: ['PCI-DSS access control review'],
      createdAt: now - 21 * 60 * 1000,
      resolvedAt: undefined,
    })

    await ctx.db.patch('breachDisclosures', disclosureId, {
      findingId,
    })

    const semanticFindingId = await ctx.db.insert('findings', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: scanWorkflowId,
      source: 'semantic_fingerprint',
      vulnClass: 'jwt_validation_bypass',
      title: 'Authentication flow drift may need semantic validation in payments-api',
      summary:
        'payments-api changed authentication-sensitive paths that overlap with known token-validation failure patterns and should be queued for exploit-first validation.',
      confidence: 0.82,
      severity: 'high',
      validationStatus: 'likely_exploitable',
      status: 'open',
      businessImpactScore: 78,
      blastRadiusSummary:
        'payments-api changed auth-sensitive paths that can affect token issuance and request authorization.',
      prUrl: undefined,
      reasoningLogUrl: 'artifact://reasoning/svf-auth-001-scan',
      pocArtifactUrl: undefined,
      affectedServices: ['payments-api', 'auth-gateway'],
      affectedFiles: ['services/auth/jwt.py'],
      affectedPackages: ['pyjwt'],
      regulatoryImplications: [],
      createdAt: now - 73 * 60 * 1000,
      resolvedAt: undefined,
    })

    await ctx.db.insert('exploitValidationRuns', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: breachWorkflowId,
      findingId,
      status: 'completed',
      outcome: 'validated',
      validationConfidence: 0.93,
      sandboxSummary:
        'Reconstructed a local validation plan for the payments API auth gateway and matched the vulnerable dependency context.',
      evidenceSummary:
        'Upstream exploit intelligence was available for GHSA-77m4-fm8m-6h7p and the affected package version was present in live inventory.',
      reproductionHint:
        'Replay the audience-check bypass against services/auth/jwt.py before accepting a patched build.',
      startedAt: now - 16 * 60 * 1000,
      completedAt: now - 15 * 60 * 1000,
    })

    await ctx.db.insert('exploitValidationRuns', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: scanWorkflowId,
      findingId: semanticFindingId,
      status: 'completed',
      outcome: 'likely_exploitable',
      validationConfidence: 0.82,
      sandboxSummary:
        'Prepared a reproducible auth-path replay plan centered on the payments-api token router.',
      evidenceSummary:
        'The changed JWT handling path aligned with a high-signal semantic fingerprint and remained likely exploitable pending live sandbox confirmation.',
      reproductionHint:
        'Start with services/auth/jwt.py and exercise token issuance through the auth gateway.',
      startedAt: now - 71 * 60 * 1000,
      completedAt: now - 69 * 60 * 1000,
    })

    await ctx.db.insert('findings', {
      tenantId,
      repositoryId: operatorConsoleId,
      workflowRunId: scanWorkflowId,
      source: 'semantic_fingerprint',
      vulnClass: 'llm_prompt_boundary',
      title: 'Prompt construction path changed without guardrail metadata',
      summary:
        'The operator console added a new prompt assembly path that should be routed through the prompt-injection shield before it becomes a merge blocker.',
      confidence: 0.61,
      severity: 'medium',
      validationStatus: 'likely_exploitable',
      status: 'accepted_risk',
      businessImpactScore: 43,
      blastRadiusSummary:
        'Limited to the internal analyst console, but it affects downstream support automations.',
      prUrl: undefined,
      reasoningLogUrl: 'artifact://reasoning/prompt-boundary-021',
      pocArtifactUrl: 'artifact://poc/prompt-boundary-021',
      affectedServices: ['operator-console'],
      affectedFiles: ['src/lib/prompt-builder.ts'],
      affectedPackages: ['openai'],
      regulatoryImplications: [],
      createdAt: now - 66 * 60 * 1000,
      resolvedAt: undefined,
    })

    await ctx.db.insert('gatePolicies', {
      tenantId,
      repositoryId: undefined,
      blockOnSeverities: ['critical', 'high'],
      blockOnValidationStatuses: ['validated', 'likely_exploitable'],
      requireExplicitApprovalForCritical: true,
      isActive: true,
      createdAt: now - 30 * 24 * hour,
      updatedAt: now - 30 * 24 * hour,
    })

    await ctx.db.insert('gateDecisions', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: breachWorkflowId,
      findingId,
      stage: 'pre_merge',
      decision: 'blocked',
      actorType: 'agent',
      actorId: 'gate-policy-v1',
      justification:
        'High-severity disclosure matched a live dependency and exploit validation produced a reproducible path.',
      expiresAt: now + 24 * hour,
      createdAt: now - 11 * 60 * 1000,
    })

    await ctx.db.insert('gateDecisions', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: scanWorkflowId,
      findingId: semanticFindingId,
      stage: 'policy',
      decision: 'blocked',
      actorType: 'agent',
      actorId: 'gate_policy_agent',
      justification:
        'Gate blocked for payments-api on main: high likely exploitable finding requires resolution before merge or deploy.',
      expiresAt: undefined,
      createdAt: now - 68 * 60 * 1000,
    })

    await ctx.db.insert('advisorySyncRuns', {
      tenantId,
      repositoryId: paymentsApiId,
      triggerType: 'scheduled',
      status: 'completed',
      packageCount: 4,
      lookbackHours: 72,
      githubQueried: 1,
      githubFetched: 1,
      githubImported: 1,
      githubDeduped: 0,
      osvQueried: 1,
      osvFetched: 1,
      osvImported: 0,
      osvDeduped: 1,
      reason: undefined,
      startedAt: now - 35 * 60 * 1000,
      completedAt: now - 34 * 60 * 1000,
    })

    await ctx.db.insert('advisorySyncRuns', {
      tenantId,
      repositoryId: operatorConsoleId,
      triggerType: 'manual',
      status: 'skipped',
      packageCount: 0,
      lookbackHours: 72,
      githubQueried: 0,
      githubFetched: 0,
      githubImported: 0,
      githubDeduped: 0,
      osvQueried: 0,
      osvFetched: 0,
      osvImported: 0,
      osvDeduped: 0,
      reason: 'Skipped advisory sync because the repository has no imported SBOM snapshot yet.',
      startedAt: now - 16 * 60 * 1000,
      completedAt: now - 16 * 60 * 1000,
    })

    await ctx.db.insert('prProposals', {
      tenantId,
      repositoryId: paymentsApiId,
      workflowRunId: breachWorkflowId,
      findingId,
      status: 'draft',
      fixType: 'version_bump',
      proposedBranch: 'sentinel/fix-pyjwt-2-10-2-a3f9d2',
      prTitle: 'fix(deps): bump pyjwt from 2.10.1 to 2.10.2',
      prBody: [
        '## Security Fix',
        '',
        'This pull request was automatically proposed by **Sentinel** to address a confirmed security finding.',
        '',
        '### Finding',
        '',
        '| Field | Value |',
        '|---|---|',
        '| Title | PyJWT audience validation wrapper needs exploit confirmation |',
        '| Severity | `high` |',
        '',
        'The current auth gateway uses a wrapper around token validation that may bypass the newly disclosed audience-check hardening path.',
        '',
        '### Proposed Fix',
        '',
        'Bumps `pyjwt` from **2.10.1** → **2.10.2**.',
        'Ecosystem: `pypi`',
        '',
        '### Affected Packages',
        '',
        '- `pyjwt`',
        '',
        '### References',
        '',
        '- Advisory: `GHSA-77m4-fm8m-6h7p`',
        '',
        '---',
        '> **Review required before merging.**',
        '',
        '*Generated by Sentinel — autonomous security platform.*',
      ].join('\n'),
      fixSummary: 'Bump pyjwt from 2.10.1 to 2.10.2',
      targetPackage: 'pyjwt',
      targetEcosystem: 'pypi',
      currentVersion: '2.10.1',
      fixVersion: '2.10.2',
      createdAt: now - 8 * 60 * 1000,
    })

    // ── Seed Neural Memory data ───────────────────────────────────────────
    // Only inserts if no project memories exist yet (idempotent).
    const existingMemoryCount = await ctx.db
      .query('projectMemories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .take(1)

    if (existingMemoryCount.length === 0) {
      const paymentsMemoryId = await ctx.db.insert('projectMemories', {
        repositoryId: paymentsApiId,
        tenantId,
        version: 4,
        lastLearningAt: now - 45 * 60 * 1000,
        memoryStats: {
          totalEpisodes: 47,
          totalPatterns: 5,
          predictionAccuracy: 0.78,
          coverageScore: 0.72,
        },
      })

      const operatorMemoryId = await ctx.db.insert('projectMemories', {
        repositoryId: operatorConsoleId,
        tenantId,
        version: 2,
        lastLearningAt: now - 3 * 60 * 60 * 1000,
        memoryStats: {
          totalEpisodes: 21,
          totalPatterns: 2,
          predictionAccuracy: 0.65,
          coverageScore: 0.44,
        },
      })

      // Episodes for payments-api
      for (const ep of [
        { episodeType: 'finding' as const, payload: { severity: 'high', cwe: 'CWE-287', filePath: 'services/auth/jwt.py', dependency: 'pyjwt' }, sourceRef: 'finding-jwt-001' },
        { episodeType: 'finding' as const, payload: { severity: 'high', cwe: 'CWE-287', filePath: 'services/auth/token_router.py', dependency: 'pyjwt' }, sourceRef: 'finding-jwt-002' },
        { episodeType: 'fix' as const, payload: { filePath: 'services/auth/jwt.py', dependency: 'pyjwt', fixVersion: '2.10.2' }, sourceRef: 'fix-jwt-001' },
        { episodeType: 'gate_block' as const, payload: { severity: 'high', reason: 'unvalidated_finding' }, sourceRef: 'gate-block-001' },
        { episodeType: 'false_positive' as const, payload: { filePath: 'tests/test_auth.py', ruleId: 'test-exposure' }, sourceRef: 'fp-test-001' },
      ]) {
        await ctx.db.insert('memoryEpisodes', {
          projectMemoryId: paymentsMemoryId,
          tenantId,
          repositoryId: paymentsApiId,
          episodeType: ep.episodeType,
          timestamp: now - Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000),
          payload: ep.payload,
          embedding: [`type:${ep.episodeType}`, ...(ep.payload.severity ? [`severity:${ep.payload.severity}`] : []), ...(ep.payload.cwe ? [`cwe:${ep.payload.cwe}`] : [])],
          sourceRef: ep.sourceRef,
          processed: true,
        })
      }

      // Episodes for operator-console
      for (const ep of [
        { episodeType: 'finding' as const, payload: { severity: 'medium', cwe: 'CWE-74', filePath: 'src/lib/prompt-builder.ts' }, sourceRef: 'finding-prompt-001' },
        { episodeType: 'scan_result' as const, payload: { totalFindings: 2, highCount: 0, mediumCount: 1 }, sourceRef: 'scan-001' },
      ]) {
        await ctx.db.insert('memoryEpisodes', {
          projectMemoryId: operatorMemoryId,
          tenantId,
          repositoryId: operatorConsoleId,
          episodeType: ep.episodeType,
          timestamp: now - Math.floor(Math.random() * 3 * 24 * 60 * 60 * 1000),
          payload: ep.payload,
          embedding: [`type:${ep.episodeType}`, ...(ep.payload.severity ? [`severity:${ep.payload.severity}`] : [])],
          sourceRef: ep.sourceRef,
          processed: true,
        })
      }

      // Patterns for payments-api
      const xssPatternId = await ctx.db.insert('memoryPatterns', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        patternType: 'recurring_vulnerability',
        name: 'JWT Validation Bypass',
        description: 'Authentication flows repeatedly exhibit CWE-287 findings in token validation wrappers. Pattern discovered across 3 separate scan cycles.',
        confidence: 0.89,
        frequency: 3,
        firstSeenAt: now - 14 * 24 * 60 * 60 * 1000,
        lastSeenAt: now - 2 * 60 * 60 * 1000,
        attributes: { commonFeatures: ['cwe:CWE-287', 'dependency:pyjwt', 'severity:high'], timeSpan: 14 * 24 * 60 * 60 * 1000 },
        severity: 'high',
        isActive: true,
        relatedPatternIds: [],
      })

      const depRiskPatternId = await ctx.db.insert('memoryPatterns', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        patternType: 'dependency_risk',
        name: 'Crypto Library Churn',
        description: 'Cryptography-related dependencies are updated more frequently than the tenant average, indicating active maintenance pressure in this area.',
        confidence: 0.74,
        frequency: 5,
        firstSeenAt: now - 30 * 24 * 60 * 60 * 1000,
        lastSeenAt: now - 5 * 24 * 60 * 60 * 1000,
        attributes: { commonFeatures: ['dependency:pyjwt', 'dependency:cryptography', 'layer:transitive'] },
        severity: 'medium',
        isActive: true,
        relatedPatternIds: [xssPatternId],
      })

      await ctx.db.insert('memoryPatterns', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        patternType: 'false_positive_signal',
        name: 'Test File Exposure',
        description: 'Findings in files matching tests/** are consistently dismissed as false positives. Suppression candidate.',
        confidence: 0.91,
        frequency: 4,
        firstSeenAt: now - 21 * 24 * 60 * 60 * 1000,
        lastSeenAt: now - 1 * 24 * 60 * 60 * 1000,
        attributes: { commonFeatures: ['directory:tests', 'extension:py'] },
        severity: 'informational',
        isActive: true,
        relatedPatternIds: [],
      })

      await ctx.db.insert('memoryPatterns', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        patternType: 'temporal_pattern',
        name: 'Friday Deploy Risk',
        description: 'Gate blocks are 2.4× more likely to occur on deployments pushed after 16:00 UTC on Fridays.',
        confidence: 0.68,
        frequency: 6,
        firstSeenAt: now - 45 * 24 * 60 * 60 * 1000,
        lastSeenAt: now - 3 * 24 * 60 * 60 * 1000,
        attributes: { commonFeatures: ['type:gate_block', 'severity:high'] },
        severity: 'medium',
        isActive: true,
        relatedPatternIds: [],
      })

      // Shared pattern between both repos (same name/type)
      await ctx.db.insert('memoryPatterns', {
        projectMemoryId: operatorMemoryId,
        tenantId,
        repositoryId: operatorConsoleId,
        patternType: 'dependency_risk',
        name: 'Crypto Library Churn',
        description: 'AI/LLM SDK dependencies are updated at high frequency, creating supply chain exposure windows.',
        confidence: 0.61,
        frequency: 2,
        firstSeenAt: now - 10 * 24 * 60 * 60 * 1000,
        lastSeenAt: now - 2 * 24 * 60 * 60 * 1000,
        attributes: { commonFeatures: ['dependency:openai', 'layer:direct'] },
        severity: 'medium',
        isActive: true,
        relatedPatternIds: [],
      })

      // Predictions for payments-api
      const predId1 = await ctx.db.insert('memoryPredictions', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        predictionType: 'vulnerability_likelihood',
        title: 'High likelihood of another JWT-class finding within 14 days',
        description: 'Based on the recurring JWT validation bypass pattern (confidence 89%) and the dependency churn pattern, there is a high probability a similar CWE-287 finding will surface within the next two weeks.',
        confidence: 0.82,
        basedOnPatternIds: [xssPatternId, depRiskPatternId],
        status: 'active',
        createdAt: now - 2 * 60 * 60 * 1000,
        expiresAt: now + 14 * 24 * 60 * 60 * 1000,
      })

      const predId2 = await ctx.db.insert('memoryPredictions', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        predictionType: 'false_positive_candidate',
        title: 'Test-file findings are likely suppressible',
        description: 'Sentinel has identified 4 dismissed findings in tests/** with identical attributes. Adding a suppression rule could reduce false positive noise by ~23%.',
        confidence: 0.91,
        basedOnPatternIds: [],
        status: 'confirmed',
        createdAt: now - 5 * 24 * 60 * 60 * 1000,
        expiresAt: undefined,
        outcome: 'Suppression rule added by team lead on 2026-05-10',
      })

      await ctx.db.insert('memoryPredictions', {
        projectMemoryId: paymentsMemoryId,
        tenantId,
        repositoryId: paymentsApiId,
        predictionType: 'deployment_risk',
        title: 'Friday afternoon deployments carry elevated gate-block risk',
        description: 'The temporal pattern shows gate blocks cluster around late-Friday deployments. Consider enforcing a staging gate or deployment freeze after 16:00 UTC on Fridays.',
        confidence: 0.68,
        basedOnPatternIds: [],
        status: 'active',
        createdAt: now - 1 * 24 * 60 * 60 * 1000,
        expiresAt: now + 30 * 24 * 60 * 60 * 1000,
      })

      // Feedback entries
      await ctx.db.insert('memoryFeedback', {
        tenantId,
        repositoryId: paymentsApiId,
        predictionId: predId2,
        outcome: 'confirmed',
        actualEvent: 'Team added suppression rule for tests/** on 2026-05-10; zero false positives since.',
        feedbackAt: now - 4 * 24 * 60 * 60 * 1000,
        accuracyDelta: 0.1,
      })

      await ctx.db.insert('memoryFeedback', {
        tenantId,
        repositoryId: paymentsApiId,
        predictionId: predId1,
        outcome: 'partial',
        actualEvent: 'A medium-severity JWT finding surfaced on 2026-05-14 — lower severity than predicted but class was correct.',
        feedbackAt: now - 2 * 24 * 60 * 60 * 1000,
        accuracyDelta: 0.05,
      })
    }

    // ── Seed integration catalog (spec §5.2) ─────────────────────────────
    // Only inserts if the catalog is empty (idempotent).
    const existingCatalogCount = await ctx.db
      .query('integrationCatalog')
      .count()

    if (existingCatalogCount === 0) {
      const integrationCatalogEntries = [
        { slug: 'github', label: 'GitHub', category: 'vcs' as const, envVarName: 'GITHUB_WEBHOOK_SECRET', description: 'Receive push / PR events from GitHub repositories.', webhookPathTemplate: '/webhooks/github' },
        { slug: 'gitlab', label: 'GitLab', category: 'vcs' as const, envVarName: 'GITLAB_WEBHOOK_SECRET', description: 'Receive push / MR events from GitLab repositories.', webhookPathTemplate: '/webhooks/gitlab' },
        { slug: 'jenkins', label: 'Jenkins', category: 'ci' as const, envVarName: 'JENKINS_WEBHOOK_SECRET', description: 'Receive build-status webhooks from Jenkins.', webhookPathTemplate: '/webhooks/jenkins' },
        { slug: 'circleci', label: 'CircleCI', category: 'ci' as const, envVarName: 'CIRCLECI_WEBHOOK_SECRET', description: 'Receive pipeline events from CircleCI.', webhookPathTemplate: '/webhooks/circleci' },
        { slug: 'buildkite', label: 'Buildkite', category: 'ci' as const, envVarName: 'BUILDKITE_WEBHOOK_TOKEN', description: 'Receive build events from Buildkite.', webhookPathTemplate: '/webhooks/buildkite' },
        { slug: 'azure-devops', label: 'Azure DevOps', category: 'ci' as const, envVarName: 'AZURE_DEVOPS_WEBHOOK_SECRET', description: 'Receive pipeline events from Azure DevOps.', webhookPathTemplate: '/webhooks/azure-devops' },
        { slug: 'bitbucket', label: 'Bitbucket', category: 'vcs' as const, envVarName: 'BITBUCKET_WEBHOOK_SECRET', description: 'Receive push / PR events from Bitbucket.', webhookPathTemplate: '/webhooks/bitbucket' },
        { slug: 'slack', label: 'Slack', category: 'chat' as const, envVarName: 'SLACK_WEBHOOK_URL', description: 'Send security alerts and digests to Slack channels.', webhookPathTemplate: undefined },
        { slug: 'pagerduty', label: 'PagerDuty', category: 'paging' as const, envVarName: 'PAGERDUTY_ROUTING_KEY', description: 'Escalate critical findings to PagerDuty on-call.', webhookPathTemplate: undefined },
        { slug: 'jira', label: 'Jira', category: 'ticket' as const, envVarName: 'JIRA_API_TOKEN', description: 'Create and sync Jira issues from security findings.', webhookPathTemplate: undefined },
        { slug: 'linear', label: 'Linear', category: 'ticket' as const, envVarName: 'LINEAR_API_KEY', description: 'Create and sync Linear issues from security findings.', webhookPathTemplate: undefined },
        { slug: 'datadog', label: 'Datadog', category: 'obs' as const, envVarName: 'DATADOG_API_KEY', description: 'Push security metrics and events to Datadog dashboards.', webhookPathTemplate: undefined },
        { slug: 'opsgenie', label: 'OpsGenie', category: 'paging' as const, envVarName: 'OPSGENIE_API_KEY', description: 'Create OpsGenie alerts for critical security findings.', webhookPathTemplate: undefined },
      ]

      for (const entry of integrationCatalogEntries) {
        await ctx.db.insert('integrationCatalog', {
          ...entry,
          docsUrl: undefined,
        })
      }
    }

    // ── Seed billing plans (§6.12 / §8.1) ───────────────────────────────
    // Only inserts if no plans exist yet (idempotent).
    const existingPlanCount = await ctx.db
      .query('billingPlans')
      .count()

    if (existingPlanCount === 0) {
      const billingPlanEntries = [
        {
          slug: 'free',
          name: 'Free',
          description: 'For individuals and small teams getting started with security scanning.',
          priceCents: 0,
          currency: 'usd',
          interval: 'month' as const,
          maxRepositories: 5,
          maxMembers: 3,
          features: [
            'Up to 5 repositories',
            'Basic vulnerability scanning',
            'Community support',
            'SBOM generation',
            'Security posture score',
          ],
          highlighted: false,
          sortOrder: 1,
        },
        {
          slug: 'team',
          name: 'Team',
          description: 'For growing teams that need advanced security intelligence and automation.',
          priceCents: 4900,
          currency: 'usd',
          interval: 'month' as const,
          maxRepositories: 50,
          maxMembers: 25,
          features: [
            'Up to 50 repositories',
            'All Free features',
            'Exploit validation sandbox',
            'Auto-remediation PRs',
            'Gate enforcement policies',
            'Compliance frameworks (SOC2, GDPR, HIPAA)',
            'Executive reports & dashboards',
            'API access',
            'Priority support',
          ],
          highlighted: true,
          sortOrder: 2,
        },
        {
          slug: 'enterprise',
          name: 'Enterprise',
          description: 'For organizations requiring full security coverage, SSO, and dedicated support.',
          priceCents: 19900,
          currency: 'usd',
          interval: 'month' as const,
          maxRepositories: -1, // unlimited
          maxMembers: -1, // unlimited
          features: [
            'Unlimited repositories & members',
            'All Team features',
            'SSO / SAML integration',
            'Custom RBAC roles & permissions',
            'On-prem deployment option',
            'Data retention policies',
            'MSSP partner portal',
            'Dedicated account manager',
            'SLA-backed uptime guarantee',
            'Custom policy builder',
            'Compliance attestation add-on',
          ],
          highlighted: false,
          sortOrder: 3,
        },
      ]

      for (const plan of billingPlanEntries) {
        await ctx.db.insert('billingPlans', plan)
      }
    }

    // ── Seed §8.1 plans (slug-indexed tiers + feature flags) ─────────────
    const existingPlansCount = await ctx.db.query('plans').count()
    if (existingPlansCount === 0) {
      const planEntries = [
        {
          slug: 'free',
          name: 'Free',
          monthlyPrice: 0,
          repoLimit: 5,
          seatLimit: 3,
          featureFlags: [
            'basic_scanning',
            'sbom',
            'security_posture',
          ],
        },
        {
          slug: 'team',
          name: 'Team',
          monthlyPrice: 49,
          repoLimit: 25,
          seatLimit: 10,
          featureFlags: [
            'basic_scanning',
            'sbom',
            'security_posture',
            'exploit_validation',
            'auto_remediation',
            'gate_policies',
            'executive_reports',
            'api_access',
            'cross_repo_intel',
          ],
        },
        {
          slug: 'enterprise',
          name: 'Enterprise',
          monthlyPrice: 199,
          repoLimit: -1,
          seatLimit: -1,
          featureFlags: [
            'basic_scanning',
            'sbom',
            'security_posture',
            'exploit_validation',
            'auto_remediation',
            'gate_policies',
            'executive_reports',
            'api_access',
            'cross_repo_intel',
            'sso',
            'rbac_custom',
            'on_prem',
            'deployment_toggle',
            'mssp_portal',
            'compliance_attestation',
            'custom_policies',
            'dedicated_support',
          ],
        },
      ]

      for (const plan of planEntries) {
        await ctx.db.insert('plans', plan)
      }
    }

    return {
      tenantId,
      repositoryIds: [paymentsApiId, operatorConsoleId],
      created: true,
    }
  },
})
