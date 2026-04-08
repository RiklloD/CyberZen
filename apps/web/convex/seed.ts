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

    return {
      tenantId,
      repositoryIds: [paymentsApiId, operatorConsoleId],
      created: true,
    }
  },
})
