import { httpRouter } from 'convex/server'
import { api, internal } from './_generated/api'
import { httpAction } from './_generated/server'
import type { Id } from './_generated/dataModel'
import { requireMsspApiKey } from './mssp'
import { buildMetricsPage, sentinelMetricsToSamples } from './lib/prometheusMetrics'

const http = httpRouter()

function jsonResponse(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}

// ---------------------------------------------------------------------------
// API key guard for operator-facing endpoints.
//
// Reads the expected key from the SENTINEL_API_KEY Convex environment variable.
// If the variable is not set the guard is a no-op (fail-open), which preserves
// local-development ergonomics — no key needed until it is explicitly configured.
//
// Set in production with:  npx convex env set SENTINEL_API_KEY <value>
//
// Clients may supply the key in either of two ways:
//   • X-Sentinel-Api-Key: <key>          (preferred for dashboard / SDK calls)
//   • Authorization: Bearer <key>        (compatible with standard API tooling)
// ---------------------------------------------------------------------------

function requireApiKey(request: Request): Response | null {
  const expectedKey = process.env.SENTINEL_API_KEY
  if (!expectedKey) return null // not configured — open in local dev

  const apiKeyHeader = request.headers.get('x-sentinel-api-key')
  const authHeader = request.headers.get('authorization')
  const providedKey =
    apiKeyHeader ??
    (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null)

  if (!providedKey || providedKey !== expectedKey) {
    return jsonResponse(
      {
        error:
          'Unauthorized. Provide a valid API key via the X-Sentinel-Api-Key header ' +
          'or Authorization: Bearer <key>.',
      },
      401,
    )
  }

  return null
}

http.route({
  path: '/webhooks/github',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const event = request.headers.get('x-github-event')
    const signature = request.headers.get('x-hub-signature-256')
    const deliveryId = request.headers.get('x-github-delivery') ?? undefined

    if (!event) {
      return jsonResponse(
        { error: 'Missing X-GitHub-Event header.' },
        400,
      )
    }

    if (!signature) {
      return jsonResponse(
        { error: 'Missing X-Hub-Signature-256 header.' },
        401,
      )
    }

    const body = await request.text()
    const result = await ctx.runAction(
      internal.githubWebhooks.verifyAndRouteGithubWebhook,
      {
        body,
        event,
        signature,
        deliveryId,
      },
    )

    return jsonResponse(
      {
        status: result.status,
        reason: result.reason,
        eventId: result.eventId,
        workflowRunId: result.workflowRunId,
        deduped: result.deduped,
      },
      result.httpStatus,
    )
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/azure-devops
//
// Azure DevOps Service Hooks: git.push and git.pullrequest.merged events.
// Basic auth: Authorization: Basic base64(sentinel:<AZURE_DEVOPS_WEBHOOK_SECRET>)
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/azure-devops',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authorization = request.headers.get('authorization') ?? undefined
    const body = await request.text()
    const result = await ctx.runAction(
      internal.azureDevOpsWebhooks.verifyAndRouteAzureDevOpsWebhook,
      { body, authorization },
    )
    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/bitbucket
//
// Bitbucket Cloud webhook: repo:push and pullrequest:fulfilled events.
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/bitbucket',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const event = request.headers.get('x-event-key') // Bitbucket uses x-event-key
    const signature = request.headers.get('x-hub-signature') ?? undefined

    if (!event) {
      return jsonResponse({ error: 'Missing X-Event-Key header.' }, 400)
    }

    const body = await request.text()
    const result = await ctx.runAction(
      internal.bitbucketWebhooks.verifyAndRouteBitbucketWebhook,
      { body, event, signature },
    )

    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/circleci
//
// CircleCI Webhook: workflow-completed events trigger a repository scan.
// Signature: circleci-signature: v1=<HMAC-SHA256>
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/circleci',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const signature = request.headers.get('circleci-signature') ?? undefined
    const body = await request.text()

    const result = await ctx.runAction(
      internal.circleciWebhooks.verifyAndRouteCircleCiWebhook,
      { body, signature },
    )

    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/gitlab
//
// GitLab webhook ingest endpoint. Verifies the X-Gitlab-Token secret and
// routes Push Hook + Merge Request Hook events into the ingestion pipeline.
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/gitlab',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const event = request.headers.get('x-gitlab-event')
    const token = request.headers.get('x-gitlab-token') ?? undefined

    if (!event) {
      return jsonResponse({ error: 'Missing X-Gitlab-Event header.' }, 400)
    }

    const body = await request.text()
    const result = await ctx.runAction(
      internal.gitlabWebhooks.verifyAndRouteGitLabWebhook,
      { body, event, token },
    )

    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/export?snapshotId=<id>[&format=cyclonedx|spdx]
//
// Returns an SBOM in the requested format (default: cyclonedx).
// Supported formats:
//   cyclonedx   — CycloneDX 1.5 JSON (default, security tooling)
//   spdx        — SPDX 2.3 JSON (legal/compliance, Linux Foundation)
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/export',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const snapshotId = searchParams.get('snapshotId')
    const format = (searchParams.get('format') ?? 'cyclonedx').toLowerCase()

    if (!snapshotId) {
      return jsonResponse({ error: 'Missing required query parameter: snapshotId' }, 400)
    }

    if (format !== 'cyclonedx' && format !== 'spdx') {
      return jsonResponse({ error: 'Invalid format. Supported: cyclonedx, spdx' }, 400)
    }

    // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
    const bom = await ctx.runQuery(api.sbom.exportSnapshot, {
      snapshotId: snapshotId as any,
    })

    if (!bom) {
      return jsonResponse({ error: 'Snapshot not found.' }, 404)
    }

    if (format === 'spdx') {
      // Import SPDX builder inline (http.ts can't have top-level imports from lib
      // because those are bundled separately; we use api.sbom.exportSnapshotAsSpdx instead)
      const spdxBom = await ctx.runQuery(api.sbom.exportSnapshotAsSpdx, {
        snapshotId: snapshotId as any,
      })
      return new Response(JSON.stringify(spdxBom, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/spdx+json',
          'Content-Disposition': `attachment; filename="sbom-${snapshotId}.spdx.json"`,
          'Cache-Control': 'no-store',
        },
      })
    }

    return new Response(JSON.stringify(bom, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.cyclonedx+json',
        'Content-Disposition': `attachment; filename="sbom-${snapshotId}.cdx.json"`,
        'Cache-Control': 'no-store',
      },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings?tenantSlug=<slug>[&status=<s>][&severity=<s>][&limit=<n>]
// Returns a JSON array of findings for the given tenant with optional filters.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }

    const status = searchParams.get('status') ?? undefined
    const severity = searchParams.get('severity') ?? undefined
    const limitRaw = searchParams.get('limit')
    const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || 50, 200) : 50

    const validStatuses = new Set(['open', 'pr_opened', 'merged', 'resolved', 'accepted_risk'])
    const validSeverities = new Set(['critical', 'high', 'medium', 'low', 'informational'])

    if (status && !validStatuses.has(status)) {
      return jsonResponse(
        { error: `Invalid status. Must be one of: ${[...validStatuses].join(', ')}` },
        400,
      )
    }
    if (severity && !validSeverities.has(severity)) {
      return jsonResponse(
        { error: `Invalid severity. Must be one of: ${[...validSeverities].join(', ')}` },
        400,
      )
    }

    // biome-ignore lint/suspicious/noExplicitAny: runtime union cast required for httpAction ctx
    const findings = await ctx.runQuery(api.findings.list, {
      tenantSlug,
      status: status as any,
      severity: severity as any,
      limit,
    })

    return new Response(JSON.stringify(findings, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/compliance/evidence?tenantSlug=<slug>&repositoryFullName=<name>[&framework=soc2]
//
// Returns compliance evidence snapshots for the specified repository.
// When `framework` is provided, returns evidence for that framework only.
// When omitted, returns the latest snapshot for all 5 frameworks.
// Spec §10.1 (SOC 2 Automated Evidence Collection).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/compliance/evidence',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')
    const framework = url.searchParams.get('framework')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse({ error: 'tenantSlug and repositoryFullName are required.' }, 400)
    }

    if (framework) {
      const validFrameworks = ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2']
      if (!validFrameworks.includes(framework)) {
        return jsonResponse(
          { error: `Invalid framework. Must be one of: ${validFrameworks.join(', ')}.` },
          400,
        )
      }
    }

    const allEvidence = await ctx.runQuery(
      api.complianceEvidenceIntel.getFrameworkEvidenceBySlug,
      { tenantSlug, repositoryFullName },
    )

    if (!allEvidence) {
      return jsonResponse({ error: 'Repository not found.' }, 404)
    }

    if (framework) {
      const single = allEvidence.find((fw) => fw.framework === framework)
      return jsonResponse({ framework, evidence: single ?? null }, single ? 200 : 404)
    }

    return jsonResponse({ repository: repositoryFullName, frameworks: allEvidence }, 200)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/reports/security-posture?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns a unified SecurityPostureReport for the requested repository,
// aggregating findings, attack surface, regulatory drift, red/blue rounds,
// and learning profile into a single 0–100 score with a prioritised action
// list. Spec §7.1 /reports/security-posture.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/reports/security-posture',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const report = await ctx.runQuery(api.securityPosture.getSecurityPostureReport, {
      tenantSlug,
      repositoryFullName,
    })

    if (!report) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName} in tenant ${tenantSlug}` },
        404,
      )
    }

    return new Response(JSON.stringify(report, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/detail?findingId=<id>
//
// Returns a single enriched finding by ID including linked disclosure, gate
// decisions, validation runs, and PR proposals. Spec §7.1 GET /api/findings/{id}.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/detail',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const findingId = searchParams.get('findingId')

    if (!findingId) {
      return jsonResponse({ error: 'Missing required query parameter: findingId' }, 400)
    }

    // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
    const finding = await ctx.runQuery(api.findings.get, { findingId: findingId as any })

    if (!finding) {
      return jsonResponse({ error: `Finding not found: ${findingId}` }, 404)
    }

    return new Response(JSON.stringify(finding, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// PATCH /api/findings/status
//
// Operator-facing status update. Body: { findingId, newStatus, reason? }.
// Fires a finding.resolved webhook when status transitions to "resolved".
// Spec §7.1 PATCH /api/findings/status.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/status',
  method: 'PATCH',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    const { findingId, newStatus, reason } = body as Record<string, unknown>

    if (typeof findingId !== 'string' || !findingId) {
      return jsonResponse({ error: 'Missing required field: findingId' }, 400)
    }
    const validStatuses = ['open', 'pr_opened', 'merged', 'resolved', 'accepted_risk', 'false_positive', 'ignored']
    if (typeof newStatus !== 'string' || !validStatuses.includes(newStatus)) {
      return jsonResponse(
        { error: `Invalid newStatus. Must be one of: ${validStatuses.join(', ')}` },
        400,
      )
    }

    try {
      const result = await ctx.runMutation(api.findings.updateFindingStatus, {
        // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
        findingId: findingId as any,
        // biome-ignore lint/suspicious/noExplicitAny: runtime union cast required for httpAction ctx
        newStatus: newStatus as any,
        reason: typeof reason === 'string' ? reason : undefined,
      })
      return jsonResponse(result, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Status update failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/attack-surface/score/history?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the latest attack surface snapshot and the last 20 score history
// data points for sparkline rendering. Spec §7.1 GET /api/attack-surface/score/history.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/attack-surface/score/history',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const dashboard = await ctx.runQuery(
      api.attackSurfaceIntel.getAttackSurfaceDashboard,
      { tenantSlug, repositoryFullName },
    )

    if (!dashboard) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(dashboard, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/reports/compliance?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the latest regulatory drift snapshot with per-framework scores,
// drift level, and gap counts. Spec §7.1 GET /api/reports/compliance.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/reports/compliance',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const report = await ctx.runQuery(
      api.regulatoryDriftIntel.getLatestRegulatoryDrift,
      { tenantSlug, repositoryFullName },
    )

    if (!report) {
      return jsonResponse(
        { error: `No compliance data for repository: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(report, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/reports/adversarial?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns an adversarial simulation summary: win/loss/draw counts, exploit
// chain samples, and average detection scores. Spec §7.1 GET /api/reports/adversarial.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/reports/adversarial',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const summary = await ctx.runQuery(
      api.redBlueIntel.adversarialSummaryForRepository,
      { tenantSlug, repositoryFullName },
    )

    if (!summary) {
      return jsonResponse(
        { error: `No adversarial simulation data for repository: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(summary, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/blast-radius?findingId=<id>
//
// Returns the blast radius snapshot for a specific finding, including
// reachable services, exposed data layers, attack path depth, and business
// impact score. Spec §7.1 GET /api/blast-radius/{finding_id}.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/blast-radius',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const findingId = searchParams.get('findingId')

    if (!findingId) {
      return jsonResponse({ error: 'Missing required query parameter: findingId' }, 400)
    }

    // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
    const snapshot = await ctx.runQuery(api.blastRadiusIntel.getBlastRadius, {
      findingId: findingId as any,
    })

    if (!snapshot) {
      return jsonResponse({ error: `No blast radius data for finding: ${findingId}` }, 404)
    }

    return new Response(JSON.stringify(snapshot, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the latest SBOM snapshot for a repository with component counts,
// layer breakdown, diff against previous snapshot, and vulnerable-component
// preview. Spec §7.1 GET /sbom.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const snapshot = await ctx.runQuery(api.sbom.latestRepositorySnapshot, {
      tenantSlug,
      repositoryFullName,
    })

    if (!snapshot) {
      return jsonResponse(
        { error: `No SBOM snapshot found for repository: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(snapshot, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/attack-surface/score?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the current attack surface score and trend. Lightweight alias for
// the head of the history endpoint. Spec §7.1 GET /attack-surface/score.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/attack-surface/score',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const dashboard = await ctx.runQuery(
      api.attackSurfaceIntel.getAttackSurfaceDashboard,
      { tenantSlug, repositoryFullName },
    )

    if (!dashboard || !dashboard.snapshot) {
      return jsonResponse(
        { error: `No attack surface data for repository: ${repositoryFullName}` },
        404,
      )
    }

    const { snapshot } = dashboard
    const current = {
      score: snapshot.score,
      trend: snapshot.trend,
      remediationRate: snapshot.remediationRate,
      openCriticalCount: snapshot.openCriticalCount,
      openHighCount: snapshot.openHighCount,
      activeMitigationCount: snapshot.activeMitigationCount,
      computedAt: snapshot.computedAt,
      repositoryFullName,
    }

    return new Response(JSON.stringify(current, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// POST /api/attack-surface/scan
//
// Triggers an immediate attack surface recalculation for the given repository.
// Useful as a CI/CD webhook target after deployments. Spec §7.1.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/attack-surface/scan',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    const { tenantSlug, repositoryFullName } = body as Record<string, unknown>

    if (typeof tenantSlug !== 'string' || !tenantSlug) {
      return jsonResponse({ error: 'Missing required field: tenantSlug' }, 400)
    }
    if (typeof repositoryFullName !== 'string' || !repositoryFullName) {
      return jsonResponse({ error: 'Missing required field: repositoryFullName' }, 400)
    }

    try {
      const result = await ctx.runMutation(
        api.attackSurfaceIntel.refreshAttackSurfaceForRepository,
        { tenantSlug, repositoryFullName },
      )
      return jsonResponse({ scheduled: result.scheduled, repositoryId: result.repositoryId }, 202)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Scan trigger failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/trust-scores?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the supply chain risk analysis for the latest SBOM snapshot,
// including per-component risk signals and trust scores. Spec §7.1.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/trust-scores',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const analysis = await ctx.runQuery(
      api.promptIntelligence.supplyChainAnalysis,
      { tenantSlug, repositoryFullName },
    )

    if (!analysis) {
      return jsonResponse(
        { error: `No trust score data for repository: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(analysis, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// Webhook endpoint registration (spec §7.2)
//
// POST   /api/webhooks           — register a new outbound webhook endpoint
// GET    /api/webhooks           — list all endpoints for a tenant (secrets omitted)
// DELETE /api/webhooks           — remove an endpoint by ?endpointId=<id>
// GET    /api/webhooks/deliveries — delivery audit log for a tenant
//
// All routes are guarded by the SENTINEL_API_KEY.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/webhooks',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    if (typeof body !== 'object' || body === null) {
      return jsonResponse({ error: 'Request body must be a JSON object.' }, 400)
    }

    const {
      tenantSlug,
      url,
      secret,
      description,
      events,
    } = body as Record<string, unknown>

    if (typeof tenantSlug !== 'string' || !tenantSlug) {
      return jsonResponse({ error: 'Missing required field: tenantSlug' }, 400)
    }
    if (typeof url !== 'string' || !url) {
      return jsonResponse({ error: 'Missing required field: url' }, 400)
    }
    if (typeof secret !== 'string' || !secret) {
      return jsonResponse({ error: 'Missing required field: secret' }, 400)
    }
    const eventList = Array.isArray(events) ? (events as string[]) : []

    try {
      const result = await ctx.runMutation(api.webhooks.registerEndpoint, {
        tenantSlug,
        url,
        secret,
        description: typeof description === 'string' ? description : undefined,
        events: eventList,
      })
      return jsonResponse(result, 201)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

http.route({
  path: '/api/webhooks',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }

    const endpoints = await ctx.runQuery(api.webhooks.listEndpoints, { tenantSlug })
    return new Response(JSON.stringify(endpoints, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

http.route({
  path: '/api/webhooks',
  method: 'DELETE',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const endpointId = searchParams.get('endpointId')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!endpointId) {
      return jsonResponse({ error: 'Missing required query parameter: endpointId' }, 400)
    }

    try {
      const result = await ctx.runMutation(api.webhooks.deleteEndpoint, {
        tenantSlug,
        // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
        endpointId: endpointId as any,
      })
      return jsonResponse(result, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Deletion failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

http.route({
  path: '/api/webhooks/deliveries',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }

    const limitRaw = searchParams.get('limit')
    const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || 50, 200) : 50

    const deliveries = await ctx.runQuery(api.webhooks.listRecentDeliveries, {
      tenantSlug,
      limit,
    })
    return new Response(JSON.stringify(deliveries, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/poc?findingId=<id>
//
// Returns PoC artifact URL and metadata for a finding. Only present after
// a successful exploit validation run (spec §7.1, §8.1).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/poc',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const findingId = searchParams.get('findingId')

    if (!findingId) {
      return jsonResponse({ error: 'Missing required query parameter: findingId' }, 400)
    }

    const result = await ctx.runQuery(api.findings.getPocArtifact, {
      findingId: findingId as any,
    })

    if (!result) {
      return jsonResponse({ error: `Finding not found: ${findingId}` }, 404)
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/reasoning?findingId=<id>
//
// Returns reasoning log URL and validation run evidence for a finding.
// The evidence summary and reproduction hint are always populated; the
// reasoningLogUrl is present only when object-storage logging is active (spec §7.1).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/reasoning',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const findingId = searchParams.get('findingId')

    if (!findingId) {
      return jsonResponse({ error: 'Missing required query parameter: findingId' }, 400)
    }

    const result = await ctx.runQuery(api.findings.getReasoningLog, {
      findingId: findingId as any,
    })

    if (!result) {
      return jsonResponse({ error: `Finding not found: ${findingId}` }, 404)
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/commit?commitSha=<sha>&tenantSlug=<slug>&repositoryFullName=<repo>
//
// Returns the SBOM snapshot for a specific commit SHA (spec §7.1).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/commit',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')
    const commitSha = searchParams.get('commitSha')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }
    if (!commitSha) {
      return jsonResponse({ error: 'Missing required query parameter: commitSha' }, 400)
    }

    const result = await ctx.runQuery(api.sbom.snapshotByCommit, {
      tenantSlug,
      repositoryFullName,
      commitSha,
    })

    if (!result) {
      return jsonResponse(
        { error: `No SBOM snapshot found for commit: ${commitSha}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/diff?from=<sha>&to=<sha>&tenantSlug=<slug>&repositoryFullName=<repo>
//
// Diffs two SBOM snapshots by commit SHA (spec §7.1).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/diff',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')
    const fromCommitSha = searchParams.get('from')
    const toCommitSha = searchParams.get('to')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }
    if (!fromCommitSha) {
      return jsonResponse({ error: 'Missing required query parameter: from (commit SHA)' }, 400)
    }
    if (!toCommitSha) {
      return jsonResponse({ error: 'Missing required query parameter: to (commit SHA)' }, 400)
    }

    const result = await ctx.runQuery(api.sbom.snapshotDiff, {
      tenantSlug,
      repositoryFullName,
      fromCommitSha,
      toCommitSha,
    })

    if (!result) {
      return jsonResponse(
        {
          error: `One or both commits not found: from=${fromCommitSha} to=${toCommitSha}`,
        },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/trust-scores/detail?package=<name>&tenantSlug=<slug>&repositoryFullName=<repo>
//
// Returns the trust score for a specific package from the latest SBOM snapshot.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/trust-scores/detail',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')
    const packageName = searchParams.get('package')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }
    if (!packageName) {
      return jsonResponse({ error: 'Missing required query parameter: package' }, 400)
    }

    const result = await ctx.runQuery(api.sbom.packageTrustScore, {
      tenantSlug,
      repositoryFullName,
      packageName,
    })

    if (!result) {
      return jsonResponse(
        { error: `Package not found in latest snapshot: ${packageName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/trust-scores/history?package=<name>&tenantSlug=<slug>&repositoryFullName=<repo>
//
// Returns the trust score history for a package across up to 20 SBOM snapshots.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/trust-scores/history',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')
    const packageName = searchParams.get('package')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }
    if (!packageName) {
      return jsonResponse({ error: 'Missing required query parameter: package' }, 400)
    }

    const result = await ctx.runQuery(api.sbom.packageTrustScoreHistory, {
      tenantSlug,
      repositoryFullName,
      packageName,
    })

    if (!result) {
      return jsonResponse(
        { error: `No trust score history found for package: ${packageName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/attack-surface/components?tenantSlug=<slug>&repositoryFullName=<repo>
//
// Returns all tracked attack surface components from the latest SBOM snapshot,
// sorted by risk (vulnerable first, then by ascending trustScore). Spec §7.1.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/attack-surface/components',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const result = await ctx.runQuery(api.sbom.attackSurfaceComponents, {
      tenantSlug,
      repositoryFullName,
    })

    if (!result) {
      return jsonResponse(
        { error: `No SBOM snapshot found for repository: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/blast-radius/graph?tenantSlug=<slug>&repositoryFullName=<repo>
//
// Returns the full architectural graph of blast radius nodes + edges for all
// open findings in a repository. Spec §7.1 GET /blast-radius/graph.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/blast-radius/graph',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName')

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }
    if (!repositoryFullName) {
      return jsonResponse({ error: 'Missing required query parameter: repositoryFullName' }, 400)
    }

    const result = await ctx.runQuery(api.blastRadiusIntel.architecturalGraph, {
      tenantSlug,
      repositoryFullName,
    })

    if (!result) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// POST /api/reports/generate
//
// Generate a custom report with parameters. Supported report types:
//   • security_posture  — current composite security score and top actions
//   • compliance        — regulatory drift gap summary per framework
//   • adversarial       — red-blue loop outcomes and escalated findings
//
// Body: { tenantSlug, repositoryFullName, reportType, filters? }
// ---------------------------------------------------------------------------

http.route({
  path: '/api/reports/generate',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    if (typeof body !== 'object' || body === null) {
      return jsonResponse({ error: 'Request body must be a JSON object.' }, 400)
    }

    const { tenantSlug, repositoryFullName, reportType } = body as Record<string, unknown>

    if (typeof tenantSlug !== 'string' || !tenantSlug) {
      return jsonResponse({ error: 'Missing required field: tenantSlug' }, 400)
    }
    if (typeof repositoryFullName !== 'string' || !repositoryFullName) {
      return jsonResponse({ error: 'Missing required field: repositoryFullName' }, 400)
    }
    if (typeof reportType !== 'string' || !reportType) {
      return jsonResponse({ error: 'Missing required field: reportType' }, 400)
    }

    const SUPPORTED_REPORT_TYPES = ['security_posture', 'compliance', 'adversarial'] as const
    type ReportType = (typeof SUPPORTED_REPORT_TYPES)[number]

    if (!SUPPORTED_REPORT_TYPES.includes(reportType as ReportType)) {
      return jsonResponse(
        {
          error: `Unknown reportType: ${reportType}. Supported: ${SUPPORTED_REPORT_TYPES.join(', ')}`,
        },
        400,
      )
    }

    try {
      let reportData: unknown

      if (reportType === 'security_posture') {
        reportData = await ctx.runQuery(api.securityPosture.getSecurityPostureReport, {
          tenantSlug,
          repositoryFullName,
        })
      } else if (reportType === 'compliance') {
        reportData = await ctx.runQuery(api.regulatoryDriftIntel.getLatestRegulatoryDrift, {
          tenantSlug,
          repositoryFullName,
        })
      } else {
        // adversarial
        reportData = await ctx.runQuery(api.redBlueIntel.adversarialSummaryForRepository, {
          tenantSlug,
          repositoryFullName,
        })
      }

      if (!reportData) {
        return jsonResponse(
          {
            error: `No data available for ${reportType} report. Ensure at least one scan has run.`,
          },
          404,
        )
      }

      return new Response(
        JSON.stringify(
          {
            reportType,
            tenantSlug,
            repositoryFullName,
            generatedAt: new Date().toISOString(),
            data: reportData,
          },
          null,
          2,
        ),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        },
      )
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Report generation failed.'
      return jsonResponse({ error: message }, 500)
    }
  }),
})

// ---------------------------------------------------------------------------
// POST /api/honeypot/trigger
//
// Records a honeypot trigger event and immediately dispatches a
// honeypot.triggered webhook to all subscribed endpoints.
//
// Body: { tenantSlug, repositoryFullName, honeypotPath, honeypotKind,
//         sourceIdentifier?, metadata? }
// ---------------------------------------------------------------------------

http.route({
  path: '/api/honeypot/trigger',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    if (typeof body !== 'object' || body === null) {
      return jsonResponse({ error: 'Request body must be a JSON object.' }, 400)
    }

    const {
      tenantSlug,
      repositoryFullName,
      honeypotPath,
      honeypotKind,
      sourceIdentifier,
      metadata,
    } = body as Record<string, unknown>

    if (typeof tenantSlug !== 'string' || !tenantSlug) {
      return jsonResponse({ error: 'Missing required field: tenantSlug' }, 400)
    }
    if (typeof repositoryFullName !== 'string' || !repositoryFullName) {
      return jsonResponse({ error: 'Missing required field: repositoryFullName' }, 400)
    }
    if (typeof honeypotPath !== 'string' || !honeypotPath) {
      return jsonResponse({ error: 'Missing required field: honeypotPath' }, 400)
    }

    const VALID_KINDS = ['endpoint', 'database_field', 'file', 'token'] as const
    type HoneypotKind = (typeof VALID_KINDS)[number]

    if (!honeypotKind || !VALID_KINDS.includes(honeypotKind as HoneypotKind)) {
      return jsonResponse(
        {
          error: `Missing or invalid honeypotKind. Must be one of: ${VALID_KINDS.join(', ')}`,
        },
        400,
      )
    }

    try {
      const result = await ctx.runMutation(api.honeypotIntel.recordHoneypotTrigger, {
        tenantSlug,
        repositoryFullName,
        honeypotPath,
        honeypotKind: honeypotKind as HoneypotKind,
        sourceIdentifier: typeof sourceIdentifier === 'string' ? sourceIdentifier : undefined,
        metadata: typeof metadata === 'string' ? metadata : undefined,
      })
      return jsonResponse({ ...result, honeypotPath, honeypotKind }, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to record trigger.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/detection-rules?tenantSlug=<slug>&repositoryFullName=<name>&format=nginx|modsecurity|splunk|elastic|sentinel|log_regex
//
// Export detection rules generated by the Blue Agent from Red Agent wins.
// Format param selects the target toolchain.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/detection-rules',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')
    const format = url.searchParams.get('format') ?? 'splunk'

    const VALID_FORMATS = ['nginx', 'modsecurity', 'splunk', 'elastic', 'sentinel', 'log_regex']
    if (!VALID_FORMATS.includes(format)) {
      return jsonResponse(
        { error: `Invalid format. Supported: ${VALID_FORMATS.join(', ')}` },
        400,
      )
    }

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'Missing required params: tenantSlug, repositoryFullName' },
        400,
      )
    }

    try {
      // biome-ignore lint/suspicious/noExplicitAny: runtime format cast
      const result = await ctx.runQuery(api.blueAgentIntel.getDetectionRulesBySlug, {
        tenantSlug,
        repositoryFullName,
        format: format as any,
      })

      if (!result) {
        return jsonResponse({ error: 'No detection rules found for this repository' }, 404)
      }

      // Return as plain text for easy piping to config files
      const contentType = format === 'nginx' || format === 'modsecurity'
        ? 'text/plain'
        : 'application/json'

      if (contentType === 'text/plain') {
        const rulesText = (result.rules as string[]).join('\n\n# ---\n\n')
        return new Response(rulesText, {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename="sentinel-${format}-rules.conf"`,
          },
        })
      }

      return jsonResponse(result, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Query failed'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sandbox/environment?findingId=<id>
//
// Returns the latest sandbox environment (exploit run + PoC artifacts)
// for a finding. Spec §7.1 — extends GET /findings/{id}/poc.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sandbox/environment',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const findingId = url.searchParams.get('findingId')
    if (!findingId) {
      return jsonResponse({ error: 'Missing required param: findingId' }, 400)
    }

    try {
      const env = await ctx.runQuery(api.sandboxValidation.getLatestSandboxEnvironment, {
        findingId: findingId as Id<'findings'>,
      })
      return jsonResponse({ environment: env }, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Query failed'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sandbox/summary?tenantSlug=<slug>&repositoryFullName=<name>
//
// Sandbox validation summary for a repository — exploit counts, PoC coverage.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sandbox/summary',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'Missing required params: tenantSlug, repositoryFullName' },
        400,
      )
    }

    try {
      const summary = await ctx.runQuery(
        api.sandboxValidation.getSandboxSummaryBySlug,
        { tenantSlug, repositoryFullName },
      )
      if (!summary) return jsonResponse({ error: 'Repository not found' }, 404)
      return jsonResponse(summary, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Query failed'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ── MSSP Partner API ──────────────────────────────────────────────────────────
//
// Multi-tenant management endpoints for Managed Security Service Providers.
// All routes require X-MSSP-Api-Key header (MSSP_API_KEY env var).
// ---------------------------------------------------------------------------

// POST /api/mssp/tenants — provision a new customer tenant

http.route({
  path: '/api/mssp/tenants',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireMsspApiKey(request)
    if (authError) return authError

    let body: Record<string, unknown>
    try {
      body = await request.json() as Record<string, unknown>
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400)
    }

    const { slug, name, deploymentMode } = body
    if (typeof slug !== 'string' || typeof name !== 'string') {
      return jsonResponse({ error: 'Missing required fields: slug, name' }, 400)
    }

    try {
      const result = await ctx.runMutation(internal.mssp.provisionTenant, {
        slug,
        name,
        deploymentMode: (deploymentMode as 'cloud_saas' | 'vpc_injection' | 'on_prem') ?? 'cloud_saas',
      })
      return jsonResponse({ ...result, provisioned: true }, 201)
    } catch (err) {
      return jsonResponse({ error: String(err) }, 400)
    }
  }),
})

// GET /api/mssp/tenants — list all managed tenants

http.route({
  path: '/api/mssp/tenants',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireMsspApiKey(request)
    if (authError) return authError

    const tenants = await ctx.runQuery(internal.mssp.listAllTenants, {})
    return jsonResponse({ tenants, total: tenants.length }, 200)
  }),
})

// GET /api/mssp/tenants/:slug/summary — per-tenant risk summary

http.route({
  path: '/api/mssp/tenant/summary',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireMsspApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const slug = url.searchParams.get('slug')
    if (!slug) return jsonResponse({ error: 'Missing slug param' }, 400)

    const summary = await ctx.runQuery(internal.mssp.getTenantSummary, { slug })
    if (!summary) return jsonResponse({ error: `Tenant ${slug} not found` }, 404)
    return jsonResponse(summary, 200)
  }),
})

// DELETE /api/mssp/tenant — deprovision (pause) a tenant

http.route({
  path: '/api/mssp/tenant',
  method: 'DELETE',
  handler: httpAction(async (ctx, request) => {
    const authError = requireMsspApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const slug = url.searchParams.get('slug')
    if (!slug) return jsonResponse({ error: 'Missing slug param' }, 400)

    try {
      const result = await ctx.runMutation(internal.mssp.deprovisionTenant, { slug })
      return jsonResponse(result, 200)
    } catch (err) {
      return jsonResponse({ error: String(err) }, 400)
    }
  }),
})

// GET /api/mssp/dashboard — cross-tenant risk overview

http.route({
  path: '/api/mssp/dashboard',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireMsspApiKey(request)
    if (authError) return authError

    const dashboard = await ctx.runQuery(internal.mssp.getCrossTenantDashboard, {})
    return jsonResponse(dashboard, 200)
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/buildkite
//
// Buildkite Webhook: build.finished events trigger a repository scan.
// Auth: X-Buildkite-Token shared secret (compared verbatim — no HMAC).
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/buildkite',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const token = request.headers.get('x-buildkite-token') ?? undefined
    const body = await request.text()

    const result = await ctx.runAction(
      internal.buildkiteWebhooks.verifyAndRouteBuildkiteWebhook,
      { body, token },
    )

    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/jenkins
//
// Jenkins Webhook: FINALIZED build events trigger a repository scan.
// Auth: X-Jenkins-Token shared secret (compared verbatim — no HMAC).
// Closes spec §4.6.2 — final CI provider (parity with Buildkite auth model).
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/jenkins',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const token = request.headers.get('x-jenkins-token') ?? undefined
    const body = await request.text()

    const result = await ctx.runAction(
      internal.jenkinsWebhooks.verifyAndRouteJenkinsWebhook,
      { body, token },
    )

    return jsonResponse(result, result.accepted ? 200 : 400)
  }),
})

// ---------------------------------------------------------------------------
// POST /api/siem/push
//
// Manually trigger a SIEM rule push for a repository.
// Body: { "repositoryId": "<id>" }
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/siem/push',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: { repositoryId?: string }
    try {
      body = await request.json() as { repositoryId?: string }
    } catch {
      return jsonResponse({ error: 'Invalid JSON body' }, 400)
    }

    const { repositoryId } = body
    if (!repositoryId) {
      return jsonResponse({ error: 'repositoryId is required' }, 400)
    }

    try {
      await ctx.runMutation(api.siemIntel.triggerSiemPushForRepository, {
        repositoryId: repositoryId as import('./_generated/dataModel').Id<'repositories'>,
      })
      return jsonResponse({ scheduled: true }, 202)
    } catch (err) {
      return jsonResponse({ error: String(err) }, 404)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /metrics
//
// Prometheus metrics endpoint (text exposition format 0.0.4).
// Scraped by Prometheus or Grafana Agent.
//
// Configuration:
//   npx convex env set PROMETHEUS_DEFAULT_TENANT atlas-fintech
//   npx convex env set PROMETHEUS_SCRAPE_TOKEN <secret>   (optional auth)
//
// Query params:
//   ?tenantSlug=<slug>   override the default tenant for this scrape
//
// Grafana scrape config:
//   - job_name: sentinel
//     static_configs:
//       - targets: [<convex-site-url>]
//     metrics_path: /metrics
//     params:
//       tenantSlug: [atlas-fintech]
//     bearer_token: <PROMETHEUS_SCRAPE_TOKEN>
// ---------------------------------------------------------------------------

http.route({
  path: '/metrics',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    // Optional Prometheus scrape token guard
    const scrapeToken = process.env.PROMETHEUS_SCRAPE_TOKEN
    if (scrapeToken) {
      const authHeader = request.headers.get('authorization')
      const provided = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
      if (provided !== scrapeToken) {
        return new Response('# Unauthorized\n', {
          status: 401,
          headers: { 'Content-Type': 'text/plain' },
        })
      }
    }

    const { searchParams } = new URL(request.url)
    const tenantSlug =
      searchParams.get('tenantSlug') ??
      process.env.PROMETHEUS_DEFAULT_TENANT ??
      ''

    if (!tenantSlug) {
      return new Response(
        '# No tenant configured. Set PROMETHEUS_DEFAULT_TENANT or pass ?tenantSlug=<slug>\n',
        { status: 200, headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' } },
      )
    }

    const repositoryFullName = searchParams.get('repositoryFullName') ?? undefined

    const metricsArray = await ctx.runQuery(api.observabilityIntel.getMetricsSnapshot, {
      tenantSlug,
      repositoryFullName,
    })

    const allSamples = metricsArray.flatMap((m) => sentinelMetricsToSamples(m))

    const page = buildMetricsPage(allSamples)
    return new Response(page, {
      status: 200,
      headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/observability/metrics?tenantSlug=<slug>
//
// JSON version of the Prometheus metrics endpoint. Returns structured
// metric snapshots for API consumers. Guarded by SENTINEL_API_KEY.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/observability/metrics',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug')
    const repositoryFullName = searchParams.get('repositoryFullName') ?? undefined

    if (!tenantSlug) {
      return jsonResponse({ error: 'Missing required query parameter: tenantSlug' }, 400)
    }

    const metrics = await ctx.runQuery(api.observabilityIntel.getMetricsSnapshot, {
      tenantSlug,
      repositoryFullName,
    })

    return new Response(JSON.stringify({ tenantSlug, repositories: metrics }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// PATCH /api/findings/triage
//
// Analyst triage action — mark false positive, accept risk, reopen, ignore,
// or add a note to a finding.  All actions are appended to the immutable
// `findingTriageEvents` audit log.  Status-changing actions also patch the
// finding's `status` field.
//
// Body: { findingId, action, note?, analyst? }
// Actions: mark_false_positive | mark_accepted_risk | reopen | add_note | ignore
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/triage',
  method: 'PATCH',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Request body must be valid JSON.' }, 400)
    }

    const { findingId, action, note, analyst } = body as Record<string, unknown>

    if (typeof findingId !== 'string' || !findingId) {
      return jsonResponse({ error: 'Missing required field: findingId' }, 400)
    }

    const VALID_ACTIONS = [
      'mark_false_positive',
      'mark_accepted_risk',
      'reopen',
      'add_note',
      'ignore',
    ] as const
    type ValidAction = (typeof VALID_ACTIONS)[number]

    if (typeof action !== 'string' || !VALID_ACTIONS.includes(action as ValidAction)) {
      return jsonResponse(
        { error: `Invalid action. Must be one of: ${VALID_ACTIONS.join(', ')}` },
        400,
      )
    }

    if (action === 'add_note' && (typeof note !== 'string' || !note.trim())) {
      return jsonResponse({ error: 'add_note requires a non-empty note field' }, 400)
    }

    try {
      const result = await ctx.runMutation(api.findingTriage.applyTriageAction, {
        // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast
        findingId: findingId as any,
        action: action as ValidAction,
        note: typeof note === 'string' ? note : undefined,
        analyst: typeof analyst === 'string' ? analyst : undefined,
      })
      return jsonResponse(result, 200)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Triage action failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/triage?findingId=<id>
//
// Returns the full triage event history and current summary for a finding.
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/triage',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const findingId = searchParams.get('findingId')

    if (!findingId) {
      return jsonResponse({ error: 'Missing required query parameter: findingId' }, 400)
    }

    try {
      const result = await ctx.runQuery(api.findingTriage.getTriageHistory, {
        // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast
        findingId: findingId as any,
      })
      return new Response(JSON.stringify(result, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Query failed.'
      return jsonResponse({ error: message }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// POST /webhooks/telegram
//
// Telegram Bot API webhook endpoint.
// Telegram sends signed updates here when the bot receives channel posts or
// direct messages.  We verify the shared secret via X-Telegram-Bot-Api-Secret-Token
// header (set via TELEGRAM_WEBHOOK_SECRET env var).
// Signals with threatLevel='none' are silently acknowledged.
// ---------------------------------------------------------------------------

http.route({
  path: '/webhooks/telegram',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const webhookSecret = process.env.TELEGRAM_WEBHOOK_SECRET
    if (webhookSecret) {
      const incoming = request.headers.get('x-telegram-bot-api-secret-token') ?? ''
      if (incoming !== webhookSecret) {
        return new Response('Forbidden', { status: 403 })
      }
    }

    const body = await request.text()
    const result = await ctx.runAction(internal.tier3Intel.handleTelegramUpdate, {
      updateJson: body,
    })

    return jsonResponse({ ok: true, stored: result.stored, threatLevel: result.threatLevel }, 200)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/threat-intel/cisa-kev
//
// Returns the latest CISA KEV sync snapshot and recent high-priority signals.
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/threat-intel/cisa-kev',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const snapshot = await ctx.runQuery(api.tier3Intel.getLatestCisaKevSnapshot, {})
    const signals = await ctx.runQuery(api.tier3Intel.getHighPrioritySignals, {})

    return jsonResponse({ snapshot, signals }, 200)
  }),
})

// ---------------------------------------------------------------------------
// POST /api/threat-intel/cisa-kev/sync
//
// Manually trigger a CISA KEV catalog sync.
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/threat-intel/cisa-kev/sync',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    await ctx.runMutation(api.tier3Intel.triggerCisaKevSync, {})

    return jsonResponse({ scheduled: true }, 202)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/threat-intel/epss
//
// Returns the latest EPSS sync snapshot and top-scored CVEs.
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/threat-intel/epss',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const snapshot = await ctx.runQuery(api.epssIntel.getLatestEpssSnapshot, {})
    const enriched = await ctx.runQuery(api.epssIntel.getEpssEnrichedDisclosures, { limit: 25 })

    return jsonResponse({ snapshot, enriched }, 200)
  }),
})

// ---------------------------------------------------------------------------
// POST /api/threat-intel/epss/sync
//
// Manually trigger an EPSS sync run.
// Auth: X-Sentinel-Api-Key / Authorization: Bearer
// ---------------------------------------------------------------------------

http.route({
  path: '/api/threat-intel/epss/sync',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    await ctx.runMutation(api.epssIntel.triggerEpssSync, {})

    return jsonResponse({ scheduled: true }, 202)
  }),
})

// ---------------------------------------------------------------------------
// POST /api/findings/risk-accept
//
// Formally accept a risk for a finding.  Supply justification, approver, and
// optional durationDays (omit for permanent acceptance).
// Spec §4.3 (Risk Acceptance Lifecycle).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/risk-accept',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Invalid JSON body.' }, 400)
    }

    if (
      typeof body !== 'object' ||
      body === null ||
      typeof (body as Record<string, unknown>).findingId !== 'string' ||
      typeof (body as Record<string, unknown>).justification !== 'string' ||
      typeof (body as Record<string, unknown>).approver !== 'string'
    ) {
      return jsonResponse(
        { error: 'findingId, justification, and approver are required.' },
        400,
      )
    }

    const {
      findingId,
      justification,
      approver,
      durationDays,
    } = body as {
      findingId: string
      justification: string
      approver: string
      durationDays?: number
    }

    if (durationDays !== undefined && (typeof durationDays !== 'number' || durationDays <= 0)) {
      return jsonResponse(
        { error: 'durationDays must be a positive number when provided.' },
        400,
      )
    }

    try {
      const result = await ctx.runMutation(
        api.riskAcceptanceIntel.createRiskAcceptance,
        {
          findingId: findingId as Id<'findings'>,
          justification,
          approver,
          durationDays,
        },
      )
      return jsonResponse(result, 201)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error'
      return jsonResponse({ error: msg }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// DELETE /api/findings/risk-accept?findingId=<id>&revokedBy=<who>
//
// Revoke an active risk acceptance and re-open the finding.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/risk-accept',
  method: 'DELETE',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const findingId = url.searchParams.get('findingId')
    const revokedBy = url.searchParams.get('revokedBy') ?? undefined

    if (!findingId) {
      return jsonResponse({ error: 'findingId is required.' }, 400)
    }

    try {
      const result = await ctx.runMutation(
        api.riskAcceptanceIntel.revokeRiskAcceptance,
        { findingId: findingId as Id<'findings'>, revokedBy },
      )
      return jsonResponse(result, 200)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error'
      return jsonResponse({ error: msg }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/risk-acceptances?tenantSlug=<slug>&repositoryFullName=<name>
//
// Lists risk acceptances for a repository with expiry status.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/risk-acceptances',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.riskAcceptanceIntel.getRiskAcceptancesBySlug,
      { tenantSlug, repositoryFullName },
    )

    if (!result) return jsonResponse({ error: 'Repository not found.' }, 404)

    return jsonResponse(result, 200)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sla/status?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns per-finding SLA assessments, a rolled-up summary, and MTTR for
// the specified repository.  Spec §3.13.3 (SLA enforcement).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sla/status',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(api.slaIntel.getSlaStatusBySlug, {
      tenantSlug,
      repositoryFullName,
    })

    if (!result) return jsonResponse({ error: 'Repository not found.' }, 404)

    return jsonResponse(result, 200)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/remediation/queue?tenantSlug=<slug>&repositoryFullName=<name>[&limit=<n>]
//
// Returns the prioritised remediation queue for a repository.  Findings are
// ranked by a composite score combining SLA status, exploit availability,
// validation outcome, blast radius, and severity.  Each entry includes a
// P0/P1/P2/P3 priority tier and a human-readable rationale.
// Spec §3.16 (Automated Remediation Priority Queue).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/remediation/queue',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')
    const limitRaw = url.searchParams.get('limit')
    const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || 25, 100) : 25

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.remediationQueueIntel.getRemediationQueueBySlug,
      { tenantSlug, repositoryFullName, limit },
    )

    if (!result) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/cross-repo-impact?tenantSlug=<slug>&packageName=<name>
//
// Returns the cross-repository impact record for a given package across all
// tenant repositories.  Spec §3.2.1 (Cross-Repository Impact Detection).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/cross-repo-impact',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const packageName = url.searchParams.get('packageName')

    if (!tenantSlug || !packageName) {
      return jsonResponse(
        { error: 'tenantSlug and packageName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.crossRepoIntel.getCrossRepoImpactBySlug,
      { tenantSlug, packageName },
    )

    if (!result) {
      return jsonResponse(
        { error: 'No cross-repo impact record found for this package.' },
        404,
      )
    }

    return jsonResponse(result, 200)
  }),
})

// ---------------------------------------------------------------------------
// GET /api/findings/escalations?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the escalation summary for a repository — total escalations,
// per-trigger counts, and the 10 most recent escalation events.
// Spec §3.17 (Finding Severity Escalation Engine).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/findings/escalations',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.escalationIntel.getEscalationSummaryBySlug,
      { tenantSlug, repositoryFullName },
    )

    if (!result) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/remediation/auto-runs?tenantSlug=<slug>&repositoryFullName=<name>
//
// Returns the auto-remediation run summary for a repository — total runs,
// total PRs dispatched, skip-reason counts, and the 10 most recent run records.
// Spec §3.18 (Autonomous Remediation Dispatch).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/remediation/auto-runs',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName are required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.autoRemediationIntel.getAutoRemediationSummaryBySlug,
      { tenantSlug, repositoryFullName },
    )

    if (!result) {
      return jsonResponse(
        { error: `Repository not found: ${repositoryFullName}` },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// POST /api/marketplace/contributions
//
// Submit a new community vulnerability fingerprint or detection rule.
// Body: { contributorTenantId, type, title, description, vulnClass, severity, patternText }
// Spec §10 Phase 4 — Community Rule/Fingerprint Marketplace.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/marketplace/contributions',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: Record<string, unknown>
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Invalid JSON body.' }, 400)
    }

    const required = [
      'contributorTenantId',
      'type',
      'title',
      'description',
      'vulnClass',
      'severity',
      'patternText',
    ]
    for (const field of required) {
      if (!body[field]) {
        return jsonResponse({ error: `Missing required field: ${field}` }, 400)
      }
    }

    try {
      const result = await ctx.runMutation(
        api.communityMarketplace.submitContribution,
        {
          contributorTenantId: body.contributorTenantId as Id<'tenants'>,
          type: body.type as 'fingerprint' | 'detection_rule',
          title: String(body.title),
          description: String(body.description),
          vulnClass: String(body.vulnClass),
          severity: body.severity as 'critical' | 'high' | 'medium' | 'low' | 'informational',
          patternText: String(body.patternText),
        },
      )
      return jsonResponse({ id: result.id }, 201)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return jsonResponse({ error: msg }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/marketplace/contributions?type=<type>&status=<status>&vulnClass=<cls>&limit=<n>
//
// List community contributions, ranked by net score. All query params are optional.
// Spec §10 Phase 4 — Community Rule/Fingerprint Marketplace.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/marketplace/contributions',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const typeParam = url.searchParams.get('type')
    const statusParam = url.searchParams.get('status')
    const vulnClass = url.searchParams.get('vulnClass') ?? undefined
    const limitParam = url.searchParams.get('limit')
    const limit = limitParam ? Math.min(parseInt(limitParam, 10), 200) : 50

    const contributions = await ctx.runQuery(
      api.communityMarketplace.listContributions,
      {
        type: typeParam as 'fingerprint' | 'detection_rule' | undefined ?? undefined,
        status: statusParam as 'pending' | 'under_review' | 'approved' | 'rejected' | undefined ?? undefined,
        vulnClass,
        limit,
      },
    )

    return new Response(JSON.stringify(contributions, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// POST /api/marketplace/contributions/vote
//
// Cast or switch a vote on a community contribution.
// Body: { contributionId, voterTenantId, voteType: 'upvote'|'downvote' }
// Spec §10 Phase 4 — Community Rule/Fingerprint Marketplace.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/marketplace/contributions/vote',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    let body: Record<string, unknown>
    try {
      body = await request.json()
    } catch {
      return jsonResponse({ error: 'Invalid JSON body.' }, 400)
    }

    if (!body.contributionId || !body.voterTenantId || !body.voteType) {
      return jsonResponse(
        { error: 'contributionId, voterTenantId, and voteType are required.' },
        400,
      )
    }

    try {
      const result = await ctx.runMutation(
        api.communityMarketplace.voteOnContribution,
        {
          contributionId: body.contributionId as Id<'communityContributions'>,
          voterTenantId: body.voterTenantId as Id<'tenants'>,
          voteType: body.voteType as 'upvote' | 'downvote',
        },
      )
      return jsonResponse(result, 200)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return jsonResponse({ error: msg }, 400)
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/marketplace/stats
//
// Return aggregate marketplace statistics: counts by type, status, vulnClass.
// Spec §10 Phase 4 — Community Rule/Fingerprint Marketplace.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/marketplace/stats',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const stats = await ctx.runQuery(api.communityMarketplace.getMarketplaceStats, {})

    return new Response(JSON.stringify(stats, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GET /api/crypto/weaknesses?tenantSlug=&repositoryFullName=
//
// Return the latest cryptographic weakness scan result for a repository.
// Spec §8 — Sentinel's own security posture (crypto hygiene checks).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/crypto/weaknesses',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.cryptoWeaknessIntel.getLatestCryptoWeaknessScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No crypto weakness scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// POST /api/traffic/events — Production Traffic Anomaly Detection (WS-29)
// Spec §10 Phase 4: agent-less monitoring via HTTP access log ingestion.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/traffic/events',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName query params required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    if (!Array.isArray(body)) {
      return new Response(
        JSON.stringify({ error: 'Body must be a JSON array of traffic events' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    try {
      const result = await ctx.runMutation(api.trafficAnomalyIntel.ingestTrafficEvents, {
        tenantSlug,
        repositoryFullName,
        events: body as never,
      })
      return new Response(JSON.stringify(result, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return new Response(JSON.stringify({ error: msg }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }
  }),
})

// ---------------------------------------------------------------------------
// GET /api/abandonment/scan?tenantSlug=&repositoryFullName=
//
// Return the latest open-source package abandonment scan result for a repository.
// Includes supply-chain-compromised, archived, deprecated, and superseded packages.
// Spec §3.11 (SBOM Living Registry) — abandonment status enrichment (WS-39).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/abandonment/scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.abandonmentScanIntel.getLatestAbandonmentScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No abandonment scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/eol/scan?tenantSlug=&repositoryFullName=
//
// Return the latest End-of-Life scan result for a repository.
// Spec §3.11 (SBOM Living Registry) — EOL status enrichment.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/eol/scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.eolDetectionIntel.getLatestEolScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No EOL scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/attestation?tenantSlug=&repositoryFullName=
//
// Return the latest SBOM attestation record for a repository.
// Includes contentHash, attestationHash, componentCount, and verification status.
// Spec §3.11 (SBOM Living Registry) — integrity attestation (WS-40).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/attestation',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const attestation = await ctx.runQuery(
      api.sbomAttestationIntel.getLatestAttestation,
      { tenantSlug, repositoryFullName },
    )

    if (!attestation) {
      return jsonResponse({ error: 'No attestation record found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(attestation, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/malicious-scan?tenantSlug=&repositoryFullName=
//
// Return the latest malicious package scan result for a repository.
// Includes overallRisk, per-severity counts, and the top suspicious findings
// with signal annotations (known_malicious / typosquat / suspicious_pattern).
// Spec §3.13 (Malicious Package Detection) — WS-42.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/malicious-scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.maliciousPackageIntel.getLatestMaliciousScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No malicious package scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/cve-scan?tenantSlug=&repositoryFullName=
//
// Return the latest known-CVE version-range scan result for a repository.
// Includes overallRisk, per-severity counts, top findings with CVE IDs and
// CVSS scores, and a human-readable summary.
// Spec §3.14 (Known CVE Version Range Scanner) — WS-43.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/cve-scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.cveVersionScanIntel.getLatestCveScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No CVE scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/supply-chain-posture?tenantSlug=&repositoryFullName=
//
// Return the latest supply chain posture score for a repository.
// Includes score (0–100), grade (A–F), riskLevel, per-category breakdown,
// and pass-through risk strings from each sub-scanner.
// Spec WS-44 (Supply Chain Posture Score).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/supply-chain-posture',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const score = await ctx.runQuery(
      api.supplyChainPostureIntel.getLatestSupplyChainPosture,
      { tenantSlug, repositoryFullName },
    )

    if (!score) {
      return jsonResponse({ error: 'No supply chain posture score found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(score, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/container-image-scan?tenantSlug=&repositoryFullName=
//
// Return the latest container image security scan for a repository.
// Includes per-image findings (signal, riskLevel, EOL date, recommended
// version) and aggregate counts. Spec WS-45 (Container Image Security Analyzer).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/container-image-scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.containerImageIntel.getLatestContainerImageScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse(
        { error: 'No container image scan found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/compliance/attestation?tenantSlug=&repositoryFullName=
//
// Return the latest compliance attestation report for a repository.
// Includes per-framework status (SOC2/GDPR/PCI-DSS/HIPAA/NIS2), scores, gap
// counts, and control-level detail. Spec WS-46 (Compliance Attestation Report Generator).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/compliance/attestation',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const attestation = await ctx.runQuery(
      api.complianceAttestationIntel.getLatestComplianceAttestation,
      { tenantSlug, repositoryFullName },
    )

    if (!attestation) {
      return jsonResponse(
        { error: 'No compliance attestation found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(attestation, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/compliance/remediation-plan?tenantSlug=&repositoryFullName=
//
// Return the latest compliance gap remediation plan for a repository.
// Includes ordered actions (critical → low), per-action playbook steps,
// root-cause-deduplicated estimatedTotalDays, and automation stats.
// Spec WS-47 (Compliance Gap Remediation Planner).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/compliance/remediation-plan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const plan = await ctx.runQuery(
      api.complianceRemediationIntel.getLatestComplianceRemediationPlan,
      { tenantSlug, repositoryFullName },
    )

    if (!plan) {
      return jsonResponse(
        { error: 'No compliance remediation plan found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(plan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/license-scan?tenantSlug=&repositoryFullName=
//
// Return the latest SPDX-based license risk scan for a repository.
// Includes per-package findings (strong copyleft → critical, weak copyleft /
// proprietary → high, unknown → medium), licenseBreakdown, and overallRisk.
// Spec WS-48 (License Compliance & Risk Scanner).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/license-scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.licenseScanIntel.getLatestLicenseComplianceScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse(
        { error: 'No license scan found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/confusion-scan?tenantSlug=&repositoryFullName=
//
// Return the latest dependency confusion attack scan result for a repository.
// Includes overallRisk, per-severity counts, and the top suspicious findings.
// Spec §3.12 (Dependency Confusion Attack Detector) — WS-41.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/confusion-scan',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const scan = await ctx.runQuery(
      api.confusionAttackIntel.getLatestConfusionScan,
      { tenantSlug, repositoryFullName },
    )

    if (!scan) {
      return jsonResponse({ error: 'No confusion scan found for this repository.' }, 404)
    }

    return new Response(JSON.stringify(scan, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/health-score?tenantSlug=&repositoryFullName=
//
// Return the latest security health score for a repository: weighted 0–100
// overall score, A–F grade, per-category breakdown, trend, and top risk
// signals. Spec §3.49 (Repository Security Health Score) — WS-49.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/health-score',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const score = await ctx.runQuery(
      api.repositoryHealthIntel.getLatestRepositoryHealthScore,
      { tenantSlug, repositoryFullName },
    )

    if (!score) {
      return jsonResponse(
        { error: 'No health score found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(score, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/sbom/update-recommendations?tenantSlug=&repositoryFullName=
//
// Return the latest dependency update recommendations for a repository:
// concrete upgrade paths with urgency, effort classification, breaking-change
// risk, and combined reasons from CVE/EOL/abandonment scanners.
// Spec §3.50 (Dependency Update Recommendation Engine) — WS-50.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/update-recommendations',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const result = await ctx.runQuery(
      api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations,
      { tenantSlug, repositoryFullName },
    )

    if (!result) {
      return jsonResponse(
        { error: 'No update recommendations found for this repository.' },
        404,
      )
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/security/timeline?tenantSlug=&repositoryFullName=&limit=50
//
// Return a chronological audit log of all security lifecycle events for a
// repository: findings created, severity escalations, analyst triage, gate
// decisions, fix PR proposals/merges, SLA breaches, risk acceptances, red
// agent wins, auto-remediation dispatches, and secret detections.
// API-key-guarded.  Spec WS-51 (Security Event Timeline).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/security/timeline',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug')
    const repositoryFullName = url.searchParams.get('repositoryFullName')
    const limitParam = url.searchParams.get('limit')
    const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 100) : 50

    if (!tenantSlug || !repositoryFullName) {
      return jsonResponse(
        { error: 'tenantSlug and repositoryFullName query params required.' },
        400,
      )
    }

    const timeline = await ctx.runQuery(
      api.securityTimelineIntel.getSecurityTimelineBySlug,
      { tenantSlug, repositoryFullName, limit },
    )

    return new Response(
      JSON.stringify({ timeline, count: timeline.length }, null, 2),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      },
    )
  }),
})

// ---------------------------------------------------------------------------
// GET /api/security/debt?tenantSlug=&repositoryFullName=
//
// Return the latest security debt velocity snapshot for a repository: open
// backlog, overdue SLA counts, net velocity, trend, projected clearance days,
// and the 0–100 debt score. API-key-guarded. Spec WS-52.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/security/debt',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const snapshot = await ctx.runQuery(
      api.securityDebtIntel.getLatestSecurityDebtBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(
      JSON.stringify({ snapshot }, null, 2),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      },
    )
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/sensitive-files?tenantSlug=&repositoryFullName=
//
// Return the latest sensitive-file scan for a repository: per-path findings
// with category, severity, and remediation recommendations. API-key-guarded.
// Spec WS-54.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/sensitive-files',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.sensitiveFileIntel.getLatestSensitiveFileScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/branch-protection?tenantSlug=&repositoryFullName=
//
// Return the latest branch protection scan for a repository: risk score,
// risk level, per-rule findings, and remediation recommendations.
// API-key-guarded. Spec WS-53.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/branch-protection',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.branchProtectionIntel.getLatestBranchProtectionBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/commit-messages?tenantSlug=&repositoryFullName=
//
// Return the latest commit message security scan for a repository: risk score,
// risk level, per-message findings, and remediation recommendations.
// API-key-guarded. Spec WS-55.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/commit-messages',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.commitMessageIntel.getLatestCommitMessageScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/git-integrity?tenantSlug=&repositoryFullName=
//
// Return the latest Git supply-chain integrity scan for a repository: risk
// score, risk level, per-path findings, and remediation recommendations.
// API-key-guarded. Spec WS-56.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/git-integrity',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.gitIntegrityIntel.getLatestGitIntegrityScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/high-risk-changes?tenantSlug=&repositoryFullName=
//
// Return the latest security-hotspot change scan for a repository: risk
// score, risk level, per-rule findings with match counts, and remediation
// recommendations. API-key-guarded. Spec WS-57.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/high-risk-changes',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.highRiskChangeIntel.getLatestHighRiskChangeScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GET /api/repository/security-config-drift?tenantSlug=&repositoryFullName=
//
// Return the latest application security configuration drift scan for a
// repository: risk score, risk level, per-rule findings with matched paths,
// and remediation recommendations. API-key-guarded. Spec WS-60.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/security-config-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.securityConfigDriftIntel.getLatestSecurityConfigDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/test-coverage-gaps?tenantSlug=&repositoryFullName=
//
// Return the latest test-coverage gap scan for a repository: risk score,
// risk level, and per-domain findings. API-key-guarded. Spec WS-61.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/test-coverage-gaps',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.testCoverageGapIntel.getLatestTestCoverageGapBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/database-security?tenantSlug=&repositoryFullName=
//
// Return the latest database security configuration drift scan for a repository:
// risk score, risk level, and per-rule findings covering PostgreSQL, MySQL,
// MongoDB, Redis, database TLS, connection pool, security migrations, and
// Elasticsearch security configuration. API-key-guarded. Spec WS-64.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/database-security',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required query parameters.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.databaseSecurityDriftIntel.getLatestDatabaseSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/container-hardening?tenantSlug=&repositoryFullName=
//
// Return the latest Kubernetes & container security hardening drift scan for
// a repository: risk score, risk level, and per-rule findings covering RBAC,
// NetworkPolicy, PodSecurity, admission controllers, external secrets,
// Dockerfiles, container runtime profiles, and Helm security values.
// API-key-guarded. Spec WS-63.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/container-hardening',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required query parameters.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.containerHardeningDriftIntel.getLatestContainerHardeningDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/cloud-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest cloud security configuration drift scan for a repository:
// risk score, risk level, and per-rule findings covering IAM policy, KMS key
// policy, network security, storage policy, API Gateway auth, secrets backend,
// audit logging, and CDN/WAF configuration. API-key-guarded. Spec WS-62.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/cloud-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required query parameters.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.cloudSecurityDriftIntel.getLatestCloudSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/build-config?tenantSlug=&repositoryFullName=
//
// Return the latest build toolchain integrity scan for a repository: risk
// score, risk level, per-rule findings with match counts, and remediation
// recommendations. API-key-guarded. Spec WS-59.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/build-config',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.buildConfigIntel.getLatestBuildConfigScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/dep-lock?tenantSlug=&repositoryFullName=
//
// Return the latest dependency lock-file integrity scan for a repository:
// risk score, risk level, per-rule findings with match counts, and
// remediation recommendations. API-key-guarded. Spec WS-58.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/dep-lock',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.depLockIntel.getLatestDepLockVerifyScanBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/api-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest API security configuration drift scan for a repository:
// risk score, risk level, and per-rule findings covering rate limiting,
// API key management, GraphQL security, OpenAPI security schemas, webhook
// validation, quota enforcement, schema validation, and REST API security
// policies. API-key-guarded. Spec WS-65.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/api-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug          = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName  = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.apiSecurityDriftIntel.getLatestApiSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/cert-pki-drift?tenantSlug=&repositoryFullName=
//
// Return the latest cryptographic certificate & PKI configuration drift scan
// for a repository: risk score, risk level, and per-rule findings covering
// cert-manager CRDs, PKI/CA certificates, ACME/Let's Encrypt renewal,
// certificate pinning, SSH authorized keys, GPG keyrings, Sigstore/cosign,
// and TLS CA-bundle/trust-store files. API-key-guarded. Spec WS-66.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/cert-pki-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.certPkiDriftIntel.getLatestCertPkiDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/endpoint-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest endpoint security & EDR drift scan for a repo: risk score,
// risk level, and per-rule findings covering CrowdStrike Falcon agent and
// prevention policy, SentinelOne agent and policy, Microsoft Defender for
// Endpoint managed configuration, EDR/AV exclusion lists, MDM/UEM device
// enrollment and compliance policy, Carbon Black/Sophos endpoint security,
// vulnerability scanner agent configuration, and Tanium/BigFix endpoint
// management.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/endpoint-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(api.endpointSecurityDriftIntel.getLatestEndpointSecurityDriftBySlug, {
      tenantSlug,
      repositoryFullName,
    })
    if (!data) {
      return new Response(JSON.stringify({ error: 'not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/drift-posture?tenantSlug=&repositoryFullName=
//
// Returns the latest configuration drift aggregate health score for a repo:
// 0–100 overall score, A–F grade, trend, per-category breakdown (8 categories
// covering all 36 drift detectors WS-60 through WS-95), critical/high counts,
// top risk signals, and a human-readable summary.
// ---------------------------------------------------------------------------
http.route({
  path: '/api/repository/drift-posture',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const err = requireApiKey(req)
    if (err) return err
    const { searchParams } = new URL(req.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''
    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }), {
        status: 400, headers: { 'Content-Type': 'application/json' },
      })
    }
    const data = await ctx.runQuery(api.driftPostureIntel.getLatestDriftPostureBySlug, {
      tenantSlug,
      repositoryFullName,
    })
    if (!data) {
      return new Response(JSON.stringify({ error: 'not found' }), {
        status: 404, headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/network-monitoring-drift?tenantSlug=&repositoryFullName=
//
// Return the latest network monitoring & SNMP security drift scan for a repo:
// risk score, risk level, and per-rule findings covering SNMP daemon community
// strings/v3 auth, Nagios/NRPE monitoring, Zabbix server/agent, NetFlow/sFlow
// traffic analysis, LibreNMS/Oxidized NMS, Netdata streaming, SNMP trap
// receivers, and network probe/scanner configuration.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/network-monitoring-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(api.networkMonitoringDriftIntel.getLatestNetworkMonitoringDriftBySlug, {
      tenantSlug,
      repositoryFullName,
    })
    if (!data) {
      return new Response(JSON.stringify({ error: 'not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// GET /api/repository/voip-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest VoIP & UC security drift scan for a repo: risk score,
// risk level, and per-rule findings covering Asterisk PBX / FreePBX, Kamailio /
// OpenSIPS SIP proxy, FreeSWITCH, SIP trunk credentials, Jitsi / TURN / WebRTC,
// VoIP gateway and ATA configuration, web conferencing servers (Matrix/Synapse,
// BigBlueButton, Rocket.Chat, Mattermost), and VoIP CDR / SIP capture monitoring.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/voip-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(api.voipSecurityDriftIntel.getLatestVoipSecurityDriftBySlug, {
      tenantSlug,
      repositoryFullName,
    })
    if (!data) {
      return new Response(JSON.stringify({ error: 'not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/virtualization-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest virtualization & hypervisor security drift scan for a repo:
// risk score, risk level, and per-rule findings covering VMware vSphere/ESXi/
// vCenter configuration, KVM/QEMU/libvirt host configuration, Docker daemon and
// containerd host configuration, Proxmox VE cluster configuration, Xen/XenServer/
// XCP-ng configuration, Hyper-V configuration, VM remote console access
// configuration, and Open vSwitch / SDN configuration.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/virtualization-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.virtualizationSecurityDriftIntel.getLatestVirtualizationSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/iot-embedded-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest IoT & embedded device security drift scan for a repo: risk
// score, risk level, and per-rule findings covering Balena IoT fleet config,
// AWS IoT Greengrass config, firmware signing / secure-boot config, Mender OTA
// update config, Zigbee/Z-Wave controller config, Azure IoT Hub / DPS config,
// IoT device management platforms (ThingsBoard, Hawkbit, EdgeX), and LoRaWAN /
// network gateway configuration (ChirpStack, The Things Stack, lorawan-server).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/iot-embedded-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.iotEmbeddedSecurityDriftIntel.getLatestIotEmbeddedSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/wireless-radius-drift?tenantSlug=&repositoryFullName=
//
// Return the latest wireless network & RADIUS authentication drift scan for a
// repo: risk score, risk level, and per-rule findings covering Wi-Fi AP daemon
// configuration (hostapd.conf), WPA supplicant configuration, FreeRADIUS server
// configuration (radiusd.conf, clients.conf, users, huntgroups, dictionary,
// sites-enabled/, policy.d/, mods-enabled/), TACACS+ authentication server
// configuration, wireless controller configuration (UniFi, Aruba, WLC),
// RADIUS policy files, 802.1X / EAP authentication profiles, and captive-portal
// configuration.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/wireless-radius-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.wirelessRadiusDriftIntel.getLatestWirelessRadiusDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/os-security-hardening-drift?tenantSlug=&repositoryFullName=
//
// Return the latest OS security hardening drift scan for a repo: risk score,
// risk level, and per-rule findings covering sysctl kernel security parameters,
// OpenSSH daemon configuration (sshd_config), sudo privilege escalation policy,
// GRUB2 bootloader security settings, SELinux policy configuration, OS access
// control files (hosts.allow/deny, cron/at.allow), NTP/time-sync daemon
// configuration, and OS login banner/MOTD files.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/os-security-hardening-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.osSecurityHardeningDriftIntel.getLatestOsSecurityHardeningDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/dns-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest DNS security drift scan for a repo: risk score, risk level,
// and per-rule findings covering BIND named.conf, Unbound resolver config,
// PowerDNS authoritative and recursor configs, CoreDNS Corefile, dnsmasq
// DNS/DHCP forwarder config, Pi-hole filtering config, encrypted DNS proxy
// settings (dnscrypt-proxy, Stubby), and RPKI route-origin validation daemon
// configuration (routinator, fort, rpki-client).
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/dns-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.dnsSecurityDriftIntel.getLatestDnsSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/storage-data-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest storage & data security drift scan for a repo: risk score,
// risk level, and per-rule findings covering NFS export configs, Samba/SMB
// server configs, disk encryption (LUKS crypttab, dm-crypt), object storage
// client credentials (AWS ~/.aws/credentials, s3cmd .s3cfg, MinIO client),
// database backup encryption (pgbackrest/barman/wal-g), file integrity
// monitoring (AIDE/Tripwire/Samhain), DLP policy configs, and storage audit
// webhook configuration.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/storage-data-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.storageDataSecurityDriftIntel.getLatestStorageDataSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/siem-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest SIEM & security analytics drift scan for a repo: risk score,
// risk level, and per-rule findings covering Splunk detection configs, Elastic
// SIEM detection rules, Microsoft Sentinel analytics rules and hunting queries,
// osquery configuration, SIEM detection suppression rules, SOAR playbook configs,
// threat intelligence feed configs (MISP/OpenCTI/TAXII), and SIEM log source
// input/output configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/siem-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.siemSecurityDriftIntel.getLatestSiemSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/backup-dr-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest backup & DR security drift scan for a repo: risk score,
// risk level, and per-rule findings covering rclone cloud sync credentials,
// Restic backup password files and repo configuration, BorgBackup passphrase
// and borgmatic YAML configs, generic backup encryption keys and passphrases,
// rsync daemon configuration and secrets, Bacula/Amanda enterprise backup
// server configs, Velero/Duplicati/Duplicity cloud backup agent credentials,
// and backup shell scripts that frequently contain hardcoded credentials.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/backup-dr-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url            = new URL(request.url)
    const tenantSlug     = url.searchParams.get('tenantSlug')     ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''
    if (!tenantSlug || !repositoryFullName) {
      return new Response(JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const result = await ctx.runQuery(
      api.backupDrSecurityDriftIntel.getLatestBackupDrSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )
    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/vpn-remote-access-drift?tenantSlug=&repositoryFullName=
//
// Return the latest VPN & remote access security drift scan for a repo:
// risk score, risk level, and per-rule findings covering OpenVPN server/client
// configuration and TLS auth key material, WireGuard interface configs with
// embedded private keys, IPsec/StrongSwan/Libreswan configuration and PSK
// secrets, VPN-context PKI credential material, Apache Guacamole/Teleport
// bastion configuration, Cisco AnyConnect profiles, Pritunl/ocserv/pptpd SSL
// VPN server configuration, and VPN client profiles.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/vpn-remote-access-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.vpnRemoteAccessDriftIntel.getLatestVpnRemoteAccessDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/cfg-mgmt-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest configuration management security drift scan for a repo:
// risk score, risk level, and per-rule findings covering Ansible configuration
// and vault password files, Chef workstation API keys and encrypted data bag
// secrets, Puppet master server configuration and r10k Puppetfiles, SaltStack
// master/minion configuration and SSH rosters, Ansible inventory and
// group/host variable files, Chef Berkshelf/Policyfile cookbook dependency
// manifests, Puppet Hiera eyaml-encrypted data files, and Test Kitchen/Molecule
// CI framework configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/cfg-mgmt-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.cfgMgmtSecurityDriftIntel.getLatestCfgMgmtSecurityDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/artifact-registry-drift?tenantSlug=&repositoryFullName=
//
// Return the latest artifact registry security drift scan for a repo:
// risk score, risk level, and per-rule findings covering JFrog Artifactory,
// Sonatype Nexus, Harbor OCI registry, Docker Distribution v2, Verdaccio
// npm registry, Bandersnatch/DevPI PyPI mirror, ChartMuseum Helm chart
// repository, and Athens Go module proxy configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/artifact-registry-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.artifactRegistryDriftIntel.getLatestArtifactRegistryDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/ml-ai-platform-drift?tenantSlug=&repositoryFullName=
//
// Return the latest ML/AI platform security drift scan for a repo:
// risk score, risk level, and per-rule findings covering MLflow tracking,
// Kubeflow Pipelines/KServe, Ray clusters, SageMaker/Vertex AI/Azure ML
// platform access, Feast feature stores, model serving (BentoML/Seldon/
// Triton), MLOps pipelines (DVC/ClearML/W&B), and model governance artifacts.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/ml-ai-platform-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.mlAiPlatformDriftIntel.getLatestMlAiPlatformDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/data-pipeline-drift?tenantSlug=&repositoryFullName=
//
// Return the latest data pipeline & ETL security drift scan for a repo:
// risk score, risk level, and per-rule findings covering Airflow, Spark, dbt,
// Hadoop/Hive/HBase/Flink, Trino/Presto, Dagster/Prefect, Great Expectations,
// DataHub, and Jupyter notebook server configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/data-pipeline-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.dataPipelineDriftIntel.getLatestDataPipelineDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/sso-provider-drift?tenantSlug=&repositoryFullName=
//
// Return the latest SSO provider & auth configuration drift scan for a repo:
// risk score, risk level, and per-rule findings covering Keycloak, SAML,
// OAuth2/OIDC servers, Auth0/Okta/PingFederate, Dex/Authelia, Duo MFA,
// SCIM provisioning, and oauth2-proxy configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/sso-provider-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.ssoProviderDriftIntel.getLatestSsoProviderDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/messaging-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest messaging & event streaming security drift scan for a repo:
// risk score, risk level, and per-rule findings covering Kafka, RabbitMQ, NATS,
// MQTT brokers, transport TLS, auth/ACL policies, Schema Registry, and Pulsar /
// ActiveMQ broker configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/messaging-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.messagingSecurityDriftIntel.getLatestMessagingSecurityDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/serverless-faas-drift?tenantSlug=&repositoryFullName=
//
// Return the latest serverless & FaaS security drift scan for a repository:
// risk score, risk level, and per-rule findings covering Serverless Framework,
// AWS SAM/Lambda, Azure Functions, Cloudflare Workers, GCP Cloud Run, edge
// deployment configs, function IAM permissions, and Knative/OpenWhisk.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/serverless-faas-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.serverlessFaasDriftIntel.getLatestServerlessFaasDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/email-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest email security drift scan for a repository: risk score,
// risk level, and per-rule findings covering MTA configs, DKIM signing,
// SASL auth, anti-spam filters, mail TLS, relay restrictions, access
// policies, and header/body filter rules.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/email-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.emailSecurityDriftIntel.getLatestEmailSecurityDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/web-server-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest web server & reverse proxy security drift scan for a
// repository: risk score, risk level, and per-rule findings covering nginx,
// Apache, Traefik, Caddy, ingress controllers, ModSecurity WAF, SSL
// termination configs, and access control files.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/web-server-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.webServerSecurityDriftIntel.getLatestWebServerSecurityDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/mobile-app-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest mobile application security drift scan for a repository:
// risk score, risk level, and per-rule findings covering iOS entitlements,
// Android manifests, signing configs, ProGuard/R8 obfuscation, Firebase
// configs, deep link verification, and mobile platform configs.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/mobile-app-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url        = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''
    const repoName   = url.searchParams.get('repositoryFullName') ?? ''

    const result = await ctx.runQuery(
      api.mobileAppSecurityDriftIntel.getLatestMobileAppSecurityDriftBySlug,
      { tenantSlug, repositoryFullName: repoName },
    )

    return new Response(JSON.stringify(result ?? null), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/cicd-pipeline-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest CI/CD pipeline security configuration drift scan for a
// repository: risk score, risk level, and per-rule findings covering GitHub
// Actions workflows, Jenkinsfile, GitLab CI, ArgoCD, FluxCD, Buildkite/
// CircleCI, Tekton pipelines, and SLSA artifact signing configs.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/cicd-pipeline-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.cicdPipelineSecurityDriftIntel.getLatestCicdPipelineSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/service-mesh-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest service mesh & zero-trust network security configuration
// drift scan for a repository: risk score, risk level, and per-rule findings
// covering Istio auth policy, Envoy proxy, SPIFFE/SPIRE, Linkerd, Consul
// Connect, CNI network policies, zero-trust access proxies, and mesh gateways.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/service-mesh-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.serviceMeshSecurityDriftIntel.getLatestServiceMeshSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/observability-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest observability & security monitoring configuration drift scan
// for a repository: risk score, risk level, and per-rule findings covering
// Prometheus alert rules, Alertmanager, log pipelines, OTEL, Grafana, CloudWatch
// alarms, distributed tracing backends, and log retention policies.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/observability-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.observabilitySecurityDriftIntel.getLatestObservabilitySecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/identity-access-drift?tenantSlug=&repositoryFullName=
//
// Return the latest identity & privileged access management configuration drift
// scan for a repository: risk score, risk level, and per-rule findings covering
// Vault policies, LDAP/PAM, MFA enforcement, SAML federation, and app RBAC.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/identity-access-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.identityAccessDriftIntel.getLatestIdentityAccessDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/dev-sec-tools-drift?tenantSlug=&repositoryFullName=
//
// Return the latest developer security tooling & SAST configuration drift scan
// for a repository: risk score, risk level, and per-rule findings covering
// secret scanning, SAST, SCA, security linting, DAST, license policy,
// container scanning, and security baseline configurations.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/dev-sec-tools-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.devSecToolsDriftIntel.getLatestDevSecToolsDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/network-firewall-drift?tenantSlug=&repositoryFullName=
//
// Return the latest network perimeter & firewall configuration drift scan
// for a repository: risk score, risk level, and per-rule findings covering
// iptables/nftables rules, HAProxy ACL config, UFW rules, VPN configs,
// DNS/BIND security, proxy access control, and firewalld zones.
// API-key-guarded. Spec WS-68.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/network-firewall-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.networkFirewallDriftIntel.getLatestNetworkFirewallDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/runtime-security-drift?tenantSlug=&repositoryFullName=
//
// Return the latest runtime security policy & enforcement configuration drift
// scan for a repository: risk score, risk level, and per-rule findings covering
// Falco behavioral rules, OPA Rego policies, seccomp/AppArmor profiles,
// Kyverno ClusterPolicy CRDs, fail2ban config, Linux auditd rules,
// Snort/Suricata IDS rules, and Sigma/YARA threat detection rules.
// API-key-guarded. Spec WS-67.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/runtime-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug         = url.searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = url.searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const result = await ctx.runQuery(
      api.runtimeSecurityDriftIntel.getLatestRuntimeSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ result }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/tenant/executive-report?tenantSlug=<slug>
//
// Returns the cross-repository tenant executive security summary: composite
// scores per domain (health, drift, supply chain, compliance), overall grade,
// risk tier, worst/best repos, top-5 action items, and framework roll-up.
// No new table — assembled at query time from WS-49, WS-96, WS-44, WS-46.
// API-key-guarded. Spec WS-97.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/tenant/executive-report',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const url = new URL(request.url)
    const tenantSlug = url.searchParams.get('tenantSlug') ?? ''

    if (!tenantSlug) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug is required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const report = await ctx.runQuery(
      api.executiveReportIntel.getExecutiveReport,
      { tenantSlug },
    )

    if (!report) {
      return new Response(
        JSON.stringify({ error: `Tenant not found: ${tenantSlug}` }),
        { status: 404, headers: { 'Content-Type': 'application/json' } },
      )
    }

    return new Response(JSON.stringify({ report }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/zero-day-detections?tenantSlug=&repositoryFullName=
//
// Returns the latest zero-day anomaly detection result. Spec WS-98 (§3.1.3).
// API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/zero-day-detections',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const latest = await ctx.runQuery(
      api.zeroDayDetectionIntel.getLatestZeroDayDetectionBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ zeroDayDetection: latest ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/maturity-assessment?tenantSlug=&repositoryFullName=
//
// Returns the latest Security Program Maturity Assessment. Spec WS-99.
// API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/maturity-assessment',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const assessment = await ctx.runQuery(
      api.maturityAssessmentIntel.getLatestMaturityAssessmentBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ maturityAssessment: assessment ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/business-impact?tenantSlug=&repositoryFullName=
//
// Returns the latest Business Impact Assessment for a repository. Spec WS-100 (§3.5.4).
// API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/business-impact',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.businessImpactIntel.getLatestBusinessImpactBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ businessImpact: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/supply-chain-attestation-drift?tenantSlug=&repositoryFullName=
//
// Returns the latest Supply Chain Build Integrity & Attestation Drift scan for
// a repository. Spec WS-109. API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/supply-chain-attestation-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.supplyChainAttestationDriftIntel.getLatestSupplyChainAttestationDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ supplyChainAttestationDrift: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/k8s-admission-drift?tenantSlug=&repositoryFullName=
//
// Returns the latest Kubernetes Admission Controller & Policy Engine Drift scan
// for a repository. Spec WS-107. API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/k8s-admission-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.k8sAdmissionDriftIntel.getLatestK8sAdmissionDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ k8sAdmissionDrift: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/secret-mgmt-drift?tenantSlug=&repositoryFullName=
//
// Returns the latest Secret Management Configuration Drift scan for a
// repository. Spec WS-105. API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/secret-mgmt-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.secretMgmtDriftIntel.getLatestSecretMgmtDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ secretMgmtDrift: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/dep-mgr-security-drift?tenantSlug=&repositoryFullName=
//
// Returns the latest Dependency Manager Security Configuration Drift scan for
// a repository. Spec WS-103. API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/dep-mgr-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.depMgrSecurityDriftIntel.getLatestDepMgrSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ depMgrSecurityDrift: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

// ---------------------------------------------------------------------------
// GET /api/repository/ai-ml-security-drift?tenantSlug=&repositoryFullName=
//
// Returns the latest AI/ML Dependency Security Drift scan for a repository.
// Spec WS-101 (§3.11.2 Layer 6). API-key-guarded.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/repository/ai-ml-security-drift',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const tenantSlug         = searchParams.get('tenantSlug') ?? ''
    const repositoryFullName = searchParams.get('repositoryFullName') ?? ''

    if (!tenantSlug || !repositoryFullName) {
      return new Response(
        JSON.stringify({ error: 'tenantSlug and repositoryFullName are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    }

    const data = await ctx.runQuery(
      api.aiMlSecurityDriftIntel.getLatestAiMlSecurityDriftBySlug,
      { tenantSlug, repositoryFullName },
    )

    return new Response(JSON.stringify({ aiMlSecurityDrift: data ?? null }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    })
  }),
})

export default http
