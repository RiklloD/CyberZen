import { httpRouter } from 'convex/server'
import { api, internal } from './_generated/api'
import { httpAction } from './_generated/server'

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
// GET /api/sbom/export?snapshotId=<id>
// Returns a CycloneDX 1.5 JSON BOM for the requested snapshot.
// Content-Type is set to the official CycloneDX media type so tooling
// (Dependency Track, FOSSA, etc.) can consume the response directly.
// ---------------------------------------------------------------------------

http.route({
  path: '/api/sbom/export',
  method: 'GET',
  handler: httpAction(async (ctx, request) => {
    const authError = requireApiKey(request)
    if (authError) return authError

    const { searchParams } = new URL(request.url)
    const snapshotId = searchParams.get('snapshotId')

    if (!snapshotId) {
      return jsonResponse({ error: 'Missing required query parameter: snapshotId' }, 400)
    }

    // Convex IDs are opaque strings — pass as-is; Convex will validate the type
    // biome-ignore lint/suspicious/noExplicitAny: runtime Id cast required for httpAction ctx
    const bom = await ctx.runQuery(api.sbom.exportSnapshot, {
      snapshotId: snapshotId as any,
    })

    if (!bom) {
      return jsonResponse({ error: 'Snapshot not found.' }, 404)
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
    const validStatuses = ['open', 'pr_opened', 'merged', 'resolved', 'accepted_risk']
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

export default http
