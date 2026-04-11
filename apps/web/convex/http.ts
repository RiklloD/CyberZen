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

export default http
