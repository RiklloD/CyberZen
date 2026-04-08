import { httpRouter } from 'convex/server'
import { internal } from './_generated/api'
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

export default http
