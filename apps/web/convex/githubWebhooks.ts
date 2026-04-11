"use node";

import { createHmac, timingSafeEqual } from 'node:crypto'
import { v } from 'convex/values'
import { internal } from './_generated/api'
import type { Id } from './_generated/dataModel'
import { internalAction } from './_generated/server'
import {
  collectCommitMessages,
  normalizeGithubPushPayload,
  type GithubPushPayload,
} from './lib/githubWebhooks'

type WebhookRouteResult = {
  status: 'processed' | 'ignored' | 'rejected'
  reason: string
  httpStatus: number
  eventId?: Id<'ingestionEvents'>
  workflowRunId?: Id<'workflowRuns'>
  deduped?: boolean
}

function computeGithubSignature(secret: string, body: string) {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`
}

function isValidGithubSignature(secret: string, body: string, signature: string) {
  const expected = Buffer.from(computeGithubSignature(secret, body))
  const received = Buffer.from(signature)

  if (expected.length !== received.length) {
    return false
  }

  return timingSafeEqual(expected, received)
}

export const verifyAndRouteGithubWebhook = internalAction({
  args: {
    body: v.string(),
    event: v.string(),
    signature: v.string(),
    deliveryId: v.optional(v.string()),
  },
  returns: v.object({
    status: v.union(
      v.literal('processed'),
      v.literal('ignored'),
      v.literal('rejected'),
    ),
    reason: v.string(),
    httpStatus: v.number(),
    eventId: v.optional(v.id('ingestionEvents')),
    workflowRunId: v.optional(v.id('workflowRuns')),
    deduped: v.optional(v.boolean()),
  }),
  handler: async (ctx, args): Promise<WebhookRouteResult> => {
    const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET

    if (!webhookSecret) {
      return {
        status: 'rejected',
        reason: 'GITHUB_WEBHOOK_SECRET is not configured in Convex.',
        httpStatus: 500,
      }
    }

    if (!isValidGithubSignature(webhookSecret, args.body, args.signature)) {
      return {
        status: 'rejected',
        reason: 'GitHub webhook signature verification failed.',
        httpStatus: 401,
      }
    }

    if (args.event !== 'push') {
      return {
        status: 'ignored',
        reason: `GitHub event ${args.event} is not routed yet.`,
        httpStatus: 202,
      }
    }

    let payload: GithubPushPayload
    try {
      payload = JSON.parse(args.body) as GithubPushPayload
    } catch {
      return {
        status: 'rejected',
        reason: 'GitHub webhook body is not valid JSON.',
        httpStatus: 400,
      }
    }

    const normalizedPush = normalizeGithubPushPayload(payload)

    if (normalizedPush.status !== 'processed') {
      return {
        status: normalizedPush.status,
        reason: normalizedPush.reason,
        httpStatus: normalizedPush.status === 'ignored' ? 202 : 400,
      }
    }

    const result: {
      eventId: Id<'ingestionEvents'>
      workflowRunId: Id<'workflowRuns'>
      deduped: boolean
    } = await ctx.runMutation(internal.events.ingestGithubPushFromWebhook, {
      repositoryFullName: normalizedPush.repositoryFullName,
      branch: normalizedPush.branch,
      commitSha: normalizedPush.commitSha,
      changedFiles: normalizedPush.changedFiles,
    })

    // Fire-and-forget prompt injection scan on commit messages.
    // Runs only for new (non-deduped) events so we don't re-scan identical
    // pushes. Failures are logged and swallowed — a scan error must never
    // prevent a successful webhook acknowledgement.
    if (!result.deduped) {
      const commitMessages = collectCommitMessages(payload.commits, payload.head_commit)
      if (commitMessages) {
        try {
          await ctx.runMutation(internal.promptIntelligence.scanContentByRef, {
            repositoryFullName: normalizedPush.repositoryFullName,
            workflowRunId: result.workflowRunId,
            contentRef: 'push_commit_messages',
            content: commitMessages,
          })
        } catch (err) {
          console.warn('[sentinel] prompt injection scan failed for push event:', err)
        }
      }
    }

    return {
      status: 'processed',
      reason: args.deliveryId
        ? `Processed GitHub delivery ${args.deliveryId}.`
        : 'Processed GitHub push delivery.',
      httpStatus: 200,
      eventId: result.eventId,
      workflowRunId: result.workflowRunId,
      deduped: result.deduped,
    }
  },
})
