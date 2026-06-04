import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import type { Id } from './_generated/dataModel'

// ─── Internal Mutations ───────────────────────────────────────────────────────

export const recordJobStart = internalMutation({
  args: {
    jobName: v.string(),
    tenantId: v.optional(v.id('tenants')),
  },
  handler: async (ctx, args): Promise<Id<'cronJobRuns'>> => {
    return await ctx.db.insert('cronJobRuns', {
      jobName: args.jobName,
      tenantId: args.tenantId,
      startedAt: Date.now(),
      status: 'running',
    })
  },
})

export const recordJobEnd = internalMutation({
  args: {
    runId: v.id('cronJobRuns'),
    status: v.union(v.literal('success'), v.literal('failed')),
    error: v.optional(v.string()),
    recordsProcessed: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const run = await ctx.db.get(args.runId)
    if (!run) return

    const completedAt = Date.now()
    const duration = completedAt - run.startedAt

    await ctx.db.patch(args.runId, {
      completedAt,
      status: args.status,
      duration,
      error: args.error,
      recordsProcessed: args.recordsProcessed,
    })

    if (args.status === 'failed') {
      await checkConsecutiveFailures(ctx, args.runId, run.jobName)
    }
  },
})

async function checkConsecutiveFailures(
  ctx: { db: any },
  _runId: Id<'cronJobRuns'>,
  jobName: string,
) {
  const recent = await ctx.db
    .query('cronJobRuns')
    .withIndex('by_job_name_and_started_at', (q: any) => q.eq('jobName', jobName))
    .order('desc')
    .take(3)

  const allFailed =
    recent.length === 3 && recent.every((r: any) => r.status === 'failed')

  if (allFailed) {
    console.error(
      `[jobMonitoring] ALERT: job "${jobName}" has failed 3 consecutive times. ` +
        `Last error: ${recent[0]?.error ?? 'unknown'}`,
    )
  }
}

// ─── Public Queries ───────────────────────────────────────────────────────────

export const getJobHealth = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, _args) => {
    const allRuns = await ctx.db
      .query('cronJobRuns')
      .withIndex('by_status_and_started_at', (q) => q.eq('status', 'success'))
      .order('desc')
      .take(500)

    const failedRuns = await ctx.db
      .query('cronJobRuns')
      .withIndex('by_status_and_started_at', (q) => q.eq('status', 'failed'))
      .order('desc')
      .take(500)

    const runningRuns = await ctx.db
      .query('cronJobRuns')
      .withIndex('by_status_and_started_at', (q) => q.eq('status', 'running'))
      .order('desc')
      .take(100)

    const combined = [...allRuns, ...failedRuns, ...runningRuns]

    const byJob: Record<
      string,
      {
        jobName: string
        lastRun: number | null
        lastStatus: string | null
        lastDuration: number | null
        lastError: string | null
        successCount: number
        failureCount: number
        avgDuration: number | null
        consecutiveFailures: number
        alertCount: number
      }
    > = {}

    for (const run of combined) {
      if (!byJob[run.jobName]) {
        byJob[run.jobName] = {
          jobName: run.jobName,
          lastRun: null,
          lastStatus: null,
          lastDuration: null,
          lastError: null,
          successCount: 0,
          failureCount: 0,
          avgDuration: null,
          consecutiveFailures: 0,
          alertCount: 0,
        }
      }
      const entry = byJob[run.jobName]
      if (run.status === 'success') entry.successCount++
      if (run.status === 'failed') entry.failureCount++

      if (entry.lastRun === null || run.startedAt > entry.lastRun) {
        entry.lastRun = run.startedAt
        entry.lastStatus = run.status
        entry.lastDuration = run.duration ?? null
        entry.lastError = run.error ?? null
      }
    }

    for (const entry of Object.values(byJob)) {
      const total = entry.successCount + entry.failureCount
      if (total > 0) {
        const durations = combined
          .filter((r) => r.jobName === entry.jobName && r.duration != null)
          .map((r) => r.duration as number)
        if (durations.length > 0) {
          entry.avgDuration = Math.round(
            durations.reduce((a, b) => a + b, 0) / durations.length,
          )
        }
      }

      // Count consecutive failures from most recent
      const jobRuns = combined
        .filter((r) => r.jobName === entry.jobName)
        .sort((a, b) => b.startedAt - a.startedAt)

      let consecutive = 0
      for (const run of jobRuns) {
        if (run.status === 'failed') consecutive++
        else break
      }
      entry.consecutiveFailures = consecutive
      entry.alertCount = consecutive >= 3 ? 1 : 0
    }

    return Object.values(byJob).sort((a, b) => (b.lastRun ?? 0) - (a.lastRun ?? 0))
  },
})

export const getJobHistory = query({
  args: {
    tenantSlug: v.string(),
    jobName: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = args.limit ?? 20
    return ctx.db
      .query('cronJobRuns')
      .withIndex('by_job_name_and_started_at', (q) => q.eq('jobName', args.jobName))
      .order('desc')
      .take(limit)
  },
})

export const listJobNames = query({
  args: {},
  handler: async (ctx) => {
    const runs = await ctx.db.query('cronJobRuns').take(200)
    const names = [...new Set(runs.map((r) => r.jobName))]
    return names.sort()
  },
})
