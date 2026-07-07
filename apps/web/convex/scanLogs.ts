// ── Live Scan Logs Backend ──────────────────────────────────────────────
//
// Writes structured log entries during a scan. Convex reactivity streams
// these to the dashboard so users can watch a scan progress in real time.
//
// Architecture:
//   runRealScan (action) calls appendScanLog (internal mutation) at each phase
//   Dashboard calls getActiveScans / getScanLogs (queries) — reactive

import { query, internalMutation } from './_generated/server'
import { internal } from './_generated/api'
import { v } from 'convex/values'
import type { Id } from './_generated/dataModel'

const logLevel = v.union(
  v.literal('info'),
  v.literal('success'),
  v.literal('warning'),
  v.literal('error'),
)

// ── Append a single log line (called from runRealScan action) ────────────

export const appendScanLog = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    phase: v.string(),
    level: logLevel,
    message: v.string(),
    detail: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert('scanLogs', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      workflowRunId: args.workflowRunId,
      phase: args.phase,
      level: args.level,
      message: args.message,
      detail: args.detail,
      createdAt: Date.now(),
    })
    return null
  },
})

// ── Batch append (reduces mutation calls when logging many lines) ────────

export const appendScanLogs = internalMutation({
  args: {
    logs: v.array(
      v.object({
        tenantId: v.id('tenants'),
        repositoryId: v.id('repositories'),
        workflowRunId: v.id('workflowRuns'),
        phase: v.string(),
        level: logLevel,
        message: v.string(),
        detail: v.optional(v.string()),
        createdAt: v.number(),
      }),
    ),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    for (const log of args.logs) {
      await ctx.db.insert('scanLogs', log)
    }
    return null
  },
})

// ── Get logs for a specific workflow run (reactive, paginated) ───────────

export const getScanLogs = query({
  args: {
    workflowRunId: v.id('workflowRuns'),
    limit: v.optional(v.number()),
  },
  returns: v.array(
    v.object({
      _id: v.id('scanLogs'),
      phase: v.string(),
      level: logLevel,
      message: v.string(),
      detail: v.optional(v.string()),
      createdAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const limit = args.limit ?? 100
    const logs = await ctx.db
      .query('scanLogs')
      .withIndex('by_workflow_run_and_created_at', (q) =>
        q.eq('workflowRunId', args.workflowRunId),
      )
      .order('desc')
      .take(limit)

    return logs.reverse().map((l) => ({
      _id: l._id,
      phase: l.phase,
      level: l.level,
      message: l.message,
      detail: l.detail,
      createdAt: l.createdAt,
    }))
  },
})

// ── Get all active scans for a tenant ────────────────────────────────────
//
// Returns workflow runs that are queued or running, enriched with repo
// names and the latest log line so the dashboard can show a summary card.

export const getActiveScans = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('workflowRuns'),
      workflowType: v.string(),
      status: v.string(),
      summary: v.string(),
      startedAt: v.number(),
      repositoryId: v.id('repositories'),
      repositoryName: v.string(),
      repositoryFullName: v.string(),
      completedTaskCount: v.number(),
      totalTaskCount: v.number(),
      logCount: v.number(),
      latestLogAt: v.optional(v.number()),
    }),
  ),
  handler: async (ctx: any, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    // Get repos for this tenant (for name resolution)
    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()
    const repoMap = new Map(repos.map((r: any) => [r._id, r]))

    // Get active workflow runs
    const activeRuns = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'running'),
      )
      .collect()

    const queuedRuns = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'queued'),
      )
      .collect()

    const allActive = [...activeRuns, ...queuedRuns]

    const enriched = await Promise.all(
      allActive.map(async (run: any) => {
        const repo = run.repositoryId ? repoMap.get(run.repositoryId) : null

        // Count logs for this run and get the latest timestamp
        const logs = await ctx.db
          .query('scanLogs')
          .withIndex('by_workflow_run_and_created_at', (q) =>
            q.eq('workflowRunId', run._id),
          )
          .order('desc')
          .take(1)

        return {
          _id: run._id,
          workflowType: run.workflowType,
          status: run.status,
          summary: run.summary,
          startedAt: run.startedAt,
          repositoryId: run.repositoryId,
          repositoryName: repo?.name ?? 'Unknown',
          repositoryFullName: repo?.fullName ?? 'Unknown',
          completedTaskCount: run.completedTaskCount,
          totalTaskCount: run.totalTaskCount,
          logCount: 0, // not fetched in detail to keep query light
          latestLogAt: logs[0]?.createdAt,
        }
      }),
    )

    return enriched.sort((a, b) => b.startedAt - a.startedAt)
  },
})

// ── Get recent scans (last N completed/failed, for the dashboard feed) ───

export const getRecentScanActivity = query({
  args: {
    tenantSlug: v.string(),
    limit: v.optional(v.number()),
  },
  returns: v.array(
    v.object({
      workflowRunId: v.id('workflowRuns'),
      repositoryFullName: v.string(),
      workflowType: v.string(),
      status: v.string(),
      phase: v.string(),
      level: logLevel,
      message: v.string(),
      detail: v.optional(v.string()),
      createdAt: v.number(),
    }),
  ),
  handler: async (ctx: any, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q: any) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    const limit = args.limit ?? 30

    const logs = await ctx.db
      .query('scanLogs')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(limit)

    // Resolve repo names
    const repoIds = new Set(logs.map((l: any) => l.repositoryId))
    const repos = await Promise.all(
      Array.from(repoIds).map((id) => ctx.db.get(id as Id<'repositories'>)),
    )
    const repoMap = new Map(
      repos.filter(Boolean).map((r: any) => [r._id, r.fullName]),
    )

    return logs.map((l: any) => ({
      workflowRunId: l.workflowRunId,
      repositoryFullName: repoMap.get(l.repositoryId) ?? 'Unknown',
      workflowType: '',
      status: '',
      phase: l.phase,
      level: l.level,
      message: l.message,
      detail: l.detail,
      createdAt: l.createdAt,
    }))
  },
})
