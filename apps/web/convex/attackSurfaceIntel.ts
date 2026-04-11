// WS-14 Phase 3 — Attack Surface Reduction Agent (spec 3.7): Convex entrypoints.
//
//   refreshAttackSurface              — internalMutation: loads findings + latest
//       memory snapshot, runs computeAttackSurface, inserts a new snapshot.
//
//   refreshAttackSurfaceForRepository — public mutation: dashboard trigger.
//
//   getAttackSurfaceDashboard         — public query: latest full snapshot + up to
//       20 lean history entries (score/trend/computedAt) for the sparkline.
//       A single subscription replaces separate snapshot + history queries.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  computeAttackSurface,
  type FindingForSurfaceInput,
} from './lib/attackSurface'
import {
  EMPTY_MEMORY_RECORD,
  type RepositoryMemoryRecord,
} from './lib/memoryController'

// ---------------------------------------------------------------------------
// refreshAttackSurface (internal)
// ---------------------------------------------------------------------------

export const refreshAttackSurface = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // All four reads are independent within the same transaction snapshot —
    // run them in parallel to cut wall-clock latency.
    const [findingDocs, memoryDoc, latestSbom, previousSnapshot] =
      await Promise.all([
        ctx.db
          .query('findings')
          .withIndex('by_repository_and_status', (q) =>
            q.eq('repositoryId', args.repositoryId),
          )
          .take(200),
        ctx.db
          .query('agentMemorySnapshots')
          .withIndex('by_repository_and_computed_at', (q) =>
            q.eq('repositoryId', args.repositoryId),
          )
          .order('desc')
          .first(),
        ctx.db
          .query('sbomSnapshots')
          .withIndex('by_repository_and_captured_at', (q) =>
            q.eq('repositoryId', args.repositoryId),
          )
          .order('desc')
          .first(),
        ctx.db
          .query('attackSurfaceSnapshots')
          .withIndex('by_repository_and_computed_at', (q) =>
            q.eq('repositoryId', args.repositoryId),
          )
          .order('desc')
          .first(),
      ])

    const findings: FindingForSurfaceInput[] = findingDocs.map((f) => ({
      severity: f.severity,
      status: f.status,
      validationStatus: f.validationStatus,
    }))

    const repositoryMemory: RepositoryMemoryRecord =
      memoryDoc ?? EMPTY_MEMORY_RECORD

    const result = computeAttackSurface({
      findings,
      repositoryMemory,
      hasActiveSbom: latestSbom !== null,
      previousScore: previousSnapshot?.score ?? null,
      repositoryName: repository.name,
    })

    await ctx.db.insert('attackSurfaceSnapshots', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      score: result.score,
      remediationRate: result.remediationRate,
      openCriticalCount: result.openCriticalCount,
      openHighCount: result.openHighCount,
      activeMitigationCount: result.activeMitigationCount,
      totalFindings: result.totalFindings,
      resolvedFindings: result.resolvedFindings,
      trend: result.trend,
      summary: result.summary,
      computedAt: Date.now(),
    })

    // Fire-and-forget outbound webhook when attack surface is degrading.
    if (result.trend === 'degrading' && previousSnapshot !== null) {
      try {
        const tenant = await ctx.db.get(repository.tenantId)
        if (tenant) {
          await ctx.scheduler.runAfter(
            0,
            internal.webhooks.dispatchWebhookEvent,
            {
              tenantId: repository.tenantId,
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              eventPayload: {
                event: 'attack_surface.increased' as const,
                data: {
                  previousScore: previousSnapshot.score,
                  newScore: result.score,
                  delta: result.score - previousSnapshot.score,
                  trend: result.trend,
                },
              },
            },
          )
        }
      } catch (e) {
        console.error('[webhooks] attack_surface.increased dispatch failed', e)
      }
    }

    return result
  },
})

// ---------------------------------------------------------------------------
// refreshAttackSurfaceForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const refreshAttackSurfaceForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new Error(`Tenant ${args.tenantSlug} not found`)
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new Error(`Repository ${args.repositoryFullName} not found`)
    }

    await ctx.scheduler.runAfter(
      0,
      internal.attackSurfaceIntel.refreshAttackSurface,
      { repositoryId: repository._id },
    )

    return { scheduled: true, repositoryId: repository._id }
  },
})

// ---------------------------------------------------------------------------
// getAttackSurfaceDashboard (public query)
//
// Returns the latest full snapshot (all fields, for the detail row) and up to
// 20 lean history entries (score/trend/computedAt, oldest-first for sparkline).
// One subscription covers both pieces the panel needs.
// ---------------------------------------------------------------------------

export const getAttackSurfaceDashboard = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return null

    // Take the 20 most recent snapshots descending; the first is the latest.
    const snapshots = await ctx.db
      .query('attackSurfaceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(20)

    if (snapshots.length === 0) return null

    const latest = snapshots[0]

    // Reverse for oldest-first sparkline rendering (unavoidable — Convex index
    // must scan desc to get the newest 20, then we flip for the chart).
    const history = snapshots
      .slice()
      .reverse()
      .map((s) => ({ score: s.score, trend: s.trend, computedAt: s.computedAt }))

    return { snapshot: latest, history }
  },
})
