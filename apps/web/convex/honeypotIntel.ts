// WS-15 Phase 2 — Honeypot Code Auto-Injection (spec 3.9): Convex entrypoints.
//
//   refreshHoneypotPlan              — internalMutation: aggregates blast radius
//       snapshots for the repository, runs computeHoneypotPlan, inserts a
//       honeypotSnapshot.
//
//   refreshHoneypotPlanForRepository — public mutation: dashboard / manual trigger.
//
//   getLatestHoneypotPlan            — public query: latest snapshot or null.

import { ConvexError, v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { computeHoneypotPlan } from './lib/honeypotInjector'

// ---------------------------------------------------------------------------
// refreshHoneypotPlan (internal)
// ---------------------------------------------------------------------------

export const refreshHoneypotPlan = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // Load up to 50 blast radius snapshots for this repository so we can
    // aggregate across all findings.
    const blastSnapshots = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(50)

    // Union of reachable services and data layers across all snapshots.
    const serviceSet = new Set<string>()
    const layerSet = new Set<string>()
    let maxDepth = 0

    for (const snap of blastSnapshots) {
      for (const s of snap.reachableServices) serviceSet.add(s)
      for (const l of snap.exposedDataLayers) layerSet.add(l)
      if (snap.attackPathDepth > maxDepth) maxDepth = snap.attackPathDepth
    }

    // Count open critical findings for this repository.
    const criticalFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'open'),
      )
      .take(200)

    const openCriticalCount = criticalFindings.filter((f) => f.severity === 'critical').length

    const result = computeHoneypotPlan({
      reachableServices: Array.from(serviceSet),
      exposedDataLayers: Array.from(layerSet),
      attackPathDepth: maxDepth,
      openCriticalCount,
    })

    await ctx.db.insert('honeypotSnapshots', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      totalProposals: result.totalProposals,
      endpointCount: result.endpointCount,
      fileCount: result.fileCount,
      databaseFieldCount: result.databaseFieldCount,
      tokenCount: result.tokenCount,
      topAttractiveness: result.topAttractiveness,
      proposals: result.proposals.map((p) => ({
        kind: p.kind,
        path: p.path,
        description: p.description,
        rationale: p.rationale,
        ...(p.targetContext !== undefined ? { targetContext: p.targetContext } : {}),
        attractivenessScore: p.attractivenessScore,
      })),
      summary: result.summary,
      computedAt: Date.now(),
    })

    return result
  },
})

// ---------------------------------------------------------------------------
// refreshHoneypotPlanForRepository (public mutation — dashboard / manual trigger)
// ---------------------------------------------------------------------------

export const refreshHoneypotPlanForRepository = mutation({
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
      internal.honeypotIntel.refreshHoneypotPlan,
      { repositoryId: repository._id },
    )

    return { scheduled: true, repositoryId: repository._id }
  },
})

// ---------------------------------------------------------------------------
// getLatestHoneypotPlan (public query)
// ---------------------------------------------------------------------------

export const getLatestHoneypotPlan = query({
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

    return await ctx.db
      .query('honeypotSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// recordHoneypotTrigger — operator or sensor calls this when a honeypot fires.
//
// A honeypot trigger is treated as a near-certain breach indicator (spec §3.9).
// This mutation records the event and immediately dispatches a
// `honeypot.triggered` webhook so connected SIEMs and incident workflows fire.
//
// POST /api/honeypot/trigger wraps this mutation.
// ---------------------------------------------------------------------------

export const recordHoneypotTrigger = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** The honeypot path or identifier that was accessed. */
    honeypotPath: v.string(),
    /** Human-readable description of what kind of honeypot fired. */
    honeypotKind: v.union(
      v.literal('endpoint'),
      v.literal('database_field'),
      v.literal('file'),
      v.literal('token'),
    ),
    /** Source IP or actor identifier from the sensor. */
    sourceIdentifier: v.optional(v.string()),
    /** Additional metadata from the sensor, free-form. */
    metadata: v.optional(v.string()),
  },
  returns: v.object({
    recorded: v.boolean(),
    webhookScheduled: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new ConvexError('Tenant not found')

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()
    if (!repository) throw new ConvexError('Repository not found')

    let webhookScheduled = false
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.webhooks.dispatchWebhookEvent,
        {
          tenantId: repository.tenantId,
          tenantSlug: tenant.slug,
          repositoryFullName: repository.fullName,
          eventPayload: {
            event: 'honeypot.triggered' as const,
            data: {
              honeypotPath: args.honeypotPath,
              honeypotKind: args.honeypotKind,
              sourceIdentifier: args.sourceIdentifier ?? 'unknown',
              metadata: args.metadata ?? '',
              triggeredAt: Date.now(),
            },
          },
        },
      )
      webhookScheduled = true
    } catch (e) {
      console.error('[webhooks] honeypot.triggered dispatch failed', e)
    }

    return { recorded: true, webhookScheduled }
  },
})
