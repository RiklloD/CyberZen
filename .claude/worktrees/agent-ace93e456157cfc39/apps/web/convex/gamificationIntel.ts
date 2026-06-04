// WS-28 — Gamification Layer (spec §3.7.4): Convex entrypoints.
//
//   refreshGamification                 — internalMutation: loads attack surface
//       snapshots + PR proposals for a tenant, runs computeGamification, inserts
//       a new snapshot, prunes to 20 rows per tenant.
//
//   refreshGamificationForTenant        — public mutation: dashboard / cron trigger.
//
//   getLatestGamification               — public query: latest snapshot for a
//       tenant (resolved via tenantSlug).
//
//   recordPrMergedBy                    — public mutation: called by GitHub
//       webhook on pull_request:closed+merged to populate mergedBy on a prProposal.
//
//   getGamificationHistory              — public query: last N snapshots (lean,
//       leaderboards stripped) for trend sparklines.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  computeGamification,
  type PrProposalInput,
  type RepositorySnapshotInput,
} from './lib/gamification'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Retain at most this many snapshots per tenant. */
const MAX_SNAPSHOTS_PER_TENANT = 20

/** Default sprint window used by the cron-triggered refresh. */
const DEFAULT_WINDOW_DAYS = 14

// ---------------------------------------------------------------------------
// refreshGamification (internal)
// ---------------------------------------------------------------------------

export const refreshGamification = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    windowDays: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const windowDays = args.windowDays ?? DEFAULT_WINDOW_DAYS

    // ── Load all repositories for the tenant ─────────────────────────────────
    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', args.tenantId))
      .collect()

    const repoIds = new Set(repos.map((r) => r._id))

    // ── Load attack surface snapshots (up to 50 per repo) ───────────────────
    // We need a wide enough lookback to capture both the "current" (in-window)
    // and "previous" (baseline) snapshot for each repository.  windowDays×2
    // covers both sides of the comparison window.
    const lookbackMs = windowDays * 2 * 24 * 60 * 60 * 1000
    const lookbackCutoff = Date.now() - lookbackMs

    const snapshots: RepositorySnapshotInput[] = []
    for (const repo of repos) {
      const repoSnaps = await ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repo._id).gte('computedAt', lookbackCutoff),
        )
        .order('desc')
        .take(50)

      for (const snap of repoSnaps) {
        snapshots.push({
          repositoryId: snap.repositoryId,
          repositoryName: repo.fullName,
          score: snap.score,
          trend: snap.trend,
          computedAt: snap.computedAt,
        })
      }
    }

    // ── Load PR proposals for the tenant (merged within 2× window) ──────────
    const prDocs = await ctx.db
      .query('prProposals')
      .withIndex('by_tenant_and_created_at', (q) =>
        q.eq('tenantId', args.tenantId).gte('createdAt', lookbackCutoff),
      )
      .take(500)

    const prProposals: PrProposalInput[] = prDocs
      .filter((p) => repoIds.has(p.repositoryId))
      .map((p) => ({
        repositoryId: p.repositoryId,
        status: p.status,
        mergedAt: p.mergedAt ?? null,
        mergedBy: (p as { mergedBy?: string }).mergedBy ?? null,
        createdAt: p.createdAt,
      }))

    // ── Compute ──────────────────────────────────────────────────────────────
    const result = computeGamification(snapshots, prProposals, windowDays, Date.now())

    // ── Persist ──────────────────────────────────────────────────────────────
    await ctx.db.insert('gamificationSnapshots', {
      tenantId: args.tenantId,
      windowDays: result.windowDays,
      repositoryLeaderboard: result.repositoryLeaderboard,
      engineerLeaderboard: result.engineerLeaderboard,
      mostImprovedRepository: result.mostImprovedRepository,
      totalScoreDelta: result.totalScoreDelta,
      totalPrsMerged: result.totalPrsMerged,
      summary: result.summary,
      computedAt: result.computedAt,
    })

    // ── Prune old rows ────────────────────────────────────────────────────────
    const allRows = await ctx.db
      .query('gamificationSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', args.tenantId))
      .order('desc')
      .collect()

    if (allRows.length > MAX_SNAPSHOTS_PER_TENANT) {
      const toDelete = allRows.slice(MAX_SNAPSHOTS_PER_TENANT)
      await Promise.all(toDelete.map((row) => ctx.db.delete(row._id)))
    }
  },
})

// ---------------------------------------------------------------------------
// refreshGamificationForTenant (public)
// ---------------------------------------------------------------------------

export const refreshGamificationForTenant = mutation({
  args: {
    tenantSlug: v.string(),
    windowDays: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    await ctx.scheduler.runAfter(0, internal.gamificationIntel.refreshGamification, {
      tenantId: tenant._id,
      windowDays: args.windowDays,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestGamification (public query)
// ---------------------------------------------------------------------------

export const getLatestGamification = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    return ctx.db
      .query('gamificationSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getGamificationHistory (public query)
// ---------------------------------------------------------------------------

/**
 * Return the last N snapshots for a tenant, with leaderboard arrays stripped
 * for a lightweight sparkline payload.
 */
export const getGamificationHistory = query({
  args: { tenantSlug: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 10, 30)
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return []

    const rows = await ctx.db
      .query('gamificationSnapshots')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      windowDays: r.windowDays,
      totalScoreDelta: r.totalScoreDelta,
      totalPrsMerged: r.totalPrsMerged,
      computedAt: r.computedAt,
      summary: r.summary,
    }))
  },
})

// ---------------------------------------------------------------------------
// refreshAllTenantsGamification (internal — zero-arg cron target)
// ---------------------------------------------------------------------------

/**
 * Fans out refreshGamification across every active tenant.
 * Each per-tenant refresh runs as an independent scheduled mutation so
 * isolated failures and retries don't block other tenants.
 */
export const refreshAllTenantsGamification = internalMutation({
  args: {},
  handler: async (ctx) => {
    const tenants = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('status'), 'active'))
      .take(200)

    await Promise.all(
      tenants.map((tenant) =>
        ctx.scheduler.runAfter(0, internal.gamificationIntel.refreshGamification, {
          tenantId: tenant._id,
          windowDays: DEFAULT_WINDOW_DAYS,
        }),
      ),
    )
  },
})

// ---------------------------------------------------------------------------
// recordPrMergedBy (public mutation)
// ---------------------------------------------------------------------------

/**
 * Called by the GitHub webhook handler when a `pull_request` event with
 * `action: "closed"` and `merged: true` arrives.  Records the merger's login
 * on the corresponding prProposal row so the engineer leaderboard has data.
 *
 * Matches by prNumber + repositoryId.  Safe to call even if no matching
 * proposal exists (no-op).
 */
export const recordPrMergedBy = mutation({
  args: {
    repositoryId: v.id('repositories'),
    prNumber: v.number(),
    mergedBy: v.string(),
    mergedAt: v.number(),
  },
  handler: async (ctx, args) => {
    // Find the proposal by prNumber inside this repository
    const proposals = await ctx.db
      .query('prProposals')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .collect()

    const match = proposals.find((p) => p.prNumber === args.prNumber)
    if (!match) return // no proposal for this PR — safe no-op

    await ctx.db.patch(match._id, {
      mergedBy: args.mergedBy,
      mergedAt: args.mergedAt,
      status: 'merged',
    })
  },
})
