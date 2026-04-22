// AI/ML Model Supply Chain Intelligence — Convex entrypoints (spec §3.5).
//
// Scans the latest SBOM snapshot for AI/ML framework risks and persists a
// typed `modelSupplyChainScans` row for dashboard display and alerting.
//
// Entrypoints:
//   refreshModelSupplyChain              — internalMutation: pulls latest SBOM
//       components for a repository, runs scanModelSupplyChain, inserts snapshot.
//
//   refreshModelSupplyChainForRepository — public mutation: dashboard/manual trigger.
//
//   getLatestModelScan                   — public query: latest scan for dashboard.
//   getModelScanHistory                  — public query: history for trend sparkline.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { scanModelSupplyChain, type MlComponentInput } from './lib/modelSupplyChain'

// ---------------------------------------------------------------------------
// refreshModelSupplyChain (internal)
// ---------------------------------------------------------------------------

export const refreshModelSupplyChain = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Load the latest SBOM snapshot for this repository
    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    if (!latestSnapshot) {
      // No SBOM yet — nothing to scan
      return null
    }

    // Load the SBOM components for this snapshot
    const sbomComponents = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .take(500)

    const mlInputs: MlComponentInput[] = sbomComponents.map((c) => ({
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
      isDirect: c.isDirect,
      layer: c.layer,
      hasKnownVulnerabilities: c.hasKnownVulnerabilities,
      trustScore: c.trustScore,
    }))

    const scan = scanModelSupplyChain(mlInputs)

    // Persist scan snapshot
    await ctx.db.insert('modelSupplyChainScans', {
      tenantId: latestSnapshot.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: latestSnapshot._id,
      overallRiskScore: scan.overallRiskScore,
      riskLevel: scan.riskLevel,
      mlFrameworkCount: scan.mlFrameworkCount,
      mlFrameworks: scan.mlFrameworks,
      hasPickleRisk: scan.hasPickleRisk,
      hasUnpinnedFramework: scan.hasUnpinnedFramework,
      vulnerableFrameworkCount: scan.vulnerableFrameworkCount,
      flaggedComponentCount: scan.flaggedComponents.length,
      flaggedComponents: scan.flaggedComponents.slice(0, 10).map((c) => ({
        name: c.name,
        version: c.version,
        riskScore: c.riskScore,
        riskLevel: c.riskLevel,
        topSignalKind: c.signals[0]?.kind ?? 'none',
        summary: c.summary.slice(0, 280),
      })),
      summary: scan.summary,
      scannedAt: Date.now(),
    })

    return {
      riskLevel: scan.riskLevel,
      mlFrameworkCount: scan.mlFrameworkCount,
      flaggedCount: scan.flaggedComponents.length,
    }
  },
})

// ---------------------------------------------------------------------------
// refreshModelSupplyChainForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const refreshModelSupplyChainForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Validate the repository exists
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error(`Repository ${args.repositoryId} not found`)

    // Schedule the internal mutation to run immediately
    await ctx.scheduler.runAfter(0, internal.modelSupplyChainIntel.refreshModelSupplyChain, {
      repositoryId: args.repositoryId,
    })

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// getLatestModelScan (public query — dashboard)
// ---------------------------------------------------------------------------

export const getLatestModelScan = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('modelSupplyChainScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getModelScanHistory (public query — sparkline / trend view)
// ---------------------------------------------------------------------------

export const getModelScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 10, 30)

    const rows = await ctx.db
      .query('modelSupplyChainScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      riskLevel: r.riskLevel,
      overallRiskScore: r.overallRiskScore,
      mlFrameworkCount: r.mlFrameworkCount,
      hasPickleRisk: r.hasPickleRisk,
      flaggedComponentCount: r.flaggedComponentCount,
      scannedAt: r.scannedAt,
    }))
  },
})
