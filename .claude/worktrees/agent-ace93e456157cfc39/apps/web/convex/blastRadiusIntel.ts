// WS-14 Phase 1 — Blast Radius Causality Graph: Convex entrypoints.
//
//   computeAndStoreBlastRadius — internalMutation: loads finding + SBOM snapshot,
//       runs computeBlastRadius, patches the finding, inserts a blastRadiusSnapshot.
//
//   getBlastRadius — public query: latest blastRadiusSnapshot for a finding (or null).
//
//   blastRadiusSummaryForRepository — public query: aggregate stats across all open
//       findings for a repository (max riskTier, total reachable services, top 3).
//
//   architecturalGraph — public query: full graph of blast radius nodes + edges for
//       all open findings in a repository (spec §7.1 GET /blast-radius/graph).

import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, query } from './_generated/server'
import {
  computeBlastRadius,
  type SbomComponentInput,
} from './lib/blastRadius'

// ---------------------------------------------------------------------------
// computeAndStoreBlastRadius
// ---------------------------------------------------------------------------

export const computeAndStoreBlastRadius = internalMutation({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    // --- load finding ---
    const finding = await ctx.db.get(args.findingId)
    if (!finding) {
      throw new Error(`Finding ${args.findingId} not found`)
    }

    // --- load repository ---
    const repository = await ctx.db.get(finding.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${finding.repositoryId} not found`)
    }

    // --- load latest SBOM snapshot for this repository ---
    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', finding.repositoryId),
      )
      .order('desc')
      .first()

    // --- load SBOM components (all components for the snapshot) ---
    const components: SbomComponentInput[] = latestSnapshot
      ? await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) =>
            q.eq('snapshotId', latestSnapshot._id),
          )
          .collect()
      : []

    // --- resolve exploit availability from linked breach disclosure ---
    let exploitAvailable = false
    if (finding.breachDisclosureId) {
      const disclosure = await ctx.db.get(finding.breachDisclosureId)
      exploitAvailable = disclosure?.exploitAvailable ?? false
    }

    // --- compute blast radius (pure function, no DB) ---
    const result = computeBlastRadius({
      finding: {
        affectedPackages: finding.affectedPackages,
        affectedFiles: finding.affectedFiles,
        severity: finding.severity,
        source: finding.source,
        exploitAvailable,
      },
      components,
      repositoryName: repository.name,
    })

    // --- patch finding with live computed values ---
    await ctx.db.patch('findings', finding._id, {
      businessImpactScore: result.businessImpactScore,
      blastRadiusSummary: result.summary,
    })

    // --- persist structured snapshot ---
    const now = Date.now()
    await ctx.db.insert('blastRadiusSnapshots', {
      findingId: finding._id,
      repositoryId: finding.repositoryId,
      tenantId: finding.tenantId,
      reachableServices: result.reachableServices,
      exposedDataLayers: result.exposedDataLayers,
      directExposureCount: result.directExposureCount,
      transitiveExposureCount: result.transitiveExposureCount,
      attackPathDepth: result.attackPathDepth,
      businessImpactScore: result.businessImpactScore,
      riskTier: result.riskTier,
      summary: result.summary,
      computedAt: now,
    })

    // --- fire-and-forget: compute cloud blast radius in parallel ---
    await ctx.scheduler.runAfter(
      0,
      internal.cloudBlastRadiusIntel.computeAndStoreCloudBlastRadius,
      { repositoryId: finding.repositoryId },
    )

    // --- fire-and-forget: re-evaluate severity escalation now that blast
    //     radius context has changed (new businessImpactScore available) ---
    await ctx.scheduler.runAfter(
      0,
      internal.escalationIntel.checkAndEscalateFinding,
      { findingId: finding._id },
    )

    return result
  },
})

// ---------------------------------------------------------------------------
// getBlastRadius
// ---------------------------------------------------------------------------

export const getBlastRadius = query({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// blastRadiusSummaryForRepository
// ---------------------------------------------------------------------------

const RISK_TIER_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

export const blastRadiusSummaryForRepository = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    // --- resolve tenant + repository ---
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q
          .eq('tenantId', tenant._id)
          .eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return null

    // --- load open findings (bounded to 50 to stay within transaction limits) ---
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'open'),
      )
      .take(50)

    if (openFindings.length === 0) {
      return {
        maxRiskTier: 'low' as const,
        totalReachableServices: [] as string[],
        topFindings: [] as Array<{
          findingId: string
          title: string
          severity: string
          businessImpactScore: number
          riskTier: string
        }>,
      }
    }

    // --- load latest blast radius snapshot for each finding ---
    const snapshots = await Promise.all(
      openFindings.map((f) =>
        ctx.db
          .query('blastRadiusSnapshots')
          .withIndex('by_finding', (q) => q.eq('findingId', f._id))
          .order('desc')
          .first(),
      ),
    )

    // --- aggregate: max risk tier + service union ---
    let maxRiskTier: 'critical' | 'high' | 'medium' | 'low' = 'low'
    const serviceSet = new Set<string>()

    for (const snap of snapshots) {
      if (!snap) continue
      if ((RISK_TIER_ORDER[snap.riskTier] ?? 0) > (RISK_TIER_ORDER[maxRiskTier] ?? 0)) {
        maxRiskTier = snap.riskTier
      }
      for (const svc of snap.reachableServices) {
        serviceSet.add(svc)
      }
    }

    // --- top 3 findings by businessImpactScore ---
    const topFindings = openFindings
      .map((f, i) => ({ finding: f, snap: snapshots[i] }))
      .filter((x): x is { finding: (typeof openFindings)[number]; snap: NonNullable<(typeof snapshots)[number]> } =>
        x.snap !== null && x.snap !== undefined,
      )
      .sort(
        (a, b) =>
          (b.snap.businessImpactScore ?? 0) - (a.snap.businessImpactScore ?? 0),
      )
      .slice(0, 3)
      .map(({ finding, snap }) => ({
        findingId: finding._id as string,
        title: finding.title,
        severity: finding.severity,
        businessImpactScore: snap.businessImpactScore,
        riskTier: snap.riskTier,
      }))

    return {
      maxRiskTier,
      totalReachableServices: [...serviceSet],
      topFindings,
    }
  },
})

// ---------------------------------------------------------------------------
// architecturalGraph — full blast radius graph for a repository.
//
// Returns graph nodes (services / data layers) and edges (finding→service links)
// suitable for rendering a dependency visualization or feeding into a graph DB.
// Bounded to the 50 most recent blast radius snapshots across all findings.
// ---------------------------------------------------------------------------

export const architecturalGraph = query({
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

    // Load the most recent blast radius snapshot per finding (bounded to 50)
    const snapshots = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(50)

    // Build node set (services + data layers) and edge list (finding → node)
    const nodeMap = new Map<
      string,
      { id: string; kind: 'service' | 'data_layer'; label: string; maxRiskTier: string }
    >()

    const edges: Array<{
      findingId: string
      target: string
      riskTier: string
      businessImpactScore: number
    }> = []

    // Deduplicate: keep only the latest snapshot per findingId
    const latestByFinding = new Map<string, (typeof snapshots)[number]>()
    for (const snap of snapshots) {
      const key = snap.findingId as string
      if (!latestByFinding.has(key)) {
        latestByFinding.set(key, snap)
      }
    }

    for (const snap of latestByFinding.values()) {
      for (const svc of snap.reachableServices) {
        const id = `service:${svc}`
        const existing = nodeMap.get(id)
        if (
          !existing ||
          (RISK_TIER_ORDER[snap.riskTier] ?? 0) > (RISK_TIER_ORDER[existing.maxRiskTier] ?? 0)
        ) {
          nodeMap.set(id, { id, kind: 'service', label: svc, maxRiskTier: snap.riskTier })
        }
        edges.push({
          findingId: snap.findingId as string,
          target: id,
          riskTier: snap.riskTier,
          businessImpactScore: snap.businessImpactScore,
        })
      }
      for (const layer of snap.exposedDataLayers) {
        const id = `data_layer:${layer}`
        const existing = nodeMap.get(id)
        if (
          !existing ||
          (RISK_TIER_ORDER[snap.riskTier] ?? 0) > (RISK_TIER_ORDER[existing.maxRiskTier] ?? 0)
        ) {
          nodeMap.set(id, { id, kind: 'data_layer', label: layer, maxRiskTier: snap.riskTier })
        }
        edges.push({
          findingId: snap.findingId as string,
          target: id,
          riskTier: snap.riskTier,
          businessImpactScore: snap.businessImpactScore,
        })
      }
    }

    return {
      repositoryFullName: repository.fullName,
      computedAt: Date.now(),
      nodeCount: nodeMap.size,
      edgeCount: edges.length,
      findingCount: latestByFinding.size,
      nodes: [...nodeMap.values()],
      edges,
    }
  },
})
