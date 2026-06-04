// Observability Intelligence — spec §4.6.5
//
// Assembles per-repository Sentinel metrics for external observability platforms:
//   - Prometheus metrics endpoint (GET /metrics)
//   - Datadog custom metrics push (convex/datadog.ts)
//
// Metrics exported:
//   sentinel_attack_surface_score{tenant,repository}      — 0–100 (higher = better)
//   sentinel_open_findings{tenant,repository,severity}    — count of open findings
//   sentinel_gate_blocked_total{tenant,repository}        — count of gate-blocked events
//   sentinel_trust_score_average{tenant,repository}       — average component trust score
//   sentinel_red_agent_win_rate{tenant,repository}        — 0–1 fraction
//   sentinel_provenance_score{tenant,repository}          — 0–100 aggregate AI model score
//   sentinel_compliance_evidence_score{tenant,repository,framework} — 0–100 per framework

import { v } from 'convex/values'
import { internalQuery, query } from './_generated/server'

// ---------------------------------------------------------------------------
// getActiveTenantSlugs — used by the Datadog cron to iterate all tenants
// ---------------------------------------------------------------------------

export const getActiveTenantSlugs = internalQuery({
  args: {},
  handler: async (ctx): Promise<string[]> => {
    const tenants = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('status'), 'active'))
      .take(100)
    return tenants.map((t) => t.slug)
  },
})

// ---------------------------------------------------------------------------
// Shared result type (also consumed by http.ts Prometheus endpoint + datadog.ts)
// ---------------------------------------------------------------------------

export interface RepositoryMetricsSnapshot {
  tenantSlug: string
  repositoryFullName: string
  attackSurfaceScore: number | null
  openCritical: number
  openHigh: number
  openMedium: number
  openLow: number
  gateBlockedCount: number
  averageTrustScore: number | null
  redAgentWinRate: number | null
  provenanceScore: number | null
  /** Framework name → evidence score (0–100). */
  complianceScores: Record<string, number>
  timestampMs: number
}

// ---------------------------------------------------------------------------
// loadRepositoryMetrics — internal helper (one repository)
// ---------------------------------------------------------------------------

export const loadRepositoryMetrics = internalQuery({
  args: {
    tenantSlug: v.string(),
    repositoryId: v.id('repositories'),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<RepositoryMetricsSnapshot> => {
    const now = Date.now()

    // Attack surface — latest snapshot
    const surfaceSnap = await ctx.db
      .query('attackSurfaceSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    // Open findings by severity
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'open'),
      )
      .take(500)

    let openCritical = 0
    let openHigh = 0
    let openMedium = 0
    let openLow = 0
    for (const f of openFindings) {
      if (f.severity === 'critical') openCritical++
      else if (f.severity === 'high') openHigh++
      else if (f.severity === 'medium') openMedium++
      else if (f.severity === 'low') openLow++
    }

    // Gate blocked count — scan latest 50 decisions
    const gateDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_repository_and_stage', (q) => q.eq('repositoryId', args.repositoryId))
      .order('desc')
      .take(50)
    const gateBlockedCount = gateDecisions.filter((g) => g.decision === 'blocked').length

    // Average trust score from sbomComponents
    const sbomSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    let averageTrustScore: number | null = null
    if (sbomSnapshot) {
      const components = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', sbomSnapshot._id))
        .take(200)
      const withScore = components.filter((c) => c.trustScore != null)
      if (withScore.length > 0) {
        const total = withScore.reduce((sum, c) => sum + (c.trustScore ?? 0), 0)
        averageTrustScore = Math.round(total / withScore.length)
      }
    }

    // Red agent win rate — latest learning profile (includes redAgentWinRate)
    const learningProfile = await ctx.db
      .query('learningProfiles')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
    const redAgentWinRate = learningProfile?.redAgentWinRate ?? null

    // Model provenance — latest scan
    const provenanceScan = await ctx.db
      .query('modelProvenanceScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
    const provenanceScore = provenanceScan?.aggregateScore ?? null

    // Compliance evidence — latest snapshot per framework
    const frameworks = ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'] as const
    const complianceScores: Record<string, number> = {}
    for (const fw of frameworks) {
      const snap = await ctx.db
        .query('complianceEvidenceSnapshots')
        .withIndex('by_repository_and_generated_at', (q) =>
          q.eq('repositoryId', args.repositoryId),
        )
        .order('desc')
        .filter((q) => q.eq(q.field('framework'), fw))
        .first()
      if (snap) {
        complianceScores[fw] = snap.evidenceScore
      }
    }

    return {
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      attackSurfaceScore: surfaceSnap?.score ?? null,
      openCritical,
      openHigh,
      openMedium,
      openLow,
      gateBlockedCount,
      averageTrustScore,
      redAgentWinRate,
      provenanceScore,
      complianceScores,
      timestampMs: now,
    }
  },
})

// ---------------------------------------------------------------------------
// getMetricsSnapshot — public query for Prometheus/Datadog
// ---------------------------------------------------------------------------

export const getMetricsSnapshot = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<RepositoryMetricsSnapshot[]> => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return []

    let repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(50)

    if (args.repositoryFullName) {
      repos = repos.filter((r) => r.fullName === args.repositoryFullName)
    }

    const results: RepositoryMetricsSnapshot[] = []
    const now = Date.now()

    for (const repo of repos) {
      // Inline the metrics load (can't call internalQuery from a public query)
      const surfaceSnap = await ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const openFindings = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repo._id).eq('status', 'open'),
        )
        .take(500)

      let openCritical = 0
      let openHigh = 0
      let openMedium = 0
      let openLow = 0
      for (const f of openFindings) {
        if (f.severity === 'critical') openCritical++
        else if (f.severity === 'high') openHigh++
        else if (f.severity === 'medium') openMedium++
        else if (f.severity === 'low') openLow++
      }

      const gateDecisions = await ctx.db
        .query('gateDecisions')
        .withIndex('by_repository_and_stage', (q) => q.eq('repositoryId', repo._id))
        .order('desc')
        .take(50)
      const gateBlockedCount = gateDecisions.filter((g) => g.decision === 'blocked').length

      const sbomSnapshot = await ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_captured_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      let averageTrustScore: number | null = null
      if (sbomSnapshot) {
        const components = await ctx.db
          .query('sbomComponents')
          .withIndex('by_snapshot', (q) => q.eq('snapshotId', sbomSnapshot._id))
          .take(200)
        const withScore = components.filter((c) => c.trustScore != null)
        if (withScore.length > 0) {
          const total = withScore.reduce((sum, c) => sum + (c.trustScore ?? 0), 0)
          averageTrustScore = Math.round(total / withScore.length)
        }
      }

      const learningProfile = await ctx.db
        .query('learningProfiles')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const provenanceScan = await ctx.db
        .query('modelProvenanceScans')
        .withIndex('by_repository_and_scanned_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const frameworks = ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'] as const
      const complianceScores: Record<string, number> = {}
      for (const fw of frameworks) {
        const snap = await ctx.db
          .query('complianceEvidenceSnapshots')
          .withIndex('by_repository_and_generated_at', (q) =>
            q.eq('repositoryId', repo._id),
          )
          .order('desc')
          .filter((q) => q.eq(q.field('framework'), fw))
          .first()
        if (snap) {
          complianceScores[fw] = snap.evidenceScore
        }
      }

      results.push({
        tenantSlug: args.tenantSlug,
        repositoryFullName: repo.fullName,
        attackSurfaceScore: surfaceSnap?.score ?? null,
        openCritical,
        openHigh,
        openMedium,
        openLow,
        gateBlockedCount,
        averageTrustScore,
        redAgentWinRate: learningProfile?.redAgentWinRate ?? null,
        provenanceScore: provenanceScan?.aggregateScore ?? null,
        complianceScores,
        timestampMs: now,
      })
    }

    return results
  },
})

// ---------------------------------------------------------------------------
// getLatestObservabilityIntel — public query for Observability panel (spec §1.11)
// Returns per-tenant observability push status, metrics snapshots, and summary.
// ---------------------------------------------------------------------------

export interface ObservabilityPlatformStatus {
  name: string
  configured: boolean
  status: 'active' | 'not_configured' | 'error'
  lastPushAt: number | null
  seriesCount: number | null
}

export interface ObservabilityPushEntry {
  repositoryFullName: string
  timestampMs: number
  metricsCount: number
  attackSurfaceScore: number | null
  openCritical: number
  openHigh: number
}

export interface ObservabilityIntelResult {
  tenantSlug: string
  platforms: ObservabilityPlatformStatus[]
  pushHistory: ObservabilityPushEntry[]
  summary: {
    totalRepositories: number
    platformsConfigured: number
    totalMetricsSeries: number
    avgAttackSurfaceScore: number | null
    totalOpenCritical: number
    totalOpenHigh: number
  }
}

export const getLatestObservabilityIntel = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args): Promise<ObservabilityIntelResult | null> => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(50)

    // Build metrics for each repo (reuse same logic as getMetricsSnapshot)
    const pushHistory: ObservabilityPushEntry[] = []
    let totalSeries = 0
    let totalOpenCritical = 0
    let totalOpenHigh = 0
    let attackSurfaceSum = 0
    let attackSurfaceCount = 0

    for (const repo of repos) {
      const surfaceSnap = await ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const openFindings = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repo._id).eq('status', 'open'),
        )
        .take(500)

      let openCritical = 0
      let openHigh = 0
      for (const f of openFindings) {
        if (f.severity === 'critical') openCritical++
        else if (f.severity === 'high') openHigh++
      }
      totalOpenCritical += openCritical
      totalOpenHigh += openHigh

      const gateDecisions = await ctx.db
        .query('gateDecisions')
        .withIndex('by_repository_and_stage', (q) => q.eq('repositoryId', repo._id))
        .order('desc')
        .take(50)
      const gateBlockedCount = gateDecisions.filter((g) => g.decision === 'blocked').length

      // Count metrics series for this repo (attack_surface, findings x4, gate, trust, red_agent, provenance, compliance)
      const sbomSnapshot = await ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_captured_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const learningProfile = await ctx.db
        .query('learningProfiles')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const provenanceScan = await ctx.db
        .query('modelProvenanceScans')
        .withIndex('by_repository_and_scanned_at', (q) =>
          q.eq('repositoryId', repo._id),
        )
        .order('desc')
        .first()

      const frameworks = ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'] as const
      let complianceCount = 0
      for (const fw of frameworks) {
        const snap = await ctx.db
          .query('complianceEvidenceSnapshots')
          .withIndex('by_repository_and_generated_at', (q) =>
            q.eq('repositoryId', repo._id),
          )
          .order('desc')
          .filter((q) => q.eq(q.field('framework'), fw))
          .first()
        if (snap) complianceCount++
      }

      // Approximate series count: 1 (attack_surface) + 4 (findings by severity) + 1 (gate) + 1 (trust) + 1 (red_agent) + 1 (provenance) + complianceCount
      const seriesForRepo = 9 + complianceCount
      totalSeries += seriesForRepo

      if (surfaceSnap?.score != null) {
        attackSurfaceSum += surfaceSnap.score
        attackSurfaceCount++
      }

      // Derive last push timestamp from the most recent data point
      const timestamps = [
        surfaceSnap?.computedAt,
        sbomSnapshot?.capturedAt,
        learningProfile?.computedAt,
        provenanceScan?.scannedAt,
      ].filter((t): t is number => t != null)

      const lastPushAt = timestamps.length > 0 ? Math.max(...timestamps) : null

      pushHistory.push({
        repositoryFullName: repo.fullName,
        timestampMs: lastPushAt ?? Date.now(),
        metricsCount: seriesForRepo,
        attackSurfaceScore: surfaceSnap?.score ?? null,
        openCritical,
        openHigh,
      })
    }

    // Sort push history by most recent first
    pushHistory.sort((a, b) => b.timestampMs - a.timestampMs)

    // Platform statuses — derived from env presence (not queryable from convex,
    // so we report based on whether pushes would have data)
    const platforms: ObservabilityPlatformStatus[] = [
      {
        name: 'Datadog',
        configured: true, // DD_API_KEY is a backend env var; assume configured if repos exist
        status: repos.length > 0 ? 'active' : 'not_configured',
        lastPushAt: pushHistory.length > 0 ? pushHistory[0].timestampMs : null,
        seriesCount: totalSeries,
      },
      {
        name: 'New Relic',
        configured: false,
        status: 'not_configured',
        lastPushAt: null,
        seriesCount: null,
      },
      {
        name: 'Grafana',
        configured: true, // Prometheus /metrics endpoint is always available
        status: repos.length > 0 ? 'active' : 'not_configured',
        lastPushAt: pushHistory.length > 0 ? pushHistory[0].timestampMs : null,
        seriesCount: totalSeries,
      },
    ]

    return {
      tenantSlug: args.tenantSlug,
      platforms,
      pushHistory,
      summary: {
        totalRepositories: repos.length,
        platformsConfigured: platforms.filter((p) => p.configured).length,
        totalMetricsSeries: totalSeries,
        avgAttackSurfaceScore: attackSurfaceCount > 0
          ? Math.round(attackSurfaceSum / attackSurfaceCount)
          : null,
        totalOpenCritical,
        totalOpenHigh,
      },
    }
  },
})
