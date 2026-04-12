// Trust Score Intelligence — Convex entrypoints.
//
// Computes real per-component trust scores using static signals (CVE count,
// typosquat risk, version stability) and fires outbound webhook events when:
//
//   trust_score.degraded    — a package's score drops ≥ DEGRADED_DELTA_THRESHOLD
//                             points compared to the previous SBOM snapshot
//   trust_score.compromised — a package's score newly falls below
//                             COMPROMISED_SCORE_THRESHOLD (was ≥ threshold before)
//
// This completes spec §7.2 webhook coverage: 11/11 event types are now wired.

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { computeComponentTrustScore } from './lib/componentTrustScore'
import { aggregateTrustScore } from './lib/trustScore'
import { normalizePackageName } from './lib/breachMatching'

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/** A drop of this many points (or more) from the previous snapshot triggers
 *  a trust_score.degraded webhook. Chosen so that minor natural variation
 *  (±3–5 pts) doesn't flood customer endpoints. */
const DEGRADED_DELTA_THRESHOLD = 10

/** A component with an absolute trust score below this value is considered
 *  "compromised" — too risky to trust in the build pipeline. The threshold
 *  matches the untrustedComponentCount boundary in trustScore.ts (score < 40)
 *  but is set slightly lower to reserve the compromised label for the worst
 *  cases (typosquats + CVEs, or very old pre-release packages). */
const COMPROMISED_SCORE_THRESHOLD = 30

// ---------------------------------------------------------------------------
// refreshComponentTrustScores — internalMutation
// ---------------------------------------------------------------------------

/**
 * Compute and persist real trust scores for every component in a snapshot.
 *
 * Called fire-and-forget from:
 *   - sbom.ingestRepositoryInventory — immediately after snapshot creation
 *   - events.ingestCanonicalDisclosure — after marking affected components
 *     as hasKnownVulnerabilities=true (so scores reflect the new CVE signal)
 *
 * The mutation:
 *   1. Batch-loads all breach disclosures for this repository (one query).
 *   2. Loads the previous snapshot's component scores for delta comparison.
 *   3. Computes each component's score using the pure library.
 *   4. Patches sbomComponents.trustScore (and hasKnownVulnerabilities when
 *      the CVE count implies a vulnerability not yet patched by breach intake).
 *   5. Fire-and-forgets trust_score.degraded / trust_score.compromised
 *      webhook dispatches where thresholds are crossed.
 */
export const refreshComponentTrustScores = internalMutation({
  args: { snapshotId: v.id('sbomSnapshots') },
  returns: v.object({
    updatedCount: v.number(),
    degradedCount: v.number(),
    compromisedCount: v.number(),
  }),
  handler: async (ctx, args) => {
    // ── 1. Load snapshot context ──────────────────────────────────────────
    const snapshot = await ctx.db.get(args.snapshotId)
    if (!snapshot) return { updatedCount: 0, degradedCount: 0, compromisedCount: 0 }

    const repository = await ctx.db.get(snapshot.repositoryId)
    if (!repository) return { updatedCount: 0, degradedCount: 0, compromisedCount: 0 }

    const tenant = await ctx.db.get(repository.tenantId)
    if (!tenant) return { updatedCount: 0, degradedCount: 0, compromisedCount: 0 }

    // ── 2. Load this snapshot's components ───────────────────────────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .collect()

    if (components.length === 0) {
      return { updatedCount: 0, degradedCount: 0, compromisedCount: 0 }
    }

    // ── 3. Build previous score map for delta comparison ─────────────────
    // Load the 2 most-recent snapshots; the one that is not this snapshot is
    // the previous one. Order desc gives us newest-first.
    const recentSnapshots = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(2)

    const prevSnapshot = recentSnapshots.find((s) => s._id !== snapshot._id) ?? null

    const prevScoreMap = new Map<string, number>()
    if (prevSnapshot) {
      const prevComponents = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', prevSnapshot._id))
        .collect()
      for (const c of prevComponents) {
        prevScoreMap.set(c.normalizedName, c.trustScore)
      }
    }

    // ── 4. Batch-load breach disclosures for this repository ──────────────
    // One query scoped to this repository's disclosure history.
    // Only "matched" disclosures are counted — unmatched records exist for
    // packages that appeared in a *different* repository's advisory but were
    // looked up against this one.
    const disclosures = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_repository_and_source_ref', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .take(500)

    const cveCounts = new Map<string, number>()
    for (const d of disclosures) {
      if (d.matchStatus === 'matched') {
        const key = normalizePackageName(d.packageName)
        cveCounts.set(key, (cveCounts.get(key) ?? 0) + 1)
      }
    }

    // ── 5. Score, patch, and dispatch webhooks ────────────────────────────
    let updatedCount = 0
    let degradedCount = 0
    let compromisedCount = 0

    for (const component of components) {
      const cveCount = cveCounts.get(component.normalizedName) ?? 0
      const isVulnerable = component.hasKnownVulnerabilities || cveCount > 0

      const result = computeComponentTrustScore({
        name: component.name,
        version: component.version,
        ecosystem: component.ecosystem,
        isDirect: component.isDirect,
        hasKnownVulnerabilities: isVulnerable,
        cveCount,
      })

      const previousScore = prevScoreMap.get(component.normalizedName) ?? null
      const newScore = result.score

      await ctx.db.patch('sbomComponents', component._id, {
        trustScore: newScore,
        // Propagate CVE knowledge back to the component row even if the
        // breach-intake path hasn't patched it yet.
        hasKnownVulnerabilities: isVulnerable,
      })
      updatedCount++

      // ── trust_score.degraded: score dropped ≥ threshold vs previous ───
      if (previousScore !== null && newScore <= previousScore - DEGRADED_DELTA_THRESHOLD) {
        degradedCount++
        try {
          await ctx.scheduler.runAfter(0, internal.webhooks.dispatchWebhookEvent, {
            tenantId: tenant._id,
            tenantSlug: tenant.slug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'trust_score.degraded' as const,
              data: {
                packageName: component.name,
                ecosystem: component.ecosystem,
                previousScore,
                newScore,
                delta: newScore - previousScore,
              },
            },
          })
        } catch (e) {
          console.error('[trust-score] degraded dispatch failed for', component.name, e)
        }
      }

      // ── trust_score.compromised: newly below absolute threshold ────────
      // Only fires when the component *crosses* below the threshold — not on
      // every ingestion where it is already in the compromised zone. This
      // prevents webhook spam for persistently low-scored packages.
      const wasAboveThreshold =
        previousScore === null || previousScore >= COMPROMISED_SCORE_THRESHOLD
      if (newScore < COMPROMISED_SCORE_THRESHOLD && wasAboveThreshold) {
        compromisedCount++
        try {
          await ctx.scheduler.runAfter(0, internal.webhooks.dispatchWebhookEvent, {
            tenantId: tenant._id,
            tenantSlug: tenant.slug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'trust_score.compromised' as const,
              data: {
                packageName: component.name,
                ecosystem: component.ecosystem,
                score: newScore,
                threshold: COMPROMISED_SCORE_THRESHOLD,
              },
            },
          })
        } catch (e) {
          console.error('[trust-score] compromised dispatch failed for', component.name, e)
        }
      }
    }

    return { updatedCount, degradedCount, compromisedCount }
  },
})

// ---------------------------------------------------------------------------
// getRepositoryTrustScoreSummary — public query
// ---------------------------------------------------------------------------

/**
 * Returns an aggregated trust score summary for the latest SBOM snapshot of
 * a repository, including the per-tier component distribution.
 *
 * Used by the dashboard and the GET /api/trust-scores/detail endpoint to show
 * the overall health of a repository's dependency trust posture.
 */
export const getRepositoryTrustScoreSummary = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      repositoryScore: v.number(),
      directDepScore: v.number(),
      transitiveDepScore: v.number(),
      untrustedCount: v.number(),
      vulnerableCount: v.number(),
      totalComponents: v.number(),
      breakdown: v.array(
        v.object({
          tier: v.string(),
          label: v.string(),
          count: v.number(),
        }),
      ),
    }),
  ),
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

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
    if (!latestSnapshot) return null

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .collect()

    const aggregate = aggregateTrustScore(
      components.map((c) => ({
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        isDirect: c.isDirect,
        trustScore: c.trustScore,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
      })),
    )

    // Score tier distribution (4 buckets matching the threshold constants)
    const breakdown = [
      {
        tier: 'trusted',
        label: 'Trusted (80–100)',
        count: components.filter((c) => c.trustScore >= 80).length,
      },
      {
        tier: 'acceptable',
        label: 'Acceptable (60–79)',
        count: components.filter((c) => c.trustScore >= 60 && c.trustScore < 80).length,
      },
      {
        tier: 'at_risk',
        label: 'At Risk (30–59)',
        count: components.filter(
          (c) => c.trustScore >= COMPROMISED_SCORE_THRESHOLD && c.trustScore < 60,
        ).length,
      },
      {
        tier: 'compromised',
        label: `Compromised (<${COMPROMISED_SCORE_THRESHOLD})`,
        count: components.filter((c) => c.trustScore < COMPROMISED_SCORE_THRESHOLD).length,
      },
    ]

    return {
      repositoryScore: aggregate.repositoryScore,
      directDepScore: aggregate.directDepScore,
      transitiveDepScore: aggregate.transitiveDepScore,
      untrustedCount: aggregate.untrustedComponentCount,
      vulnerableCount: aggregate.vulnerableComponentCount,
      totalComponents: components.length,
      breakdown,
    }
  },
})
