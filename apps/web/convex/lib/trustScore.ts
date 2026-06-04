// Trust score aggregation — pure, no Convex dependencies.
// Individual component trust scores (0–100) are stored in sbomComponents.
// This module rolls them up into a repository-level aggregate.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TrustScoreInput = {
  name: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  trustScore: number
  hasKnownVulnerabilities: boolean
}

export type TrustScoreLayerBreakdown = {
  layer: string
  count: number
  averageScore: number
}

export type TrustScoreAggregate = {
  /** Composite score for the whole repository — 0 (untrusted) to 100 (fully trusted). */
  repositoryScore: number
  /** Average trust score of direct (first-degree) dependencies only. */
  directDepScore: number
  /** Average trust score of transitive dependencies only. */
  transitiveDepScore: number
  /** Components with trustScore < 40 (considered critically untrusted). */
  untrustedComponentCount: number
  /** Components with known CVEs regardless of trust score. */
  vulnerableComponentCount: number
  /** Per-layer breakdown for UI drill-down. */
  breakdown: TrustScoreLayerBreakdown[]
}

/** Inputs for the weighted-average repository score (§4.4). */
export type RepositoryScoreInput = {
  /** Health score 0–100 from repositoryHealthIntel. */
  health: number
  /** Supply-chain posture score 0–100. */
  posture: number
  /** Number of critical findings. */
  criticalFindings: number
  /** Number of high findings. */
  highFindings: number
  /** Number of medium findings. */
  mediumFindings: number
  /** Fraction of SLA breaches (0–1). */
  slaBreachRate: number
  /** Learning confidence 0–100 from the learning/intelligence pipeline. */
  learningConfidence: number
}

export type RepositoryScoreResult = {
  /** Composite repository score, rounded to int, clamped 0–100. */
  score: number
  /** Breakdown of each factor for UI display. */
  breakdown: {
    health: number
    posture: number
    findingDensityScore: number
    slaScore: number
    learningConfidence: number
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mean(scores: number[]): number {
  if (scores.length === 0) return 100
  return Math.round(scores.reduce((acc, s) => acc + s, 0) / scores.length)
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/**
 * Aggregate individual component trust scores into a single repository score.
 *
 * The `repositoryScore` is the key operator-facing metric. It must balance
 * security signal against practical usability — a single bad transitive dep
 * should not tank the score as severely as a bad direct dependency.
 *
 * Four valid strategies (trade-offs documented below):
 *
 *   A. Simple mean
 *        mean(all component scores)
 *        Pro: simple, predictable. Con: ignores the direct/transitive distinction.
 *
 *   B. Direct-weighted mean   ← suggested default
 *        (2 × directDepScore + transitiveDepScore) / 3
 *        Pro: rewards healthy direct dependency choices; noise from transitive
 *        deps is dampened. Con: may undervalue a severely compromised transitive chain.
 *
 *   C. Weakest-link (min of direct deps)
 *        min(directDeps.map(c => c.trustScore))
 *        Pro: maximally conservative — one bad direct dep tanks the score.
 *        Con: too sensitive for large dependency trees; single outlier dominates.
 *
 *   D. Vulnerability-penalized mean
 *        mean(all) × (1 − 0.4 × (vulnerableCount / total))
 *        Pro: explicit penalty for the presence of CVE-tagged components.
 *        Con: two parameters to tune (penalty factor, vulnerable ratio).
 *
 * TODO — implement the repositoryScore line below with your chosen strategy.
 * The pre-computed `directDepScore`, `transitiveDepScore`, `directDeps`,
 * `transitiveDeps`, and `vulnerableComponents` are available to use directly.
 *
 * ✅ COMPLETED (§4.4) — Strategy B chosen; also added standalone `repositoryScore`.
 */
export function aggregateTrustScore(components: TrustScoreInput[]): TrustScoreAggregate {
  if (components.length === 0) {
    return {
      repositoryScore: 100,
      directDepScore: 100,
      transitiveDepScore: 100,
      untrustedComponentCount: 0,
      vulnerableComponentCount: 0,
      breakdown: [],
    }
  }

  const directDeps = components.filter((c) => c.isDirect)
  const transitiveDeps = components.filter((c) => !c.isDirect)
  const vulnerableComponents = components.filter((c) => c.hasKnownVulnerabilities)
  const untrustedComponents = components.filter((c) => c.trustScore < 40)

  const directDepScore = mean(directDeps.map((c) => c.trustScore))
  const transitiveDepScore = mean(transitiveDeps.map((c) => c.trustScore))

  // Strategy B: Direct-weighted mean (2 × direct + 1 × transitive) / 3
  // Direct deps are weighted twice because they are explicit operator choices;
  // transitive noise is dampened but still contributes to the score.
  // When one tier is absent the formula degrades gracefully to the present tier.
  const repositoryScore = (() => {
    if (directDeps.length === 0 && transitiveDeps.length === 0) return 100
    if (directDeps.length === 0) return transitiveDepScore
    if (transitiveDeps.length === 0) return directDepScore
    return Math.round((2 * directDepScore + transitiveDepScore) / 3)
  })()

  const layerNames = [...new Set(components.map((c) => c.layer))]
  const breakdown: TrustScoreLayerBreakdown[] = layerNames.map((layer) => {
    const layerComponents = components.filter((c) => c.layer === layer)
    return {
      layer,
      count: layerComponents.length,
      averageScore: mean(layerComponents.map((c) => c.trustScore)),
    }
  })

  return {
    repositoryScore,
    directDepScore,
    transitiveDepScore,
    untrustedComponentCount: untrustedComponents.length,
    vulnerableComponentCount: vulnerableComponents.length,
    breakdown,
  }
}

// ---------------------------------------------------------------------------
// repositoryScore — §4.4 weighted-average composite score
// ---------------------------------------------------------------------------

/**
 * Compute a 0–100 repository-level score from five weighted factors:
 *
 *   health              × 0.25
 *   posture             × 0.20
 *   findingDensityScore × 0.20   = 100 − min(critical×5 + high×2 + medium, 100)
 *   slaScore            × 0.20   = 100 − min(slaBreachRate × 100, 100)
 *   learningConfidence  × 0.15
 *
 * Result is rounded to the nearest integer and clamped to [0, 100].
 */
export function repositoryScore(input: RepositoryScoreInput): RepositoryScoreResult {
  const findingDensityScore = 100 - Math.min(
    input.criticalFindings * 5 + input.highFindings * 2 + input.mediumFindings,
    100,
  )

  const slaScore = 100 - Math.min(input.slaBreachRate * 100, 100)

  const raw =
    input.health * 0.25 +
    input.posture * 0.20 +
    findingDensityScore * 0.20 +
    slaScore * 0.20 +
    input.learningConfidence * 0.15

  const score = Math.max(0, Math.min(100, Math.round(raw)))

  return {
    score,
    breakdown: {
      health: input.health,
      posture: input.posture,
      findingDensityScore,
      slaScore,
      learningConfidence: input.learningConfidence,
    },
  }
}
