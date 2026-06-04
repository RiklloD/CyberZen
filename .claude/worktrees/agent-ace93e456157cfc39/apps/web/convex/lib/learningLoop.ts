/**
 * Memory and Learning Loop — pure computation library (spec §3.13)
 *
 * Analyses historical findings, red/blue rounds, and attack surface snapshots
 * to produce a per-repository learning profile. The profile exposes:
 *
 *   • Per-vuln-class confidence multipliers (boost recurring patterns, suppress
 *     confirmed false-positive patterns)
 *   • Successful exploit paths retained from red-agent wins
 *   • Attack surface trend over time (improving / stable / degrading / unknown)
 *   • A learning-maturity score (adaptedConfidenceScore) that grows as more
 *     confirmed findings and adversarial rounds accumulate
 *
 * All logic is pure and synchronous — no Convex runtime required.
 */

// ─── Input types ──────────────────────────────────────────────────────────────

export type FindingHistoryEntry = {
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  /** 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' */
  status: string
  /** 'pending' | 'validated' | 'likely_exploitable' | 'unexploitable' | 'skipped' | 'dismissed' */
  validationStatus: string
}

export type RedBlueRoundEntry = {
  roundOutcome: 'red_wins' | 'blue_wins' | 'draw'
  /** Exploit chains from the round (each is a freeform description string). */
  exploitChains: string[]
}

export type AttackSurfacePoint = {
  /** 0–100 attack surface score; higher = better (less exposure). */
  score: number
}

export type LearningLoopInput = {
  findingHistory: FindingHistoryEntry[]
  redBlueRounds: RedBlueRoundEntry[]
  /** Ordered oldest-first; used for trend detection. */
  attackSurfaceHistory: AttackSurfacePoint[]
}

// ─── Output types ─────────────────────────────────────────────────────────────

export type VulnClassLearning = {
  vulnClass: string
  /** All findings for this class (confirmed + FP + pending). */
  totalCount: number
  /** Findings classified as validated or likely_exploitable. */
  confirmedCount: number
  /** Findings classified as unexploitable. */
  falsePositiveCount: number
  /** falsePositiveCount / totalCount, or 0 when totalCount = 0. */
  falsePositiveRate: number
  /** true when confirmedCount >= 2 (patterns that keep recurring). */
  isRecurring: boolean
  /** true when falsePositiveRate > 0.6 (pattern is mostly noise for this repo). */
  isSuppressed: boolean
  /**
   * 0.5–2.0 scaling factor for future confidence in this class:
   *   - Suppressed  → 0.5 (deprioritise)
   *   - Recurring   → min(2.0, 1.0 + confirmedCount × 0.25)
   *   - Otherwise   → 1.0
   */
  confidenceMultiplier: number
}

export type AttackSurfaceTrend = 'improving' | 'stable' | 'degrading' | 'unknown'

export type LearningProfileResult = {
  /** All detected patterns, sorted: recurring first, then by confirmedCount desc. */
  vulnClassPatterns: VulnClassLearning[]
  /** Number of vuln classes classified as recurring. */
  recurringCount: number
  /** Number of vuln classes classified as suppressed (high FP rate). */
  suppressedCount: number
  /**
   * Unique exploit chains drawn from rounds where red agent won.
   * Retained so the system can re-attempt them on every new build.
   */
  successfulExploitPaths: string[]
  attackSurfaceTrend: AttackSurfaceTrend
  /**
   * 0–100 learning-maturity score. Grows as confirmed findings and
   * adversarial rounds accumulate. Reflects how well the system has
   * calibrated its model for this specific repository.
   */
  adaptedConfidenceScore: number
  /** Fraction of red/blue rounds won by the red agent (0–1). */
  redAgentWinRate: number
  totalFindingsAnalyzed: number
  totalRoundsAnalyzed: number
  summary: string
}

// ─── Internal constants ───────────────────────────────────────────────────────

/** FP rate threshold above which a vuln class is considered suppressed. */
const FP_SUPPRESSION_THRESHOLD = 0.6

/** Minimum confirmed findings for a class to be considered recurring. */
const RECURRING_MIN_CONFIRMED = 2

/**
 * Minimum number of attack surface data points needed to calculate a trend.
 * Fewer than this → 'unknown'.
 */
const MIN_TREND_POINTS = 3

/** Difference in average score between halves that triggers a non-stable trend. */
const TREND_DELTA_THRESHOLD = 5

/** Points added to adaptedConfidenceScore per confirmed finding. */
const SCORE_PER_CONFIRMED = 5

/** Points added to adaptedConfidenceScore per completed round. */
const SCORE_PER_ROUND = 3

// ─── Normalisation ────────────────────────────────────────────────────────────

function normaliseVulnClass(raw: string): string {
  return raw.toLowerCase().replaceAll('-', '_').replaceAll(' ', '_')
}

// ─── Trend detection ─────────────────────────────────────────────────────────

function detectTrend(history: AttackSurfacePoint[]): AttackSurfaceTrend {
  if (history.length < MIN_TREND_POINTS) return 'unknown'

  const mid = Math.floor(history.length / 2)
  const firstHalf = history.slice(0, mid)
  const secondHalf = history.slice(history.length - mid)

  const avg = (pts: AttackSurfacePoint[]) =>
    pts.reduce((s, p) => s + p.score, 0) / pts.length

  const firstAvg = avg(firstHalf)
  const secondAvg = avg(secondHalf)

  if (secondAvg - firstAvg > TREND_DELTA_THRESHOLD) return 'improving'
  if (firstAvg - secondAvg > TREND_DELTA_THRESHOLD) return 'degrading'
  return 'stable'
}

// ─── Main computation ─────────────────────────────────────────────────────────

/**
 * Produces the per-repository learning profile from historical data.
 *
 * Designed to be run periodically (e.g., after each ingestion cycle) so the
 * profile stays current as new findings and red/blue rounds arrive.
 */
export function computeLearningProfile(input: LearningLoopInput): LearningProfileResult {
  // ── 1. Group findings by normalised vuln class ───────────────────────────
  type ClassBucket = {
    confirmed: number
    falsePositives: number
    total: number
  }
  const buckets = new Map<string, ClassBucket>()

  for (const f of input.findingHistory) {
    const key = normaliseVulnClass(f.vulnClass)
    const bucket = buckets.get(key) ?? { confirmed: 0, falsePositives: 0, total: 0 }
    bucket.total += 1
    if (f.validationStatus === 'validated' || f.validationStatus === 'likely_exploitable') {
      bucket.confirmed += 1
    } else if (f.validationStatus === 'unexploitable') {
      bucket.falsePositives += 1
    }
    buckets.set(key, bucket)
  }

  // ── 2. Compute per-class learning signals ────────────────────────────────
  const vulnClassPatterns: VulnClassLearning[] = []

  for (const [vulnClass, { confirmed, falsePositives, total }] of buckets) {
    const fpRate = total > 0 ? falsePositives / total : 0
    const isRecurring = confirmed >= RECURRING_MIN_CONFIRMED
    const isSuppressed = fpRate > FP_SUPPRESSION_THRESHOLD

    let multiplier: number
    if (isSuppressed) {
      multiplier = 0.5
    } else if (isRecurring) {
      multiplier = Math.min(2.0, 1.0 + confirmed * 0.25)
    } else {
      multiplier = 1.0
    }

    vulnClassPatterns.push({
      vulnClass,
      totalCount: total,
      confirmedCount: confirmed,
      falsePositiveCount: falsePositives,
      falsePositiveRate: Math.round(fpRate * 100) / 100,
      isRecurring,
      isSuppressed,
      confidenceMultiplier: Math.round(multiplier * 100) / 100,
    })
  }

  // Sort: recurring first, then by confirmedCount desc, then alphabetically.
  vulnClassPatterns.sort((a, b) => {
    if (a.isRecurring !== b.isRecurring) return a.isRecurring ? -1 : 1
    if (b.confirmedCount !== a.confirmedCount) return b.confirmedCount - a.confirmedCount
    return a.vulnClass.localeCompare(b.vulnClass)
  })

  const recurringCount = vulnClassPatterns.filter((p) => p.isRecurring).length
  const suppressedCount = vulnClassPatterns.filter((p) => p.isSuppressed).length

  // ── 3. Collect successful exploit paths from red-agent wins ──────────────
  const exploitPathSet = new Set<string>()
  let redWins = 0

  for (const round of input.redBlueRounds) {
    if (round.roundOutcome === 'red_wins') {
      redWins += 1
      for (const chain of round.exploitChains) {
        if (chain.trim().length > 0) exploitPathSet.add(chain.trim())
      }
    }
  }

  const successfulExploitPaths = Array.from(exploitPathSet)
  const totalRoundsAnalyzed = input.redBlueRounds.length
  const redAgentWinRate =
    totalRoundsAnalyzed > 0 ? Math.round((redWins / totalRoundsAnalyzed) * 100) / 100 : 0

  // ── 4. Attack surface trend ──────────────────────────────────────────────
  const attackSurfaceTrend = detectTrend(input.attackSurfaceHistory)

  // ── 5. Learning maturity score ───────────────────────────────────────────
  const totalConfirmed = vulnClassPatterns.reduce((s, p) => s + p.confirmedCount, 0)
  const adaptedConfidenceScore = Math.min(
    100,
    totalConfirmed * SCORE_PER_CONFIRMED + totalRoundsAnalyzed * SCORE_PER_ROUND,
  )

  // ── 6. Summary ──────────────────────────────────────────────────────────
  const totalFindingsAnalyzed = input.findingHistory.length

  const trendLabel: Record<AttackSurfaceTrend, string> = {
    improving: 'improving',
    stable: 'stable',
    degrading: 'degrading',
    unknown: 'insufficient history',
  }

  const summary =
    `Analysed ${totalFindingsAnalyzed} finding${totalFindingsAnalyzed !== 1 ? 's' : ''} across ` +
    `${vulnClassPatterns.length} vuln class${vulnClassPatterns.length !== 1 ? 'es' : ''}` +
    (recurringCount > 0 ? ` (${recurringCount} recurring` : '') +
    (suppressedCount > 0 && recurringCount > 0 ? `, ${suppressedCount} suppressed)` : '') +
    (suppressedCount > 0 && recurringCount === 0 ? ` (${suppressedCount} suppressed)` : '') +
    (recurringCount > 0 && suppressedCount === 0 ? ')' : '') +
    `. ` +
    `${totalRoundsAnalyzed} adversarial round${totalRoundsAnalyzed !== 1 ? 's' : ''} run` +
    (totalRoundsAnalyzed > 0 ? ` (${Math.round(redAgentWinRate * 100)}% red-agent wins)` : '') +
    `. Attack surface trend: ${trendLabel[attackSurfaceTrend]}.` +
    ` Learning maturity: ${adaptedConfidenceScore}/100.`

  return {
    vulnClassPatterns,
    recurringCount,
    suppressedCount,
    successfulExploitPaths,
    attackSurfaceTrend,
    adaptedConfidenceScore,
    redAgentWinRate,
    totalFindingsAnalyzed,
    totalRoundsAnalyzed,
    summary,
  }
}
