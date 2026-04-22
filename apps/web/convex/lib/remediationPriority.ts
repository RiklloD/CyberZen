// Automated Remediation Priority — pure library with no Convex imports.
//
// Computes a composite 0–100 priority score for each open finding by
// combining five independent signals:
//
//   Signal                    Max weight  Notes
//   ─────────────────────     ──────────  ──────────────────────────────────────────
//   SLA breach                       40  Highest weight — contractual obligation
//   SLA approaching                  25  Give time to act before breach
//   Exploit code publicly available  20  Threat is imminent, not theoretical
//   Validation confirmed/likely      15  Sandbox verified exploitability
//   Blast radius (3 tiers)           15  Scope of impact if exploited
//   Severity (3 tiers)               10  Base signal, lowest weight (already in SLA)
//
// Priority tiers derived from score:
//   P0 (immediate)  ≥ 70
//   P1 (this week)  ≥ 45
//   P2 (backlog)    ≥ 20
//   P3 (low)        < 20

// ─── Types ─────────────────────────────────────────────────────────────────────

export type RemediationSlaStatus =
  | 'within_sla'
  | 'approaching_sla'
  | 'breached_sla'
  | 'not_applicable'

export type RemediationValidationStatus =
  | 'pending'
  | 'validated'
  | 'likely_exploitable'
  | 'unexploitable'
  | 'dismissed'

export type RemediationSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export type RemediationCandidate = {
  /** Opaque finding identifier (Convex Id stringified or a test stub). */
  findingId: string
  title: string
  severity: RemediationSeverity
  slaStatus: RemediationSlaStatus
  /**
   * businessImpactScore from the most recent blastRadiusSnapshot (0–100).
   * Pass -1 when no blast radius snapshot is available yet.
   */
  blastRadiusScore: number
  exploitAvailable: boolean
  validationStatus: RemediationValidationStatus
  /** Unix ms timestamp when the finding was created. */
  createdAt: number
  repositoryName: string
  affectedPackages: string[]
}

export type PrioritizedFinding = RemediationCandidate & {
  /** Composite score, clamped 0–100. */
  priorityScore: number
  /** Derived tier from score. */
  priorityTier: 'p0' | 'p1' | 'p2' | 'p3'
  /** Human-readable reasons that drove the score upward. */
  priorityRationale: string[]
}

// ─── Weight constants ──────────────────────────────────────────────────────────

const W_SLA_BREACHED = 40
const W_SLA_APPROACHING = 25
const W_EXPLOIT = 20
const W_VALIDATION = 15
const W_BLAST_HIGH = 15 // blastRadiusScore ≥ 80
const W_BLAST_MED = 10 // blastRadiusScore ≥ 50
const W_BLAST_LOW = 5 // blastRadiusScore ≥ 20
const W_SEVERITY_CRITICAL = 10
const W_SEVERITY_HIGH = 6
const W_SEVERITY_MEDIUM = 2

// ─── Priority tier boundaries ─────────────────────────────────────────────────

const TIER_P0_THRESHOLD = 70
const TIER_P1_THRESHOLD = 45
const TIER_P2_THRESHOLD = 20

// ─── Core scoring ─────────────────────────────────────────────────────────────

/**
 * Computes the composite remediation priority score and rationale for a
 * single finding candidate.
 *
 * Each signal is additive; the total is clamped to 100.  Rationale strings
 * are ordered from highest-weight signal to lowest, giving operators a quick
 * explanation of why a finding ranked where it did.
 */
export function computeRemediationScore(c: RemediationCandidate): {
  score: number
  rationale: string[]
} {
  let score = 0
  const rationale: string[] = []

  // ── SLA signal ────────────────────────────────────────────────────────────
  if (c.slaStatus === 'breached_sla') {
    score += W_SLA_BREACHED
    rationale.push('SLA deadline has been breached')
  } else if (c.slaStatus === 'approaching_sla') {
    score += W_SLA_APPROACHING
    rationale.push('SLA deadline is approaching (≥75% of window elapsed)')
  }

  // ── Exploit availability ──────────────────────────────────────────────────
  if (c.exploitAvailable) {
    score += W_EXPLOIT
    rationale.push('Exploit code is publicly available')
  }

  // ── Validation signal ─────────────────────────────────────────────────────
  if (c.validationStatus === 'validated') {
    score += W_VALIDATION
    rationale.push('Exploit confirmed by sandbox validation')
  } else if (c.validationStatus === 'likely_exploitable') {
    score += W_VALIDATION
    rationale.push('Likely exploitable per sandbox analysis')
  }

  // ── Blast radius signal ───────────────────────────────────────────────────
  if (c.blastRadiusScore >= 80) {
    score += W_BLAST_HIGH
    rationale.push(`Very high blast radius (impact score ${c.blastRadiusScore})`)
  } else if (c.blastRadiusScore >= 50) {
    score += W_BLAST_MED
    rationale.push(`High blast radius (impact score ${c.blastRadiusScore})`)
  } else if (c.blastRadiusScore >= 20) {
    score += W_BLAST_LOW
    rationale.push(`Moderate blast radius (impact score ${c.blastRadiusScore})`)
  }
  // blastRadiusScore === -1 means unknown — no contribution either way

  // ── Severity signal ───────────────────────────────────────────────────────
  if (c.severity === 'critical') {
    score += W_SEVERITY_CRITICAL
    rationale.push('Critical severity')
  } else if (c.severity === 'high') {
    score += W_SEVERITY_HIGH
    rationale.push('High severity')
  } else if (c.severity === 'medium') {
    score += W_SEVERITY_MEDIUM
    // Medium severity contributes to score but is omitted from rationale to
    // keep the list focused on high-signal reasons.
  }

  return { score: Math.min(100, score), rationale }
}

// ─── Tier classification ───────────────────────────────────────────────────────

/**
 * Maps a composite score to a human-actionable priority tier.
 *
 *   P0 (≥70): Immediate action — SLA breached or exploit-confirmed critical
 *   P1 (≥45): This sprint — SLA approaching or exploit-available high
 *   P2 (≥20): Next sprint — blast radius or approaching deadline
 *   P3 (< 20): Backlog — low blast radius, no immediate threat signals
 */
export function classifyPriorityTier(
  score: number,
): 'p0' | 'p1' | 'p2' | 'p3' {
  if (score >= TIER_P0_THRESHOLD) return 'p0'
  if (score >= TIER_P1_THRESHOLD) return 'p1'
  if (score >= TIER_P2_THRESHOLD) return 'p2'
  return 'p3'
}

// ─── Queue assembly ────────────────────────────────────────────────────────────

/**
 * Scores all candidates and returns them sorted by priority (highest first).
 *
 * Tie-breaking: candidates with the same score are ordered by `createdAt`
 * ascending — oldest open findings surface first as they represent more
 * technical debt.
 */
export function prioritizeRemediationQueue(
  candidates: RemediationCandidate[],
): PrioritizedFinding[] {
  const scored = candidates.map((c) => {
    const { score, rationale } = computeRemediationScore(c)
    return {
      ...c,
      priorityScore: score,
      priorityTier: classifyPriorityTier(score),
      priorityRationale: rationale,
    }
  })

  return scored.sort((a, b) => {
    if (b.priorityScore !== a.priorityScore) {
      return b.priorityScore - a.priorityScore
    }
    // Older findings first on tie
    return a.createdAt - b.createdAt
  })
}

// ─── Summary helpers ────────────────────────────────────────────────────────────

export type RemediationQueueSummary = {
  totalCandidates: number
  p0Count: number
  p1Count: number
  p2Count: number
  p3Count: number
  /** Average priority score across all candidates; 0 when queue is empty. */
  averageScore: number
}

/**
 * Produces a summary of the prioritized queue suitable for dashboard pills.
 */
export function computeQueueSummary(
  queue: PrioritizedFinding[],
): RemediationQueueSummary {
  if (queue.length === 0) {
    return {
      totalCandidates: 0,
      p0Count: 0,
      p1Count: 0,
      p2Count: 0,
      p3Count: 0,
      averageScore: 0,
    }
  }

  const p0Count = queue.filter((f) => f.priorityTier === 'p0').length
  const p1Count = queue.filter((f) => f.priorityTier === 'p1').length
  const p2Count = queue.filter((f) => f.priorityTier === 'p2').length
  const p3Count = queue.filter((f) => f.priorityTier === 'p3').length
  const averageScore = Math.round(
    queue.reduce((sum, f) => sum + f.priorityScore, 0) / queue.length,
  )

  return {
    totalCandidates: queue.length,
    p0Count,
    p1Count,
    p2Count,
    p3Count,
    averageScore,
  }
}
