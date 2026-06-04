// Autonomous Remediation Dispatch — pure library with no Convex imports.
//
// Implements the candidate-selection policy for automatic PR generation:
// given the current prioritised remediation queue and the set of finding IDs
// that already have an in-flight PR proposal, decide which findings are
// eligible for auto-dispatch and which are skipped (with a reason).
//
// Design principles:
//   • Opt-in — `enabled = false` by default; operators must explicitly turn on
//   • Monotone — only findings with no active proposal are considered
//   • Capped  — `maxConcurrentPrs` prevents flooding CI with bulk PRs
//   • Ordered — the queue is already sorted by composite priority score, so
//               the first `maxConcurrentPrs` eligible findings are selected

// ─── Types ─────────────────────────────────────────────────────────────────────

export type AutoRemediationTierThreshold = 'p0' | 'p0_p1'

export type AutoRemediationPolicy = {
  /**
   * Master switch. When false the engine returns an empty selection regardless
   * of all other settings.  Default: false (opt-in).
   */
  enabled: boolean
  /**
   * Which priority tiers are eligible for auto-dispatch.
   *   'p0'      — only P0 findings (score ≥ 70)
   *   'p0_p1'   — P0 and P1 findings (score ≥ 45)
   * Default: 'p0'
   */
  tierThreshold: AutoRemediationTierThreshold
  /**
   * Maximum number of PRs that may be open simultaneously for a single
   * repository.  Includes PRs dispatched in earlier runs that are still
   * open/draft.  Default: 3.
   */
  maxConcurrentPrs: number
  /**
   * Only findings with these severities are eligible.  An empty list means
   * "all severities".  Default: ['critical', 'high'].
   */
  allowedSeverities: string[]
}

export const DEFAULT_AUTO_REMEDIATION_POLICY: AutoRemediationPolicy = {
  enabled: false,
  tierThreshold: 'p0',
  maxConcurrentPrs: 3,
  allowedSeverities: ['critical', 'high'],
}

export type AutoRemediationSkipReason =
  | 'disabled'
  | 'concurrency_cap'
  | 'already_has_pr'
  | 'below_tier'
  | 'below_severity'

export type AutoRemediationEligible = {
  findingId: string
  title: string
  severity: string
  priorityTier: string
  priorityScore: number
}

export type AutoRemediationSkipped = {
  findingId: string
  reason: AutoRemediationSkipReason
}

export type AutoRemediationSelection = {
  eligible: AutoRemediationEligible[]
  skipped: AutoRemediationSkipped[]
  /** True when the policy is disabled — callers can skip DB work entirely. */
  policyDisabled: boolean
}

// ─── Tier eligibility ─────────────────────────────────────────────────────────

/**
 * Returns true when the finding's priorityTier meets the configured threshold.
 */
export function isTierEligible(
  tier: string,
  threshold: AutoRemediationTierThreshold,
): boolean {
  if (threshold === 'p0') return tier === 'p0'
  if (threshold === 'p0_p1') return tier === 'p0' || tier === 'p1'
  return false
}

// ─── Core selection function ──────────────────────────────────────────────────

type QueueEntry = {
  findingId: string
  title: string
  severity: string
  priorityTier: string
  priorityScore: number
}

/**
 * Selects findings from the prioritised queue that are eligible for
 * autonomous PR generation dispatch.
 *
 * @param queue               Findings already sorted by composite score
 *                            descending (highest priority first).
 * @param existingPrFindingIds Finding IDs with an open or draft PR proposal.
 * @param currentOpenPrCount  How many auto-dispatched PRs are already open for
 *                            this repository.  Deducted from the concurrency cap.
 * @param policy              Dispatch policy (defaults to
 *                            DEFAULT_AUTO_REMEDIATION_POLICY).
 */
export function selectRemediationCandidates(
  queue: QueueEntry[],
  existingPrFindingIds: Set<string>,
  currentOpenPrCount: number,
  policy: AutoRemediationPolicy = DEFAULT_AUTO_REMEDIATION_POLICY,
): AutoRemediationSelection {
  if (!policy.enabled) {
    return {
      eligible: [],
      skipped: queue.map((f) => ({ findingId: f.findingId, reason: 'disabled' })),
      policyDisabled: true,
    }
  }

  const eligible: AutoRemediationEligible[] = []
  const skipped: AutoRemediationSkipped[] = []
  let slotsRemaining = Math.max(0, policy.maxConcurrentPrs - currentOpenPrCount)

  for (const finding of queue) {
    // Already has an in-flight PR — skip regardless of tier or severity.
    if (existingPrFindingIds.has(finding.findingId)) {
      skipped.push({ findingId: finding.findingId, reason: 'already_has_pr' })
      continue
    }

    // Tier check.
    if (!isTierEligible(finding.priorityTier, policy.tierThreshold)) {
      skipped.push({ findingId: finding.findingId, reason: 'below_tier' })
      continue
    }

    // Severity check.
    if (
      policy.allowedSeverities.length > 0 &&
      !policy.allowedSeverities.includes(finding.severity)
    ) {
      skipped.push({ findingId: finding.findingId, reason: 'below_severity' })
      continue
    }

    // Concurrency cap.
    if (slotsRemaining <= 0) {
      skipped.push({ findingId: finding.findingId, reason: 'concurrency_cap' })
      continue
    }

    eligible.push({
      findingId: finding.findingId,
      title: finding.title,
      severity: finding.severity,
      priorityTier: finding.priorityTier,
      priorityScore: finding.priorityScore,
    })
    slotsRemaining--
  }

  return { eligible, skipped, policyDisabled: false }
}
