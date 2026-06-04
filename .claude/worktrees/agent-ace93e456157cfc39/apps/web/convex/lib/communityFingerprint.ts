/**
 * Community Rule/Fingerprint Marketplace — pure business logic
 *
 * Spec §10 Phase 4: "Public rule/fingerprint contribution marketplace"
 *
 * Operators submit custom vulnerability fingerprint patterns and detection rule
 * templates. The community votes on them; approved contributions are
 * incorporated into the platform's detection library, creating a network-effect
 * moat — more contributors → better detection coverage for everyone.
 *
 * Zero Convex imports — safe to use in Vitest unit tests.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The kind of security artefact being contributed. */
export type ContributionType = 'fingerprint' | 'detection_rule'

/**
 * Lifecycle states for a community contribution.
 *
 * Flow: pending → under_review (when reports accumulate) → approved | rejected
 *       OR:      pending                                  → approved | rejected  (operator fast-track)
 */
export type ContributionStatus =
  | 'pending'
  | 'under_review'
  | 'approved'
  | 'rejected'

/** Severity levels mirroring the existing findings model. */
export type ContributionSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

/**
 * Minimal shape of a community contribution as stored in the DB.
 * All fields used by the pure-library functions live here.
 */
export interface CommunityContribution {
  type: ContributionType
  title: string
  description: string
  vulnClass: string
  severity: ContributionSeverity
  /** The raw pattern text — fingerprint regex / rule YAML / description prose. */
  patternText: string
  status: ContributionStatus
  upvoteCount: number
  downvoteCount: number
  /** Number of abuse/accuracy reports filed against this contribution. */
  reportCount: number
  createdAt: number
  approvedAt?: number | null
  reviewNote?: string | null
}

/** Computed quality signal for a single contribution. */
export interface ContributionScore {
  /** upvotes − downvotes − reports×2 */
  netScore: number
  /** Ratio of upvotes to total votes cast (0 when no votes). */
  upvoteRatio: number
  /** True when the contribution meets the bar for operator approval. */
  approvalEligible: boolean
}

/** Aggregate summary for the entire marketplace. */
export interface MarketplaceStats {
  totalContributions: number
  pendingCount: number
  underReviewCount: number
  approvedCount: number
  rejectedCount: number
  fingerprintCount: number
  detectionRuleCount: number
  /** Counts per vulnerability class for approved contributions. */
  approvedByVulnClass: Record<string, number>
  /** Counts per severity for approved contributions. */
  approvedBySeverity: Record<string, number>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum net score required for approval eligibility. */
export const APPROVAL_NET_SCORE_THRESHOLD = 3

/** Contributions with this many reports or more are moved to under_review. */
export const REPORT_REVIEW_THRESHOLD = 2

/** Maximum reports a contribution can have while still being approval-eligible. */
export const MAX_REPORTS_FOR_APPROVAL = 1

// ---------------------------------------------------------------------------
// computeContributionScore
// ---------------------------------------------------------------------------

/**
 * Compute the quality signal for a contribution.
 *
 * Net score = upvotes − downvotes − reports×2.
 * Reports carry double weight to surface potentially harmful submissions quickly.
 */
export function computeContributionScore(
  contribution: Pick<
    CommunityContribution,
    'upvoteCount' | 'downvoteCount' | 'reportCount'
  >,
): ContributionScore {
  const { upvoteCount, downvoteCount, reportCount } = contribution
  const netScore = upvoteCount - downvoteCount - reportCount * 2
  const totalVotes = upvoteCount + downvoteCount
  const upvoteRatio = totalVotes === 0 ? 0 : upvoteCount / totalVotes

  const approvalEligible =
    netScore >= APPROVAL_NET_SCORE_THRESHOLD &&
    reportCount <= MAX_REPORTS_FOR_APPROVAL

  return { netScore, upvoteRatio, approvalEligible }
}

// ---------------------------------------------------------------------------
// isApprovalEligible
// ---------------------------------------------------------------------------

/**
 * Returns true when the contribution's vote signal passes the approval bar.
 *
 * Rules:
 * - Net score ≥ APPROVAL_NET_SCORE_THRESHOLD
 * - Report count ≤ MAX_REPORTS_FOR_APPROVAL
 * - Status must be pending or under_review (already-approved/rejected are skipped)
 */
export function isApprovalEligible(contribution: CommunityContribution): boolean {
  if (
    contribution.status === 'approved' ||
    contribution.status === 'rejected'
  ) {
    return false
  }
  const { approvalEligible } = computeContributionScore(contribution)
  return approvalEligible
}

// ---------------------------------------------------------------------------
// deriveStatus
// ---------------------------------------------------------------------------

/**
 * Derive the expected status from vote and report signals alone — used to
 * decide whether to transition a pending contribution to `under_review`.
 *
 * Does NOT overwrite `approved` or `rejected` (those are set by operators).
 */
export function deriveStatus(
  contribution: CommunityContribution,
): ContributionStatus {
  // Operator decisions are final.
  if (
    contribution.status === 'approved' ||
    contribution.status === 'rejected'
  ) {
    return contribution.status
  }

  // Enough reports → move to human review.
  if (contribution.reportCount >= REPORT_REVIEW_THRESHOLD) {
    return 'under_review'
  }

  return 'pending'
}

// ---------------------------------------------------------------------------
// validateContribution
// ---------------------------------------------------------------------------

export interface ValidationResult {
  valid: boolean
  errors: string[]
}

const VALID_VULN_CLASSES = new Set([
  'sql_injection',
  'xss',
  'path_traversal',
  'rce',
  'ssrf',
  'auth_bypass',
  'insecure_deserialization',
  'supply_chain_backdoor',
  'prompt_injection',
  'idor',
  'xxe',
  'open_redirect',
  'memory_corruption',
  'cryptographic_weakness',
  'hardcoded_secret',
  'insecure_dependency',
  'prototype_pollution',
  'template_injection',
  'other',
])

/**
 * Validate a submission before it is persisted.
 *
 * Rules:
 * - title: 5–120 characters
 * - description: 20–2000 characters
 * - patternText: 10–5000 characters
 * - vulnClass: must be in the known set
 */
export function validateContribution(
  input: Pick<
    CommunityContribution,
    'title' | 'description' | 'patternText' | 'vulnClass'
  >,
): ValidationResult {
  const errors: string[] = []

  const title = input.title.trim()
  if (title.length < 5) errors.push('title must be at least 5 characters')
  if (title.length > 120) errors.push('title must be at most 120 characters')

  const description = input.description.trim()
  if (description.length < 20)
    errors.push('description must be at least 20 characters')
  if (description.length > 2000)
    errors.push('description must be at most 2000 characters')

  const patternText = input.patternText.trim()
  if (patternText.length < 10)
    errors.push('patternText must be at least 10 characters')
  if (patternText.length > 5000)
    errors.push('patternText must be at most 5000 characters')

  if (!VALID_VULN_CLASSES.has(input.vulnClass)) {
    errors.push(`unknown vulnClass: ${input.vulnClass}`)
  }

  return { valid: errors.length === 0, errors }
}

// ---------------------------------------------------------------------------
// summarizeMarketplaceStats
// ---------------------------------------------------------------------------

/**
 * Aggregate community contributions into a MarketplaceStats summary.
 *
 * Used by the dashboard panel and the `/api/marketplace/stats` endpoint.
 */
export function summarizeMarketplaceStats(
  contributions: CommunityContribution[],
): MarketplaceStats {
  const stats: MarketplaceStats = {
    totalContributions: contributions.length,
    pendingCount: 0,
    underReviewCount: 0,
    approvedCount: 0,
    rejectedCount: 0,
    fingerprintCount: 0,
    detectionRuleCount: 0,
    approvedByVulnClass: {},
    approvedBySeverity: {},
  }

  for (const c of contributions) {
    // Status counts
    if (c.status === 'pending') stats.pendingCount++
    else if (c.status === 'under_review') stats.underReviewCount++
    else if (c.status === 'approved') stats.approvedCount++
    else if (c.status === 'rejected') stats.rejectedCount++

    // Type counts
    if (c.type === 'fingerprint') stats.fingerprintCount++
    else if (c.type === 'detection_rule') stats.detectionRuleCount++

    // Approved breakdowns
    if (c.status === 'approved') {
      stats.approvedByVulnClass[c.vulnClass] =
        (stats.approvedByVulnClass[c.vulnClass] ?? 0) + 1
      stats.approvedBySeverity[c.severity] =
        (stats.approvedBySeverity[c.severity] ?? 0) + 1
    }
  }

  return stats
}

// ---------------------------------------------------------------------------
// rankContributions
// ---------------------------------------------------------------------------

/**
 * Sort contributions by net score descending, using createdAt as a tiebreaker
 * (newer first). Used for the marketplace listing.
 */
export function rankContributions(
  contributions: CommunityContribution[],
): CommunityContribution[] {
  return [...contributions].sort((a, b) => {
    const scoreA = computeContributionScore(a).netScore
    const scoreB = computeContributionScore(b).netScore
    if (scoreB !== scoreA) return scoreB - scoreA
    return b.createdAt - a.createdAt
  })
}
