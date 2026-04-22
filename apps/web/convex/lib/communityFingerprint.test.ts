import { describe, expect, it } from 'vitest'
import {
  APPROVAL_NET_SCORE_THRESHOLD,
  MAX_REPORTS_FOR_APPROVAL,
  REPORT_REVIEW_THRESHOLD,
  type CommunityContribution,
  computeContributionScore,
  deriveStatus,
  isApprovalEligible,
  rankContributions,
  summarizeMarketplaceStats,
  validateContribution,
} from './communityFingerprint'

// ── helpers ────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000

function make(
  overrides: Partial<CommunityContribution> = {},
): CommunityContribution {
  return {
    type: 'fingerprint',
    title: 'SQL injection via raw query concat',
    description:
      'Detects raw string concatenation into SQL queries without parameterisation.',
    vulnClass: 'sql_injection',
    severity: 'high',
    patternText:
      'SELECT * FROM users WHERE id = \' + userId + \'',
    status: 'pending',
    upvoteCount: 0,
    downvoteCount: 0,
    reportCount: 0,
    createdAt: NOW,
    ...overrides,
  }
}

// ── computeContributionScore ───────────────────────────────────────────────

describe('computeContributionScore', () => {
  it('zero votes → zero net score, zero ratio, not eligible', () => {
    const s = computeContributionScore(make())
    expect(s.netScore).toBe(0)
    expect(s.upvoteRatio).toBe(0)
    expect(s.approvalEligible).toBe(false)
  })

  it('net score = upvotes − downvotes − reports×2', () => {
    const s = computeContributionScore(
      make({ upvoteCount: 10, downvoteCount: 3, reportCount: 1 }),
    )
    expect(s.netScore).toBe(10 - 3 - 2) // 5
  })

  it('upvoteRatio is correct', () => {
    const s = computeContributionScore(
      make({ upvoteCount: 3, downvoteCount: 1 }),
    )
    expect(s.upvoteRatio).toBeCloseTo(0.75)
  })

  it('upvoteRatio is 0 when no votes', () => {
    expect(computeContributionScore(make()).upvoteRatio).toBe(0)
  })

  it(`eligible when netScore ≥ ${APPROVAL_NET_SCORE_THRESHOLD} and reports ≤ ${MAX_REPORTS_FOR_APPROVAL}`, () => {
    const s = computeContributionScore(
      make({ upvoteCount: 5, downvoteCount: 0, reportCount: 0 }),
    )
    expect(s.approvalEligible).toBe(true)
  })

  it('ineligible when netScore is exactly below threshold', () => {
    const s = computeContributionScore(
      make({
        upvoteCount: APPROVAL_NET_SCORE_THRESHOLD - 1,
        downvoteCount: 0,
        reportCount: 0,
      }),
    )
    expect(s.approvalEligible).toBe(false)
  })

  it('ineligible when reportCount exceeds MAX_REPORTS_FOR_APPROVAL', () => {
    const s = computeContributionScore(
      make({
        upvoteCount: 10,
        downvoteCount: 0,
        reportCount: MAX_REPORTS_FOR_APPROVAL + 1,
      }),
    )
    expect(s.approvalEligible).toBe(false)
  })

  it('reports drive net score negative', () => {
    const s = computeContributionScore(
      make({ upvoteCount: 3, downvoteCount: 0, reportCount: 5 }),
    )
    expect(s.netScore).toBe(3 - 10) // -7
    expect(s.approvalEligible).toBe(false)
  })
})

// ── isApprovalEligible ─────────────────────────────────────────────────────

describe('isApprovalEligible', () => {
  it('returns false for already-approved contributions', () => {
    expect(isApprovalEligible(make({ status: 'approved', upvoteCount: 10 }))).toBe(false)
  })

  it('returns false for already-rejected contributions', () => {
    expect(isApprovalEligible(make({ status: 'rejected', upvoteCount: 10 }))).toBe(false)
  })

  it('returns true for pending contribution with enough votes', () => {
    expect(
      isApprovalEligible(make({ upvoteCount: APPROVAL_NET_SCORE_THRESHOLD, status: 'pending' })),
    ).toBe(true)
  })

  it('returns true for under_review contribution with enough votes and low reports', () => {
    expect(
      isApprovalEligible(
        make({ upvoteCount: 5, status: 'under_review', reportCount: 1 }),
      ),
    ).toBe(true)
  })

  it('returns false for under_review with too many reports', () => {
    expect(
      isApprovalEligible(
        make({ upvoteCount: 10, status: 'under_review', reportCount: 3 }),
      ),
    ).toBe(false)
  })
})

// ── deriveStatus ───────────────────────────────────────────────────────────

describe('deriveStatus', () => {
  it('approved is preserved unchanged', () => {
    expect(deriveStatus(make({ status: 'approved' }))).toBe('approved')
  })

  it('rejected is preserved unchanged', () => {
    expect(deriveStatus(make({ status: 'rejected' }))).toBe('rejected')
  })

  it('pending stays pending when reports < threshold', () => {
    expect(
      deriveStatus(make({ status: 'pending', reportCount: REPORT_REVIEW_THRESHOLD - 1 })),
    ).toBe('pending')
  })

  it(`moves to under_review when reportCount ≥ ${REPORT_REVIEW_THRESHOLD}`, () => {
    expect(
      deriveStatus(make({ status: 'pending', reportCount: REPORT_REVIEW_THRESHOLD })),
    ).toBe('under_review')
  })

  it('under_review with reports now below threshold → reverts to pending', () => {
    expect(deriveStatus(make({ status: 'under_review', reportCount: 1 }))).toBe('pending')
  })

  it('under_review escalates further when reports grow', () => {
    expect(
      deriveStatus(make({ status: 'under_review', reportCount: REPORT_REVIEW_THRESHOLD })),
    ).toBe('under_review')
  })
})

// ── validateContribution ───────────────────────────────────────────────────

describe('validateContribution', () => {
  const good = {
    title: 'Safe title for test',
    description: 'A long enough description that passes the minimum length requirement easily.',
    patternText: 'Pattern that is definitely long enough to pass.',
    vulnClass: 'sql_injection',
  }

  it('valid input passes', () => {
    const result = validateContribution(good)
    expect(result.valid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  it('title too short', () => {
    const result = validateContribution({ ...good, title: 'hi' })
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('title'))).toBe(true)
  })

  it('title too long', () => {
    const result = validateContribution({ ...good, title: 'x'.repeat(121) })
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('title'))).toBe(true)
  })

  it('description too short', () => {
    const result = validateContribution({ ...good, description: 'Too short.' })
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('description'))).toBe(true)
  })

  it('patternText too short', () => {
    const result = validateContribution({ ...good, patternText: 'tiny' })
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('patternText'))).toBe(true)
  })

  it('unknown vulnClass', () => {
    const result = validateContribution({ ...good, vulnClass: 'not_a_class' })
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.includes('vulnClass'))).toBe(true)
  })

  it('multiple errors reported together', () => {
    const result = validateContribution({
      title: 'x',
      description: 'short',
      patternText: 'tiny',
      vulnClass: 'bad',
    })
    expect(result.errors.length).toBeGreaterThanOrEqual(3)
  })
})

// ── summarizeMarketplaceStats ──────────────────────────────────────────────

describe('summarizeMarketplaceStats', () => {
  it('empty list → all zeros', () => {
    const s = summarizeMarketplaceStats([])
    expect(s.totalContributions).toBe(0)
    expect(s.approvedCount).toBe(0)
    expect(s.approvedByVulnClass).toEqual({})
  })

  it('counts status correctly', () => {
    const s = summarizeMarketplaceStats([
      make({ status: 'pending' }),
      make({ status: 'pending' }),
      make({ status: 'under_review' }),
      make({ status: 'approved' }),
      make({ status: 'rejected' }),
    ])
    expect(s.pendingCount).toBe(2)
    expect(s.underReviewCount).toBe(1)
    expect(s.approvedCount).toBe(1)
    expect(s.rejectedCount).toBe(1)
    expect(s.totalContributions).toBe(5)
  })

  it('counts types correctly', () => {
    const s = summarizeMarketplaceStats([
      make({ type: 'fingerprint' }),
      make({ type: 'fingerprint' }),
      make({ type: 'detection_rule' }),
    ])
    expect(s.fingerprintCount).toBe(2)
    expect(s.detectionRuleCount).toBe(1)
  })

  it('approvedByVulnClass only counts approved contributions', () => {
    const s = summarizeMarketplaceStats([
      make({ status: 'approved', vulnClass: 'xss' }),
      make({ status: 'approved', vulnClass: 'xss' }),
      make({ status: 'pending', vulnClass: 'xss' }),
      make({ status: 'approved', vulnClass: 'sql_injection' }),
    ])
    expect(s.approvedByVulnClass.xss).toBe(2)
    expect(s.approvedByVulnClass.sql_injection).toBe(1)
    expect(Object.keys(s.approvedByVulnClass)).toHaveLength(2)
  })

  it('approvedBySeverity only counts approved contributions', () => {
    const s = summarizeMarketplaceStats([
      make({ status: 'approved', severity: 'critical' }),
      make({ status: 'approved', severity: 'high' }),
      make({ status: 'pending', severity: 'critical' }),
    ])
    expect(s.approvedBySeverity.critical).toBe(1)
    expect(s.approvedBySeverity.high).toBe(1)
  })
})

// ── rankContributions ──────────────────────────────────────────────────────

describe('rankContributions', () => {
  it('higher net score ranks first', () => {
    const low = make({ upvoteCount: 2 })
    const high = make({ upvoteCount: 8 })
    const [first, second] = rankContributions([low, high])
    expect(computeContributionScore(first).netScore).toBeGreaterThan(
      computeContributionScore(second).netScore,
    )
  })

  it('equal score → newer createdAt ranks first', () => {
    const older = make({ createdAt: NOW - 1000, upvoteCount: 3 })
    const newer = make({ createdAt: NOW, upvoteCount: 3 })
    const [first] = rankContributions([older, newer])
    expect(first.createdAt).toBe(NOW)
  })

  it('does not mutate the input array', () => {
    const arr = [make({ upvoteCount: 5 }), make({ upvoteCount: 1 })]
    const original = [...arr]
    rankContributions(arr)
    expect(arr[0]).toBe(original[0])
  })

  it('empty array returns empty', () => {
    expect(rankContributions([])).toHaveLength(0)
  })

  it('reports-penalized contribution sinks below a clean lower-vote one', () => {
    const clean = make({ upvoteCount: 3, reportCount: 0 })        // netScore 3
    const reported = make({ upvoteCount: 8, reportCount: 5 })     // netScore 8 - 10 = -2
    const [first] = rankContributions([reported, clean])
    expect(first).toBe(clean)
  })
})
