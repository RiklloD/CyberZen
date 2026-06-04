import { describe, expect, it } from 'vitest'
import {
  type BranchProtectionInput,
  type BranchProtectionRuleId,
  computeBranchProtection,
} from './branchProtection'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fully secure configuration — all best practices applied. */
const SECURE: BranchProtectionInput = {
  enabled: true,
  requiredReviewerCount: 2,
  allowForcePushes: false,
  hasRequiredStatusChecks: true,
  dismissStaleReviews: true,
  hasCodeowners: true,
  adminsBypass: false,
  allowDeletions: false,
  requireSignedCommits: true,
  requireLinearHistory: true,
}

/** Fully insecure configuration — protection disabled. */
const UNPROTECTED: BranchProtectionInput = {
  enabled: false,
  requiredReviewerCount: 0,
  allowForcePushes: true,
  hasRequiredStatusChecks: false,
  dismissStaleReviews: false,
  hasCodeowners: false,
  adminsBypass: true,
  allowDeletions: true,
  requireSignedCommits: false,
  requireLinearHistory: false,
}

function withOverride(overrides: Partial<BranchProtectionInput>): BranchProtectionInput {
  return { ...SECURE, ...overrides }
}

function findingIds(input: BranchProtectionInput): BranchProtectionRuleId[] {
  return computeBranchProtection(input).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// NO_BRANCH_PROTECTION
// ---------------------------------------------------------------------------

describe('NO_BRANCH_PROTECTION rule', () => {
  it('fires when enabled=false', () => {
    const result = computeBranchProtection(UNPROTECTED)
    expect(findingIds(UNPROTECTED)).toContain('NO_BRANCH_PROTECTION')
    expect(result.criticalCount).toBe(1)
  })

  it('produces riskScore=75 and riskLevel=critical', () => {
    const result = computeBranchProtection(UNPROTECTED)
    expect(result.riskScore).toBe(75)
    expect(result.riskLevel).toBe('critical')
  })

  it('summary mentions "no protection rules"', () => {
    expect(computeBranchProtection(UNPROTECTED).summary).toMatch(/no protection rules/i)
  })

  it('does not fire when enabled=true', () => {
    expect(findingIds(SECURE)).not.toContain('NO_BRANCH_PROTECTION')
  })
})

// ---------------------------------------------------------------------------
// NO_REQUIRED_REVIEWS
// ---------------------------------------------------------------------------

describe('NO_REQUIRED_REVIEWS rule', () => {
  it('fires when requiredReviewerCount=0', () => {
    const cfg = withOverride({ requiredReviewerCount: 0 })
    expect(findingIds(cfg)).toContain('NO_REQUIRED_REVIEWS')
  })

  it('does not fire when requiredReviewerCount≥1', () => {
    expect(findingIds(SECURE)).not.toContain('NO_REQUIRED_REVIEWS')
  })

  it('does not fire when branch protection is disabled (covered by NO_BRANCH_PROTECTION)', () => {
    expect(findingIds(UNPROTECTED)).not.toContain('NO_REQUIRED_REVIEWS')
  })
})

// ---------------------------------------------------------------------------
// FORCE_PUSH_ALLOWED
// ---------------------------------------------------------------------------

describe('FORCE_PUSH_ALLOWED rule', () => {
  it('fires when allowForcePushes=true', () => {
    const cfg = withOverride({ allowForcePushes: true })
    expect(findingIds(cfg)).toContain('FORCE_PUSH_ALLOWED')
  })

  it('has severity=high', () => {
    const cfg = withOverride({ allowForcePushes: true })
    const finding = computeBranchProtection(cfg).findings.find(
      (f) => f.ruleId === 'FORCE_PUSH_ALLOWED',
    )
    expect(finding?.severity).toBe('high')
  })

  it('does not fire when allowForcePushes=false', () => {
    expect(findingIds(SECURE)).not.toContain('FORCE_PUSH_ALLOWED')
  })
})

// ---------------------------------------------------------------------------
// NO_REQUIRED_STATUS_CHECKS
// ---------------------------------------------------------------------------

describe('NO_REQUIRED_STATUS_CHECKS rule', () => {
  it('fires when hasRequiredStatusChecks=false', () => {
    const cfg = withOverride({ hasRequiredStatusChecks: false })
    expect(findingIds(cfg)).toContain('NO_REQUIRED_STATUS_CHECKS')
  })

  it('has severity=medium', () => {
    const cfg = withOverride({ hasRequiredStatusChecks: false })
    const finding = computeBranchProtection(cfg).findings.find(
      (f) => f.ruleId === 'NO_REQUIRED_STATUS_CHECKS',
    )
    expect(finding?.severity).toBe('medium')
  })

  it('does not fire when hasRequiredStatusChecks=true', () => {
    expect(findingIds(SECURE)).not.toContain('NO_REQUIRED_STATUS_CHECKS')
  })
})

// ---------------------------------------------------------------------------
// STALE_REVIEWS_NOT_DISMISSED
// ---------------------------------------------------------------------------

describe('STALE_REVIEWS_NOT_DISMISSED rule', () => {
  it('fires when reviewers required but stale reviews not dismissed', () => {
    const cfg = withOverride({ requiredReviewerCount: 1, dismissStaleReviews: false })
    expect(findingIds(cfg)).toContain('STALE_REVIEWS_NOT_DISMISSED')
  })

  it('does NOT fire when requiredReviewerCount=0 (no reviews means no stale review risk)', () => {
    const cfg = withOverride({ requiredReviewerCount: 0, dismissStaleReviews: false })
    expect(findingIds(cfg)).not.toContain('STALE_REVIEWS_NOT_DISMISSED')
  })

  it('does not fire when dismissStaleReviews=true', () => {
    expect(findingIds(SECURE)).not.toContain('STALE_REVIEWS_NOT_DISMISSED')
  })
})

// ---------------------------------------------------------------------------
// NO_CODEOWNERS
// ---------------------------------------------------------------------------

describe('NO_CODEOWNERS rule', () => {
  it('fires when hasCodeowners=false', () => {
    const cfg = withOverride({ hasCodeowners: false })
    expect(findingIds(cfg)).toContain('NO_CODEOWNERS')
  })

  it('has severity=medium', () => {
    const cfg = withOverride({ hasCodeowners: false })
    const finding = computeBranchProtection(cfg).findings.find((f) => f.ruleId === 'NO_CODEOWNERS')
    expect(finding?.severity).toBe('medium')
  })

  it('does not fire when hasCodeowners=true', () => {
    expect(findingIds(SECURE)).not.toContain('NO_CODEOWNERS')
  })
})

// ---------------------------------------------------------------------------
// ADMIN_BYPASS_ALLOWED
// ---------------------------------------------------------------------------

describe('ADMIN_BYPASS_ALLOWED rule', () => {
  it('fires when adminsBypass=true', () => {
    const cfg = withOverride({ adminsBypass: true })
    expect(findingIds(cfg)).toContain('ADMIN_BYPASS_ALLOWED')
  })

  it('has severity=low', () => {
    const cfg = withOverride({ adminsBypass: true })
    const finding = computeBranchProtection(cfg).findings.find(
      (f) => f.ruleId === 'ADMIN_BYPASS_ALLOWED',
    )
    expect(finding?.severity).toBe('low')
  })

  it('does not fire when adminsBypass=false', () => {
    expect(findingIds(SECURE)).not.toContain('ADMIN_BYPASS_ALLOWED')
  })
})

// ---------------------------------------------------------------------------
// DELETIONS_ALLOWED
// ---------------------------------------------------------------------------

describe('DELETIONS_ALLOWED rule', () => {
  it('fires when allowDeletions=true', () => {
    const cfg = withOverride({ allowDeletions: true })
    expect(findingIds(cfg)).toContain('DELETIONS_ALLOWED')
  })

  it('has severity=low', () => {
    const cfg = withOverride({ allowDeletions: true })
    const finding = computeBranchProtection(cfg).findings.find(
      (f) => f.ruleId === 'DELETIONS_ALLOWED',
    )
    expect(finding?.severity).toBe('low')
  })

  it('does not fire when allowDeletions=false', () => {
    expect(findingIds(SECURE)).not.toContain('DELETIONS_ALLOWED')
  })
})

// ---------------------------------------------------------------------------
// Fully secure configuration
// ---------------------------------------------------------------------------

describe('fully secure configuration', () => {
  it('returns 0 findings', () => {
    expect(computeBranchProtection(SECURE).totalFindings).toBe(0)
  })

  it('returns riskScore=0', () => {
    expect(computeBranchProtection(SECURE).riskScore).toBe(0)
  })

  it('returns riskLevel=none', () => {
    expect(computeBranchProtection(SECURE).riskLevel).toBe('none')
  })

  it('returns summary indicating no misconfigurations', () => {
    expect(computeBranchProtection(SECURE).summary).toMatch(/no misconfigurations/i)
  })
})

// ---------------------------------------------------------------------------
// Scoring and riskLevel boundaries
// ---------------------------------------------------------------------------

describe('riskScore and riskLevel', () => {
  it('single low finding → riskScore=3, riskLevel=low', () => {
    const result = computeBranchProtection(withOverride({ adminsBypass: true }))
    expect(result.riskScore).toBe(3)
    expect(result.riskLevel).toBe('low')
  })

  it('two low findings → riskScore=6, riskLevel=low', () => {
    const result = computeBranchProtection(
      withOverride({ adminsBypass: true, allowDeletions: true }),
    )
    expect(result.riskScore).toBe(6)
    expect(result.riskLevel).toBe('low')
  })

  it('single medium finding → riskScore=8, riskLevel=low', () => {
    const result = computeBranchProtection(withOverride({ hasRequiredStatusChecks: false }))
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('three medium findings → riskScore=20 (cap), riskLevel=low', () => {
    const result = computeBranchProtection(
      withOverride({
        hasRequiredStatusChecks: false,
        hasCodeowners: false,
        dismissStaleReviews: false, // fires because requiredReviewerCount=2 in SECURE
      }),
    )
    // 3 × 8 = 24, but medium cap is 20
    expect(result.riskScore).toBe(20)
    expect(result.riskLevel).toBe('low')
  })

  it('single high finding → riskScore=15, riskLevel=low', () => {
    const result = computeBranchProtection(withOverride({ allowForcePushes: true }))
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('two high findings → riskScore=30 (cap), riskLevel=medium', () => {
    const result = computeBranchProtection(
      withOverride({ allowForcePushes: true, requiredReviewerCount: 0 }),
    )
    // 2 × 15 = 30, cap is 30 → riskScore=30 → riskLevel=medium (≥25)
    expect(result.riskScore).toBe(30)
    expect(result.riskLevel).toBe('medium')
  })

  it('no protection (critical) → riskScore=75, riskLevel=critical', () => {
    const result = computeBranchProtection(UNPROTECTED)
    expect(result.riskScore).toBe(75)
    expect(result.riskLevel).toBe('critical')
  })

  it('compound high+medium+low → score accumulates correctly', () => {
    const result = computeBranchProtection(
      withOverride({
        allowForcePushes: true, // high +15
        hasRequiredStatusChecks: false, // medium +8
        adminsBypass: true, // low +3
      }),
    )
    expect(result.riskScore).toBe(26)
    expect(result.riskLevel).toBe('medium')
  })

  it('riskLevel=high for score in [50,75)', () => {
    // Force two high + two medium + two low = 30+16+6 = 52
    const result = computeBranchProtection(
      withOverride({
        requiredReviewerCount: 0, // high +15
        allowForcePushes: true, // high +15 → subtotal high=30 (cap)
        hasRequiredStatusChecks: false, // medium +8
        hasCodeowners: false, // medium +8 → subtotal medium=16
        adminsBypass: true, // low +3
        allowDeletions: true, // low +3 → subtotal low=6
      }),
    )
    expect(result.riskScore).toBe(52)
    expect(result.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Finding counts
// ---------------------------------------------------------------------------

describe('finding counts', () => {
  it('counts are consistent with findings array', () => {
    const cfg = withOverride({
      allowForcePushes: true, // high
      hasRequiredStatusChecks: false, // medium
      adminsBypass: true, // low
    })
    const result = computeBranchProtection(cfg)
    expect(result.totalFindings).toBe(3)
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.criticalCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('high severity summary mentions high-severity finding', () => {
    const result = computeBranchProtection(withOverride({ allowForcePushes: true }))
    expect(result.summary).toMatch(/high-severity/i)
  })

  it('medium-only findings produce a count-based summary', () => {
    const result = computeBranchProtection(withOverride({ hasRequiredStatusChecks: false }))
    expect(result.summary).toMatch(/1 branch protection misconfiguration/i)
  })

  it('plural summary for 2+ findings', () => {
    const result = computeBranchProtection(
      withOverride({
        hasRequiredStatusChecks: false,
        hasCodeowners: false,
      }),
    )
    expect(result.summary).toMatch(/2 branch protection misconfigurations/i)
  })
})
