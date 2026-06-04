import { describe, expect, it } from 'vitest'
import { type CommitMessageRuleId, analyzeCommitMessages } from './commitMessageAnalyzer'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ruleIds(messages: string[]): CommitMessageRuleId[] {
  return analyzeCommitMessages(messages).findings.map((f) => f.ruleId)
}

function hasRule(messages: string[], rule: CommitMessageRuleId): boolean {
  return ruleIds(messages).includes(rule)
}

// ---------------------------------------------------------------------------
// SECURITY_BYPASS rule
// ---------------------------------------------------------------------------

describe('SECURITY_BYPASS rule', () => {
  it('fires on "disable auth check"', () => {
    expect(hasRule(['disable auth check for now'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('fires on "bypass authentication"', () => {
    expect(hasRule(['bypass authentication for internal users'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('fires on "skip validation"', () => {
    expect(hasRule(['skip input validation to unblock release'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('fires on "remove security middleware"', () => {
    expect(hasRule(['remove security middleware temporarily'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('fires on "no auth needed"', () => {
    expect(hasRule(['no-auth needed for this endpoint'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('fires on "disable csrf"', () => {
    expect(hasRule(['disable csrf for mobile clients'], 'SECURITY_BYPASS')).toBe(true)
  })

  it('has severity=critical', () => {
    const result = analyzeCommitMessages(['disable auth for testing'])
    const f = result.findings.find((x) => x.ruleId === 'SECURITY_BYPASS')
    expect(f?.severity).toBe('critical')
  })

  it('does not fire on unrelated messages', () => {
    expect(hasRule(['update README'], 'SECURITY_BYPASS')).toBe(false)
    expect(hasRule(['add user profile page'], 'SECURITY_BYPASS')).toBe(false)
  })

  it('does not fire on "improved security checks"', () => {
    expect(hasRule(['improved security checks for admin routes'], 'SECURITY_BYPASS')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// REVERT_SECURITY_FIX rule
// ---------------------------------------------------------------------------

describe('REVERT_SECURITY_FIX rule', () => {
  it('fires on "Revert: fix sql injection"', () => {
    expect(hasRule(['Revert: fix sql injection vulnerability'], 'REVERT_SECURITY_FIX')).toBe(true)
  })

  it('fires on "revert security patch"', () => {
    expect(hasRule(['revert security patch for now'], 'REVERT_SECURITY_FIX')).toBe(true)
  })

  it('fires on "undo the auth fix"', () => {
    expect(hasRule(['undo the auth fix — breaking tests'], 'REVERT_SECURITY_FIX')).toBe(true)
  })

  it('fires on "Revert: fix CVE"', () => {
    expect(hasRule(['Revert: fix CVE-2024-1234 patch'], 'REVERT_SECURITY_FIX')).toBe(true)
  })

  it('has severity=high', () => {
    const result = analyzeCommitMessages(['revert the xss fix'])
    const f = result.findings.find((x) => x.ruleId === 'REVERT_SECURITY_FIX')
    expect(f?.severity).toBe('high')
  })

  it('does not fire on "revert feature flag change"', () => {
    expect(hasRule(['revert feature flag change'], 'REVERT_SECURITY_FIX')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// FORCE_MERGE_BYPASS rule
// ---------------------------------------------------------------------------

describe('FORCE_MERGE_BYPASS rule', () => {
  it('fires on "force merge"', () => {
    expect(hasRule(['force merge to unblock deployment'], 'FORCE_MERGE_BYPASS')).toBe(true)
  })

  it('fires on "merge without review"', () => {
    expect(hasRule(['merge without review — urgent'], 'FORCE_MERGE_BYPASS')).toBe(true)
  })

  it('fires on "skip review"', () => {
    expect(hasRule(['skip review for this critical fix'], 'FORCE_MERGE_BYPASS')).toBe(true)
  })

  it('fires on "bypassing approval"', () => {
    expect(hasRule(['bypassing approval process'], 'FORCE_MERGE_BYPASS')).toBe(true)
  })

  it('has severity=high', () => {
    const result = analyzeCommitMessages(['force merge this PR'])
    const f = result.findings.find((x) => x.ruleId === 'FORCE_MERGE_BYPASS')
    expect(f?.severity).toBe('high')
  })

  it('does not fire on "code review completed"', () => {
    expect(hasRule(['code review completed — merging'], 'FORCE_MERGE_BYPASS')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CVE_ACKNOWLEDGED rule
// ---------------------------------------------------------------------------

describe('CVE_ACKNOWLEDGED rule', () => {
  it('fires on bare CVE reference', () => {
    expect(hasRule(['fixes CVE-2024-44228'], 'CVE_ACKNOWLEDGED')).toBe(true)
  })

  it('fires on different CVE format', () => {
    expect(hasRule(['patch for CVE-2023-1234 log4j'], 'CVE_ACKNOWLEDGED')).toBe(true)
  })

  it('fires on upper case', () => {
    expect(hasRule(['FIXES CVE-2021-44228 log4shell'], 'CVE_ACKNOWLEDGED')).toBe(true)
  })

  it('has severity=medium', () => {
    const result = analyzeCommitMessages(['address CVE-2024-9999'])
    const f = result.findings.find((x) => x.ruleId === 'CVE_ACKNOWLEDGED')
    expect(f?.severity).toBe('medium')
  })

  it('does not fire on random number sequences', () => {
    expect(hasRule(['update ticket #2024-1234'], 'CVE_ACKNOWLEDGED')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TODO_SECURITY_DEBT rule
// ---------------------------------------------------------------------------

describe('TODO_SECURITY_DEBT rule', () => {
  it('fires on "TODO: add authentication"', () => {
    expect(hasRule(['TODO: add authentication for this route'], 'TODO_SECURITY_DEBT')).toBe(true)
  })

  it('fires on "FIXME: validate input"', () => {
    expect(hasRule(['FIXME: validate input before saving'], 'TODO_SECURITY_DEBT')).toBe(true)
  })

  it('fires on "HACK: skip validation"', () => {
    expect(hasRule(['HACK: skip validation for now'], 'TODO_SECURITY_DEBT')).toBe(true)
  })

  it('fires on "temporarily disable security"', () => {
    expect(hasRule(['temporarily disable security checks'], 'TODO_SECURITY_DEBT')).toBe(true)
  })

  it('has severity=medium', () => {
    const result = analyzeCommitMessages(['TODO: add auth check'])
    const f = result.findings.find((x) => x.ruleId === 'TODO_SECURITY_DEBT')
    expect(f?.severity).toBe('medium')
  })

  it('does not fire on "TODO: update README"', () => {
    expect(hasRule(['TODO: update README'], 'TODO_SECURITY_DEBT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// DEBUG_MODE_ENABLED rule
// ---------------------------------------------------------------------------

describe('DEBUG_MODE_ENABLED rule', () => {
  it('fires on "enable debug mode in prod"', () => {
    expect(hasRule(['enable debug mode in prod'], 'DEBUG_MODE_ENABLED')).toBe(true)
  })

  it('fires on "debug logging on in production"', () => {
    expect(hasRule(['verbose debug logging on in production'], 'DEBUG_MODE_ENABLED')).toBe(true)
  })

  it('fires on "disabling rate limit"', () => {
    expect(hasRule(['disabling rate-limit for load test'], 'DEBUG_MODE_ENABLED')).toBe(true)
  })

  it('has severity=medium', () => {
    const result = analyzeCommitMessages(['enable debug mode in production'])
    const f = result.findings.find((x) => x.ruleId === 'DEBUG_MODE_ENABLED')
    expect(f?.severity).toBe('medium')
  })

  it('does not fire on "add debug logging to dev environment"', () => {
    expect(hasRule(['add debug logging to dev environment'], 'DEBUG_MODE_ENABLED')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// EMERGENCY_DEPLOYMENT rule
// ---------------------------------------------------------------------------

describe('EMERGENCY_DEPLOYMENT rule', () => {
  it('fires on "hotfix for prod"', () => {
    expect(hasRule(['hotfix for prod — payments down'], 'EMERGENCY_DEPLOYMENT')).toBe(true)
  })

  it('fires on "emergency patch"', () => {
    expect(hasRule(['emergency patch for production'], 'EMERGENCY_DEPLOYMENT')).toBe(true)
  })

  it('fires on "deploy without tests for emergency"', () => {
    expect(
      hasRule(['deploying without tests for emergency fix'], 'EMERGENCY_DEPLOYMENT'),
    ).toBe(true)
  })

  it('has severity=low', () => {
    const result = analyzeCommitMessages(['hotfix for prod'])
    const f = result.findings.find((x) => x.ruleId === 'EMERGENCY_DEPLOYMENT')
    expect(f?.severity).toBe('low')
  })

  it('does not fire on "fix minor bug in dev"', () => {
    expect(hasRule(['fix minor bug in dev'], 'EMERGENCY_DEPLOYMENT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SENSITIVE_DATA_REFERENCE rule
// ---------------------------------------------------------------------------

describe('SENSITIVE_DATA_REFERENCE rule', () => {
  it('fires on "testing with real user data"', () => {
    expect(
      hasRule(['testing with real user data from production'], 'SENSITIVE_DATA_REFERENCE'),
    ).toBe(true)
  })

  it('fires on "copied from prod database"', () => {
    expect(hasRule(['copied from prod database for local dev'], 'SENSITIVE_DATA_REFERENCE')).toBe(
      true,
    )
  })

  it('fires on "debug with actual credentials"', () => {
    expect(
      hasRule(['debug with actual production credentials'], 'SENSITIVE_DATA_REFERENCE'),
    ).toBe(true)
  })

  it('has severity=low', () => {
    const result = analyzeCommitMessages(['testing with real data from production'])
    const f = result.findings.find((x) => x.ruleId === 'SENSITIVE_DATA_REFERENCE')
    expect(f?.severity).toBe('low')
  })

  it('does not fire on "add test fixtures"', () => {
    expect(hasRule(['add test fixtures for user profile'], 'SENSITIVE_DATA_REFERENCE')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Clean messages
// ---------------------------------------------------------------------------

describe('clean commit messages', () => {
  const clean = [
    'fix: resolve null pointer in payment processor',
    'feat: add OAuth2 login flow',
    'chore: upgrade dependencies',
    'docs: update API reference',
    'test: add unit tests for auth service',
  ]

  it('returns riskScore=0', () => {
    expect(analyzeCommitMessages(clean).riskScore).toBe(0)
  })

  it('returns riskLevel=none', () => {
    expect(analyzeCommitMessages(clean).riskLevel).toBe('none')
  })

  it('returns 0 findings', () => {
    expect(analyzeCommitMessages(clean).totalFindings).toBe(0)
  })

  it('empty array returns riskLevel=none', () => {
    expect(analyzeCommitMessages([]).riskLevel).toBe('none')
  })

  it('whitespace-only messages are skipped', () => {
    expect(analyzeCommitMessages(['   ', '\n', '\t']).totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Multiple messages — compound scoring
// ---------------------------------------------------------------------------

describe('multiple messages and scoring', () => {
  it('two critical findings → riskScore=60, riskLevel=high', () => {
    const result = analyzeCommitMessages([
      'disable auth check', // SECURITY_BYPASS critical +30
      'bypass authentication middleware', // SECURITY_BYPASS critical +30 → cap=75 but 2×30=60
    ])
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
    expect(result.criticalCount).toBe(2)
  })

  it('three critical findings → riskScore=75 (cap), riskLevel=critical', () => {
    const result = analyzeCommitMessages([
      'disable auth',
      'skip authentication middleware',
      'bypass security check',
    ])
    expect(result.riskScore).toBe(75)
    expect(result.riskLevel).toBe('critical')
  })

  it('one critical + one high + one medium + one low', () => {
    const result = analyzeCommitMessages([
      'disable auth for testing', // critical +30
      'force merge this urgent fix', // high +15
      'fixes CVE-2024-1234', // medium +8
      'hotfix for prod', // low +3
    ])
    expect(result.riskScore).toBe(56)
    expect(result.riskLevel).toBe('high')
    expect(result.totalFindings).toBe(4)
  })

  it('different messages can trigger different rules', () => {
    const result = analyzeCommitMessages([
      'revert the xss fix', // REVERT_SECURITY_FIX
      'fixes CVE-2024-5678', // CVE_ACKNOWLEDGED
    ])
    const ids = result.findings.map((f) => f.ruleId)
    expect(ids).toContain('REVERT_SECURITY_FIX')
    expect(ids).toContain('CVE_ACKNOWLEDGED')
  })

  it('single low finding → riskScore=3, riskLevel=low', () => {
    const result = analyzeCommitMessages(['hotfix for prod'])
    expect(result.riskScore).toBe(3)
    expect(result.riskLevel).toBe('low')
  })

  it('medium finding → riskScore=8, riskLevel=low', () => {
    const result = analyzeCommitMessages(['fixes CVE-2024-1234'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('high finding → riskScore=15, riskLevel=low', () => {
    const result = analyzeCommitMessages(['force merge'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('medium cap: four medium findings → riskScore=20 (cap)', () => {
    const result = analyzeCommitMessages([
      'TODO: add authentication',
      'TODO: add input validation',
      'FIXME: sanitize input',
      'FIXME: add authorization',
    ])
    // Each fires TODO_SECURITY_DEBT, 4×8=32, cap=20
    expect(result.mediumCount).toBe(4)
    expect(result.riskScore).toBe(20)
  })
})

// ---------------------------------------------------------------------------
// matchedMessage truncation
// ---------------------------------------------------------------------------

describe('matchedMessage truncation', () => {
  it('truncates messages longer than 120 chars', () => {
    const longMessage = 'disable auth check ' + 'x'.repeat(200)
    const result = analyzeCommitMessages([longMessage])
    const finding = result.findings[0]
    expect(finding.matchedMessage.length).toBeLessThanOrEqual(120)
    expect(finding.matchedMessage.endsWith('...')).toBe(true)
  })

  it('preserves messages shorter than 120 chars verbatim', () => {
    const msg = 'disable auth temporarily'
    const result = analyzeCommitMessages([msg])
    expect(result.findings[0].matchedMessage).toBe(msg)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('clean summary mentions message count', () => {
    const result = analyzeCommitMessages(['update readme', 'fix typo'])
    expect(result.summary).toMatch(/2 commit messages/)
  })

  it('critical summary mentions "security control bypass"', () => {
    const result = analyzeCommitMessages(['disable auth check'])
    expect(result.summary).toMatch(/security control bypass/i)
  })

  it('high summary mentions "high-risk"', () => {
    const result = analyzeCommitMessages(['force merge this PR'])
    expect(result.summary).toMatch(/high-risk/i)
  })
})
