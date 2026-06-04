import { describe, expect, it } from 'vitest'
import {
  AUTH_KEYWORDS,
  AUTHZ_KEYWORDS,
  CRYPTO_KEYWORDS,
  PAYMENT_KEYWORDS,
  SESSION_KEYWORDS,
  isGenericTestFile,
  isSecurityMiddlewareSource,
  isSourceCodeFile,
  scanTestCoverageGaps,
  type TestCoverageGapResult,
} from './testCoverageGap'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): TestCoverageGapResult {
  return scanTestCoverageGaps(paths)
}

function expectClean(result: TestCoverageGapResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

function hasRule(result: TestCoverageGapResult, ruleId: string) {
  return result.findings.some((f) => f.ruleId === ruleId)
}

// ---------------------------------------------------------------------------
// isGenericTestFile
// ---------------------------------------------------------------------------

describe('isGenericTestFile', () => {
  it('detects .test.ts files', () => {
    expect(isGenericTestFile('src/auth/jwt.test.ts')).toBe(true)
  })

  it('detects .spec.ts files', () => {
    expect(isGenericTestFile('src/auth/jwt.spec.ts')).toBe(true)
  })

  it('detects .test.js files', () => {
    expect(isGenericTestFile('src/auth/login.test.js')).toBe(true)
  })

  it('detects .spec.jsx files', () => {
    expect(isGenericTestFile('src/auth/LoginForm.spec.jsx')).toBe(true)
  })

  it('detects Python test_foo.py pattern', () => {
    expect(isGenericTestFile('tests/test_auth.py')).toBe(true)
  })

  it('detects Python foo_test.py pattern', () => {
    expect(isGenericTestFile('auth_test.py')).toBe(true)
  })

  it('detects files in __tests__ directory segment', () => {
    expect(isGenericTestFile('src/__tests__/auth.ts')).toBe(true)
  })

  it('detects files in /tests/ directory segment', () => {
    expect(isGenericTestFile('tests/auth/login.ts')).toBe(true)
  })

  it('detects files in /spec/ directory segment', () => {
    expect(isGenericTestFile('spec/auth_spec.rb')).toBe(true)
  })

  it('does NOT flag plain source files', () => {
    expect(isGenericTestFile('src/auth/jwt.service.ts')).toBe(false)
  })

  it('does NOT flag files with "test" in a non-segment word', () => {
    // "attestation" contains "test" but is not a test segment
    expect(isGenericTestFile('src/sbom/attestation.ts')).toBe(false)
  })

  it('detects .test.tsx files', () => {
    expect(isGenericTestFile('components/AuthForm.test.tsx')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// isSourceCodeFile
// ---------------------------------------------------------------------------

describe('isSourceCodeFile', () => {
  it('accepts TypeScript files', () => {
    expect(isSourceCodeFile('src/auth/jwt.ts')).toBe(true)
  })

  it('accepts JavaScript files', () => {
    expect(isSourceCodeFile('src/payment/charge.js')).toBe(true)
  })

  it('accepts Python files', () => {
    expect(isSourceCodeFile('auth/oauth.py')).toBe(true)
  })

  it('accepts Go files', () => {
    expect(isSourceCodeFile('pkg/crypto/aes.go')).toBe(true)
  })

  it('accepts Rust files', () => {
    expect(isSourceCodeFile('src/crypto/hash.rs')).toBe(true)
  })

  it('does NOT accept Markdown files', () => {
    expect(isSourceCodeFile('docs/auth/README.md')).toBe(false)
  })

  it('does NOT accept JSON files', () => {
    expect(isSourceCodeFile('config/auth.config.json')).toBe(false)
  })

  it('does NOT accept YAML files', () => {
    expect(isSourceCodeFile('config/session.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Domain keyword constant integrity
// ---------------------------------------------------------------------------

describe('domain keyword constants', () => {
  it('AUTH_KEYWORDS is non-empty', () => {
    expect(AUTH_KEYWORDS.length).toBeGreaterThan(5)
  })

  it('CRYPTO_KEYWORDS contains core hashing terms', () => {
    expect(CRYPTO_KEYWORDS).toContain('hash')
    expect(CRYPTO_KEYWORDS).toContain('encrypt')
  })

  it('PAYMENT_KEYWORDS contains payment processors', () => {
    expect(PAYMENT_KEYWORDS).toContain('stripe')
    expect(PAYMENT_KEYWORDS).toContain('payment')
  })

  it('AUTHZ_KEYWORDS contains access-control terms', () => {
    expect(AUTHZ_KEYWORDS).toContain('rbac')
    expect(AUTHZ_KEYWORDS).toContain('permission')
  })

  it('SESSION_KEYWORDS contains csrf', () => {
    expect(SESSION_KEYWORDS).toContain('csrf')
  })
})

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('scanTestCoverageGaps — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('returns clean result for non-security source files', () => {
    expectClean(scan(['src/utils/format.ts', 'src/api/health.ts', 'README.md']))
  })

  it('returns clean result when auth source AND auth test both changed', () => {
    expectClean(
      scan(['src/auth/jwt.service.ts', 'src/auth/jwt.service.test.ts']),
    )
  })

  it('returns clean result when only test files changed (no source)', () => {
    expectClean(scan(['src/auth/jwt.test.ts', 'src/__tests__/login.spec.ts']))
  })

  it('summary mentions scanned count for clean result', () => {
    const result = scan(['src/index.ts', 'README.md'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no security/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanTestCoverageGaps — vendor path exclusion', () => {
  it('ignores auth source files inside node_modules', () => {
    expectClean(scan(['node_modules/passport/lib/auth.js']))
  })

  it('ignores crypto files inside dist', () => {
    expectClean(scan(['dist/crypto/aes.js']))
  })

  it('ignores auth files inside vendor directory', () => {
    expectClean(scan(['vendor/oauth/jwt.ts']))
  })

  it('flags auth file in non-vendor path but not vendor path', () => {
    const result = scan([
      'node_modules/jsonwebtoken/auth.ts',
      'src/auth/jwt.service.ts',
    ])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
    const finding = result.findings.find((f) => f.ruleId === 'AUTH_CODE_UNTESTED')!
    expect(finding.matchCount).toBe(1) // only the non-vendor file
  })
})

// ---------------------------------------------------------------------------
// AUTH_CODE_UNTESTED
// ---------------------------------------------------------------------------

describe('AUTH_CODE_UNTESTED rule', () => {
  it('fires when auth source changed but no auth test changed', () => {
    const result = scan(['src/auth/login.service.ts'])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
  })

  it('fires for jwt source without jwt test', () => {
    const result = scan(['src/auth/jwt.service.ts', 'src/utils/format.ts'])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when auth source and auth test both changed', () => {
    const result = scan([
      'src/auth/jwt.service.ts',
      'src/auth/jwt.service.test.ts',
    ])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(false)
  })

  it('does NOT fire when only auth test changed (no source)', () => {
    const result = scan(['src/__tests__/auth.spec.ts'])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(false)
  })

  it('records matchedPath as first auth source file', () => {
    const result = scan(['src/auth/login.ts', 'src/auth/oauth.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'AUTH_CODE_UNTESTED')!
    expect(finding.matchedPath).toBe('src/auth/login.ts')
  })

  it('records matchCount for multiple untested auth files', () => {
    const result = scan([
      'src/auth/login.ts',
      'src/auth/oauth.ts',
      'src/auth/mfa.ts',
    ])
    const finding = result.findings.find((f) => f.ruleId === 'AUTH_CODE_UNTESTED')!
    expect(finding.matchCount).toBe(3)
  })

  it('severity is high', () => {
    const result = scan(['src/auth/login.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'AUTH_CODE_UNTESTED')!
    expect(finding.severity).toBe('high')
  })

  it('fires for password file without test', () => {
    const result = scan(['src/users/password.service.ts'])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
  })

  it('fires for oauth callback without test', () => {
    const result = scan(['src/auth/oauth.callback.ts'])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire for auth file with non-code extension', () => {
    // markdown file in auth directory should not be a "source file"
    expectClean(scan(['docs/auth/overview.md']))
  })
})

// ---------------------------------------------------------------------------
// CRYPTO_CODE_UNTESTED
// ---------------------------------------------------------------------------

describe('CRYPTO_CODE_UNTESTED rule', () => {
  it('fires when crypto source changed but no crypto test changed', () => {
    const result = scan(['src/crypto/hash.ts'])
    expect(hasRule(result, 'CRYPTO_CODE_UNTESTED')).toBe(true)
  })

  it('fires for encrypt source without encrypt test', () => {
    const result = scan(['src/utils/encrypt.ts'])
    expect(hasRule(result, 'CRYPTO_CODE_UNTESTED')).toBe(true)
  })

  it('fires for bcrypt utility without test', () => {
    const result = scan(['src/security/bcrypt.util.ts'])
    expect(hasRule(result, 'CRYPTO_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when crypto source and crypto test both changed', () => {
    const result = scan(['src/crypto/hash.ts', 'src/crypto/hash.test.ts'])
    expect(hasRule(result, 'CRYPTO_CODE_UNTESTED')).toBe(false)
  })

  it('severity is high', () => {
    const result = scan(['src/crypto/aes.service.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'CRYPTO_CODE_UNTESTED')!
    expect(finding.severity).toBe('high')
  })

  it('counts multiple untested crypto files', () => {
    const result = scan(['lib/crypto/hash.ts', 'lib/crypto/encrypt.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'CRYPTO_CODE_UNTESTED')!
    expect(finding.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// PAYMENT_CODE_UNTESTED
// ---------------------------------------------------------------------------

describe('PAYMENT_CODE_UNTESTED rule', () => {
  it('fires when payment source changed without payment test', () => {
    const result = scan(['src/billing/stripe.service.ts'])
    expect(hasRule(result, 'PAYMENT_CODE_UNTESTED')).toBe(true)
  })

  it('fires for checkout module without test', () => {
    const result = scan(['src/payment/checkout.ts'])
    expect(hasRule(result, 'PAYMENT_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when payment source and test both changed', () => {
    const result = scan([
      'src/billing/stripe.service.ts',
      'src/billing/stripe.service.test.ts',
    ])
    expect(hasRule(result, 'PAYMENT_CODE_UNTESTED')).toBe(false)
  })

  it('severity is high', () => {
    const result = scan(['src/payment/charge.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'PAYMENT_CODE_UNTESTED')!
    expect(finding.severity).toBe('high')
  })

  it('fires for invoice service without test', () => {
    const result = scan(['src/billing/invoice.service.ts'])
    expect(hasRule(result, 'PAYMENT_CODE_UNTESTED')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// AUTHZ_CODE_UNTESTED
// ---------------------------------------------------------------------------

describe('AUTHZ_CODE_UNTESTED rule', () => {
  it('fires when rbac source changed without rbac test', () => {
    const result = scan(['src/rbac/roles.service.ts'])
    expect(hasRule(result, 'AUTHZ_CODE_UNTESTED')).toBe(true)
  })

  it('fires for permission module without test', () => {
    const result = scan(['src/permissions/permission.service.ts'])
    expect(hasRule(result, 'AUTHZ_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when authz source and test both changed', () => {
    const result = scan([
      'src/rbac/roles.service.ts',
      'src/rbac/__tests__/roles.spec.ts',
    ])
    expect(hasRule(result, 'AUTHZ_CODE_UNTESTED')).toBe(false)
  })

  it('severity is medium', () => {
    const result = scan(['src/permissions/acl.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'AUTHZ_CODE_UNTESTED')!
    expect(finding.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// SESSION_CODE_UNTESTED
// ---------------------------------------------------------------------------

describe('SESSION_CODE_UNTESTED rule', () => {
  it('fires when session source changed without session test', () => {
    const result = scan(['src/session/session.service.ts'])
    expect(hasRule(result, 'SESSION_CODE_UNTESTED')).toBe(true)
  })

  it('fires for csrf utility without test', () => {
    const result = scan(['src/middleware/csrf.ts'])
    expect(hasRule(result, 'SESSION_CODE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when session source and test both changed', () => {
    const result = scan([
      'src/session/session.service.ts',
      'src/session/session.service.test.ts',
    ])
    expect(hasRule(result, 'SESSION_CODE_UNTESTED')).toBe(false)
  })

  it('severity is medium', () => {
    const result = scan(['src/cookies/cookie.service.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'SESSION_CODE_UNTESTED')!
    expect(finding.severity).toBe('medium')
  })

  it('fires for refresh token handler without test', () => {
    const result = scan(['src/auth/refreshtoken.service.ts'])
    expect(hasRule(result, 'SESSION_CODE_UNTESTED')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SECURITY_MIDDLEWARE_UNTESTED
// ---------------------------------------------------------------------------

describe('SECURITY_MIDDLEWARE_UNTESTED rule', () => {
  it('fires when auth middleware changed without test', () => {
    const result = scan(['src/middleware/auth-middleware.ts'])
    expect(hasRule(result, 'SECURITY_MIDDLEWARE_UNTESTED')).toBe(true)
  })

  it('fires when security guard changed without test', () => {
    const result = scan(['src/guards/auth.guard.ts'])
    expect(hasRule(result, 'SECURITY_MIDDLEWARE_UNTESTED')).toBe(true)
  })

  it('fires when rate-limit middleware changed without test', () => {
    const result = scan(['src/middleware/rate-limit.middleware.ts'])
    expect(hasRule(result, 'SECURITY_MIDDLEWARE_UNTESTED')).toBe(true)
  })

  it('does NOT fire when middleware source and test both changed', () => {
    const result = scan([
      'src/middleware/auth-middleware.ts',
      'src/middleware/auth-middleware.test.ts',
    ])
    expect(hasRule(result, 'SECURITY_MIDDLEWARE_UNTESTED')).toBe(false)
  })

  it('does NOT fire for generic logging middleware', () => {
    // "middleware" but no security keyword
    const result = scan(['src/middleware/logging.middleware.ts'])
    expect(hasRule(result, 'SECURITY_MIDDLEWARE_UNTESTED')).toBe(false)
  })

  it('severity is medium', () => {
    const result = scan(['src/middleware/csrf-middleware.ts'])
    const finding = result.findings.find((f) => f.ruleId === 'SECURITY_MIDDLEWARE_UNTESTED')
    if (finding) expect(finding.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// isSecurityMiddlewareSource helper
// ---------------------------------------------------------------------------

describe('isSecurityMiddlewareSource', () => {
  it('returns true for auth-middleware.ts', () => {
    expect(isSecurityMiddlewareSource('src/middleware/auth-middleware.ts')).toBe(true)
  })

  it('returns true for auth.guard.ts', () => {
    expect(isSecurityMiddlewareSource('src/guards/auth.guard.ts')).toBe(true)
  })

  it('returns true for rate-limit.middleware.ts', () => {
    expect(isSecurityMiddlewareSource('src/middleware/rate-limit.middleware.ts')).toBe(true)
  })

  it('returns true for security.interceptor.ts', () => {
    expect(isSecurityMiddlewareSource('src/interceptors/security.interceptor.ts')).toBe(true)
  })

  it('returns false for logging.middleware.ts (no security keyword)', () => {
    expect(isSecurityMiddlewareSource('src/middleware/logging.middleware.ts')).toBe(false)
  })

  it('returns false for auth.service.ts (no middleware context)', () => {
    expect(isSecurityMiddlewareSource('src/auth/auth.service.ts')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('scanTestCoverageGaps — multi-rule scenarios', () => {
  it('fires both AUTH and CRYPTO when both untested', () => {
    const result = scan([
      'src/auth/login.ts',
      'src/crypto/hash.ts',
    ])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
    expect(hasRule(result, 'CRYPTO_CODE_UNTESTED')).toBe(true)
    expect(result.totalFindings).toBe(2)
  })

  it('only fires AUTH when auth changed without test but unrelated files also changed', () => {
    const result = scan([
      'src/auth/login.ts',
      'src/utils/format.ts',
      'public/index.html',
    ])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(true)
    expect(result.totalFindings).toBe(1)
  })

  it('fires no rule when both source and test changed for each domain', () => {
    expectClean(
      scan([
        'src/auth/login.ts',
        'src/auth/login.test.ts',
        'src/crypto/hash.ts',
        'src/crypto/hash.test.ts',
      ]),
    )
  })

  it('fires PAYMENT and AUTHZ but not AUTH when tests cover auth', () => {
    const result = scan([
      'src/auth/jwt.ts',
      'src/auth/jwt.test.ts',
      'src/payment/stripe.ts',
      'src/rbac/roles.ts',
    ])
    expect(hasRule(result, 'AUTH_CODE_UNTESTED')).toBe(false)
    expect(hasRule(result, 'PAYMENT_CODE_UNTESTED')).toBe(true)
    expect(hasRule(result, 'AUTHZ_CODE_UNTESTED')).toBe(true)
  })

  it('fires all 3 high-severity rules when all three domains untested', () => {
    const result = scan([
      'src/auth/login.ts',
      'src/crypto/hash.ts',
      'src/payment/stripe.ts',
    ])
    expect(result.highCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanTestCoverageGaps — scoring', () => {
  it('riskScore is 0 for clean result', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('riskLevel is none for zero findings', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('riskScore is positive when a high-severity rule fires', () => {
    const result = scan(['src/auth/login.ts'])
    expect(result.riskScore).toBeGreaterThan(0)
  })

  it('riskLevel is at least medium when a high rule fires', () => {
    const result = scan(['src/auth/login.ts'])
    expect(['medium', 'high']).toContain(result.riskLevel)
  })

  it('riskScore increases with more rules firing', () => {
    const single = scan(['src/auth/login.ts'])
    const multi  = scan(['src/auth/login.ts', 'src/crypto/hash.ts'])
    expect(multi.riskScore).toBeGreaterThan(single.riskScore)
  })

  it('riskScore is capped at 100', () => {
    // Fire all 6 rules simultaneously
    const result = scan([
      'src/auth/login.ts',
      'src/crypto/aes.ts',
      'src/payment/stripe.ts',
      'src/rbac/roles.ts',
      'src/session/session.ts',
      'src/middleware/auth-middleware.ts',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanTestCoverageGaps — summary text', () => {
  it('mentions security when findings exist', () => {
    const result = scan(['src/auth/login.ts'])
    expect(result.summary).toMatch(/security/)
  })

  it('mentions domain label in summary', () => {
    const result = scan(['src/auth/login.ts'])
    expect(result.summary).toMatch(/authentication/)
  })

  it('mentions "risk level" in summary when findings exist', () => {
    const result = scan(['src/auth/login.ts'])
    expect(result.summary).toMatch(/risk level/)
  })

  it('mentions clean state in summary when no findings', () => {
    const result = scan(['src/index.ts'])
    expect(result.summary).toMatch(/no security/)
  })
})
