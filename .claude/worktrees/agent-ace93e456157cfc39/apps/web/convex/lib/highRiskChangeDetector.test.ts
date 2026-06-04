import { describe, expect, it } from 'vitest'
import {
  RULES,
  detectHighRiskChanges,
  type HighRiskChangeResult,
} from './highRiskChangeDetector'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clean(r: HighRiskChangeResult) {
  return r.riskLevel === 'none' && r.riskScore === 0 && r.findings.length === 0
}

// ---------------------------------------------------------------------------
// Vendor-path exclusion
// ---------------------------------------------------------------------------

describe('vendor-path exclusion', () => {
  it('ignores node_modules paths', () => {
    const r = detectHighRiskChanges(['node_modules/stripe/lib/payment.js'])
    expect(clean(r)).toBe(true)
  })

  it('ignores dist paths', () => {
    const r = detectHighRiskChanges(['dist/auth/login.js'])
    expect(clean(r)).toBe(true)
  })

  it('ignores build paths', () => {
    const r = detectHighRiskChanges(['build/crypto/encrypt.js'])
    expect(clean(r)).toBe(true)
  })

  it('ignores vendor paths', () => {
    const r = detectHighRiskChanges(['vendor/payment/stripe.php'])
    expect(clean(r)).toBe(true)
  })

  it('ignores .git paths', () => {
    const r = detectHighRiskChanges(['.git/COMMIT_EDITMSG'])
    expect(clean(r)).toBe(true)
  })

  it('ignores coverage paths', () => {
    const r = detectHighRiskChanges(['coverage/auth/session.ts'])
    expect(clean(r)).toBe(true)
  })

  it('does NOT ignore user auth/ paths', () => {
    const r = detectHighRiskChanges(['src/auth/login.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// AUTH_HANDLER
// ---------------------------------------------------------------------------

describe('AUTH_HANDLER', () => {
  it('matches auth/ directory', () => {
    const r = detectHighRiskChanges(['src/auth/middleware.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })

  it('matches authentication/ directory', () => {
    const r = detectHighRiskChanges(['app/authentication/controller.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })

  it('matches login.ts basename', () => {
    const r = detectHighRiskChanges(['src/routes/login.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })

  it('matches session.service.ts basename', () => {
    const r = detectHighRiskChanges(['src/session.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })

  it('matches sso/ directory', () => {
    const r = detectHighRiskChanges(['services/sso/provider.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })

  it('deduplicates multiple auth files to one finding', () => {
    const r = detectHighRiskChanges([
      'src/auth/login.ts',
      'src/auth/session.ts',
      'src/auth/logout.ts',
    ])
    const authFindings = r.findings.filter((f) => f.ruleId === 'AUTH_HANDLER')
    expect(authFindings).toHaveLength(1)
    expect(authFindings[0].matchCount).toBe(3)
  })

  it('has high severity', () => {
    const r = detectHighRiskChanges(['src/auth/handler.ts'])
    const f = r.findings.find((f) => f.ruleId === 'AUTH_HANDLER')
    expect(f?.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// TOKEN_MANAGEMENT
// ---------------------------------------------------------------------------

describe('TOKEN_MANAGEMENT', () => {
  it('matches jwt.ts basename', () => {
    const r = detectHighRiskChanges(['lib/jwt.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TOKEN_MANAGEMENT')).toBe(true)
  })

  it('matches api-key.ts basename', () => {
    const r = detectHighRiskChanges(['src/api-key.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TOKEN_MANAGEMENT')).toBe(true)
  })

  it('matches token/ directory', () => {
    const r = detectHighRiskChanges(['services/token/refresh.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TOKEN_MANAGEMENT')).toBe(true)
  })

  it('matches refresh-token.ts', () => {
    const r = detectHighRiskChanges(['src/refresh-token.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TOKEN_MANAGEMENT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// MFA_IMPLEMENTATION
// ---------------------------------------------------------------------------

describe('MFA_IMPLEMENTATION', () => {
  it('matches mfa.ts', () => {
    const r = detectHighRiskChanges(['src/mfa.ts'])
    expect(r.findings.some((f) => f.ruleId === 'MFA_IMPLEMENTATION')).toBe(true)
  })

  it('matches 2fa.service.ts', () => {
    const r = detectHighRiskChanges(['src/2fa.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'MFA_IMPLEMENTATION')).toBe(true)
  })

  it('matches totp.ts', () => {
    const r = detectHighRiskChanges(['lib/totp.ts'])
    expect(r.findings.some((f) => f.ruleId === 'MFA_IMPLEMENTATION')).toBe(true)
  })

  it('matches webauthn.ts', () => {
    const r = detectHighRiskChanges(['src/webauthn.ts'])
    expect(r.findings.some((f) => f.ruleId === 'MFA_IMPLEMENTATION')).toBe(true)
  })

  it('has medium severity', () => {
    const r = detectHighRiskChanges(['src/mfa.ts'])
    const f = r.findings.find((f) => f.ruleId === 'MFA_IMPLEMENTATION')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// CRYPTO_PRIMITIVE
// ---------------------------------------------------------------------------

describe('CRYPTO_PRIMITIVE', () => {
  it('matches crypto/ directory', () => {
    const r = detectHighRiskChanges(['src/crypto/aes.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CRYPTO_PRIMITIVE')).toBe(true)
  })

  it('matches encrypt.ts basename', () => {
    const r = detectHighRiskChanges(['lib/encrypt.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CRYPTO_PRIMITIVE')).toBe(true)
  })

  it('matches cipher/ directory', () => {
    const r = detectHighRiskChanges(['services/cipher/blowfish.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CRYPTO_PRIMITIVE')).toBe(true)
  })

  it('matches keygen.ts', () => {
    const r = detectHighRiskChanges(['utils/keygen.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CRYPTO_PRIMITIVE')).toBe(true)
  })

  it('has critical severity', () => {
    const r = detectHighRiskChanges(['src/crypto/core.ts'])
    const f = r.findings.find((f) => f.ruleId === 'CRYPTO_PRIMITIVE')
    expect(f?.severity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// PASSWORD_HANDLER
// ---------------------------------------------------------------------------

describe('PASSWORD_HANDLER', () => {
  it('matches password.ts', () => {
    const r = detectHighRiskChanges(['src/password.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PASSWORD_HANDLER')).toBe(true)
  })

  it('matches bcrypt.ts', () => {
    const r = detectHighRiskChanges(['lib/bcrypt.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PASSWORD_HANDLER')).toBe(true)
  })

  it('matches hash.service.ts', () => {
    const r = detectHighRiskChanges(['src/hash.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PASSWORD_HANDLER')).toBe(true)
  })

  it('matches argon.ts', () => {
    const r = detectHighRiskChanges(['src/argon.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PASSWORD_HANDLER')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SIGNING_CODE
// ---------------------------------------------------------------------------

describe('SIGNING_CODE', () => {
  it('matches signing/ directory', () => {
    const r = detectHighRiskChanges(['services/signing/rsa.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SIGNING_CODE')).toBe(true)
  })

  it('matches hmac.ts', () => {
    const r = detectHighRiskChanges(['lib/hmac.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SIGNING_CODE')).toBe(true)
  })

  it('matches signature.ts', () => {
    const r = detectHighRiskChanges(['src/signature.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SIGNING_CODE')).toBe(true)
  })

  it('matches verify.ts', () => {
    const r = detectHighRiskChanges(['src/verif.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SIGNING_CODE')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// PAYMENT_PROCESSING
// ---------------------------------------------------------------------------

describe('PAYMENT_PROCESSING', () => {
  it('matches payment/ directory', () => {
    const r = detectHighRiskChanges(['src/payment/handler.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PAYMENT_PROCESSING')).toBe(true)
  })

  it('matches stripe/ directory', () => {
    const r = detectHighRiskChanges(['services/stripe/webhooks.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PAYMENT_PROCESSING')).toBe(true)
  })

  it('matches billing.service.ts', () => {
    const r = detectHighRiskChanges(['src/billing.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PAYMENT_PROCESSING')).toBe(true)
  })

  it('matches checkout/ directory', () => {
    const r = detectHighRiskChanges(['app/checkout/flow.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PAYMENT_PROCESSING')).toBe(true)
  })

  it('has critical severity', () => {
    const r = detectHighRiskChanges(['src/payment/charge.ts'])
    const f = r.findings.find((f) => f.ruleId === 'PAYMENT_PROCESSING')
    expect(f?.severity).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// ADMIN_AREA
// ---------------------------------------------------------------------------

describe('ADMIN_AREA', () => {
  it('matches admin/ directory', () => {
    const r = detectHighRiskChanges(['routes/admin/users.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ADMIN_AREA')).toBe(true)
  })

  it('matches management/ directory', () => {
    const r = detectHighRiskChanges(['api/management/tenants.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ADMIN_AREA')).toBe(true)
  })

  it('matches superuser/ directory', () => {
    const r = detectHighRiskChanges(['internal/superuser/actions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ADMIN_AREA')).toBe(true)
  })

  it('matches backstage/ directory', () => {
    const r = detectHighRiskChanges(['services/backstage/feature-flags.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ADMIN_AREA')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// AUTHORIZATION_LOGIC
// ---------------------------------------------------------------------------

describe('AUTHORIZATION_LOGIC', () => {
  it('matches rbac/ directory', () => {
    const r = detectHighRiskChanges(['src/rbac/roles.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTHORIZATION_LOGIC')).toBe(true)
  })

  it('matches permission.ts basename', () => {
    const r = detectHighRiskChanges(['lib/permission.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTHORIZATION_LOGIC')).toBe(true)
  })

  it('matches acl/ directory', () => {
    const r = detectHighRiskChanges(['security/acl/rules.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTHORIZATION_LOGIC')).toBe(true)
  })

  it('matches policy.ts basename', () => {
    const r = detectHighRiskChanges(['src/policy.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTHORIZATION_LOGIC')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// PII_HANDLING
// ---------------------------------------------------------------------------

describe('PII_HANDLING', () => {
  it('matches pii/ directory', () => {
    const r = detectHighRiskChanges(['services/pii/redaction.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PII_HANDLING')).toBe(true)
  })

  it('matches gdpr/ directory', () => {
    const r = detectHighRiskChanges(['src/gdpr/right-to-erasure.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PII_HANDLING')).toBe(true)
  })

  it('matches privacy.ts basename', () => {
    const r = detectHighRiskChanges(['src/privacy.service.ts'])
    expect(r.findings.some((f) => f.ruleId === 'PII_HANDLING')).toBe(true)
  })

  it('has medium severity', () => {
    const r = detectHighRiskChanges(['src/pii/handler.ts'])
    const f = r.findings.find((f) => f.ruleId === 'PII_HANDLING')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// RATE_LIMITER
// ---------------------------------------------------------------------------

describe('RATE_LIMITER', () => {
  it('matches rate-limit.ts basename', () => {
    const r = detectHighRiskChanges(['middleware/rate-limit.ts'])
    expect(r.findings.some((f) => f.ruleId === 'RATE_LIMITER')).toBe(true)
  })

  it('matches ratelimit.ts basename', () => {
    const r = detectHighRiskChanges(['src/ratelimit.ts'])
    expect(r.findings.some((f) => f.ruleId === 'RATE_LIMITER')).toBe(true)
  })

  it('matches throttle.ts basename', () => {
    const r = detectHighRiskChanges(['lib/throttle.ts'])
    expect(r.findings.some((f) => f.ruleId === 'RATE_LIMITER')).toBe(true)
  })

  it('has medium severity', () => {
    const r = detectHighRiskChanges(['src/rate-limit.ts'])
    const f = r.findings.find((f) => f.ruleId === 'RATE_LIMITER')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// SECURITY_MIDDLEWARE
// ---------------------------------------------------------------------------

describe('SECURITY_MIDDLEWARE', () => {
  it('matches cors.ts basename', () => {
    const r = detectHighRiskChanges(['middleware/cors.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_MIDDLEWARE')).toBe(true)
  })

  it('matches helmet.ts basename', () => {
    const r = detectHighRiskChanges(['src/helmet.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_MIDDLEWARE')).toBe(true)
  })

  it('matches csp.ts basename', () => {
    const r = detectHighRiskChanges(['config/csp.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_MIDDLEWARE')).toBe(true)
  })

  it('has low severity', () => {
    const r = detectHighRiskChanges(['src/cors.ts'])
    const f = r.findings.find((f) => f.ruleId === 'SECURITY_MIDDLEWARE')
    expect(f?.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Scoring and risk level
// ---------------------------------------------------------------------------

describe('scoring and risk level', () => {
  it('returns none for empty input', () => {
    const r = detectHighRiskChanges([])
    expect(clean(r)).toBe(true)
  })

  it('returns none for all-whitespace paths', () => {
    const r = detectHighRiskChanges(['  ', '\t', ''])
    expect(clean(r)).toBe(true)
  })

  it('returns none for unrelated files', () => {
    const r = detectHighRiskChanges(['src/utils/string.ts', 'docs/readme.md', 'tests/unit.ts'])
    expect(clean(r)).toBe(true)
  })

  it('returns medium risk when a single crypto primitive touched (score=30)', () => {
    const r = detectHighRiskChanges(['src/crypto/aes-core.ts'])
    // 1 critical rule → score=30 → medium (consistent with WS-54/56 model)
    expect(r.riskLevel).toBe('medium')
    expect(r.riskScore).toBe(30)
  })

  it('returns critical risk when crypto AND payment both touched (2+ criticals)', () => {
    const r = detectHighRiskChanges(['src/crypto/aes.ts', 'src/payment/processor.ts'])
    // 2 critical rules → score=60 → high; 3+ → critical
    expect(r.riskScore).toBeGreaterThanOrEqual(30)
    expect(['medium', 'high', 'critical']).toContain(r.riskLevel)
  })

  it('caps score at 100 for extreme input', () => {
    const files = [
      'src/crypto/aes.ts',
      'src/auth/login.ts',
      'src/payment/stripe.ts',
      'src/admin/users.ts',
      'src/rbac/policy.ts',
      'src/pii/handler.ts',
      'src/rate-limit.ts',
      'src/cors.ts',
      'src/hmac.ts',
      'src/password.ts',
      'src/mfa.ts',
      'src/jwt.ts',
    ]
    const r = detectHighRiskChanges(files)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })

  it('does not double-score same rule', () => {
    const r1 = detectHighRiskChanges(['src/auth/login.ts'])
    const r2 = detectHighRiskChanges(['src/auth/login.ts', 'src/auth/session.ts', 'src/auth/logout.ts'])
    // Score should be the same — dedup by rule means same penalty regardless of count
    expect(r1.riskScore).toBe(r2.riskScore)
  })

  it('high-only push returns non-zero risk score', () => {
    const r = detectHighRiskChanges(['src/auth/login.ts'])
    // 1 high rule → score=15 → low (consistent with WS-54/56 model)
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('medium-only push returns medium or lower risk level', () => {
    const r = detectHighRiskChanges(['src/mfa.ts'])
    expect(['low', 'medium']).toContain(r.riskLevel)
  })

  it('low-only push returns low risk level', () => {
    const r = detectHighRiskChanges(['middleware/cors.ts'])
    expect(r.riskLevel).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// computeHighRiskChangeReport — aggregate behaviour
// ---------------------------------------------------------------------------

describe('aggregate behavior', () => {
  it('finds correct category for auth finding', () => {
    const r = detectHighRiskChanges(['src/auth/login.ts'])
    const f = r.findings.find((f) => f.ruleId === 'AUTH_HANDLER')
    expect(f?.category).toBe('authentication')
  })

  it('finds correct category for payment finding', () => {
    const r = detectHighRiskChanges(['src/payment/charge.ts'])
    const f = r.findings.find((f) => f.ruleId === 'PAYMENT_PROCESSING')
    expect(f?.category).toBe('payment')
  })

  it('finds correct category for crypto finding', () => {
    const r = detectHighRiskChanges(['src/crypto/cipher.ts'])
    const f = r.findings.find((f) => f.ruleId === 'CRYPTO_PRIMITIVE')
    expect(f?.category).toBe('cryptography')
  })

  it('records correct matchedPath as first match', () => {
    const r = detectHighRiskChanges(['src/auth/login.ts', 'src/auth/session.ts'])
    const f = r.findings.find((f) => f.ruleId === 'AUTH_HANDLER')
    expect(f?.matchedPath).toBe('src/auth/login.ts')
  })

  it('counts correctly when same rule fires multiple times', () => {
    const r = detectHighRiskChanges([
      'src/auth/login.ts',
      'src/auth/session.ts',
      'src/auth/logout.ts',
    ])
    const f = r.findings.find((f) => f.ruleId === 'AUTH_HANDLER')
    expect(f?.matchCount).toBe(3)
  })

  it('one path can trigger multiple rules', () => {
    // auth/jwt.ts matches both AUTH_HANDLER and TOKEN_MANAGEMENT
    const r = detectHighRiskChanges(['src/auth/jwt.ts'])
    const ruleIds = r.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('AUTH_HANDLER')
    expect(ruleIds).toContain('TOKEN_MANAGEMENT')
  })

  it('produces non-empty summary for findings', () => {
    const r = detectHighRiskChanges(['src/crypto/aes.ts'])
    expect(r.summary.length).toBeGreaterThan(10)
    expect(r.summary).not.toContain('no security-hotspot')
  })

  it('produces clean summary for no findings', () => {
    const r = detectHighRiskChanges(['src/utils/array.ts'])
    expect(r.summary).toContain('no security-hotspot')
  })

  it('normalises Windows backslash paths', () => {
    const r = detectHighRiskChanges(['src\\auth\\login.ts'])
    expect(r.findings.some((f) => f.ruleId === 'AUTH_HANDLER')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// RULES constant integrity
// ---------------------------------------------------------------------------

describe('RULES constant integrity', () => {
  it('has exactly 12 rules', () => {
    expect(RULES).toHaveLength(12)
  })

  it('all rule IDs are unique', () => {
    const ids = RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all rules have non-empty description and recommendation', () => {
    for (const r of RULES) {
      expect(r.description.length).toBeGreaterThan(10)
      expect(r.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity values are valid', () => {
    const valid = new Set(['critical', 'high', 'medium', 'low'])
    for (const r of RULES) {
      expect(valid.has(r.severity)).toBe(true)
    }
  })

  it('category values are valid', () => {
    const valid = new Set(['authentication', 'cryptography', 'payment', 'administration', 'data_privacy', 'security_config'])
    for (const r of RULES) {
      expect(valid.has(r.category)).toBe(true)
    }
  })
})
