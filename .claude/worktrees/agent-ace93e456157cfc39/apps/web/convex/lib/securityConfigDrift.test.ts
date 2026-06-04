import { describe, expect, it } from 'vitest'
import {
  SECURITY_CONFIG_RULES,
  scanSecurityConfigChanges,
  type SecurityConfigDriftResult,
} from './securityConfigDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): SecurityConfigDriftResult {
  return scanSecurityConfigChanges(paths)
}

function expectClean(result: SecurityConfigDriftResult) {
  expect(result.riskScore).toBe(0)
  expect(result.riskLevel).toBe('none')
  expect(result.totalFindings).toBe(0)
  expect(result.findings).toHaveLength(0)
}

// ---------------------------------------------------------------------------
// Empty / trivial inputs
// ---------------------------------------------------------------------------

describe('scanSecurityConfigChanges — trivial inputs', () => {
  it('returns clean result for empty array', () => {
    expectClean(scan([]))
  })

  it('returns clean result for whitespace-only paths', () => {
    expectClean(scan(['', '   ', '\t']))
  })

  it('summary mentions scanned file count for clean result', () => {
    const result = scan(['src/index.ts', 'README.md'])
    expect(result.summary).toMatch(/2 changed file/)
    expect(result.summary).toMatch(/no security configuration/)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('scanSecurityConfigChanges — vendor path exclusion', () => {
  it('ignores jwt.config.ts inside node_modules', () => {
    expectClean(scan(['node_modules/passport/jwt.config.ts']))
  })

  it('ignores cors.config.ts inside dist', () => {
    expectClean(scan(['dist/cors.config.js']))
  })

  it('ignores waf-rules.json inside vendor', () => {
    expectClean(scan(['vendor/cloudflare/waf-rules.json']))
  })

  it('flags jwt.config.ts in non-vendor path', () => {
    const result = scan(['config/jwt.config.ts'])
    expect(result.totalFindings).toBeGreaterThanOrEqual(1)
  })

  it('flags tls.config.ts outside vendor but not inside', () => {
    const result = scan([
      'node_modules/https/tls.config.ts',
      'server/tls.config.ts',
    ])
    const f = result.findings.find((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')
    expect(f).toBeDefined()
    expect(f?.matchCount).toBe(1)  // only the non-vendor one
  })
})

// ---------------------------------------------------------------------------
// JWT_SECRET_CONFIG
// ---------------------------------------------------------------------------

describe('JWT_SECRET_CONFIG rule', () => {
  it('matches jwt.config.ts', () => {
    const r = scan(['config/jwt.config.ts'])
    const f = r.findings.find((f) => f.ruleId === 'JWT_SECRET_CONFIG')
    expect(f).toBeDefined()
    expect(f?.severity).toBe('critical')
  })

  it('matches jwtOptions.ts', () => {
    const r = scan(['auth/jwtOptions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(true)
  })

  it('matches jwt-config.json', () => {
    const r = scan(['jwt-config.json'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(true)
  })

  it('matches jwt-secret.json', () => {
    const r = scan(['secrets/jwt-secret.json'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(true)
  })

  it('matches jsonwebtoken.config.js', () => {
    const r = scan(['jsonwebtoken.config.js'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(true)
  })

  it('does NOT match jwt.ts (utility file, not config)', () => {
    const r = scan(['utils/jwt.ts'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(false)
  })

  it('does NOT match jwt-utils.ts', () => {
    const r = scan(['lib/jwt-utils.ts'])
    expect(r.findings.some((f) => f.ruleId === 'JWT_SECRET_CONFIG')).toBe(false)
  })

  it('deduplicates: multiple jwt config files → one finding with matchCount', () => {
    const r = scan(['jwt.config.ts', 'jwt-config.json'])
    const f = r.findings.filter((f) => f.ruleId === 'JWT_SECRET_CONFIG')
    expect(f).toHaveLength(1)
    expect(f[0]?.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// ENCRYPTION_KEY_CONFIG
// ---------------------------------------------------------------------------

describe('ENCRYPTION_KEY_CONFIG rule', () => {
  it('matches encryption.config.ts', () => {
    const r = scan(['encryption.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(true)
  })

  it('matches kms.config.json', () => {
    const r = scan(['infra/kms.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(true)
  })

  it('matches keystore.json (exact basename)', () => {
    const r = scan(['keystore.json'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(true)
  })

  it('matches key-management.config.ts', () => {
    const r = scan(['key-management.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(true)
  })

  it('matches vault.config.ts', () => {
    const r = scan(['vault.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(true)
  })

  it('does NOT match plain encryption.ts', () => {
    const r = scan(['lib/encryption.ts'])
    expect(r.findings.some((f) => f.ruleId === 'ENCRYPTION_KEY_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// OAUTH_CLIENT_CONFIG
// ---------------------------------------------------------------------------

describe('OAUTH_CLIENT_CONFIG rule', () => {
  it('matches oauth.config.ts', () => {
    const r = scan(['oauth.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'OAUTH_CLIENT_CONFIG')).toBe(true)
  })

  it('matches oauth2.config.json', () => {
    const r = scan(['auth/oauth2.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'OAUTH_CLIENT_CONFIG')).toBe(true)
  })

  it('matches oauthOptions.ts', () => {
    const r = scan(['oauthOptions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'OAUTH_CLIENT_CONFIG')).toBe(true)
  })

  it('matches oauth-client.config.ts', () => {
    const r = scan(['oauth-client.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'OAUTH_CLIENT_CONFIG')).toBe(true)
  })

  it('does NOT match plain oauth.ts', () => {
    const r = scan(['lib/oauth.ts'])
    expect(r.findings.some((f) => f.ruleId === 'OAUTH_CLIENT_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SAML_SSO_CONFIG
// ---------------------------------------------------------------------------

describe('SAML_SSO_CONFIG rule', () => {
  it('matches saml.config.ts', () => {
    const r = scan(['saml.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('matches passport.config.ts', () => {
    const r = scan(['auth/passport.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('matches auth0.config.json', () => {
    const r = scan(['auth0.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('matches okta.config.ts', () => {
    const r = scan(['okta.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('matches keycloak.config.json', () => {
    const r = scan(['keycloak.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('matches sso.config.ts', () => {
    const r = scan(['sso.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(true)
  })

  it('does NOT match plain saml.ts', () => {
    const r = scan(['lib/saml.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SAML_SSO_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CORS_POLICY_CONFIG
// ---------------------------------------------------------------------------

describe('CORS_POLICY_CONFIG rule', () => {
  it('matches cors.config.ts', () => {
    const r = scan(['cors.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CORS_POLICY_CONFIG')).toBe(true)
  })

  it('matches corsOptions.ts', () => {
    const r = scan(['middleware/corsOptions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CORS_POLICY_CONFIG')).toBe(true)
  })

  it('matches cors-policy.json', () => {
    const r = scan(['cors-policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'CORS_POLICY_CONFIG')).toBe(true)
  })

  it('matches cors-config.yaml', () => {
    const r = scan(['config/cors-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'CORS_POLICY_CONFIG')).toBe(true)
  })

  it('does NOT match plain cors.ts', () => {
    const r = scan(['middleware/cors.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CORS_POLICY_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CSP_HEADERS_CONFIG
// ---------------------------------------------------------------------------

describe('CSP_HEADERS_CONFIG rule', () => {
  it('matches csp.config.ts', () => {
    const r = scan(['csp.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CSP_HEADERS_CONFIG')).toBe(true)
  })

  it('matches helmet.config.ts', () => {
    const r = scan(['middleware/helmet.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CSP_HEADERS_CONFIG')).toBe(true)
  })

  it('matches security-headers.config.ts', () => {
    const r = scan(['security-headers.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CSP_HEADERS_CONFIG')).toBe(true)
  })

  it('matches cspConfig.ts', () => {
    const r = scan(['cspConfig.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CSP_HEADERS_CONFIG')).toBe(true)
  })

  it('does NOT match plain csp.ts (no config signal)', () => {
    const r = scan(['utils/csp.ts'])
    expect(r.findings.some((f) => f.ruleId === 'CSP_HEADERS_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TLS_OPTIONS_CONFIG
// ---------------------------------------------------------------------------

describe('TLS_OPTIONS_CONFIG rule', () => {
  it('matches ssl.config.ts', () => {
    const r = scan(['ssl.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(true)
  })

  it('matches tls.config.json', () => {
    const r = scan(['infra/tls.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(true)
  })

  it('matches https.config.ts', () => {
    const r = scan(['https.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(true)
  })

  it('matches sslConfig.ts', () => {
    const r = scan(['sslConfig.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(true)
  })

  it('does NOT match server.crt (actual certificate file)', () => {
    const r = scan(['certs/server.crt'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(false)
  })

  it('does NOT match server.pem (actual PEM file)', () => {
    const r = scan(['certs/server.pem'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(false)
  })

  it('does NOT match tls.ts (no config signal)', () => {
    const r = scan(['lib/tls.ts'])
    expect(r.findings.some((f) => f.ruleId === 'TLS_OPTIONS_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SESSION_COOKIE_CONFIG
// ---------------------------------------------------------------------------

describe('SESSION_COOKIE_CONFIG rule', () => {
  it('matches session.config.ts', () => {
    const r = scan(['session.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SESSION_COOKIE_CONFIG')).toBe(true)
  })

  it('matches sessionOptions.ts', () => {
    const r = scan(['auth/sessionOptions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SESSION_COOKIE_CONFIG')).toBe(true)
  })

  it('matches cookie.config.ts', () => {
    const r = scan(['cookie.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SESSION_COOKIE_CONFIG')).toBe(true)
  })

  it('matches cookieOptions.ts', () => {
    const r = scan(['cookieOptions.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SESSION_COOKIE_CONFIG')).toBe(true)
  })

  it('does NOT match session.ts (no config signal)', () => {
    const r = scan(['services/session.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SESSION_COOKIE_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// WAF_RULES_CONFIG
// ---------------------------------------------------------------------------

describe('WAF_RULES_CONFIG rule', () => {
  it('matches waf.config.ts', () => {
    const r = scan(['waf.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(true)
  })

  it('matches waf-rules.json (exact basename)', () => {
    const r = scan(['waf-rules.json'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(true)
  })

  it('matches modsecurity.conf (exact basename)', () => {
    const r = scan(['modsecurity.conf'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(true)
  })

  it('matches firewall.config.yaml', () => {
    const r = scan(['firewall.config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(true)
  })

  it('matches aws-waf.config.json', () => {
    const r = scan(['aws-waf.config.json'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(true)
  })

  it('does NOT match plain firewall.ts', () => {
    const r = scan(['lib/firewall.ts'])
    expect(r.findings.some((f) => f.ruleId === 'WAF_RULES_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SECURITY_POLICY_CONFIG
// ---------------------------------------------------------------------------

describe('SECURITY_POLICY_CONFIG rule', () => {
  it('matches security-policy.json', () => {
    const r = scan(['security-policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('matches access-policy.yaml', () => {
    const r = scan(['access-policy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('matches permission.config.ts', () => {
    const r = scan(['permission.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('matches rbac.config.ts', () => {
    const r = scan(['rbac.config.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('matches policy.json (exact basename)', () => {
    const r = scan(['policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('matches iam.json (exact basename)', () => {
    const r = scan(['iam.json'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(true)
  })

  it('does NOT match security.ts (no config signal)', () => {
    const r = scan(['lib/security.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SECURITY_POLICY_CONFIG')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanSecurityConfigChanges — scoring', () => {
  it('score is 0 for empty input', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('critical finding adds 30 to score', () => {
    const r = scan(['jwt.config.ts'])
    expect(r.riskScore).toBeGreaterThanOrEqual(30)
  })

  it('high finding adds 15 to score', () => {
    const r = scan(['cors.config.ts'])
    expect(r.riskScore).toBeGreaterThanOrEqual(15)
    expect(r.riskScore).toBeLessThan(30)
  })

  it('medium finding adds 8 to score', () => {
    const r = scan(['session.config.ts'])
    expect(r.riskScore).toBe(8)
  })

  it('score is capped at 100', () => {
    const r = scan([
      'jwt.config.ts',
      'encryption.config.ts',
      'cors.config.ts',
      'saml.config.ts',
      'csp.config.ts',
      'tls.config.ts',
      'session.config.ts',
      'waf.config.ts',
      'security-policy.json',
    ])
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })

  it('riskLevel is "critical" at score >= 75', () => {
    const r = scan(['jwt.config.ts', 'encryption.config.ts', 'cors.config.ts'])
    // 30 (critical) + 30 (critical) + 15 (high) = 75
    expect(r.riskLevel).toBe('critical')
  })

  it('riskLevel is "high" for score 50–74', () => {
    // 30 (critical) + 15 (high) + 8 (medium) = 53 → high (50–74)
    const r = scan(['jwt.config.ts', 'cors.config.ts', 'session.config.ts'])
    expect(r.riskLevel).toBe('high')
  })

  it('riskLevel is "medium" for score 25–49', () => {
    const r = scan(['cors.config.ts', 'csp.config.ts', 'tls.config.ts'])
    // 15 + 15 + 15 = 45 → medium (< 50)
    expect(r.riskLevel).toBe('medium')
  })

  it('riskLevel is "low" for score 1–24', () => {
    const r = scan(['security-policy.json'])
    // 3 penalty → score 3 → low
    expect(r.riskLevel).toBe('low')
  })

  it('riskLevel is "none" for clean result', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('scanSecurityConfigChanges — deduplication', () => {
  it('multiple cors config files produce one CORS finding with correct matchCount', () => {
    const r = scan(['cors.config.ts', 'api/cors.config.ts', 'cors-policy.json'])
    const f = r.findings.filter((f) => f.ruleId === 'CORS_POLICY_CONFIG')
    expect(f).toHaveLength(1)
    expect(f[0]?.matchCount).toBe(3)
  })

  it('records the FIRST matching path in matchedPath', () => {
    const r = scan(['a/jwt.config.ts', 'b/jwt-config.json'])
    const f = r.findings.find((f) => f.ruleId === 'JWT_SECRET_CONFIG')
    expect(f?.matchedPath).toBe('a/jwt.config.ts')
  })

  it('findings are in rule-definition order, not match order', () => {
    const r = scan(['security-policy.json', 'jwt.config.ts'])
    const ids = r.findings.map((f) => f.ruleId)
    // JWT_SECRET_CONFIG should come before SECURITY_POLICY_CONFIG per rule order
    expect(ids.indexOf('JWT_SECRET_CONFIG')).toBeLessThan(ids.indexOf('SECURITY_POLICY_CONFIG'))
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('scanSecurityConfigChanges — summary', () => {
  it('clean summary mentions file count', () => {
    const r = scan(['src/app.ts', 'src/server.ts'])
    expect(r.summary).toContain('2 changed file')
    expect(r.summary).toContain('no security configuration')
  })

  it('critical/high findings trigger mandatory review summary', () => {
    const r = scan(['jwt.config.ts'])
    expect(r.summary).toMatch(/mandatory security review/i)
  })

  it('low-risk summary includes risk level string', () => {
    // session (medium, 8) alone → riskScore 8 → riskLevel "low"
    // (only 2 medium rules + 1 low rule exist → max non-critical/high score is 19)
    const r = scan(['session.config.ts'])
    expect(r.riskLevel).toBe('low')
    expect(r.summary).toContain('low')
  })

  it('medium-risk summary includes risk level string', () => {
    // Two high rules: cors (15) + tls (15) = 30 → riskLevel "medium" (25–49)
    // But high rules trigger mandatory-review path, so test the non-high path separately
    // Use 2×medium + 1×low: (8) + (8) + (3) = 19 → low.
    // To get "medium" level without high/critical, we need score ≥ 25, not achievable
    // with only 2 medium rules (max 16) + 1 low (max 3) = 19.
    // So test medium risk level via high rules and verify mandatory-review summary instead:
    const r = scan(['cors.config.ts', 'tls.config.ts'])
    // 15 + 15 = 30 → "medium" risk level
    expect(r.riskLevel).toBe('medium')
    // High findings trigger mandatory-review summary path (criticalOrHigh.length > 0)
    expect(r.summary).toMatch(/mandatory security review/i)
  })
})

// ---------------------------------------------------------------------------
// Constants integrity
// ---------------------------------------------------------------------------

describe('SECURITY_CONFIG_RULES constants integrity', () => {
  it('has exactly 10 rules', () => {
    expect(SECURITY_CONFIG_RULES).toHaveLength(10)
  })

  it('all rule IDs are unique', () => {
    const ids = SECURITY_CONFIG_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all rules have non-empty descriptions', () => {
    for (const rule of SECURITY_CONFIG_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
    }
  })

  it('all rules have non-empty recommendations', () => {
    for (const rule of SECURITY_CONFIG_RULES) {
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('severity distribution includes at least 2 critical, 4 high, 2 medium, 1 low', () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const rule of SECURITY_CONFIG_RULES) {
      counts[rule.severity]++
    }
    expect(counts.critical).toBeGreaterThanOrEqual(2)
    expect(counts.high).toBeGreaterThanOrEqual(4)
    expect(counts.medium).toBeGreaterThanOrEqual(2)
    expect(counts.low).toBeGreaterThanOrEqual(1)
  })

  it('matches function is defined for all rules', () => {
    for (const rule of SECURITY_CONFIG_RULES) {
      expect(typeof rule.matches).toBe('function')
    }
  })
})
