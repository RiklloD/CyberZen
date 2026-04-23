// WS-57 — Security Hotspot Change Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to security-critical code areas: authentication handlers, cryptographic
// primitives, payment processing, administration endpoints, PII handlers,
// and security middleware.
//
// This is intentionally distinct from:
//   WS-54 sensitiveFileResults  — looks for files that ARE credentials (.env,
//                                  id_rsa, etc.)
//   WS-56 gitIntegrityResults   — looks for files that corrupt git / build
//                                  toolchain (binaries, hooks, registry configs)
//
// This scanner looks for files that IMPLEMENT security-sensitive business
// logic — the kind of code where a subtle change can introduce an
// authentication bypass, weaken encryption, or expose PII.
//
// Design decisions:
//   • Path-segment analysis only — no content reading.
//   • Paths under vendor directories (node_modules, dist, build, vendor,
//     .yarn, .git) are excluded to avoid false-positives from dependencies.
//   • Findings are deduplicated per rule: one finding per rule per scan
//     showing the first matched path plus a matchCount. This prevents
//     flooding when 20 auth files change in a single commit.
//   • Same penalty/cap scoring model as WS-53/54/55/56.
//
// Exports:
//   detectHighRiskChanges — runs all 12 rules, returns HighRiskChangeResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type HighRiskRuleId =
  | 'AUTH_HANDLER'
  | 'TOKEN_MANAGEMENT'
  | 'MFA_IMPLEMENTATION'
  | 'CRYPTO_PRIMITIVE'
  | 'PASSWORD_HANDLER'
  | 'SIGNING_CODE'
  | 'PAYMENT_PROCESSING'
  | 'ADMIN_AREA'
  | 'AUTHORIZATION_LOGIC'
  | 'PII_HANDLING'
  | 'RATE_LIMITER'
  | 'SECURITY_MIDDLEWARE'

export type HighRiskCategory =
  | 'authentication'
  | 'cryptography'
  | 'payment'
  | 'administration'
  | 'data_privacy'
  | 'security_config'

export type HighRiskSeverity = 'critical' | 'high' | 'medium' | 'low'
export type HighRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface HighRiskChangeFinding {
  ruleId: HighRiskRuleId
  category: HighRiskCategory
  severity: HighRiskSeverity
  /** The first file path that triggered this rule. */
  matchedPath: string
  /** Total number of changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface HighRiskChangeResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: HighRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: HighRiskChangeFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

/** Normalise Windows backslashes to forward slashes. */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

/** Extract the final segment (filename) from a normalised path. */
function getBasename(p: string): string {
  const parts = normalizePath(p).split('/')
  return parts[parts.length - 1]
}

/**
 * Return true if the path lives inside a known vendor / generated directory
 * that should be excluded from security-logic analysis.
 */
function isVendoredPath(normalised: string): boolean {
  const segments = normalised.split('/')
  const VENDOR_DIRS = new Set([
    'node_modules', 'dist', 'build', 'vendor', '.yarn',
    '.git', 'coverage', 'out', '.next', '.nuxt',
  ])
  return segments.some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

interface HighRiskRule {
  id: HighRiskRuleId
  category: HighRiskCategory
  severity: HighRiskSeverity
  description: string
  recommendation: string
  /** Return true when the normalised file path matches this rule. */
  matches(normalisedPath: string): boolean
}

/** Test whether a path segment exactly equals one of the given names. */
function hasSegment(normalisedPath: string, names: ReadonlySet<string>): boolean {
  const segments = normalisedPath.split('/')
  // Match any directory segment (not the final filename)
  return segments.slice(0, -1).some((s) => names.has(s.toLowerCase()))
}

/** Test whether the basename (without extension) matches any of the given prefixes. */
function basenameStartsWith(normalisedPath: string, prefixes: readonly string[]): boolean {
  const base = getBasename(normalisedPath).toLowerCase()
  return prefixes.some((prefix) => base === prefix || base.startsWith(`${prefix}.`) || base.startsWith(`${prefix}-`) || base.startsWith(`${prefix}_`))
}

const AUTH_DIRS = new Set(['auth', 'authentication', 'login', 'session', 'sso', 'saml', 'oauth'])
const AUTH_PREFIXES = ['auth', 'authentication', 'login', 'session', 'sso', 'saml', 'oauth', 'signin', 'signup'] as const

const TOKEN_DIRS = new Set(['jwt', 'token', 'tokens', 'apikeys', 'api-keys'])
const TOKEN_PREFIXES = ['jwt', 'token', 'refresh-token', 'refreshtoken', 'apikey', 'api-key', 'access-token', 'bearer'] as const

const CRYPTO_DIRS = new Set(['crypto', 'cipher', 'encryption', 'decryption', 'keygen', 'crypt'])
const CRYPTO_PREFIXES = ['crypto', 'cipher', 'encrypt', 'decrypt', 'keygen', 'key-gen', 'aes', 'rsa-key', 'ecdsa'] as const

const PAYMENT_DIRS = new Set(['payment', 'payments', 'billing', 'checkout', 'stripe', 'paypal', 'braintree', 'adyen', 'plaid', 'square', 'mollie'])
const PAYMENT_PREFIXES = ['payment', 'billing', 'checkout', 'stripe', 'paypal', 'braintree', 'charge', 'invoice', 'subscription', 'credit-card', 'creditcard'] as const

const ADMIN_DIRS = new Set(['admin', 'administration', 'superuser', 'sudo', 'management', 'backstage', 'internal-tools', 'ops-tools', 'control-plane'])

const AUTHZ_DIRS = new Set(['authorization', 'acl', 'rbac', 'permissions', 'policies', 'roles', 'privileges'])
const AUTHZ_PREFIXES = ['authorization', 'acl', 'rbac', 'permission', 'policy', 'role', 'privilege', 'access-control', 'capability'] as const

const PII_DIRS = new Set(['pii', 'gdpr', 'privacy', 'personal-data', 'user-data', 'dsr', 'ccpa'])
const PII_PREFIXES = ['pii', 'gdpr', 'privacy', 'personal-data', 'data-export', 'user-export', 'profile-export', 'data-deletion', 'right-to-be-forgotten'] as const

export const RULES: readonly HighRiskRule[] = [
  // ── authentication ────────────────────────────────────────────────────────

  {
    id: 'AUTH_HANDLER',
    category: 'authentication',
    severity: 'high',
    description:
      'Authentication handler or login logic modified — changes here can introduce credential bypass or session fixation vulnerabilities.',
    recommendation:
      'Ensure this change undergoes security-focused code review. Verify that session invalidation, CSRF protection, and lockout policies remain intact.',
    matches(p) {
      return hasSegment(p, AUTH_DIRS) || basenameStartsWith(p, AUTH_PREFIXES)
    },
  },
  {
    id: 'TOKEN_MANAGEMENT',
    category: 'authentication',
    severity: 'high',
    description:
      'Token or API-key management code modified — incorrect token handling can lead to privilege escalation or account takeover.',
    recommendation:
      'Review token generation entropy, expiry enforcement, and revocation paths. Ensure tokens are not logged or stored in plaintext.',
    matches(p) {
      return hasSegment(p, TOKEN_DIRS) || basenameStartsWith(p, TOKEN_PREFIXES)
    },
  },
  {
    id: 'MFA_IMPLEMENTATION',
    category: 'authentication',
    severity: 'medium',
    description:
      'Multi-factor authentication code modified — bugs here may silently disable or weaken MFA protection.',
    recommendation:
      'Verify that MFA enforcement paths remain active, OTP windows are appropriately tight, and backup codes are handled securely.',
    matches(p) {
      const base = getBasename(p).toLowerCase()
      return (
        basenameStartsWith(p, ['mfa', '2fa', 'otp', 'totp', 'hotp', 'webauthn', 'fido', 'passkey']) ||
        base.includes('two-factor') ||
        base.includes('two_factor') ||
        base.includes('multifactor')
      )
    },
  },

  // ── cryptography ──────────────────────────────────────────────────────────

  {
    id: 'CRYPTO_PRIMITIVE',
    category: 'cryptography',
    severity: 'critical',
    description:
      'Cryptographic primitive or key-generation code modified — a subtle change can silently weaken encryption across the entire application.',
    recommendation:
      'Mandate a dedicated cryptography review. Confirm algorithm choices, key sizes, IV randomness, and authenticated encryption modes have not regressed.',
    matches(p) {
      return hasSegment(p, CRYPTO_DIRS) || basenameStartsWith(p, CRYPTO_PREFIXES)
    },
  },
  {
    id: 'PASSWORD_HANDLER',
    category: 'cryptography',
    severity: 'high',
    description:
      'Password hashing or storage code modified — incorrect changes can result in passwords being stored in a reversible or weakly-hashed form.',
    recommendation:
      'Verify that bcrypt/argon2/scrypt/PBKDF2 is still used with appropriate work factors. Confirm no plaintext storage or logging was introduced.',
    matches(p) {
      return basenameStartsWith(p, ['password', 'passwd', 'hash', 'bcrypt', 'argon', 'scrypt', 'pbkdf'])
    },
  },
  {
    id: 'SIGNING_CODE',
    category: 'cryptography',
    severity: 'high',
    description:
      'Code signing, HMAC, or digital signature implementation modified — changes here can allow forged tokens or tampered payloads.',
    recommendation:
      'Verify signature verification still rejects bad inputs, secret keys are not hardcoded, and timing-safe comparison is used for HMAC validation.',
    matches(p) {
      return (
        basenameStartsWith(p, ['signing', 'signature', 'hmac', 'sign-', 'verif', 'verify', 'checksum', 'digest']) ||
        hasSegment(p, new Set(['signing', 'signatures', 'hmac']))
      )
    },
  },

  // ── payment ───────────────────────────────────────────────────────────────

  {
    id: 'PAYMENT_PROCESSING',
    category: 'payment',
    severity: 'critical',
    description:
      'Payment processing or billing logic modified — errors here can cause financial loss, fraud exposure, or PCI-DSS scope violations.',
    recommendation:
      'Ensure payment flows are covered by integration tests. Verify that card data never flows through application logs and that Stripe/PayPal webhook signatures are still validated.',
    matches(p) {
      return hasSegment(p, PAYMENT_DIRS) || basenameStartsWith(p, PAYMENT_PREFIXES)
    },
  },

  // ── administration ────────────────────────────────────────────────────────

  {
    id: 'ADMIN_AREA',
    category: 'administration',
    severity: 'high',
    description:
      'Administration panel or privileged endpoint code modified — admin endpoints are high-value targets; access control bugs here can compromise entire tenants.',
    recommendation:
      'Verify that admin routes are still gated by role checks, audit logging is intact, and no new unauthenticated paths were introduced.',
    matches(p) {
      return hasSegment(p, ADMIN_DIRS)
    },
  },
  {
    id: 'AUTHORIZATION_LOGIC',
    category: 'administration',
    severity: 'high',
    description:
      'Access control, permission, or RBAC policy code modified — an incorrect change can silently grant or deny access to the wrong principals.',
    recommendation:
      'Review permission matrix changes, ensure deny-by-default is preserved, and run authorisation-specific test scenarios.',
    matches(p) {
      return hasSegment(p, AUTHZ_DIRS) || basenameStartsWith(p, AUTHZ_PREFIXES)
    },
  },

  // ── data_privacy ──────────────────────────────────────────────────────────

  {
    id: 'PII_HANDLING',
    category: 'data_privacy',
    severity: 'medium',
    description:
      'PII handler, data-subject request, or privacy logic modified — bugs here can expose personal data or violate GDPR/CCPA obligations.',
    recommendation:
      'Verify that data minimisation, purpose limitation, and retention controls remain intact. Check for inadvertent logging of personal fields.',
    matches(p) {
      return hasSegment(p, PII_DIRS) || basenameStartsWith(p, PII_PREFIXES)
    },
  },

  // ── security_config ───────────────────────────────────────────────────────

  {
    id: 'RATE_LIMITER',
    category: 'security_config',
    severity: 'medium',
    description:
      'Rate-limiting or request throttling code modified — weakening rate limits can expose authentication endpoints to brute-force or credential-stuffing attacks.',
    recommendation:
      'Confirm that per-IP and per-account limits on sensitive endpoints (login, password reset, MFA) are still enforced with appropriate thresholds.',
    matches(p) {
      const base = getBasename(p).toLowerCase()
      return (
        basenameStartsWith(p, ['rate-limit', 'ratelimit', 'throttle', 'rate_limit']) ||
        base.includes('ratelimiter') ||
        base.includes('rate-limiter') ||
        hasSegment(p, new Set(['rate-limiting', 'ratelimiting', 'throttling']))
      )
    },
  },
  {
    id: 'SECURITY_MIDDLEWARE',
    category: 'security_config',
    severity: 'low',
    description:
      'Security middleware (CORS, CSP, security headers) code modified — misconfiguring security headers can expose users to XSS, clickjacking, or CSRF attacks.',
    recommendation:
      'Verify that CORS origin allowlists are still restrictive, CSP directives remain tight, and security-header middleware is applied to all response paths.',
    matches(p) {
      return basenameStartsWith(p, ['cors', 'csp', 'helmet', 'security-headers', 'content-security', 'security-policy', 'hsts'])
    },
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53, WS-54, WS-55, WS-56 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<HighRiskSeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
  low:       3,
}

const PENALTY_CAP: Record<HighRiskSeverity, number> = {
  critical: 75,
  high:     30,
  medium:   20,
  low:      10,
}

function toRiskLevel(score: number): HighRiskLevel {
  if (score === 0)   return 'none'
  if (score < 25)    return 'low'
  if (score < 50)    return 'medium'
  if (score < 75)    return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function buildSummary(
  findings: HighRiskChangeFinding[],
  riskLevel: HighRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no security-hotspot areas detected.`
  }
  const totalFiles = findings.reduce((a, f) => a + f.matchCount, 0)
  const criticals = findings.filter((f) => f.severity === 'critical')
  if (criticals.length > 0) {
    const areas = criticals.map((f) => (f.category === 'cryptography' ? 'crypto' : f.category)).join(', ')
    return `Critical: ${totalFiles} file${totalFiles === 1 ? '' : 's'} touching ${criticals.length} high-sensitivity area${criticals.length === 1 ? '' : 's'} (${areas}) — security review required before merge.`
  }
  return `${findings.length} security-hotspot area${findings.length === 1 ? '' : 's'} modified across ${totalFiles} file${totalFiles === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which security-sensitive code areas were
 * touched.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor directories (node_modules, dist, build, vendor, etc.)
 *   are excluded.
 * - Each rule fires at most once per scan (deduplicated). The finding records
 *   the first matched path and a count of all paths that matched.
 * - Multiple rules can fire for a single path (e.g. an auth/jwt.ts file
 *   matches both AUTH_HANDLER and TOKEN_MANAGEMENT).
 */
export function detectHighRiskChanges(filePaths: string[]): HighRiskChangeResult {
  // Per-rule accumulator: first matched path + count
  const ruleAccumulator = new Map<HighRiskRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of RULES) {
      if (!rule.matches(normalised)) continue

      const acc = ruleAccumulator.get(rule.id)
      if (acc) {
        acc.count++
      } else {
        ruleAccumulator.set(rule.id, { firstPath: rawPath, count: 1 })
      }
    }
  }

  // Build findings in rule definition order for consistent output
  const findings: HighRiskChangeFinding[] = []
  for (const rule of RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      matchedPath: acc.firstPath,
      matchCount: acc.count,
      description: rule.description,
      recommendation: rule.recommendation,
    })
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount     = findings.filter((f) => f.severity === 'high').length
  const mediumCount   = findings.filter((f) => f.severity === 'medium').length
  const lowCount      = findings.filter((f) => f.severity === 'low').length

  const rawScore =
    Math.min(PENALTY_CAP.critical, criticalCount * PENALTY_PER.critical) +
    Math.min(PENALTY_CAP.high,     highCount     * PENALTY_PER.high) +
    Math.min(PENALTY_CAP.medium,   mediumCount   * PENALTY_PER.medium) +
    Math.min(PENALTY_CAP.low,      lowCount      * PENALTY_PER.low)

  const riskScore = Math.min(100, rawScore)
  const riskLevel = toRiskLevel(riskScore)
  const summary   = buildSummary(findings, riskLevel, filePaths.length)

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
