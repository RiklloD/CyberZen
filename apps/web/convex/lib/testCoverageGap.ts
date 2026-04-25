// WS-61 — Test Coverage Gap Detector for Security-Critical Code: pure library.
//
// Analyses the list of changed file paths from a push event to detect
// security-critical source file modifications that lack corresponding test
// coverage changes in the same commit.
//
// The scanner works entirely from file paths — no file content is read.
// For each of 6 security domains, it checks whether any source files were
// changed AND whether at least one test file for that domain was also changed.
// When source files changed with zero matching test files, the rule fires.
//
// This scanner is explicitly DISTINCT from:
//   WS-57 highRiskChangeResults     — detects WHICH security-critical code changed
//   WS-55 commitMessageScanResults  — detects security signals in commit messages
//   WS-60 securityConfigDriftResults — detects security config file changes
//
// WS-61 answers: "Were the security source changes in this push tested?"
//
// Covered rule groups (6 rules, 3 high-severity + 3 medium-severity):
//
//   AUTH_CODE_UNTESTED              — auth / login / oauth / jwt / mfa source changed,
//                                     no auth test file changed
//   CRYPTO_CODE_UNTESTED            — crypto / encrypt / hash / sign source changed,
//                                     no crypto test file changed
//   PAYMENT_CODE_UNTESTED           — payment / billing / stripe / checkout source changed,
//                                     no payment test file changed
//   AUTHZ_CODE_UNTESTED             — rbac / permission / role / acl source changed,
//                                     no authz test file changed
//   SESSION_CODE_UNTESTED           — session / cookie / csrf source changed,
//                                     no session test file changed
//   SECURITY_MIDDLEWARE_UNTESTED    — security middleware / guard / interceptor changed,
//                                     no middleware test file changed
//
// Exports:
//   isGenericTestFile          — detects any test file pattern
//   isSourceCodeFile           — detects source code file extensions
//   isSecurityMiddlewareSource — TODO: user contribution (see below)
//   scanTestCoverageGaps       — runs all 6 rules, returns TestCoverageGapResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TestCoverageRuleId =
  | 'AUTH_CODE_UNTESTED'
  | 'CRYPTO_CODE_UNTESTED'
  | 'PAYMENT_CODE_UNTESTED'
  | 'AUTHZ_CODE_UNTESTED'
  | 'SESSION_CODE_UNTESTED'
  | 'SECURITY_MIDDLEWARE_UNTESTED'

export type TestCoverageSeverity = 'high' | 'medium'
export type TestCoverageRiskLevel = 'high' | 'medium' | 'low' | 'none'

export interface TestCoverageGapFinding {
  ruleId: TestCoverageRuleId
  severity: TestCoverageSeverity
  /** First untested security source file in this domain. */
  matchedPath: string
  /** Total untested security source files in this domain. */
  matchCount: number
  description: string
  recommendation: string
}

export interface TestCoverageGapResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: TestCoverageRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  /** One finding per triggered rule (deduped by domain). */
  findings: TestCoverageGapFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(normalised: string): string {
  const parts = normalised.split('/')
  return parts[parts.length - 1] ?? ''
}

const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Source code file detection
// ---------------------------------------------------------------------------

/** File extensions considered "source code" for test-coverage gap detection. */
const SOURCE_EXTENSIONS = new Set([
  'ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs',
  'py', 'rb', 'go', 'java', 'kt', 'cs', 'php',
  'rs', 'swift', 'scala', 'cpp', 'c',
])

/** True when the path has a source code extension we care about. */
export function isSourceCodeFile(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  return SOURCE_EXTENSIONS.has(ext)
}

// ---------------------------------------------------------------------------
// Generic test file detection
// ---------------------------------------------------------------------------

/**
 * True when the file path matches common test naming conventions across
 * languages and frameworks. Used to identify test files irrespective of domain.
 *
 * Patterns detected:
 *   .test.ts / .spec.ts / .test.js / .spec.js (and any source extension)
 *   test_foo.py / foo_test.py (Python xUnit style)
 *   Path segment exactly equal to: test | tests | spec | __tests__
 */
export function isGenericTestFile(path: string): boolean {
  const normalised = normalizePath(path).toLowerCase()
  const base = getBasename(normalised)

  // Dot-separated test/spec: e.g. jwt.service.test.ts, auth.spec.js
  if (/\.(test|spec)\.[a-z]{1,4}$/.test(base)) return true

  // Python xUnit style: test_foo.py, foo_test.py
  if (base.startsWith('test_') || /_test\.[a-z]{1,4}$/.test(base)) return true

  // Test directory path segments (exact match to avoid false positives on
  // words like "attest", "contest", "protest")
  const segments = normalised.split('/')
  return segments.some(
    (s) => s === 'test' || s === 'tests' || s === 'spec' || s === '__tests__',
  )
}

// ---------------------------------------------------------------------------
// Domain keyword matchers
// ---------------------------------------------------------------------------

function includesKeyword(normalised: string, keywords: readonly string[]): boolean {
  const lower = normalised.toLowerCase()
  return keywords.some((kw) => lower.includes(kw))
}

/** Authentication keywords. */
export const AUTH_KEYWORDS: readonly string[] = [
  'auth', 'login', 'logout', 'signin', 'signup', 'register',
  'oauth', 'jwt', 'jsonwebtoken', 'saml', 'sso', 'mfa', 'totp', 'otp',
  'credential', 'identity', 'password', 'passwd', 'passphrase',
  'authenticat', // prefix matches authenticate / authentication
]

/** Cryptography keywords. */
export const CRYPTO_KEYWORDS: readonly string[] = [
  'crypto', 'cryptograph', 'encrypt', 'decrypt', 'cipher',
  'hash', 'hmac', 'sign', 'verify', 'digest',
  'pbkdf', 'argon', 'bcrypt', 'scrypt',
  'aes', 'rsa', 'ecdsa', 'elliptic',
  'keystore', 'keygen', 'keyderivation',
]

/** Payment/billing keywords. */
export const PAYMENT_KEYWORDS: readonly string[] = [
  'payment', 'billing', 'checkout', 'invoice', 'subscription',
  'stripe', 'paypal', 'braintree', 'adyen', 'square',
  'charge', 'merchant', 'transaction', 'refund', 'pci',
]

/** Authorization/access-control keywords. */
export const AUTHZ_KEYWORDS: readonly string[] = [
  'rbac', 'acl', 'permission', 'privilege', 'role',
  'accesscontrol', 'access-control', 'authorization', 'authorize',
  'grant', 'entitlement', 'iam', 'policy',
]

/** Session/cookie/CSRF keywords. */
export const SESSION_KEYWORDS: readonly string[] = [
  'session', 'cookie', 'csrf', 'xsrf',
  'refreshtoken', 'refresh-token', 'refresh_token',
  'revoke', 'invalidate',
]

// ---------------------------------------------------------------------------
// isSecurityMiddlewareSource — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a security-middleware
 * source file (not a test file) that should be covered by tests.
 *
 * Called by the SECURITY_MIDDLEWARE_UNTESTED rule.
 *
 * A security-middleware file:
 *   1. Has a middleware-context word in its name or path:
 *      middleware, guard, interceptor, filter
 *   2. AND has a security-domain word in its name or path:
 *      auth, csrf, cors, rate, limit, helmet, security, throttle, firewall, xss
 *
 * Trade-offs to consider:
 *   - Should a NestJS `auth.guard.ts` count? ("guard" + "auth" → yes)
 *   - Should `logging-middleware.ts` count? ("middleware" + no security kw → no)
 *   - Should path segment `/middleware/auth.ts` count? ("middleware" in path +
 *     "auth" in path → arguably yes, even if basename only has "auth")
 *   - How strict should the security keyword list be? Wider lists catch more
 *     real cases but risk false positives on unrelated middleware.
 *
 * The current implementation requires BOTH conditions; feel free to adjust
 * the keyword sets or relax the conjunction to match your team's conventions.
 */
export function isSecurityMiddlewareSource(normalisedPath: string): boolean {
  const lower = normalisedPath.toLowerCase()
  const MIDDLEWARE_CTX = ['middleware', 'guard', 'interceptor', 'filter'] as const
  const SECURITY_KW = [
    'auth', 'csrf', 'cors', 'rate', 'limit', 'helmet',
    'security', 'throttle', 'firewall', 'xss', 'sql',
  ] as const
  const hasMwCtx = MIDDLEWARE_CTX.some((w) => lower.includes(w))
  const hasSecKw  = SECURITY_KW.some((w) => lower.includes(w))
  return hasMwCtx && hasSecKw
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

/**
 * Computes whether a security domain has a coverage gap:
 * source files changed but no domain-specific test files changed.
 */
function hasCoverageGap(sourceCount: number, testCount: number): boolean {
  return sourceCount > 0 && testCount === 0
}

interface TestCoverageRule {
  id: TestCoverageRuleId
  severity: TestCoverageSeverity
  description: string
  recommendation: string
  /** True when this path is a security source file for this domain. */
  isSecuritySource(normalised: string): boolean
  /** True when this path is a test file relevant to this domain. */
  isDomainTest(normalised: string): boolean
}

function makeStandardRule(
  id: TestCoverageRuleId,
  severity: TestCoverageSeverity,
  keywords: readonly string[],
  description: string,
  recommendation: string,
): TestCoverageRule {
  return {
    id,
    severity,
    description,
    recommendation,
    isSecuritySource(normalised): boolean {
      if (!isSourceCodeFile(normalised)) return false
      if (isGenericTestFile(normalised)) return false
      return includesKeyword(normalised, keywords)
    },
    isDomainTest(normalised): boolean {
      if (!isGenericTestFile(normalised)) return false
      return includesKeyword(normalised, keywords)
    },
  }
}

const TEST_COVERAGE_RULES: readonly TestCoverageRule[] = [
  makeStandardRule(
    'AUTH_CODE_UNTESTED',
    'high',
    AUTH_KEYWORDS,
    'Authentication source files modified without corresponding test changes — untested auth code is a high-risk vector. Changes to login flows, JWT signing, OAuth callbacks, MFA logic, or credential handling can silently introduce authentication bypasses that will not be caught until production.',
    'Add or update test files covering the changed authentication paths. At minimum: happy-path test (valid credentials), failure-path test (invalid/expired credentials), and edge cases specific to the changed behaviour. Consider adding integration tests that exercise the full auth flow.',
  ),
  makeStandardRule(
    'CRYPTO_CODE_UNTESTED',
    'high',
    CRYPTO_KEYWORDS,
    'Cryptographic primitive or utility files modified without corresponding test changes — untested crypto code is a critical blind spot. Errors in hash functions, encryption routines, key derivation, or signature verification are notoriously difficult to debug in production and can silently degrade security for all users.',
    'Add known-answer tests (KAT) verifying that specific inputs produce the expected ciphertext, digest, or signature. Include negative tests (tampering detection, wrong-key rejection). For key derivation changes, verify the output length and entropy characteristics.',
  ),
  makeStandardRule(
    'PAYMENT_CODE_UNTESTED',
    'high',
    PAYMENT_KEYWORDS,
    'Payment or billing source files modified without corresponding test changes — payment logic is both high-severity (financial risk) and highly regulated (PCI-DSS). Untested changes here may introduce race conditions, duplicate charges, incorrect totals, or broken idempotency that appear intermittently in production.',
    'Add tests covering the changed payment paths: successful charge, declined payment, refund flow, idempotency key behaviour, and webhook event handling. Verify that amounts, currencies, and order IDs are validated before being sent to the payment provider.',
  ),
  makeStandardRule(
    'AUTHZ_CODE_UNTESTED',
    'medium',
    AUTHZ_KEYWORDS,
    'Authorization or access-control source files modified without corresponding test changes — untested RBAC, ACL, or policy changes can grant unintended access to privileged resources. A missing test for a new role or policy rule means the access control logic is unverified until a real user hits it.',
    'Add tests for each modified role or permission: verify that the allowed action succeeds, verify that forbidden actions are rejected, and check that privilege escalation paths (e.g. role inheritance chains) behave as expected.',
  ),
  makeStandardRule(
    'SESSION_CODE_UNTESTED',
    'medium',
    SESSION_KEYWORDS,
    'Session management or CSRF protection source files modified without corresponding test changes — session handling bugs (fixation, replay, premature expiry) and weakened CSRF protection are common authentication vulnerability classes that regression tests catch before deployment.',
    'Add tests for session creation, expiry, and invalidation. Verify that CSRF tokens are validated on state-changing requests and that token rotation works correctly. For cookie changes, assert the expected httpOnly, Secure, and SameSite flag values.',
  ),
  {
    id: 'SECURITY_MIDDLEWARE_UNTESTED',
    severity: 'medium',
    description:
      'Security middleware, guard, or interceptor files modified without corresponding test changes — security middleware sits on every request path and a misconfiguration (wrong order, dropped header, incorrect bypass condition) silently weakens all downstream handlers. Untested middleware changes are high-leverage bugs.',
    recommendation:
      'Add unit tests for the middleware in isolation: mock the request/response context, verify that the middleware passes compliant requests, rejects non-compliant ones, and applies the expected transformations (e.g. rate-limit headers set, CORS response correct). Add an integration test that mounts the middleware on a real route.',
    isSecuritySource(normalised): boolean {
      if (!isSourceCodeFile(normalised)) return false
      if (isGenericTestFile(normalised)) return false
      return isSecurityMiddlewareSource(normalised)
    },
    isDomainTest(normalised): boolean {
      if (!isGenericTestFile(normalised)) return false
      return isSecurityMiddlewareSource(normalised) || includesKeyword(normalised, SESSION_KEYWORDS) ||
        includesKeyword(normalised, AUTH_KEYWORDS)
    },
  },
]

// ---------------------------------------------------------------------------
// Scoring — consistent model across WS-53–61
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<TestCoverageSeverity, number> = {
  high:   25,
  medium: 12,
}

const PENALTY_CAP: Record<TestCoverageSeverity, number> = {
  high:   60,
  medium: 30,
}

function toRiskLevel(score: number): TestCoverageRiskLevel {
  if (score === 0)   return 'none'
  if (score <  25)   return 'low'
  if (score <  50)   return 'medium'
  return 'high'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_LABELS: Record<TestCoverageRuleId, string> = {
  AUTH_CODE_UNTESTED:             'authentication',
  CRYPTO_CODE_UNTESTED:           'cryptography',
  PAYMENT_CODE_UNTESTED:          'payment processing',
  AUTHZ_CODE_UNTESTED:            'authorization',
  SESSION_CODE_UNTESTED:          'session management',
  SECURITY_MIDDLEWARE_UNTESTED:   'security middleware',
}

function buildSummary(
  findings: TestCoverageGapFinding[],
  riskLevel: TestCoverageRiskLevel,
  scannedCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${scannedCount} changed file${scannedCount === 1 ? '' : 's'} — no security-critical code changes detected without test coverage.`
  }
  const domainLabels = findings.map((f) => RULE_LABELS[f.ruleId])
  const unique = [...new Set(domainLabels)]
  const joined =
    unique.length <= 2
      ? unique.join(' and ')
      : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
  const totalUntested = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${totalUntested} security-critical source file${totalUntested === 1 ? '' : 's'} changed ` +
    `across ${unique.length} domain${unique.length === 1 ? '' : 's'} (${joined}) ` +
    `without corresponding test coverage — risk level: ${riskLevel}.`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which security domains had source file changes
 * without test coverage changes in the same commit.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor directories are excluded.
 * - Each rule fires at most once per scan (deduplicated). The finding records
 *   the first unmatched security source file and a count of all such files.
 * - Only source code file extensions are considered for the source-file side;
 *   test detection uses naming patterns that are extension-agnostic.
 */
export function scanTestCoverageGaps(filePaths: string[]): TestCoverageGapResult {
  // Normalise and filter vendor paths once
  const normalised: string[] = []
  for (const raw of filePaths) {
    const trimmed = raw.trim()
    if (!trimmed) continue
    const norm = normalizePath(trimmed)
    if (isVendoredPath(norm)) continue
    normalised.push(norm)
  }

  // Evaluate each rule
  const findings: TestCoverageGapFinding[] = []

  for (const rule of TEST_COVERAGE_RULES) {
    // Collect source and test files for this domain
    const sourceFiles: string[] = []
    const testFiles:   string[] = []

    for (const norm of normalised) {
      if (rule.isDomainTest(norm)) {
        testFiles.push(norm)
      } else if (rule.isSecuritySource(norm)) {
        sourceFiles.push(norm)
      }
    }

    if (hasCoverageGap(sourceFiles.length, testFiles.length)) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        matchedPath: sourceFiles[0]!, // hasCoverageGap guarantees sourceFiles.length >= 1
        matchCount: sourceFiles.length,
        description: rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  // Score — same penalty/cap model as WS-53–60
  const penaltyByTier: Partial<Record<TestCoverageSeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [TestCoverageSeverity, number][]) {
    riskScore += Math.min(total, PENALTY_CAP[sev])
  }
  riskScore = Math.min(riskScore, 100)

  const riskLevel  = toRiskLevel(riskScore)
  const highCount  = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
