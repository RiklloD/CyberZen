// WS-60 — Application Security Configuration Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to application-level security configuration files. Security configuration
// files are distinct from security code files (WS-57): they declare *policy
// parameters* (allowed CORS origins, JWT signing algorithm, TLS cipher suites,
// WAF rules, session cookie flags) rather than implement security logic.
//
// A single misconfiguration in these files can silently weaken the entire
// application's security posture — for example, changing CORS origins to '*',
// disabling CSP headers, or lowering TLS minimum versions.
//
// Covered rule groups (10 rules):
//
//   JWT_SECRET_CONFIG       — JWT signing key / algorithm configuration files
//   ENCRYPTION_KEY_CONFIG   — Encryption key management and KMS configuration
//   OAUTH_CLIENT_CONFIG     — OAuth2 / OpenID Connect client configuration
//   SAML_SSO_CONFIG         — SAML / SSO / identity provider configuration
//   CORS_POLICY_CONFIG      — Cross-Origin Resource Sharing policy files
//   CSP_HEADERS_CONFIG      — Content Security Policy / security-headers config
//   TLS_OPTIONS_CONFIG      — TLS / HTTPS / SSL options configuration
//   SESSION_COOKIE_CONFIG   — Session and cookie security configuration
//   WAF_RULES_CONFIG        — Web Application Firewall rules configuration
//   SECURITY_POLICY_CONFIG  — General security policy / permission configuration
//
// This scanner intentionally does NOT overlap with:
//   WS-30 secretScanResults        — detects actual credential files committed to git
//   WS-33 iacScanResults           — covers Terraform, Kubernetes, Dockerfile, Compose
//   WS-35 cicdScanResults          — covers GitHub Actions, GitLab CI, CircleCI, etc.
//   WS-54 sensitiveFileResults     — detects private key files, .env files, etc.
//   WS-57 highRiskChangeResults    — detects security CODE files (auth handlers, etc.)
//   WS-58 depLockVerifyResults     — covers dependency manifest/lock file integrity
//   WS-59 buildConfigScanResults   — covers build toolchain configuration files
//
// The main difference from WS-57: WS-57 detects ANY file whose name suggests
// it implements security logic. WS-60 detects files that explicitly follow the
// *.config.* / *Options.* / *Policy.* / *Rules.* naming convention, indicating
// they configure security parameters rather than implementing security logic.
//
// Design decisions:
//   • Path-segment / basename analysis only — no content reading.
//   • Paths inside vendor directories are excluded.
//   • Same penalty/cap scoring model as WS-53–59.
//   • Dedup-per-rule: one finding per triggered rule with matchedPath + matchCount.
//
// Exports:
//   scanSecurityConfigChanges — runs all 10 rules, returns SecurityConfigDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecurityConfigRuleId =
  | 'JWT_SECRET_CONFIG'
  | 'ENCRYPTION_KEY_CONFIG'
  | 'OAUTH_CLIENT_CONFIG'
  | 'SAML_SSO_CONFIG'
  | 'CORS_POLICY_CONFIG'
  | 'CSP_HEADERS_CONFIG'
  | 'TLS_OPTIONS_CONFIG'
  | 'SESSION_COOKIE_CONFIG'
  | 'WAF_RULES_CONFIG'
  | 'SECURITY_POLICY_CONFIG'

export type SecurityConfigSeverity = 'critical' | 'high' | 'medium' | 'low'
export type SecurityConfigRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface SecurityConfigFinding {
  ruleId: SecurityConfigRuleId
  severity: SecurityConfigSeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total number of changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface SecurityConfigDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: SecurityConfigRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: SecurityConfigFinding[]
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
// Shared config-word signal helper
// ---------------------------------------------------------------------------

// These words in a basename indicate the file is a *configuration* file rather
// than a code file that incidentally implements security logic.
const CONFIG_SIGNALS = ['config', 'options', 'settings', 'configuration', 'policy', 'rules', 'props', 'conf']

function hasConfigSignal(lower: string): boolean {
  return CONFIG_SIGNALS.some((s) => lower.includes(s))
}

// ---------------------------------------------------------------------------
// Rule matching helpers
// ---------------------------------------------------------------------------

// ── JWT_SECRET_CONFIG ────────────────────────────────────────────────────

// JWT prefixes that signal a configuration file when combined with a config word.
// We require a config signal so that plain `jwt.ts` utility files (WS-57 territory)
// are excluded and only true configuration files are flagged.
const JWT_PREFIXES = ['jwt', 'json-web-token', 'json_web_token', 'jsonwebtoken']

function isJwtSecretConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const hasTopic = JWT_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  // Require a config-file signal to avoid double-counting with WS-57 utility files
  return hasConfigSignal(base) || base.includes('secret') || base.includes('signing')
}

// ── ENCRYPTION_KEY_CONFIG ────────────────────────────────────────────────

const ENCRYPTION_KEY_EXACT = new Set([
  'keystore.json', 'keystore.yaml', 'keystore.yml', 'keystore.conf',
  'keyring.json', 'keyring.yaml',
])

const ENCRYPTION_KEY_PREFIXES = [
  'encryption', 'crypto', 'kms', 'key-management', 'keymanagement',
  'key-rotation', 'keyrotation', 'key-derivation', 'keyder',
  'secrets-manager', 'secretsmanager', 'vault',
]

function isEncryptionKeyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (ENCRYPTION_KEY_EXACT.has(base)) return true
  const hasTopic = ENCRYPTION_KEY_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('key') || base.includes('secret')
}

// ── OAUTH_CLIENT_CONFIG ──────────────────────────────────────────────────

const OAUTH_PREFIXES = ['oauth', 'oauth2', 'openid-connect', 'openidconnect']

function isOauthClientConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const hasTopic = OAUTH_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('client') || base.includes('provider')
}

// ── SAML_SSO_CONFIG ──────────────────────────────────────────────────────

// Identity-provider specific prefixes: these files explicitly configure an
// external identity provider (SAML, OIDC-based SSO, Okta, Auth0, Keycloak, etc.)
// Note: WS-57 matches any file in a `sso/` or `saml/` directory. WS-60 is more
// specific: it targets named configuration files regardless of directory.
const SAML_SSO_PREFIXES = [
  'saml', 'sso', 'passport', 'auth0', 'okta', 'keycloak',
  'azuread', 'azure-ad', 'cognito', 'pingfederate', 'ping',
  'idp', 'oidc', 'openid',
]

function isSamlSsoConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const hasTopic = SAML_SSO_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('strategy') || base.includes('provider')
}

// ── CORS_POLICY_CONFIG ───────────────────────────────────────────────────

const CORS_PREFIXES = ['cors', 'cross-origin', 'crossorigin']

function isCorsPolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  return CORS_PREFIXES.some((p) => base.startsWith(p)) && hasConfigSignal(base)
}

// ── CSP_HEADERS_CONFIG ───────────────────────────────────────────────────

const CSP_PREFIXES = ['csp', 'helmet', 'security-headers', 'securityheaders', 'content-security-policy']

function isCspHeadersConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const matchedPrefix = CSP_PREFIXES.find((p) => base.startsWith(p))
  if (!matchedPrefix) return false
  // For the short prefixes (csp, helmet) require a config signal to avoid
  // matching non-config files like 'csp-validator.ts'
  if (matchedPrefix === 'csp' || matchedPrefix === 'helmet') {
    return hasConfigSignal(base) || base.includes('header') || base.includes('policy')
  }
  // For longer, more specific prefixes (security-headers, csp-, content-security-policy)
  // a basename match is already specific enough
  return true
}

// ── TLS_OPTIONS_CONFIG ───────────────────────────────────────────────────

// TLS/SSL/HTTPS options configuration files. We intentionally exclude actual
// certificate file extensions (.pem, .crt, .key, .p12, .pfx, .jks) since those
// are handled by WS-30 (secret scanning) and WS-54 (sensitive file detector).
const TLS_PREFIXES = ['ssl', 'tls', 'https']
const TLS_CERT_EXTENSIONS = new Set(['pem', 'crt', 'key', 'p12', 'pfx', 'jks', 'cer', 'der'])

function isTlsOptionsConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  // Exclude actual certificate files
  const ext = base.split('.').pop() ?? ''
  if (TLS_CERT_EXTENSIONS.has(ext)) return false

  const hasTopic = TLS_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('certificate') || base.includes('cipher')
}

// ── SESSION_COOKIE_CONFIG ────────────────────────────────────────────────

const SESSION_COOKIE_PREFIXES = ['session', 'cookie', 'express-session', 'expresssession']

function isSessionCookieConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const hasTopic = SESSION_COOKIE_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('store') || base.includes('secret')
}

// ── WAF_RULES_CONFIG ─────────────────────────────────────────────────────

const WAF_EXACT_BASENAMES = new Set([
  'modsecurity.conf', 'modsecurity.yaml', 'modsecurity.yml',
  'waf-rules.json', 'waf-rules.yaml', 'waf-rules.yml',
  'waf-rules.conf',
])

const WAF_PREFIXES = ['waf', 'modsecurity', 'firewall', 'aws-waf', 'awswaf', 'cloudflare-waf', 'nginx-waf']

function isWafRulesConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (WAF_EXACT_BASENAMES.has(base)) return true
  const hasTopic = WAF_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('rule') || base.includes('block')
}

// ── SECURITY_POLICY_CONFIG ───────────────────────────────────────────────

const SECURITY_POLICY_EXACT = new Set([
  'policy.json', 'policy.yaml', 'policy.yml', 'policy.toml',
  'iam.json', 'iam.yaml', 'iam.yml',
])

const SECURITY_POLICY_PREFIXES = [
  'security-policy', 'securitypolicy',
  'access-policy', 'accesspolicy',
  'iam-policy', 'iampolicy', 'iam.',
  'permission', 'permissions',
  'rbac', 'acl',
  'authz', 'authorization-policy', 'authorizationpolicy',
]

function isSecurityPolicyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (SECURITY_POLICY_EXACT.has(base)) return true
  const hasTopic = SECURITY_POLICY_PREFIXES.some((p) => base.startsWith(p))
  if (!hasTopic) return false
  return hasConfigSignal(base) || base.includes('role') || base.includes('access')
}

// ---------------------------------------------------------------------------
// Rule definitions (ordered for consistent output)
// ---------------------------------------------------------------------------

interface SecurityConfigRule {
  id: SecurityConfigRuleId
  severity: SecurityConfigSeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const SECURITY_CONFIG_RULES: readonly SecurityConfigRule[] = [
  {
    id: 'JWT_SECRET_CONFIG',
    severity: 'critical',
    description:
      'JWT signing key or algorithm configuration file modified — this file controls how tokens are signed and verified. A change here (e.g. algorithm from RS256 to HS256, shorter key, disabled expiry) can silently break token integrity across the entire application.',
    recommendation:
      'Review any changes to algorithm, secret/key references, expiry (exp), audience (aud), and issuer (iss) values. Ensure RSA/EC keys are at least 2048-bit/256-bit. Disable symmetric algorithms (HS256) in favour of asymmetric (RS256/ES256) for distributed systems.',
    matches: isJwtSecretConfig,
  },
  {
    id: 'ENCRYPTION_KEY_CONFIG',
    severity: 'critical',
    description:
      'Encryption key management or KMS configuration modified — this file controls how data-at-rest and data-in-transit keys are provisioned, rotated, and referenced. A misconfiguration can result in weak key derivation, disabled rotation, or exposure of key material.',
    recommendation:
      'Audit changes to key length, algorithm, rotation schedule, and KMS provider references. Ensure key derivation uses an approved KDF (PBKDF2, Argon2, bcrypt). Validate that no plaintext key material is referenced inline.',
    matches: isEncryptionKeyConfig,
  },
  {
    id: 'OAUTH_CLIENT_CONFIG',
    severity: 'high',
    description:
      'OAuth2 or OpenID Connect client configuration modified — this file defines client IDs, client secrets, redirect URIs, and requested scopes. Changes here can introduce open-redirect vulnerabilities, scope creep, or misconfigured token endpoints.',
    recommendation:
      'Verify that redirect URIs are exact matches (no wildcards). Confirm scopes follow the principle of least privilege. Check that PKCE is enabled for public clients. Review changes to token endpoint URL or grant type.',
    matches: isOauthClientConfig,
  },
  {
    id: 'SAML_SSO_CONFIG',
    severity: 'high',
    description:
      'SAML, SSO, or identity provider configuration modified — this file configures the trust relationship with an external identity provider (Auth0, Okta, Keycloak, Passport.js strategy, etc.). Misconfigurations here can result in authentication bypass, assertion replay, or unauthorized access.',
    recommendation:
      'Validate that assertion signing and encryption remain enabled. Verify SP entity ID and ACS URL are unchanged. Confirm IdP certificate fingerprints are pinned. Review any changes to NameID format or attribute mappings.',
    matches: isSamlSsoConfig,
  },
  {
    id: 'CORS_POLICY_CONFIG',
    severity: 'high',
    description:
      'CORS policy configuration modified — this file defines which origins, methods, and headers are permitted for cross-origin requests. Changes here can unintentionally open the API to unauthorized origins (e.g. wildcard `*` origins with credentials).',
    recommendation:
      'Ensure `allowedOrigins` is an explicit allowlist, not a wildcard. Verify that credentials: true is not combined with origin: "*". Review any new allowed methods or headers for minimal-necessary principle compliance.',
    matches: isCorsPolicyConfig,
  },
  {
    id: 'CSP_HEADERS_CONFIG',
    severity: 'high',
    description:
      'Content Security Policy or security headers configuration modified — this file controls browser-enforced security headers (CSP, HSTS, X-Frame-Options, etc.). Loosening these headers (e.g. adding `unsafe-inline`, disabling HSTS) directly increases XSS and clickjacking exposure.',
    recommendation:
      'Audit any additions of `unsafe-inline`, `unsafe-eval`, or wildcard source directives to CSP. Ensure HSTS maxAge is at least 31536000 (1 year). Verify X-Frame-Options or frame-ancestors policy has not been loosened.',
    matches: isCspHeadersConfig,
  },
  {
    id: 'TLS_OPTIONS_CONFIG',
    severity: 'high',
    description:
      'TLS / HTTPS / SSL options configuration modified — this file controls which TLS versions, cipher suites, and certificate options the server accepts. Downgrading minimum TLS version or enabling weak ciphers (RC4, 3DES) can expose connections to downgrade attacks.',
    recommendation:
      'Ensure minimum TLS version is 1.2 (prefer 1.3). Verify weak cipher suites (RC4, 3DES, DES, NULL, EXPORT) are explicitly excluded. Confirm certificate validation is enabled (rejectUnauthorized: true). Check HSTS settings remain intact.',
    matches: isTlsOptionsConfig,
  },
  {
    id: 'SESSION_COOKIE_CONFIG',
    severity: 'medium',
    description:
      'Session or cookie security configuration modified — this file controls session store settings, cookie flags (httpOnly, secure, sameSite), session expiry, and session secret rotation. Changes here can result in session fixation, cross-site request forgery, or stolen session tokens.',
    recommendation:
      'Verify httpOnly and secure flags remain set to true on session cookies. Ensure sameSite is Strict or Lax (not None without Secure). Confirm session expiry TTL has not been extended beyond policy. Check session secret rotation has not been removed.',
    matches: isSessionCookieConfig,
  },
  {
    id: 'WAF_RULES_CONFIG',
    severity: 'medium',
    description:
      'Web Application Firewall rules or firewall configuration modified — changes to WAF rule sets, block lists, or firewall policies can silently disable protection against SQL injection, XSS, path traversal, or rate-limit bypass attacks.',
    recommendation:
      'Review any rules that were disabled or had their action changed from BLOCK to ALLOW/COUNT. Validate that OWASP Core Rule Set (CRS) rules remain active. Ensure IP allowlists have not been expanded without justification.',
    matches: isWafRulesConfig,
  },
  {
    id: 'SECURITY_POLICY_CONFIG',
    severity: 'low',
    description:
      'Security policy, IAM policy, or access control configuration modified — this file defines role-based access control (RBAC), IAM policies, or authorization rules. Overly permissive changes here grant unintended access to sensitive resources or API endpoints.',
    recommendation:
      'Review any wildcards (*) added to resource or action fields. Ensure principle of least privilege is maintained. Confirm that new roles or permissions were reviewed by the security team. Check that deny rules have not been removed.',
    matches: isSecurityPolicyConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–59 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<SecurityConfigSeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
  low:       3,
}

const PENALTY_CAP: Record<SecurityConfigSeverity, number> = {
  critical: 75,
  high:     30,
  medium:   20,
  low:      10,
}

function toRiskLevel(score: number): SecurityConfigRiskLevel {
  if (score === 0)  return 'none'
  if (score < 25)   return 'low'
  if (score < 50)   return 'medium'
  if (score < 75)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function buildSummary(
  findings: SecurityConfigFinding[],
  riskLevel: SecurityConfigRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no security configuration file changes detected.`
  }
  const criticalOrHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  if (criticalOrHigh.length > 0) {
    const labelMap: Record<string, string> = {
      JWT_SECRET_CONFIG: 'JWT signing config',
      ENCRYPTION_KEY_CONFIG: 'encryption key config',
      OAUTH_CLIENT_CONFIG: 'OAuth client config',
      SAML_SSO_CONFIG: 'SSO identity config',
      CORS_POLICY_CONFIG: 'CORS policy',
      CSP_HEADERS_CONFIG: 'CSP/security headers config',
      TLS_OPTIONS_CONFIG: 'TLS options config',
    }
    const labels = criticalOrHigh.map((f) => labelMap[f.ruleId] ?? f.ruleId)
    const unique = [...new Set(labels)]
    const joined = unique.length <= 2
      ? unique.join(' and ')
      : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return `${findings.length} security configuration file${findings.length === 1 ? '' : 's'} modified including ${joined} — mandatory security review required before merge.`
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return `${findings.length} security configuration change${findings.length === 1 ? '' : 's'} across ${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which application security configuration files
 * were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor directories (node_modules, dist, build, vendor, etc.)
 *   are excluded to avoid false-positives from vendored config files.
 * - Each rule fires at most once per scan (deduplicated). The finding records
 *   the first matched path and a count of all paths that matched.
 */
export function scanSecurityConfigChanges(filePaths: string[]): SecurityConfigDriftResult {
  // Per-rule accumulator: first matched path + count
  const ruleAccumulator = new Map<SecurityConfigRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of SECURITY_CONFIG_RULES) {
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
  const findings: SecurityConfigFinding[] = []
  for (const rule of SECURITY_CONFIG_RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId: rule.id,
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
