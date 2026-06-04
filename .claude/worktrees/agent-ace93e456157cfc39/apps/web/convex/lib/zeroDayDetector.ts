/**
 * WS-98 — Zero-Day Anomaly Detection Mode (spec §3.1.3)
 *
 * When semantic fingerprinting finds no strong pattern match, this module
 * applies statistical anomaly heuristics to flag novel attack patterns
 * that don't yet have an assigned CVE or vulnerability class.
 *
 * Eight signal types:
 *   authentication_bypass_pattern   — new execution paths in auth code
 *   new_network_egress              — unexpected outbound calls added
 *   cryptography_weakening          — weaker algorithm/key substitution
 *   privilege_expansion             — admin/root role assignments added
 *   data_exfiltration_pattern       — data read + external write in same change
 *   code_obfuscation                — eval/Function/ base64 blobs in non-tests
 *   novel_injection_vector          — string interpolation of unvalidated data
 *   security_config_modified_untested — security config changed without tests
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type ZeroDaySignalType =
  | 'authentication_bypass_pattern'
  | 'new_network_egress'
  | 'cryptography_weakening'
  | 'privilege_expansion'
  | 'data_exfiltration_pattern'
  | 'code_obfuscation'
  | 'novel_injection_vector'
  | 'security_config_modified_untested'

export type ZeroDaySignal = {
  signalType: ZeroDaySignalType
  confidence: number        // 0–1
  evidence: string          // human-readable description
  affectedFiles: string[]
}

export type ZeroDayCategory =
  | 'potential_zero_day'    // anomalyScore >= 70
  | 'suspicious_change'     // anomalyScore >= 40
  | 'novel_pattern'         // anomalyScore >= 20 with breach-type overlap
  | 'benign'

export type ZeroDayResult = {
  signals: ZeroDaySignal[]
  anomalyScore: number        // 0–100 (max confidence × 100)
  category: ZeroDayCategory
  recommendation: string
}

export type ZeroDayInput = {
  /** Changed file paths (full paths). */
  changedFiles: string[]
  /** Raw text lines added in the diff. */
  addedLines: string[]
  /** Vuln classes seen in recent breach disclosures (last 30 days). */
  recentBreachTypes: string[]
  /** Whether any test file was modified in the same commit. */
  hasTestChanges: boolean
  /** Whether lockfile was modified (signals expected dep add). */
  hasLockfileChanges: boolean
  /**
   * Highest cosine-similarity score from the main semantic fingerprint scan
   * (0 = no pattern run or all misses, 1 = perfect match).
   * When >= 0.6 the system already identified a known vuln class — zero-day
   * mode is still run but its output is informational only.
   */
  fingerprintMatchConfidence?: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const AUTH_DIR_PATTERNS = [
  '/auth/', '/login/', '/session/', '/jwt/', '/token/', '/oauth/',
  '/middleware/', '/guard/', '/passport/', '/verify/',
]

const SECURITY_CONFIG_PATTERNS = [
  'jwt.config', 'encryption.config', 'cors.config', 'csp.config',
  'tls.config', 'ssl.config', 'session.config', 'oauth.config', 'saml.config',
  '.env', 'secrets.', 'vault.', 'kms.config',
]

const NETWORK_CALL_PATTERNS = [
  'fetch(', 'axios.', 'http.request', 'https.request', 'curl(',
  'subprocess.', 'child_process', 'exec(', 'spawn(',
  'new XMLHttpRequest', 'new WebSocket(', 'net.connect(',
]

const CRYPTO_WEAKNESS_PATTERNS = [
  'MD5', 'SHA1', 'SHA-1', 'RC4', 'DES(', '3DES', 'Blowfish', 'ECB',
  'keySize < 128', 'keyLength < 128', 'bits < 128', '1024', 'keySize = 512',
]

const PRIVILEGE_PATTERNS = [
  'isAdmin = true', 'isAdmin=true', "role: 'admin'", 'role: "admin"',
  "role = 'admin'", 'SUPERUSER', 'is_superuser = True', '.admin()',
  'grant all', 'GRANT ALL', 'allowAll', 'allow_all', 'skipAuth',
  'bypass_auth', 'bypassAuth', 'noAuth', 'no_auth',
]

const DATA_READ_PATTERNS = [
  'readFile', 'readFileSync', 'fs.read', 'db.query', 'SELECT ',
  'findOne(', 'findMany(', '.find(', 'ctx.db.query', 'prisma.',
]

const DATA_WRITE_PATTERNS = [
  'fetch(', 'axios.post', 'axios.put', 'sendMail', 'send_mail',
  'POST ', 'httpClient.post', 'request.post', 'upload(',
]

const OBFUSCATION_PATTERNS = [
  'eval(', 'new Function(', 'Function(', 'setTimeout("', "setTimeout('",
]

const BASE64_BLOB_PATTERN = /[A-Za-z0-9+/]{60,}={0,2}/

const INJECTION_PATTERNS = ['${', 'f"', 'f\'', '`$', '%s%', 'format(', '% (', '.format(']

function isTestFile(path: string): boolean {
  const lower = path.toLowerCase()
  return (
    lower.includes('/test') ||
    lower.includes('/spec') ||
    lower.includes('.test.') ||
    lower.includes('.spec.') ||
    lower.includes('__test') ||
    lower.includes('__spec')
  )
}

function isInAuthPath(path: string): boolean {
  const lower = path.toLowerCase()
  return AUTH_DIR_PATTERNS.some((p) => lower.includes(p))
}

function isSecurityConfigFile(path: string): boolean {
  const lower = path.toLowerCase()
  return SECURITY_CONFIG_PATTERNS.some((p) => lower.includes(p))
}

function linesMatch(lines: string[], patterns: string[]): boolean {
  return lines.some((l) => patterns.some((p) => l.includes(p)))
}

// ── Signal detectors ──────────────────────────────────────────────────────────

function detectAuthBypass(input: ZeroDayInput): ZeroDaySignal | null {
  const authFiles = input.changedFiles.filter(isInAuthPath)
  if (authFiles.length === 0) return null

  const BYPASS_KEYWORDS = [
    'return true', 'bypass', 'skip_auth', 'skipAuth',
    'allow_all', 'allowAll', 'no_check', 'noCheck',
  ]
  if (!linesMatch(input.addedLines, BYPASS_KEYWORDS)) return null

  return {
    signalType: 'authentication_bypass_pattern',
    confidence: 0.75,
    evidence: `Authentication code in ${authFiles[0]} modified with bypass-pattern keywords`,
    affectedFiles: authFiles,
  }
}

function detectNetworkEgress(input: ZeroDayInput): ZeroDaySignal | null {
  if (input.hasLockfileChanges) return null   // expected dep addition

  const nonTestFiles = input.changedFiles.filter((f) => !isTestFile(f))
  if (nonTestFiles.length === 0) return null

  const nonTestLines = input.addedLines.filter(
    (_, i) => !isTestFile(input.changedFiles[i % input.changedFiles.length] ?? ''),
  )

  if (!linesMatch(nonTestLines.length > 0 ? nonTestLines : input.addedLines, NETWORK_CALL_PATTERNS)) return null

  // Only flag if it doesn't look like a pre-existing client file
  const suspicious = nonTestFiles.filter((f) => {
    const lower = f.toLowerCase()
    return !lower.includes('client') && !lower.includes('api') && !lower.includes('http')
  })
  if (suspicious.length === 0 && nonTestFiles.length > 0) {
    // All modified files look like normal API client files — lower confidence
    return {
      signalType: 'new_network_egress',
      confidence: 0.4,
      evidence: `Outbound network calls added in ${nonTestFiles[0]}`,
      affectedFiles: nonTestFiles.slice(0, 3),
    }
  }

  return {
    signalType: 'new_network_egress',
    confidence: 0.6,
    evidence: `Unexpected outbound network call patterns added in non-client files`,
    affectedFiles: nonTestFiles.slice(0, 3),
  }
}

function detectCryptoWeakening(input: ZeroDayInput): ZeroDaySignal | null {
  if (!linesMatch(input.addedLines, CRYPTO_WEAKNESS_PATTERNS)) return null
  const affectedFiles = input.changedFiles.filter((f) => !isTestFile(f))
  return {
    signalType: 'cryptography_weakening',
    confidence: 0.8,
    evidence: 'Weak or deprecated cryptographic algorithm/key-size pattern detected in added lines',
    affectedFiles: affectedFiles.slice(0, 3),
  }
}

function detectPrivilegeExpansion(input: ZeroDayInput): ZeroDaySignal | null {
  if (!linesMatch(input.addedLines, PRIVILEGE_PATTERNS)) return null
  const affectedFiles = input.changedFiles.filter((f) => !isTestFile(f))
  return {
    signalType: 'privilege_expansion',
    confidence: 0.7,
    evidence: 'Admin/superuser role or auth bypass assignment added in code',
    affectedFiles: affectedFiles.slice(0, 3),
  }
}

function detectDataExfiltration(input: ZeroDayInput): ZeroDaySignal | null {
  // Requires both a data-read AND a data-write pattern in added lines
  const hasRead = linesMatch(input.addedLines, DATA_READ_PATTERNS)
  const hasWrite = linesMatch(input.addedLines, DATA_WRITE_PATTERNS)
  if (!hasRead || !hasWrite) return null

  const nonTestFiles = input.changedFiles.filter((f) => !isTestFile(f))
  if (nonTestFiles.length === 0) return null

  return {
    signalType: 'data_exfiltration_pattern',
    confidence: 0.65,
    evidence: 'Code change reads data and sends it over network in the same diff',
    affectedFiles: nonTestFiles.slice(0, 3),
  }
}

function detectCodeObfuscation(input: ZeroDayInput): ZeroDaySignal | null {
  const nonTestFiles = input.changedFiles.filter((f) => !isTestFile(f))
  if (nonTestFiles.length === 0) return null

  const hasEval = linesMatch(input.addedLines, OBFUSCATION_PATTERNS)
  const hasBlob = input.addedLines.some((l) => BASE64_BLOB_PATTERN.test(l))

  if (!hasEval && !hasBlob) return null

  const evidence = hasEval
    ? 'Dynamic code evaluation (eval / new Function) added in non-test file'
    : 'Large base64-encoded blob detected in source code'

  return {
    signalType: 'code_obfuscation',
    confidence: 0.85,
    evidence,
    affectedFiles: nonTestFiles.slice(0, 3),
  }
}

function detectNovelInjection(
  input: ZeroDayInput,
  recentBreachSet: Set<string>,
): ZeroDaySignal | null {
  const nonTestFiles = input.changedFiles.filter((f) => !isTestFile(f))
  if (nonTestFiles.length === 0) return null

  if (!linesMatch(input.addedLines, INJECTION_PATTERNS)) return null

  // Boost confidence if recent breach intel mentions injection
  const injectionBreaches = [
    'sql_injection', 'command_injection', 'code_injection', 'xss',
    'ssti', 'path_traversal', 'injection',
  ]
  const breachOverlap = injectionBreaches.some((b) => recentBreachSet.has(b))
  const confidence = breachOverlap ? 0.65 : 0.45

  return {
    signalType: 'novel_injection_vector',
    confidence,
    evidence: breachOverlap
      ? 'String interpolation pattern detected; matches recent breach types in threat intel feed'
      : 'Potentially unvalidated string interpolation added in non-test code',
    affectedFiles: nonTestFiles.slice(0, 3),
  }
}

function detectSecurityConfigUntested(input: ZeroDayInput): ZeroDaySignal | null {
  if (input.hasTestChanges) return null

  const secConfigFiles = input.changedFiles.filter(isSecurityConfigFile)
  if (secConfigFiles.length === 0) return null

  return {
    signalType: 'security_config_modified_untested',
    confidence: 0.35,
    evidence: `Security configuration file(s) modified without corresponding test changes`,
    affectedFiles: secConfigFiles.slice(0, 3),
  }
}

// ── Category derivation ───────────────────────────────────────────────────────

function deriveCategory(
  anomalyScore: number,
  signals: ZeroDaySignal[],
  recentBreachTypes: string[],
): ZeroDayCategory {
  if (anomalyScore >= 70) return 'potential_zero_day'
  if (anomalyScore >= 40) return 'suspicious_change'
  if (anomalyScore >= 20 && recentBreachTypes.length > 0 && signals.length > 0) {
    return 'novel_pattern'
  }
  return 'benign'
}

function buildRecommendation(category: ZeroDayCategory, signals: ZeroDaySignal[]): string {
  if (category === 'benign') return 'No anomalous patterns detected. Normal code change.'

  const topSignal = signals.reduce(
    (best, s) => (s.confidence > best.confidence ? s : best),
    signals[0],
  )

  const base: Record<ZeroDaySignalType, string> = {
    authentication_bypass_pattern:
      'Review authentication change for unintended bypass paths. Require security team sign-off before merge.',
    new_network_egress:
      'Validate that new outbound calls are intentional and to trusted endpoints. Confirm data minimization.',
    cryptography_weakening:
      'Replace deprecated algorithm with a NIST-approved alternative (AES-256-GCM, SHA-256+). Do not merge until remediated.',
    privilege_expansion:
      'Audit privilege assignment — admin roles must follow the principle of least privilege.',
    data_exfiltration_pattern:
      'Review combined data-read and outbound-send pattern. Ensure PII handling complies with regulatory requirements.',
    code_obfuscation:
      'Remove eval/dynamic code execution. For base64 data, move to a proper asset pipeline.',
    novel_injection_vector:
      'Ensure all interpolated values are sanitized or parameterized before use. Run SAST.',
    security_config_modified_untested:
      'Add tests covering the changed security configuration. Untested security config changes carry high regression risk.',
  }

  const prefix =
    category === 'potential_zero_day'
      ? '⚠️ Potential zero-day anomaly: '
      : category === 'suspicious_change'
        ? 'Suspicious change: '
        : 'Novel pattern: '

  return prefix + base[topSignal.signalType]
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Analyse a code diff for anomalous patterns not matching known vulnerability classes.
 *
 * Intended as a fallback when `fingerprintMatchConfidence < 0.3` — i.e., the
 * main semantic fingerprint scan found no strong match.
 */
export function detectZeroDayAnomalies(input: ZeroDayInput): ZeroDayResult {
  const recentBreachSet = new Set(
    input.recentBreachTypes.map((t) => t.toLowerCase().replace(/[- ]/g, '_')),
  )

  const rawSignals: Array<ZeroDaySignal | null> = [
    detectAuthBypass(input),
    detectNetworkEgress(input),
    detectCryptoWeakening(input),
    detectPrivilegeExpansion(input),
    detectDataExfiltration(input),
    detectCodeObfuscation(input),
    detectNovelInjection(input, recentBreachSet),
    detectSecurityConfigUntested(input),
  ]

  const signals = rawSignals.filter((s): s is ZeroDaySignal => s !== null)

  const anomalyScore =
    signals.length === 0
      ? 0
      : Math.round(Math.max(...signals.map((s) => s.confidence)) * 100)

  const category = deriveCategory(anomalyScore, signals, input.recentBreachTypes)
  const recommendation = buildRecommendation(category, signals)

  return { signals, anomalyScore, category, recommendation }
}
