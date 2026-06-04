// WS-30 — Hardcoded Credential & Secret Detection Engine
//
// Pure computation library. Zero Convex imports, zero network calls.
// Used by secretDetectionIntel.ts to scan content strings from push events.
//
// Detection strategy:
//  1. Pattern-based: 18 regex detectors across 10 credential families
//  2. Entropy-based: Shannon entropy analysis on quoted string literals (>= 4.5 bits/char)
//
// False-positive reduction:
//  - Placeholder filter: ${...}, <...>, YOUR_..., EXAMPLE_..., changeme, xxxxxxxx, all-same-char
//  - Test-file hint: marks findings from known test/spec/fixture paths
//  - UUID + hex-hash exclusion from entropy scanner

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecretCategory =
  | 'aws_credential'
  | 'gcp_credential'
  | 'azure_credential'
  | 'openai_key'
  | 'anthropic_key'
  | 'ai_provider_key'
  | 'github_token'
  | 'vcs_token'
  | 'stripe_key'
  | 'payment_credential'
  | 'sendgrid_key'
  | 'twilio_credential'
  | 'communication_key'
  | 'private_key'
  | 'database_url'
  | 'hardcoded_password'
  | 'hardcoded_api_key'
  | 'high_entropy_string'

export type SecretSeverity = 'critical' | 'high' | 'medium'

export interface SecretFinding {
  category: SecretCategory
  severity: SecretSeverity
  description: string
  /** First 4 chars + *** + last 4 chars of the matched value. */
  redactedMatch: string
  /** True when the scanned item's filename suggests a test/fixture context. */
  isTestFileHint: boolean
}

export interface SecretScanResult {
  findings: SecretFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  totalFound: number
  isClean: boolean
  summary: string
}

// ---------------------------------------------------------------------------
// Detector table
// ---------------------------------------------------------------------------

interface Detector {
  category: SecretCategory
  severity: SecretSeverity
  description: string
  pattern: RegExp
}

const DETECTORS: Detector[] = [
  // ── AWS ─────────────────────────────────────────────────────────────────
  {
    category: 'aws_credential',
    severity: 'critical',
    description: 'AWS Access Key ID',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    category: 'aws_credential',
    severity: 'critical',
    description: 'AWS Secret Access Key assignment',
    pattern: /aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+]{40}["']?/i,
  },
  // ── GCP ─────────────────────────────────────────────────────────────────
  {
    category: 'gcp_credential',
    severity: 'critical',
    description: 'GCP Service Account private key JSON fragment',
    pattern: /"private_key"\s*:\s*"-----BEGIN/,
  },
  // ── Azure ────────────────────────────────────────────────────────────────
  {
    category: 'azure_credential',
    severity: 'critical',
    description: 'Azure Storage connection string',
    pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44}/,
  },
  // ── OpenAI ───────────────────────────────────────────────────────────────
  {
    category: 'openai_key',
    severity: 'critical',
    description: 'OpenAI API key',
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  // ── Anthropic ────────────────────────────────────────────────────────────
  {
    category: 'anthropic_key',
    severity: 'critical',
    description: 'Anthropic API key',
    pattern: /\bsk-ant-api[0-9A-Za-z_-]{40,}\b/,
  },
  // ── HuggingFace / Cohere ─────────────────────────────────────────────────
  {
    category: 'ai_provider_key',
    severity: 'high',
    description: 'HuggingFace API token',
    pattern: /\bhf_[a-zA-Z0-9]{30,}\b/,
  },
  // ── GitHub ───────────────────────────────────────────────────────────────
  {
    category: 'github_token',
    severity: 'critical',
    description: 'GitHub Personal Access Token (classic)',
    pattern: /\bghp_[0-9A-Za-z]{36}\b/,
  },
  {
    category: 'github_token',
    severity: 'critical',
    description: 'GitHub OAuth token',
    pattern: /\bgho_[0-9A-Za-z]{36}\b/,
  },
  {
    category: 'github_token',
    severity: 'high',
    description: 'GitHub Actions / installation token',
    pattern: /\bghs_[0-9A-Za-z]{36}\b/,
  },
  // ── GitLab ───────────────────────────────────────────────────────────────
  {
    category: 'vcs_token',
    severity: 'high',
    description: 'GitLab Personal Access Token',
    pattern: /\bglpat-[0-9A-Za-z_-]{20,}\b/,
  },
  // ── Stripe ───────────────────────────────────────────────────────────────
  {
    category: 'stripe_key',
    severity: 'critical',
    description: 'Stripe live secret key',
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/,
  },
  {
    category: 'stripe_key',
    severity: 'high',
    description: 'Stripe test secret key',
    pattern: /\bsk_test_[0-9a-zA-Z]{24,}\b/,
  },
  // ── SendGrid ─────────────────────────────────────────────────────────────
  {
    category: 'sendgrid_key',
    severity: 'high',
    description: 'SendGrid API key',
    pattern: /\bSG\.[a-zA-Z0-9._-]{22,}\.[a-zA-Z0-9._-]{43,}\b/,
  },
  // ── Slack ────────────────────────────────────────────────────────────────
  {
    category: 'communication_key',
    severity: 'high',
    description: 'Slack bot token',
    pattern: /\bxoxb-[0-9]{9,13}-[0-9]{9,15}-[0-9a-zA-Z]{20,30}\b/,
  },
  // ── Private keys ─────────────────────────────────────────────────────────
  {
    category: 'private_key',
    severity: 'critical',
    description: 'Private key (RSA/EC/SSH/PGP)',
    pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/,
  },
  // ── Database URLs with credentials ───────────────────────────────────────
  {
    category: 'database_url',
    severity: 'high',
    description: 'PostgreSQL connection string with credentials',
    pattern: /postgresql:\/\/[^:@/\s]+:[^@/\s]{4,}@[^/\s]+/i,
  },
  {
    category: 'database_url',
    severity: 'high',
    description: 'MongoDB connection string with credentials',
    pattern: /mongodb(?:\+srv)?:\/\/[^:@/\s]+:[^@/\s]{4,}@[^/\s]+/i,
  },
  // ── Hardcoded passwords ───────────────────────────────────────────────────
  {
    category: 'hardcoded_password',
    severity: 'medium',
    description: 'Hardcoded password in assignment',
    pattern: /\b(?:password|passwd|secret|pwd)\s*[=:]\s*["'][^"'${}%<>\s]{8,}["']/i,
  },
  // ── Generic API keys ─────────────────────────────────────────────────────
  {
    category: 'hardcoded_api_key',
    severity: 'medium',
    description: 'Hardcoded API key in assignment',
    pattern: /\bapi[_-]?key\s*[=:]\s*["'][^"'${}%<>\s]{16,}["']/i,
  },
]

// ---------------------------------------------------------------------------
// Placeholder detection
// ---------------------------------------------------------------------------

/** Known placeholder tokens that should never trigger a finding. */
const PLACEHOLDER_PATTERNS: RegExp[] = [
  /^\$\{[^}]*\}$/,              // ${SOME_VAR}
  /^%[A-Z_]+%$/,                // %SOME_VAR%
  /^<[^>]+>$/,                  // <SOME_VAR>
  /^YOUR_/i,                    // YOUR_API_KEY
  /^EXAMPLE_/i,                 // EXAMPLE_SECRET
  /^REPLACE_ME/i,               // REPLACE_ME_WITH_REAL_KEY
  /^changeme$/i,                // changeme
  /^password$/i,                // password
  /^(pass|secret|key|token)123!?$/i, // password123
  /^test[-_]?key/i,             // test-key, testkey
  /^dev[-_]?key/i,              // dev-key, devkey
  /^dummy[-_]?/i,               // dummy-key
  /^fake[-_]?/i,                // fake-token
  /^mock[-_]?/i,                // mock-secret
  /^sample[-_]?/i,              // sample-key
  /^placeholder/i,              // placeholder
  /^xxx+$/i,                    // xxxx...
  /^0{8,}$/,                    // 00000000...
]

/** True if every character in the string is the same (e.g. "aaaaaaa"). */
function isAllSameChar(s: string): boolean {
  if (s.length < 2) return false
  return s.split('').every((c) => c === s[0])
}

export function isLikelyPlaceholder(value: string): boolean {
  const trimmed = value.trim()
  if (trimmed.length === 0) return true
  if (isAllSameChar(trimmed)) return true
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(trimmed)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Match redaction
// ---------------------------------------------------------------------------

/** Show first 4 + *** + last 4 of the matched value. */
export function redactMatch(match: string): string {
  const clean = match.trim()
  if (clean.length <= 12) return clean.slice(0, 4) + '***'
  return clean.slice(0, 4) + '***' + clean.slice(-4)
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/** Shannon entropy in bits per character for the given string. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq: Record<string, number> = {}
  for (const ch of s) {
    freq[ch] = (freq[ch] ?? 0) + 1
  }
  let entropy = 0
  for (const count of Object.values(freq)) {
    const p = count / s.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// ---------------------------------------------------------------------------
// Test-file hint
// ---------------------------------------------------------------------------

const TEST_FILE_PATTERNS: RegExp[] = [
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /__tests__/i,
  /test_/i,
  /spec_/i,
  /fixtures?/i,
  /mocks?/i,
  /stubs?/i,
]

export function isTestFile(filename: string): boolean {
  return TEST_FILE_PATTERNS.some((p) => p.test(filename))
}

// ---------------------------------------------------------------------------
// Entropy-based secret scanner
// ---------------------------------------------------------------------------

/** Regex to extract candidate strings from quoted literals. */
const QUOTED_STRING = /["']([^"'\n\r]{16,})["']/g

/** Patterns that indicate a high-entropy string is benign (UUID, hex hash). */
const BENIGN_HIGH_ENTROPY: RegExp[] = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^[0-9a-f]{32}$/i, // MD5 hash
  /^[0-9a-f]{40}$/i, // SHA-1
  /^[0-9a-f]{64}$/i, // SHA-256
]

const ENTROPY_THRESHOLD = 4.5

function detectEntropySecrets(
  content: string,
  testFileHint: boolean,
): SecretFinding[] {
  const findings: SecretFinding[] = []
  let match: RegExpExecArray | null
  QUOTED_STRING.lastIndex = 0
  while ((match = QUOTED_STRING.exec(content)) !== null) {
    const candidate = match[1]
    if (isLikelyPlaceholder(candidate)) continue
    if (BENIGN_HIGH_ENTROPY.some((p) => p.test(candidate))) continue
    if (shannonEntropy(candidate) >= ENTROPY_THRESHOLD) {
      findings.push({
        category: 'high_entropy_string',
        severity: 'medium',
        description: 'High-entropy string literal — possible hardcoded secret',
        redactedMatch: redactMatch(candidate),
        isTestFileHint: testFileHint,
      })
    }
  }
  return findings
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

/** Scan a single content string for secrets. */
export function scanForSecrets(
  content: string,
  filename?: string,
): SecretScanResult {
  const testFileHint = filename !== undefined && isTestFile(filename)
  const findings: SecretFinding[] = []

  // Pattern-based detection
  for (const detector of DETECTORS) {
    const match = detector.pattern.exec(content)
    if (!match) continue
    const matched = match[0]
    if (isLikelyPlaceholder(matched)) continue
    // Extract the first quoted value within the match (for assignment patterns like
    // api_key = "VALUE") and check that for placeholder patterns.
    const quotedValueMatch = /["']([^"']+)["']/.exec(matched)
    const valueToCheck = quotedValueMatch
      ? quotedValueMatch[1]
      : matched.replace(/^["']|["']$/g, '')
    if (isLikelyPlaceholder(valueToCheck)) continue
    findings.push({
      category: detector.category,
      severity: detector.severity,
      description: detector.description,
      redactedMatch: redactMatch(matched),
      isTestFileHint: testFileHint,
    })
  }

  // Entropy-based detection (only if no pattern match already caught it)
  const entropyFindings = detectEntropySecrets(content, testFileHint)
  // Deduplicate: skip entropy findings whose redactedMatch overlaps a pattern finding
  const patternRedacted = new Set(findings.map((f) => f.redactedMatch))
  for (const ef of entropyFindings) {
    if (!patternRedacted.has(ef.redactedMatch)) {
      findings.push(ef)
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const totalFound = findings.length
  const isClean = totalFound === 0

  const summary = buildSummary(isClean, criticalCount, highCount, mediumCount, filename)

  return { findings, criticalCount, highCount, mediumCount, totalFound, isClean, summary }
}

function buildSummary(
  isClean: boolean,
  critical: number,
  high: number,
  medium: number,
  filename?: string,
): string {
  const location = filename ? ` in ${filename}` : ''
  if (isClean) return `No secrets detected${location}.`
  const parts: string[] = []
  if (critical > 0) parts.push(`${critical} critical`)
  if (high > 0) parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  return `${parts.join(', ')} secret(s) detected${location}.`
}

// ---------------------------------------------------------------------------
// Combine multiple scan results
// ---------------------------------------------------------------------------

/** Aggregate multiple scan results into one summary. */
export function combineResults(results: SecretScanResult[]): SecretScanResult {
  const allFindings = results.flatMap((r) => r.findings)
  const criticalCount = allFindings.filter((f) => f.severity === 'critical').length
  const highCount = allFindings.filter((f) => f.severity === 'high').length
  const mediumCount = allFindings.filter((f) => f.severity === 'medium').length
  const totalFound = allFindings.length
  const isClean = totalFound === 0
  const summary = buildSummary(isClean, criticalCount, highCount, mediumCount)
  return { findings: allFindings, criticalCount, highCount, mediumCount, totalFound, isClean, summary }
}
