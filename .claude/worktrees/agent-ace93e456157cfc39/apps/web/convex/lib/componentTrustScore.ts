// Component-level trust score computation — pure, no Convex dependencies.
//
// Each SBOM component receives a 0–100 trust score based on static signals
// derived from its metadata. Higher = more trusted.
//
// ── Penalty model ────────────────────────────────────────────────────────────
//
//   KNOWN_VULN_PENALTY      (30)  Package has ≥1 known CVE in Sentinel's breach feed
//   EXTRA_CVE_PENALTY_PER    (8)  Each additional CVE beyond the first
//   EXTRA_CVE_MAX           (20)  Cap on the extra-CVE penalty
//   DIRECT_DEP_SURCHARGE     (5)  Operator explicitly chose a vulnerable package
//   TYPOSQUAT_PENALTY       (25)  Name ≤2 Levenshtein edits from a well-known target
//   SUSPICIOUS_NAME_PENALTY (15)  Single/two-char name or random-hex string
//   PRE_RELEASE_PENALTY      (8)  Unstable version prefix "0." (e.g. 0.9.2)
//   UNKNOWN_VERSION_PENALTY (12)  Missing, "0.0.0", "unknown", "latest", or "*"
//
// Maximum score  = 100 (no penalties apply).
// Minimum score  =   0 (clamped; penalties can never make the score negative).
// ─────────────────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Penalty constants
// ---------------------------------------------------------------------------

const KNOWN_VULN_PENALTY = 30
const EXTRA_CVE_PENALTY_PER = 8
const EXTRA_CVE_MAX = 20
const DIRECT_DEP_SURCHARGE = 5
const TYPOSQUAT_PENALTY = 25
const SUSPICIOUS_NAME_PENALTY = 15
const PRE_RELEASE_PENALTY = 8
const UNKNOWN_VERSION_PENALTY = 12

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ComponentTrustScoreInput = {
  name: string
  version: string
  ecosystem: string
  isDirect: boolean
  /** True if Sentinel's breach-matching already flagged this component. */
  hasKnownVulnerabilities: boolean
  /**
   * Number of breach disclosures in the feed that match this package name.
   * When cveCount > 0 the component is treated as vulnerable even if
   * `hasKnownVulnerabilities` has not been patched yet.
   */
  cveCount: number
}

export type ComponentTrustScoreResult = {
  /** Composite trust score, 0 (untrusted) – 100 (fully trusted). */
  score: number
  /** Human-readable explanation for each penalty that was applied. */
  signals: string[]
}

// ---------------------------------------------------------------------------
// Well-known package corpus — typosquat detection target list.
// Mirrors the corpus in supplyChainIntel.ts; keep both in sync.
// ---------------------------------------------------------------------------

const WELL_KNOWN: Record<string, string[]> = {
  npm: [
    'angular', 'axios', 'babel-core', 'chalk', 'commander', 'concurrently',
    'cors', 'cross-env', 'dotenv', 'eslint', 'express', 'helmet',
    'jest', 'jsonwebtoken', 'lodash', 'moment', 'mongoose', 'mocha',
    'next', 'nodemon', 'nuxt', 'passport', 'pm2', 'prettier',
    'prisma', 'react', 'rimraf', 'rollup', 'sequelize', 'svelte',
    'typescript', 'uuid', 'vite', 'vue', 'webpack',
  ],
  pypi: [
    'aiohttp', 'anthropic', 'black', 'boto3', 'celery', 'cryptography',
    'django', 'fastapi', 'flake8', 'flask', 'gunicorn', 'httpx',
    'mypy', 'numpy', 'openai', 'pandas', 'paramiko', 'pillow',
    'pip', 'pydantic', 'pytest', 'redis', 'requests', 'setuptools',
    'sqlalchemy', 'starlette', 'twine', 'uvicorn', 'wheel',
  ],
  cargo: [
    'actix-web', 'anyhow', 'axum', 'base64', 'chrono', 'clap',
    'env_logger', 'hex', 'hyper', 'log', 'rand', 'reqwest',
    'serde', 'thiserror', 'tokio', 'tracing', 'uuid',
  ],
  go: [
    'chi', 'cobra', 'echo', 'fiber', 'gin', 'gorm',
    'logrus', 'prometheus', 'testify', 'viper', 'zap',
  ],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Bounded Levenshtein distance — returns bound+1 when distance > bound. */
function levenshteinBounded(a: string, b: string, bound: number): number {
  if (Math.abs(a.length - b.length) > bound) return bound + 1

  const prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  const curr = new Array<number>(b.length + 1)

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i
    for (let j = 1; j <= b.length; j++) {
      curr[j] =
        a[i - 1] === b[j - 1]
          ? prev[j - 1]
          : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1])
    }
    for (let k = 0; k <= b.length; k++) prev[k] = curr[k]
  }

  return prev[b.length]
}

/**
 * Normalise a package name for typosquat comparison:
 * strip npm scope, lowercase, collapse separators.
 */
function normalizeForTyposquat(name: string): string {
  return name
    .replace(/^@[^/]+\//, '')
    .toLowerCase()
    .replace(/[-_.]/g, '')
}

/** True if the name is typographically ≤2 edits from a well-known package
 *  in the given ecosystem and is NOT an exact match (i.e. an actual typosquat). */
function isTyposquatRisk(name: string, ecosystem: string): boolean {
  const normalized = normalizeForTyposquat(name)
  const corpus = WELL_KNOWN[ecosystem] ?? []

  for (const known of corpus) {
    const normalizedKnown = normalizeForTyposquat(known)
    if (normalized === normalizedKnown) return false // exact match — legitimate package
    const dist = levenshteinBounded(normalized, normalizedKnown, 2)
    if (dist >= 1 && dist <= 2) return true
  }
  return false
}

/** True for unusually short or opaque names that are common in malicious packages. */
function isSuspiciousName(name: string): boolean {
  const bare = normalizeForTyposquat(name)
  if (bare.length <= 2) return true              // single/two-char names
  if (/^\d+$/.test(bare)) return true             // purely numeric (e.g. "123")
  if (/^[0-9a-f]{8,}$/.test(bare)) return true   // random-looking hex string
  return false
}

/** True for pre-release versions: "0.x.y" with x > 0 or y > 0. */
function isPreRelease(version: string): boolean {
  if (!version) return false
  // Match "0.anything" that is not "0.0.0" (which is in the unknown bucket)
  return /^0\.\d/.test(version) && version !== '0.0.0'
}

/** True for missing, placeholder, or floating version pins. */
function isUnknownVersion(version: string): boolean {
  if (!version) return true
  const normalized = version.trim().toLowerCase()
  return (
    normalized === '' ||
    normalized === '0.0.0' ||
    normalized === 'unknown' ||
    normalized === 'latest' ||
    normalized === '*' ||
    normalized === 'dev' ||
    normalized === 'main'
  )
}

// ---------------------------------------------------------------------------
// Core computation
// ---------------------------------------------------------------------------

/**
 * Compute a trust score for a single SBOM component.
 *
 * The formula starts at 100 and subtracts penalties for each risk signal.
 * The final score is clamped to [0, 100].
 */
export function computeComponentTrustScore(
  input: ComponentTrustScoreInput,
): ComponentTrustScoreResult {
  let deduction = 0
  const signals: string[] = []

  const hasVuln = input.hasKnownVulnerabilities || input.cveCount > 0

  // ── Vulnerability penalties ──────────────────────────────────────────────
  if (hasVuln) {
    deduction += KNOWN_VULN_PENALTY
    signals.push(
      `Known vulnerability: -${KNOWN_VULN_PENALTY} (CVE present in Sentinel breach feed)`,
    )

    if (input.cveCount > 1) {
      const extraPenalty = Math.min(EXTRA_CVE_MAX, (input.cveCount - 1) * EXTRA_CVE_PENALTY_PER)
      deduction += extraPenalty
      signals.push(
        `Multiple CVEs (${input.cveCount} total): -${extraPenalty} (each additional CVE adds ${EXTRA_CVE_PENALTY_PER}, capped at ${EXTRA_CVE_MAX})`,
      )
    }

    if (input.isDirect) {
      deduction += DIRECT_DEP_SURCHARGE
      signals.push(
        `Direct dependency surcharge: -${DIRECT_DEP_SURCHARGE} (operator explicitly selected a vulnerable package)`,
      )
    }
  }

  // ── Supply-chain name signals ────────────────────────────────────────────
  if (isTyposquatRisk(input.name, input.ecosystem)) {
    deduction += TYPOSQUAT_PENALTY
    signals.push(
      `Typosquat risk: -${TYPOSQUAT_PENALTY} ("${input.name}" is ≤2 edits from a well-known ${input.ecosystem} package)`,
    )
  } else if (isSuspiciousName(input.name)) {
    // Only apply suspicious-name penalty when not already flagged as typosquat
    deduction += SUSPICIOUS_NAME_PENALTY
    signals.push(
      `Suspicious name: -${SUSPICIOUS_NAME_PENALTY} ("${input.name}" matches known malicious naming patterns)`,
    )
  }

  // ── Version signals ──────────────────────────────────────────────────────
  if (isUnknownVersion(input.version)) {
    deduction += UNKNOWN_VERSION_PENALTY
    signals.push(
      `Unknown/floating version: -${UNKNOWN_VERSION_PENALTY} ("${input.version}" is unpinned or unresolvable)`,
    )
  } else if (isPreRelease(input.version)) {
    deduction += PRE_RELEASE_PENALTY
    signals.push(
      `Pre-release version: -${PRE_RELEASE_PENALTY} ("${input.version}" is not yet stable — 0.x series)`,
    )
  }

  return {
    score: Math.max(0, Math.min(100, 100 - deduction)),
    signals,
  }
}
