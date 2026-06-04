// WS-43 — Known CVE Version Range Scanner: pure computation library.
//
// A curated offline database of ~30 high-impact, widely-exploited CVEs with
// minimum-safe-version thresholds. For each SBOM component, compares the
// installed version against the first patched release and emits a finding
// if the component is below that threshold.
//
// This is intentionally distinct from the online breach-intel feeds (WS-07,
// WS-16): this scanner is offline-first, instant at ingest time, and covers
// the most critical vulnerabilities developers are most likely to encounter.
//
// Version comparison strategy:
//   Parse up to (major, minor, patch) numeric tuples from any version string.
//   If installed < minimumSafeVersion → vulnerable.
//   Unparseable installed versions are skipped (null is returned).
//   Pre-release / build-metadata suffixes are stripped; the base version is
//   compared, which is the conservative choice.
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

export type CveEntry = {
  /** CVE identifier. */
  cveId: string
  /** Ecosystem: 'npm' | 'maven' | 'pypi' | 'gem' | 'cargo'. */
  ecosystem: string
  /**
   * Lowercase package name.
   * Maven entries use the full `groupId:artifactId` coordinate.
   */
  packageName: string
  /**
   * The first version that is NOT vulnerable (exclusive lower bound fix).
   * All installed versions strictly below this value are considered affected.
   */
  minimumSafeVersion: string
  /** CVSS v3 base score (0.0–10.0). */
  cvss: number
  /** Brief description of the vulnerability. */
  description: string
  /** Milliseconds epoch of CVE publication. */
  publishedAt: number
}

/**
 * Curated offline CVE database.
 * Sources: NVD, GitHub Security Advisories, vendor security bulletins.
 * Version thresholds are the first patched releases per the original advisory.
 */
export const KNOWN_CVE_DATABASE: CveEntry[] = [
  // ── npm ──────────────────────────────────────────────────────────────────

  // Log4Shell-era cousin: critical SSRF in node-fetch via redirect
  { cveId: 'CVE-2022-0235',   ecosystem: 'npm', packageName: 'node-fetch',       minimumSafeVersion: '2.6.7',   cvss: 8.8,  description: 'SSRF: node-fetch forwards cookies across hosts when following redirects to different origins', publishedAt: Date.UTC(2022, 0, 14) },

  // Prototype-pollution family (critical / high)
  { cveId: 'CVE-2021-44906',  ecosystem: 'npm', packageName: 'minimist',          minimumSafeVersion: '1.2.6',   cvss: 9.8,  description: 'Prototype pollution in minimist argument parser allows code execution or property injection', publishedAt: Date.UTC(2022, 2, 17) },
  { cveId: 'CVE-2023-26136',  ecosystem: 'npm', packageName: 'tough-cookie',      minimumSafeVersion: '4.1.3',   cvss: 9.8,  description: 'Prototype pollution via CookieJar.setCookie allows arbitrary code execution', publishedAt: Date.UTC(2023, 6, 1) },
  { cveId: 'CVE-2022-24999',  ecosystem: 'npm', packageName: 'qs',                minimumSafeVersion: '6.7.3',   cvss: 7.5,  description: 'Prototype pollution in qs query-string parser; Express apps using qs < 6.7.3 are affected', publishedAt: Date.UTC(2022, 11, 2) },
  { cveId: 'CVE-2021-23358',  ecosystem: 'npm', packageName: 'underscore',        minimumSafeVersion: '1.13.0.1',cvss: 7.2,  description: 'Arbitrary code execution via template injection in _.template when user input reaches the template source', publishedAt: Date.UTC(2021, 2, 29) },

  // Sandbox escape (critical)
  { cveId: 'CVE-2023-29017',  ecosystem: 'npm', packageName: 'vm2',               minimumSafeVersion: '3.9.17',  cvss: 9.8,  description: 'Sandbox escape allows untrusted code to break out of the vm2 sandbox and execute on the host', publishedAt: Date.UTC(2023, 3, 6) },

  // Auth / JWT vulnerabilities
  { cveId: 'CVE-2022-23529',  ecosystem: 'npm', packageName: 'jsonwebtoken',      minimumSafeVersion: '9.0.0',   cvss: 7.6,  description: 'Improper handling of a secretOrPublicKey allows an attacker with a user-controlled public key to forge valid JWTs', publishedAt: Date.UTC(2022, 11, 21) },

  // ReDoS (algorithmic complexity attacks)
  { cveId: 'CVE-2021-3807',   ecosystem: 'npm', packageName: 'ansi-regex',        minimumSafeVersion: '5.0.1',   cvss: 7.5,  description: 'ReDoS: a crafted ANSI escape sequence causes catastrophic backtracking in ansi-regex', publishedAt: Date.UTC(2021, 8, 17) },
  { cveId: 'CVE-2022-25883',  ecosystem: 'npm', packageName: 'semver',            minimumSafeVersion: '7.5.2',   cvss: 7.5,  description: 'ReDoS: pathological version strings cause exponential backtracking in semver range parsing', publishedAt: Date.UTC(2023, 5, 21) },
  { cveId: 'CVE-2024-4068',   ecosystem: 'npm', packageName: 'braces',            minimumSafeVersion: '3.0.3',   cvss: 7.5,  description: 'ReDoS: crafted brace expansion patterns lead to excessive CPU usage', publishedAt: Date.UTC(2024, 4, 14) },

  // SSRF / request vulnerabilities
  { cveId: 'CVE-2024-29415',  ecosystem: 'npm', packageName: 'ip',                minimumSafeVersion: '2.0.1',   cvss: 7.5,  description: 'Incorrect handling of private IPv6 addresses allows SSRF bypass in ip.isPrivate() checks', publishedAt: Date.UTC(2024, 4, 27) },
  { cveId: 'CVE-2020-28168',  ecosystem: 'npm', packageName: 'axios',             minimumSafeVersion: '0.21.1',  cvss: 5.9,  description: 'SSRF via crafted URLs: axios < 0.21.1 follows redirects that bypass localhost SSRF protections', publishedAt: Date.UTC(2020, 10, 6) },

  // XSS
  { cveId: 'CVE-2020-11022',  ecosystem: 'npm', packageName: 'jquery',            minimumSafeVersion: '3.5.0',   cvss: 6.1,  description: 'XSS: passing HTML from untrusted sources to jQuery\'s DOM manipulation methods can execute scripts', publishedAt: Date.UTC(2020, 3, 29) },

  // Command injection
  { cveId: 'CVE-2021-23337',  ecosystem: 'npm', packageName: 'lodash',            minimumSafeVersion: '4.17.21', cvss: 7.2,  description: 'Command injection in lodash.template when user data is passed to the template source argument', publishedAt: Date.UTC(2021, 1, 15) },

  // Path traversal / DoS
  { cveId: 'CVE-2022-24785',  ecosystem: 'npm', packageName: 'moment',            minimumSafeVersion: '2.29.4',  cvss: 7.5,  description: 'Path traversal in moment\'s locale loading when using user-controlled locale strings', publishedAt: Date.UTC(2022, 3, 4) },
  { cveId: 'CVE-2022-0144',   ecosystem: 'npm', packageName: 'shelljs',           minimumSafeVersion: '0.8.5',   cvss: 7.0,  description: 'Privilege escalation via improper directory permissions when ShellJS writes temp files', publishedAt: Date.UTC(2022, 0, 11) },
  { cveId: 'CVE-2021-23343',  ecosystem: 'npm', packageName: 'path-parse',        minimumSafeVersion: '1.0.7',   cvss: 5.3,  description: 'ReDoS: certain path strings cause catastrophic backtracking in path-parse', publishedAt: Date.UTC(2021, 4, 4) },

  // ── maven ─────────────────────────────────────────────────────────────────

  // Log4Shell (the original — CVSS 10.0)
  { cveId: 'CVE-2021-44228',  ecosystem: 'maven', packageName: 'org.apache.logging.log4j:log4j-core', minimumSafeVersion: '2.15.0', cvss: 10.0, description: 'Log4Shell: JNDI lookup injection in log4j-core log messages allows unauthenticated remote code execution', publishedAt: Date.UTC(2021, 11, 10) },
  // Log4Shell second bypass
  { cveId: 'CVE-2021-45046',  ecosystem: 'maven', packageName: 'org.apache.logging.log4j:log4j-core', minimumSafeVersion: '2.16.0', cvss: 9.0,  description: 'Log4j second bypass: non-default Thread Context Map configurations allow RCE (CVE-2021-44228 was incomplete)', publishedAt: Date.UTC(2021, 11, 14) },

  // Spring4Shell
  { cveId: 'CVE-2022-22965',  ecosystem: 'maven', packageName: 'org.springframework:spring-core',     minimumSafeVersion: '5.3.18', cvss: 9.8,  description: 'Spring4Shell: data binding with MVC on JDK >= 9 allows unauthenticated remote code execution via ClassLoader manipulation', publishedAt: Date.UTC(2022, 3, 1) },

  // Text4Shell
  { cveId: 'CVE-2022-42889',  ecosystem: 'maven', packageName: 'org.apache.commons:commons-text',    minimumSafeVersion: '1.10.0', cvss: 9.8,  description: 'Text4Shell: string interpolation with ${script:}, ${dns:}, ${url:} lookups allows RCE on Apache Commons Text', publishedAt: Date.UTC(2022, 9, 13) },

  // Apache Struts RCE
  { cveId: 'CVE-2023-50164',  ecosystem: 'maven', packageName: 'org.apache.struts:struts2-core',     minimumSafeVersion: '6.3.0.2', cvss: 9.8,  description: 'File upload parameter manipulation allows an attacker to achieve path traversal and RCE in Apache Struts 2', publishedAt: Date.UTC(2023, 11, 7) },

  // Jackson-databind DoS/deserialization
  { cveId: 'CVE-2022-42003',  ecosystem: 'maven', packageName: 'com.fasterxml.jackson.core:jackson-databind', minimumSafeVersion: '2.13.4.1', cvss: 7.5, description: 'Infinite recursion in UNWRAP_SINGLE_VALUE_ARRAYS deserialization causes DoS in jackson-databind', publishedAt: Date.UTC(2022, 9, 2) },

  // ── pypi ─────────────────────────────────────────────────────────────────

  // Pillow arbitrary code execution
  { cveId: 'CVE-2023-50447',  ecosystem: 'pypi', packageName: 'pillow',            minimumSafeVersion: '10.2.0',  cvss: 8.8,  description: 'Arbitrary code execution in PIL.ImageMath.eval via crafted image files with malicious expressions', publishedAt: Date.UTC(2024, 1, 3) },

  // requests proxy header leak
  { cveId: 'CVE-2023-32681',  ecosystem: 'pypi', packageName: 'requests',          minimumSafeVersion: '2.31.0',  cvss: 6.1,  description: 'Proxy-Authorization header is forwarded to the destination server on cross-origin redirects', publishedAt: Date.UTC(2023, 4, 26) },

  // cryptography NULL pointer
  { cveId: 'CVE-2024-26130',  ecosystem: 'pypi', packageName: 'cryptography',      minimumSafeVersion: '42.0.4',  cvss: 7.5,  description: 'NULL pointer dereference in PKCS#12 parsing causes crash when certain fields are empty', publishedAt: Date.UTC(2024, 1, 20) },

  // Werkzeug debugger RCE
  { cveId: 'CVE-2024-34069',  ecosystem: 'pypi', packageName: 'werkzeug',          minimumSafeVersion: '3.0.3',   cvss: 9.8,  description: 'Remote code execution via debugger PIN brute force; the PIN generation algorithm is predictable in CI/cloud environments', publishedAt: Date.UTC(2024, 4, 6) },

  // Jinja2 XSS
  { cveId: 'CVE-2024-22195',  ecosystem: 'pypi', packageName: 'jinja2',            minimumSafeVersion: '3.1.3',   cvss: 5.4,  description: 'XSS via xmlattr filter: Jinja2 does not escape attribute keys, allowing injection of arbitrary HTML attributes', publishedAt: Date.UTC(2024, 0, 11) },

  // Paramiko Terrapin
  { cveId: 'CVE-2023-48795',  ecosystem: 'pypi', packageName: 'paramiko',          minimumSafeVersion: '3.4.0',   cvss: 5.9,  description: 'Terrapin SSH attack: prefix-truncation vulnerability allows downgrade of connection security algorithms', publishedAt: Date.UTC(2023, 11, 18) },
]

// Pre-indexed lookup: 'ecosystem:packageName' → CveEntry[]
const _CVE_INDEX = new Map<string, CveEntry[]>()
for (const entry of KNOWN_CVE_DATABASE) {
  const key = `${entry.ecosystem}:${entry.packageName.toLowerCase()}`
  const bucket = _CVE_INDEX.get(key) ?? []
  bucket.push(entry)
  _CVE_INDEX.set(key, bucket)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CveRiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type CveFinding = {
  packageName: string
  ecosystem: string
  version: string
  cveId: string
  cvss: number
  minimumSafeVersion: string
  riskLevel: CveRiskLevel
  description: string
  evidence: string
}

export type CveReport = {
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalVulnerable: number
  overallRisk: CveRiskLevel | 'none'
  findings: CveFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Version parsing helpers
// ---------------------------------------------------------------------------

/**
 * Parse a version string into a (major, minor, patch) numeric tuple.
 * Strips leading `v`/`V`, Maven `.RELEASE`/`.SNAPSHOT` qualifiers, and
 * PyPI pre-release suffixes (a1, b2, rc3, .postN, .devN) before parsing.
 * Returns null when no numeric version can be extracted.
 */
export function parseVersionTuple(version: string): [number, number, number] | null {
  // Strip common qualifiers
  const cleaned = version.trim()
    .replace(/^[vV]/, '')
    .replace(/\.(RELEASE|SNAPSHOT|BUILD-SNAPSHOT|GA)$/i, '')
    .replace(/(a|alpha|b|beta|rc|\.post|\.dev)\d*$/i, '')

  const match3 = /^(\d+)\.(\d+)\.(\d+)/.exec(cleaned)
  if (match3) {
    return [parseInt(match3[1], 10), parseInt(match3[2], 10), parseInt(match3[3], 10)]
  }
  const match2 = /^(\d+)\.(\d+)/.exec(cleaned)
  if (match2) {
    return [parseInt(match2[1], 10), parseInt(match2[2], 10), 0]
  }
  const match1 = /^(\d+)/.exec(cleaned)
  if (match1) {
    return [parseInt(match1[1], 10), 0, 0]
  }
  return null
}

/**
 * Compare two version tuples lexicographically by (major, minor, patch).
 * Returns -1 if a < b, 0 if equal, +1 if a > b.
 */
export function compareVersionTuples(
  a: [number, number, number],
  b: [number, number, number],
): -1 | 0 | 1 {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1
    if (a[i] > b[i]) return 1
  }
  return 0
}

/**
 * Return true when `installed` is strictly below `threshold`.
 * Returns null when either version cannot be parsed (skip, don't flag).
 */
export function isVersionVulnerable(installed: string, threshold: string): boolean | null {
  const a = parseVersionTuple(installed)
  const b = parseVersionTuple(threshold)
  if (!a || !b) return null
  return compareVersionTuples(a, b) < 0
}

/**
 * Map a CVSS v3 base score to a `CveRiskLevel` using standard NVD thresholds.
 *   9.0–10.0 → critical
 *   7.0–8.9  → high
 *   4.0–6.9  → medium
 *   0.1–3.9  → low
 */
export function cvssToRiskLevel(cvss: number): CveRiskLevel {
  if (cvss >= 9.0) return 'critical'
  if (cvss >= 7.0) return 'high'
  if (cvss >= 4.0) return 'medium'
  return 'low'
}

// ---------------------------------------------------------------------------
// Core detector
// ---------------------------------------------------------------------------

/**
 * Check a single SBOM component against the known CVE database.
 * Returns an array of `CveFinding` (one per matching CVE), empty if safe.
 */
export function checkComponentCves(component: {
  name: string
  version: string
  ecosystem: string
}): CveFinding[] {
  const { name, version, ecosystem } = component
  const key = `${ecosystem.toLowerCase()}:${name.toLowerCase()}`
  const entries = _CVE_INDEX.get(key)
  if (!entries) return []

  const findings: CveFinding[] = []
  for (const entry of entries) {
    const vulnerable = isVersionVulnerable(version, entry.minimumSafeVersion)
    if (vulnerable !== true) continue // null (unparseable) or false → skip

    findings.push({
      packageName: name,
      ecosystem,
      version,
      cveId: entry.cveId,
      cvss: entry.cvss,
      minimumSafeVersion: entry.minimumSafeVersion,
      riskLevel: cvssToRiskLevel(entry.cvss),
      description: entry.description,
      evidence: `package=${name} version=${version} cve=${entry.cveId} cvss=${entry.cvss} fixedIn=${entry.minimumSafeVersion}`,
    })
  }
  return findings
}

// ---------------------------------------------------------------------------
// Report aggregator
// ---------------------------------------------------------------------------

/**
 * Run CVE version-range scanning across the full SBOM component list.
 * Deduplicates by `ecosystem:name:version` before scanning.
 * Findings are sorted by CVSS descending (highest first).
 */
export function computeCveReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
): CveReport {
  // Deduplicate
  const seen = new Set<string>()
  const unique: typeof components = []
  for (const c of components) {
    const key = `${c.ecosystem.toLowerCase()}:${c.name.toLowerCase()}@${c.version}`
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(c)
    }
  }

  const findings: CveFinding[] = []
  for (const c of unique) {
    findings.push(...checkComponentCves(c))
  }

  // Sort: highest CVSS first; secondary sort alphabetically by CVE ID
  findings.sort((a, b) => {
    if (b.cvss !== a.cvss) return b.cvss - a.cvss
    return a.cveId.localeCompare(b.cveId)
  })

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length
  const totalVulnerable = findings.length

  let overallRisk: CveRiskLevel | 'none' = 'none'
  if (criticalCount > 0) overallRisk = 'critical'
  else if (highCount > 0) overallRisk = 'high'
  else if (mediumCount > 0) overallRisk = 'medium'
  else if (lowCount > 0) overallRisk = 'low'

  return {
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalVulnerable,
    overallRisk,
    findings,
    summary: buildReportSummary(totalVulnerable, criticalCount, highCount, mediumCount),
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function buildReportSummary(
  total: number,
  critical: number,
  high: number,
  medium: number,
): string {
  if (total === 0) return 'No known-CVE version matches detected.'
  const parts: string[] = [
    `${total} known CVE${total === 1 ? '' : 's'} matched in installed component versions.`,
  ]
  if (critical > 0) parts.push(`${critical} critical (CVSS ≥ 9.0).`)
  if (high > 0) parts.push(`${high} high (CVSS 7.0–8.9).`)
  if (medium > 0) parts.push(`${medium} medium (CVSS 4.0–6.9).`)
  return parts.join(' ')
}
