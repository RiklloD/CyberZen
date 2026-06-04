// WS-39 — Open-Source Package Abandonment Detector: pure computation library.
//
// Detects SBOM components that are known to be abandoned, archived, officially
// deprecated, or supply-chain-compromised — regardless of whether they have a
// formal vendor end-of-life date.
//
// This is deliberately distinct from EOL detection (WS-38):
//   EOL     → "the vendor officially stopped issuing security patches on date X"
//   Abandon → "the maintainer went dark / project archived / supply chain hit"
//
// Detection strategy:
//   Static abandoned-package database — curated catalog of definitively
//   abandoned/deprecated packages with a reason, risk level, and replacement.
//   No network calls. No heuristics. Every entry is manually verified.
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Why the package is considered abandoned.
 *
 *   supply_chain_compromised — package was used as a vector for a known attack
 *   officially_deprecated    — maintainer/org published an official deprecation notice
 *   archived                 — repository is archived and accepting no new changes
 *   superseded               — a newer package fulfils the same role (clean migration exists)
 *   unmaintained             — no meaningful activity for 3+ years, no formal notice
 */
export type AbandonmentReason =
  | 'supply_chain_compromised'
  | 'officially_deprecated'
  | 'archived'
  | 'superseded'
  | 'unmaintained'

export type AbandonmentRisk = 'critical' | 'high' | 'medium' | 'low'

/**
 * One entry in the static abandonment database.
 */
export type AbandonedRecord = {
  ecosystem: string
  name: string
  /**
   * Version prefix matched the same way as the EOL database:
   * ''    matches any version.
   * '1'   matches 1.x.x
   * '2.7' matches 2.7.x
   */
  versionPrefix: string
  reason: AbandonmentReason
  riskLevel: AbandonmentRisk
  /** Human-readable date of abandonment/deprecation (YYYY-MM-DD). */
  abandonedSince: string | null
  /** Suggested replacement library or approach. */
  replacedBy: string | null
  /** One-line explanation shown in the dashboard and API. */
  notes: string
}

export type AbandonmentFinding = {
  packageName: string
  ecosystem: string
  version: string
  reason: AbandonmentReason
  riskLevel: AbandonmentRisk
  abandonedSince: string | null
  replacedBy: string | null
  title: string
  description: string
}

export type AbandonmentReport = {
  findings: AbandonmentFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalAbandoned: number
  /** Worst risk level seen across all findings, or 'none' if clean. */
  overallRisk: AbandonmentRisk | 'none'
  summary: string
}

// ---------------------------------------------------------------------------
// Static abandonment database
// ---------------------------------------------------------------------------

export const ABANDONED_DATABASE: AbandonedRecord[] = [
  // ── Supply-chain-compromised (highest risk) ───────────────────────────────
  {
    ecosystem: 'npm',
    name: 'event-stream',
    versionPrefix: '',
    reason: 'supply_chain_compromised',
    riskLevel: 'critical',
    abandonedSince: '2018-11-26',
    replacedBy: 'through2, readable-stream, or Node.js native streams',
    notes:
      'Maintainership transferred to a malicious actor who injected a payload targeting Bitcoin wallet users (2018). Archived.',
  },
  {
    ecosystem: 'npm',
    name: 'flatmap-stream',
    versionPrefix: '',
    reason: 'supply_chain_compromised',
    riskLevel: 'critical',
    abandonedSince: '2018-11-26',
    replacedBy: null,
    notes:
      'Injected as a malicious dependency via the event-stream supply chain compromise. Remove immediately.',
  },
  {
    ecosystem: 'npm',
    name: 'ua-parser-js',
    versionPrefix: '0',
    reason: 'supply_chain_compromised',
    riskLevel: 'critical',
    abandonedSince: '2021-10-22',
    replacedBy: 'ua-parser-js 1.x (clean release)',
    notes:
      'v0 series had a 2021 supply chain compromise (malicious package published to npm). Upgrade to 1.x.',
  },
  // ── Archived / unmaintained with security implications ────────────────────
  {
    ecosystem: 'npm',
    name: 'request',
    versionPrefix: '',
    reason: 'archived',
    riskLevel: 'high',
    abandonedSince: '2020-02-11',
    replacedBy: 'node-fetch, undici, or native fetch()',
    notes:
      'Officially archived by the maintainer. No more security patches will be released.',
  },
  {
    ecosystem: 'npm',
    name: 'phantomjs',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'high',
    abandonedSince: '2018-06-06',
    replacedBy: 'Puppeteer or Playwright',
    notes:
      'The PhantomJS project was suspended in 2018. Known security vulnerabilities will never be patched.',
  },
  {
    ecosystem: 'npm',
    name: 'phantomjs-prebuilt',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'high',
    abandonedSince: '2018-06-06',
    replacedBy: 'Puppeteer or Playwright',
    notes:
      'Distribution wrapper for the abandoned PhantomJS binary. No security patches.',
  },
  {
    ecosystem: 'pypi',
    name: 'pycrypto',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'high',
    abandonedSince: '2014-01-01',
    replacedBy: 'pycryptodome (drop-in replacement)',
    notes:
      'Unmaintained since ~2014 with known unpatched vulnerabilities (heap overflow). pycryptodome is the maintained fork.',
  },
  {
    ecosystem: 'npm',
    name: 'cryptiles',
    versionPrefix: '3',
    reason: 'unmaintained',
    riskLevel: 'high',
    abandonedSince: '2018-09-01',
    replacedBy: 'native crypto module',
    notes: 'Critical vulnerability (CVE-2018-1000620) in v3; project subsequently unmaintained.',
  },
  {
    ecosystem: 'gem',
    name: 'therubyracer',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'high',
    abandonedSince: '2018-01-01',
    replacedBy: 'mini_racer',
    notes:
      'Embeds a very old V8 engine with no security updates. mini_racer is the actively maintained alternative.',
  },
  // ── Officially deprecated ─────────────────────────────────────────────────
  {
    ecosystem: 'npm',
    name: 'tslint',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2019-02-22',
    replacedBy: 'ESLint with @typescript-eslint',
    notes:
      'Palantir officially deprecated TSLint in favour of ESLint. Not receiving security updates.',
  },
  {
    ecosystem: 'npm',
    name: 'node-sass',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2022-03-01',
    replacedBy: 'sass (Dart Sass)',
    notes:
      'Officially deprecated by the Sass team. Native bindings regularly break on new Node.js releases.',
  },
  {
    ecosystem: 'npm',
    name: 'bower',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2017-01-01',
    replacedBy: 'npm, Yarn, or pnpm workspaces',
    notes: 'The Bower maintainers officially sunset the project. No security updates.',
  },
  {
    ecosystem: 'npm',
    name: 'karma',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2023-01-01',
    replacedBy: 'Vitest, Jest, or Playwright',
    notes:
      'Angular team deprecated Karma in Angular 16. The project is no longer actively maintained.',
  },
  {
    ecosystem: 'npm',
    name: 'babel-polyfill',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2020-01-01',
    replacedBy: 'core-js 3 with @babel/preset-env useBuiltIns',
    notes:
      'Babel officially deprecated @babel/polyfill. Using it risks pulling in outdated polyfills.',
  },
  {
    ecosystem: 'pypi',
    name: 'sklearn',
    versionPrefix: '',
    reason: 'officially_deprecated',
    riskLevel: 'medium',
    abandonedSince: '2019-01-01',
    replacedBy: 'scikit-learn',
    notes:
      "Stub package that warns users to install 'scikit-learn'. Installing 'sklearn' directly is a common mistake and the stub may be hijacked.",
  },
  {
    ecosystem: 'pypi',
    name: 'nose',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'medium',
    abandonedSince: '2015-06-01',
    replacedBy: 'pytest',
    notes:
      'Unmaintained since 2015. Not compatible with modern Python testing features. Use pytest.',
  },
  // ── Superseded (lower risk but still worth flagging) ───────────────────────
  {
    ecosystem: 'npm',
    name: 'node-uuid',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2014-01-01',
    replacedBy: 'uuid',
    notes: 'Superseded by the `uuid` package. No longer maintained.',
  },
  {
    ecosystem: 'npm',
    name: 'popper.js',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2019-04-01',
    replacedBy: '@popperjs/core',
    notes: 'Superseded by @popperjs/core (Popper v2). Not receiving updates.',
  },
  {
    ecosystem: 'npm',
    name: 'left-pad',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2016-04-01',
    replacedBy: 'String.prototype.padStart()',
    notes:
      "Now a no-op stub. JavaScript's built-in String.prototype.padStart() covers the same functionality.",
  },
  {
    ecosystem: 'npm',
    name: 'istanbul',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2018-01-01',
    replacedBy: 'nyc or c8',
    notes:
      'Original Istanbul CLI superseded by nyc (Istanbul v2) and then c8 (native V8 coverage).',
  },
  {
    ecosystem: 'npm',
    name: 'jshint',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2019-01-01',
    replacedBy: 'ESLint',
    notes: 'JSHint has been largely superseded by ESLint. Minimal maintenance.',
  },
  {
    ecosystem: 'npm',
    name: 'coffee-script',
    versionPrefix: '',
    reason: 'unmaintained',
    riskLevel: 'low',
    abandonedSince: '2020-01-01',
    replacedBy: 'TypeScript',
    notes:
      'CoffeeScript is effectively in maintenance mode with no active development. TypeScript covers its primary use cases.',
  },
  {
    ecosystem: 'pypi',
    name: 'distribute',
    versionPrefix: '',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2013-03-01',
    replacedBy: 'setuptools',
    notes:
      'Distribute was merged back into setuptools. Use setuptools or pip directly.',
  },
  {
    ecosystem: 'pypi',
    name: 'mock',
    versionPrefix: '1',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2016-01-01',
    replacedBy: 'unittest.mock (Python stdlib since 3.3)',
    notes: 'mock v1/v2 are superseded by the stdlib unittest.mock module.',
  },
  {
    ecosystem: 'pypi',
    name: 'mock',
    versionPrefix: '2',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2016-01-01',
    replacedBy: 'unittest.mock (Python stdlib since 3.3)',
    notes: 'mock v1/v2 are superseded by the stdlib unittest.mock module.',
  },
  {
    ecosystem: 'maven',
    name: 'commons-logging',
    versionPrefix: '1.1',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2014-01-01',
    replacedBy: 'SLF4J + Logback',
    notes:
      'Apache Commons Logging 1.1.x is very old and superseded by the SLF4J facade. Security fixes only applied to newer branches.',
  },
  {
    ecosystem: 'npm',
    name: 'grunt',
    versionPrefix: '0',
    reason: 'unmaintained',
    riskLevel: 'low',
    abandonedSince: '2016-01-01',
    replacedBy: 'Vite, esbuild, or Rollup',
    notes:
      'Grunt v0 branch is unmaintained. The broader ecosystem has shifted to modern build tools.',
  },
  {
    ecosystem: 'npm',
    name: 'core-js',
    versionPrefix: '2',
    reason: 'superseded',
    riskLevel: 'low',
    abandonedSince: '2019-01-01',
    replacedBy: 'core-js 3',
    notes:
      'core-js v2 receives no new features or bug fixes. Upgrade to core-js v3.',
  },
]

// ---------------------------------------------------------------------------
// versionMatchesPrefix
// ---------------------------------------------------------------------------

/**
 * Segment-safe version prefix comparison — identical to the one used in
 * eolDetection.ts and reproduced here to keep this module self-contained.
 *
 * '' matches any version.
 * '1' matches '1.0.0', '1.2.3' but NOT '10.0.0'.
 * '2.7' matches '2.7.0', '2.7.18' but NOT '2.70.0'.
 */
export function versionMatchesPrefix(version: string, prefix: string): boolean {
  if (prefix === '') return true
  const v = version.trim()
  const p = prefix.trim()
  if (v === p) return true
  return v.startsWith(p + '.')
}

// ---------------------------------------------------------------------------
// lookupAbandonedRecord
// ---------------------------------------------------------------------------

/**
 * Look up a package in the abandonment database.
 * When multiple entries match (different version prefixes), the most specific
 * (longest prefix) entry is returned; ties broken by risk level descending.
 */
export function lookupAbandonedRecord(
  name: string,
  version: string,
  ecosystem: string,
): AbandonedRecord | null {
  const nameLower = name.toLowerCase()
  const ecosystemLower = ecosystem.toLowerCase()

  const RISK_ORDER: Record<AbandonmentRisk, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  }

  const candidates = ABANDONED_DATABASE.filter(
    (entry) =>
      entry.name.toLowerCase() === nameLower &&
      entry.ecosystem.toLowerCase() === ecosystemLower &&
      versionMatchesPrefix(version, entry.versionPrefix),
  )

  if (candidates.length === 0) return null

  candidates.sort((a, b) => {
    // Prefer more specific prefix first.
    const lenDiff = b.versionPrefix.length - a.versionPrefix.length
    if (lenDiff !== 0) return lenDiff
    // Then prefer higher risk level (more conservative).
    return RISK_ORDER[b.riskLevel] - RISK_ORDER[a.riskLevel]
  })

  return candidates[0]
}

// ---------------------------------------------------------------------------
// checkPackageAbandonment
// ---------------------------------------------------------------------------

/**
 * Given a single SBOM component, check whether it is listed as abandoned.
 * Returns null when the package is not in the database (unknown status — not
 * necessarily safe, just untracked by this version of Sentinel).
 */
export function checkPackageAbandonment(component: {
  name: string
  version: string
  ecosystem: string
}): AbandonmentFinding | null {
  const record = lookupAbandonedRecord(component.name, component.version, component.ecosystem)
  if (!record) return null

  const title =
    record.reason === 'supply_chain_compromised'
      ? `${component.name} was used in a known supply-chain attack`
      : record.reason === 'officially_deprecated'
        ? `${component.name} is officially deprecated`
        : record.reason === 'archived'
          ? `${component.name} is archived and no longer maintained`
          : record.reason === 'superseded'
            ? `${component.name} has been superseded`
            : `${component.name} appears to be unmaintained`

  const description = record.notes + (record.replacedBy ? ` Recommended replacement: ${record.replacedBy}.` : '')

  return {
    packageName: component.name,
    ecosystem: component.ecosystem,
    version: component.version,
    reason: record.reason,
    riskLevel: record.riskLevel,
    abandonedSince: record.abandonedSince,
    replacedBy: record.replacedBy,
    title,
    description,
  }
}

// ---------------------------------------------------------------------------
// classifyOverallRisk
// ---------------------------------------------------------------------------

/**
 * Given per-level counts, return the worst risk level present.
 * Returns 'none' when there are no abandoned packages.
 */
export function classifyOverallRisk(
  criticalCount: number,
  highCount: number,
  mediumCount: number,
  lowCount: number,
): AbandonmentRisk | 'none' {
  if (criticalCount > 0) return 'critical'
  if (highCount > 0) return 'high'
  if (mediumCount > 0) return 'medium'
  if (lowCount > 0) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// computeAbandonmentReport
// ---------------------------------------------------------------------------

/**
 * Aggregate abandonment findings across all SBOM components and produce a
 * scored report.
 *
 * @param components - Array of SBOM components (name, version, ecosystem).
 * @returns AbandonmentReport
 */
export function computeAbandonmentReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
): AbandonmentReport {
  // Deduplicate by ecosystem:name:version — same package may appear multiple
  // times as both direct and transitive dependency.
  const seen = new Set<string>()
  const findings: AbandonmentFinding[] = []

  for (const component of components) {
    const dedupeKey = `${component.ecosystem}:${component.name}:${component.version}`
    if (seen.has(dedupeKey)) continue
    seen.add(dedupeKey)

    const finding = checkPackageAbandonment(component)
    if (finding) findings.push(finding)
  }

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length
  const totalAbandoned = findings.length

  const overallRisk = classifyOverallRisk(criticalCount, highCount, mediumCount, lowCount)

  let summary: string
  if (totalAbandoned === 0) {
    summary = 'No abandoned or deprecated packages detected in the SBOM.'
  } else {
    const parts: string[] = []
    if (criticalCount > 0)
      parts.push(`${criticalCount} supply-chain-compromised`)
    if (highCount > 0)
      parts.push(`${highCount} high-risk abandoned`)
    if (mediumCount > 0)
      parts.push(`${mediumCount} officially deprecated`)
    if (lowCount > 0)
      parts.push(`${lowCount} superseded`)
    summary = `${parts.join(', ')} package${totalAbandoned === 1 ? '' : 's'} detected. Review and replace to reduce supply-chain exposure.`
  }

  return {
    findings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalAbandoned,
    overallRisk,
    summary,
  }
}
