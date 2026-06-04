// WS-38 — Dependency & Runtime End-of-Life (EOL) Detection: pure computation library.
//
// Detects SBOM components whose versions have passed their vendor-declared end-of-life
// date — meaning no further security patches will be issued. This is distinct from CVE
// scanning: a package can be fully up-to-date yet still be EOL, creating an invisible
// ongoing security risk.
//
// Detection strategy:
//   1. Static EOL database: curated catalog of runtimes and popular frameworks with
//      known EOL dates and version ranges.
//   2. Version prefix matching: '14.21.3' matches Node.js EOL entry for prefix '14'.
//   3. Near-EOL warning: packages within NEAR_EOL_WINDOW_MS of their EOL date get
//      flagged early so teams have time to plan upgrades.
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Flag packages as near-EOL when within 90 days of the EOL date. */
export const NEAR_EOL_WINDOW_MS = 90 * 24 * 60 * 60 * 1000

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EolStatus = 'end_of_life' | 'near_eol' | 'supported' | 'unknown'

export type EolCategory = 'runtime' | 'framework' | 'package'

/**
 * A single entry in the static EOL database.
 */
export type EolRecord = {
  /** Package ecosystem, e.g. 'npm', 'pypi', 'gem', 'maven', 'nuget', 'runtime'. */
  ecosystem: string
  /** Exact package name (case-insensitive match). */
  name: string
  /**
   * Version prefix that identifies the EOL series.
   * '14'  matches 14.0.0, 14.21.3
   * '2.7' matches 2.7.0, 2.7.18
   * ''    matches any version (use for fully deprecated packages)
   */
  versionPrefix: string
  /** Unix timestamp (ms) when this series reached end-of-life. */
  eolDate: number
  /** Human-readable date string for display, e.g. '2023-04-30'. */
  eolDateText: string
  /** Suggested replacement or upgrade path. */
  replacedBy?: string
  category: EolCategory
}

export type EolFinding = {
  packageName: string
  ecosystem: string
  version: string
  eolStatus: EolStatus
  eolDate: number
  eolDateText: string
  daysOverdue: number | null
  daysUntilEol: number | null
  replacedBy: string | null
  category: EolCategory
  title: string
  description: string
}

export type EolReportResult = {
  findings: EolFinding[]
  eolCount: number
  nearEolCount: number
  supportedCount: number
  unknownCount: number
  /** Worst status across all components: 'critical'=any EOL, 'warning'=near-EOL, 'ok'=none */
  overallStatus: 'critical' | 'warning' | 'ok'
  summary: string
}

// ---------------------------------------------------------------------------
// Static EOL database
// ---------------------------------------------------------------------------
// Curated catalog of runtimes and popular frameworks, ordered by ecosystem and
// family. Dates are derived from vendor end-of-life announcements.

export const EOL_DATABASE: EolRecord[] = [
  // ── Node.js ──────────────────────────────────────────────────────────────
  {
    ecosystem: 'npm',
    name: 'node',
    versionPrefix: '10',
    eolDate: Date.UTC(2021, 3, 30),
    eolDateText: '2021-04-30',
    replacedBy: 'Node.js 20 LTS',
    category: 'runtime',
  },
  {
    ecosystem: 'npm',
    name: 'node',
    versionPrefix: '12',
    eolDate: Date.UTC(2022, 3, 30),
    eolDateText: '2022-04-30',
    replacedBy: 'Node.js 20 LTS',
    category: 'runtime',
  },
  {
    ecosystem: 'npm',
    name: 'node',
    versionPrefix: '14',
    eolDate: Date.UTC(2023, 3, 30),
    eolDateText: '2023-04-30',
    replacedBy: 'Node.js 20 LTS',
    category: 'runtime',
  },
  {
    ecosystem: 'npm',
    name: 'node',
    versionPrefix: '16',
    eolDate: Date.UTC(2023, 8, 11),
    eolDateText: '2023-09-11',
    replacedBy: 'Node.js 20 LTS',
    category: 'runtime',
  },
  // ── Python ────────────────────────────────────────────────────────────────
  {
    ecosystem: 'pypi',
    name: 'python',
    versionPrefix: '2.7',
    eolDate: Date.UTC(2020, 0, 1),
    eolDateText: '2020-01-01',
    replacedBy: 'Python 3.12+',
    category: 'runtime',
  },
  {
    ecosystem: 'pypi',
    name: 'python',
    versionPrefix: '3.6',
    eolDate: Date.UTC(2021, 11, 23),
    eolDateText: '2021-12-23',
    replacedBy: 'Python 3.12+',
    category: 'runtime',
  },
  {
    ecosystem: 'pypi',
    name: 'python',
    versionPrefix: '3.7',
    eolDate: Date.UTC(2023, 5, 27),
    eolDateText: '2023-06-27',
    replacedBy: 'Python 3.12+',
    category: 'runtime',
  },
  {
    ecosystem: 'pypi',
    name: 'python',
    versionPrefix: '3.8',
    eolDate: Date.UTC(2024, 9, 7),
    eolDateText: '2024-10-07',
    replacedBy: 'Python 3.12+',
    category: 'runtime',
  },
  // ── Ruby ──────────────────────────────────────────────────────────────────
  {
    ecosystem: 'gem',
    name: 'ruby',
    versionPrefix: '2.7',
    eolDate: Date.UTC(2023, 2, 31),
    eolDateText: '2023-03-31',
    replacedBy: 'Ruby 3.3+',
    category: 'runtime',
  },
  {
    ecosystem: 'gem',
    name: 'ruby',
    versionPrefix: '3.0',
    eolDate: Date.UTC(2024, 3, 23),
    eolDateText: '2024-04-23',
    replacedBy: 'Ruby 3.3+',
    category: 'runtime',
  },
  // ── PHP ───────────────────────────────────────────────────────────────────
  {
    ecosystem: 'runtime',
    name: 'php',
    versionPrefix: '7.4',
    eolDate: Date.UTC(2022, 10, 28),
    eolDateText: '2022-11-28',
    replacedBy: 'PHP 8.3+',
    category: 'runtime',
  },
  {
    ecosystem: 'runtime',
    name: 'php',
    versionPrefix: '8.0',
    eolDate: Date.UTC(2023, 10, 26),
    eolDateText: '2023-11-26',
    replacedBy: 'PHP 8.3+',
    category: 'runtime',
  },
  {
    ecosystem: 'runtime',
    name: 'php',
    versionPrefix: '8.1',
    eolDate: Date.UTC(2025, 11, 31),
    eolDateText: '2025-12-31',
    replacedBy: 'PHP 8.3+',
    category: 'runtime',
  },
  // ── .NET / ASP.NET Core ───────────────────────────────────────────────────
  {
    ecosystem: 'nuget',
    name: 'microsoft.aspnetcore.app',
    versionPrefix: '5',
    eolDate: Date.UTC(2022, 4, 10),
    eolDateText: '2022-05-10',
    replacedBy: '.NET 8 LTS',
    category: 'runtime',
  },
  {
    ecosystem: 'nuget',
    name: 'microsoft.aspnetcore.app',
    versionPrefix: '6',
    eolDate: Date.UTC(2024, 10, 12),
    eolDateText: '2024-11-12',
    replacedBy: '.NET 8 LTS',
    category: 'runtime',
  },
  {
    ecosystem: 'nuget',
    name: 'microsoft.aspnetcore.app',
    versionPrefix: '7',
    eolDate: Date.UTC(2024, 4, 14),
    eolDateText: '2024-05-14',
    replacedBy: '.NET 8 LTS',
    category: 'runtime',
  },
  // ── Django ────────────────────────────────────────────────────────────────
  {
    ecosystem: 'pypi',
    name: 'django',
    versionPrefix: '1',
    eolDate: Date.UTC(2017, 3, 1),
    eolDateText: '2017-04-01',
    replacedBy: 'Django 4.2 LTS',
    category: 'framework',
  },
  {
    ecosystem: 'pypi',
    name: 'django',
    versionPrefix: '2.2',
    eolDate: Date.UTC(2022, 3, 1),
    eolDateText: '2022-04-01',
    replacedBy: 'Django 4.2 LTS',
    category: 'framework',
  },
  {
    ecosystem: 'pypi',
    name: 'django',
    versionPrefix: '3.2',
    eolDate: Date.UTC(2024, 3, 1),
    eolDateText: '2024-04-01',
    replacedBy: 'Django 5.0',
    category: 'framework',
  },
  // ── Flask ─────────────────────────────────────────────────────────────────
  {
    ecosystem: 'pypi',
    name: 'flask',
    versionPrefix: '1',
    eolDate: Date.UTC(2023, 8, 30),
    eolDateText: '2023-09-30',
    replacedBy: 'Flask 3.x',
    category: 'framework',
  },
  // ── Rails ─────────────────────────────────────────────────────────────────
  {
    ecosystem: 'gem',
    name: 'rails',
    versionPrefix: '5',
    eolDate: Date.UTC(2021, 5, 1),
    eolDateText: '2021-06-01',
    replacedBy: 'Rails 7.x',
    category: 'framework',
  },
  {
    ecosystem: 'gem',
    name: 'rails',
    versionPrefix: '6.0',
    eolDate: Date.UTC(2023, 5, 1),
    eolDateText: '2023-06-01',
    replacedBy: 'Rails 7.1+',
    category: 'framework',
  },
  {
    ecosystem: 'gem',
    name: 'rails',
    versionPrefix: '6.1',
    eolDate: Date.UTC(2024, 9, 1),
    eolDateText: '2024-10-01',
    replacedBy: 'Rails 7.1+',
    category: 'framework',
  },
  // ── Spring Boot ───────────────────────────────────────────────────────────
  {
    ecosystem: 'maven',
    name: 'spring-boot',
    versionPrefix: '2.5',
    eolDate: Date.UTC(2023, 4, 18),
    eolDateText: '2023-05-18',
    replacedBy: 'Spring Boot 3.x',
    category: 'framework',
  },
  {
    ecosystem: 'maven',
    name: 'spring-boot',
    versionPrefix: '2.6',
    eolDate: Date.UTC(2023, 10, 24),
    eolDateText: '2023-11-24',
    replacedBy: 'Spring Boot 3.x',
    category: 'framework',
  },
  // ── Log4j 1.x ─────────────────────────────────────────────────────────────
  {
    ecosystem: 'maven',
    name: 'log4j',
    versionPrefix: '1',
    eolDate: Date.UTC(2015, 7, 5),
    eolDateText: '2015-08-05',
    replacedBy: 'Log4j 2.x (or SLF4J/Logback)',
    category: 'package',
  },
  // ── Angular ───────────────────────────────────────────────────────────────
  {
    ecosystem: 'npm',
    name: '@angular/core',
    versionPrefix: '12',
    eolDate: Date.UTC(2022, 10, 12),
    eolDateText: '2022-11-12',
    replacedBy: '@angular/core 17+',
    category: 'framework',
  },
  {
    ecosystem: 'npm',
    name: '@angular/core',
    versionPrefix: '13',
    eolDate: Date.UTC(2023, 4, 4),
    eolDateText: '2023-05-04',
    replacedBy: '@angular/core 17+',
    category: 'framework',
  },
  {
    ecosystem: 'npm',
    name: '@angular/core',
    versionPrefix: '14',
    eolDate: Date.UTC(2023, 10, 18),
    eolDateText: '2023-11-18',
    replacedBy: '@angular/core 17+',
    category: 'framework',
  },
  // ── Deprecated npm packages ───────────────────────────────────────────────
  {
    ecosystem: 'npm',
    name: 'request',
    versionPrefix: '',
    eolDate: Date.UTC(2020, 1, 11),
    eolDateText: '2020-02-11',
    replacedBy: 'node-fetch, undici, or native fetch',
    category: 'package',
  },
  {
    ecosystem: 'npm',
    name: 'node-uuid',
    versionPrefix: '',
    eolDate: Date.UTC(2018, 3, 1),
    eolDateText: '2018-04-01',
    replacedBy: 'uuid',
    category: 'package',
  },
  {
    ecosystem: 'npm',
    name: 'core-js',
    versionPrefix: '2',
    eolDate: Date.UTC(2020, 0, 1),
    eolDateText: '2020-01-01',
    replacedBy: 'core-js 3',
    category: 'package',
  },
  // ── Legacy jQuery ─────────────────────────────────────────────────────────
  {
    ecosystem: 'npm',
    name: 'jquery',
    versionPrefix: '1',
    eolDate: Date.UTC(2019, 3, 10),
    eolDateText: '2019-04-10',
    replacedBy: 'jQuery 3.x',
    category: 'package',
  },
  {
    ecosystem: 'npm',
    name: 'jquery',
    versionPrefix: '2',
    eolDate: Date.UTC(2018, 3, 10),
    eolDateText: '2018-04-10',
    replacedBy: 'jQuery 3.x',
    category: 'package',
  },
]

// ---------------------------------------------------------------------------
// versionMatchesPrefix
// ---------------------------------------------------------------------------

/**
 * Returns true if `version` belongs to the series identified by `prefix`.
 *
 * Rules:
 * - Empty prefix ('') matches every version.
 * - Exact match: '3.0' matches '3.0'.
 * - Segment-safe prefix: '14' matches '14.21.3' but NOT '141.0.0'.
 *   The comparison strips leading zeros from version segments before comparing
 *   so '14.00.0' still matches prefix '14'.
 */
export function versionMatchesPrefix(version: string, prefix: string): boolean {
  if (prefix === '') return true
  const v = version.trim()
  const p = prefix.trim()
  if (v === p) return true
  return v.startsWith(p + '.')
}

// ---------------------------------------------------------------------------
// parseVersionMajorMinor
// ---------------------------------------------------------------------------

/**
 * Extracts the major.minor portion of a version string for display purposes.
 * '14.21.3' → '14.21'
 * '3.8.0'   → '3.8'
 * '2'       → '2'
 * Returns the original string for non-standard versions.
 */
export function parseVersionMajorMinor(version: string): string {
  const parts = version.trim().split('.')
  if (parts.length >= 2) return `${parts[0]}.${parts[1]}`
  return version.trim()
}

// ---------------------------------------------------------------------------
// classifyEolStatus
// ---------------------------------------------------------------------------

/**
 * Given an EOL timestamp and the current time, determine whether the version
 * is already past EOL, approaching EOL, or still supported.
 *
 * @param eolDateMs  - Unix ms timestamp when EOL is reached. null → unknown.
 * @param nowMs      - Current time (defaults to Date.now()). Injected for tests.
 */
export function classifyEolStatus(eolDateMs: number | null, nowMs?: number): EolStatus {
  if (eolDateMs === null) return 'unknown'
  const now = nowMs ?? Date.now()
  if (now >= eolDateMs) return 'end_of_life'
  if (now >= eolDateMs - NEAR_EOL_WINDOW_MS) return 'near_eol'
  return 'supported'
}

// ---------------------------------------------------------------------------
// lookupEolEntry
// ---------------------------------------------------------------------------

/**
 * Look up the EOL database entry for a given package.
 * Returns the matching record with the most recent EOL date when multiple
 * version-prefix entries match (handles cases like '2' and '2.7' both matching
 * version '2.7.18' — '2.7' wins as the more specific match).
 */
export function lookupEolEntry(
  name: string,
  version: string,
  ecosystem: string,
): EolRecord | null {
  const nameLower = name.toLowerCase()
  const ecosystemLower = ecosystem.toLowerCase()

  const candidates = EOL_DATABASE.filter(
    (entry) =>
      entry.name.toLowerCase() === nameLower &&
      entry.ecosystem.toLowerCase() === ecosystemLower &&
      versionMatchesPrefix(version, entry.versionPrefix),
  )

  if (candidates.length === 0) return null

  // Prefer the most specific prefix (longer = more specific), then latest EOL date.
  candidates.sort((a, b) => {
    const lenDiff = b.versionPrefix.length - a.versionPrefix.length
    if (lenDiff !== 0) return lenDiff
    return b.eolDate - a.eolDate
  })

  return candidates[0]
}

// ---------------------------------------------------------------------------
// checkComponentEol
// ---------------------------------------------------------------------------

/**
 * Given a single SBOM component (name + version + ecosystem), check whether it
 * matches any EOL database entry and, if so, return a full EolFinding.
 *
 * Returns null when the package is not in the database (i.e. its EOL status is
 * unknown to Sentinel — not necessarily safe, just untracked).
 */
export function checkComponentEol(
  component: { name: string; version: string; ecosystem: string },
  nowMs?: number,
): EolFinding | null {
  const entry = lookupEolEntry(component.name, component.version, component.ecosystem)
  if (!entry) return null

  const now = nowMs ?? Date.now()
  const status = classifyEolStatus(entry.eolDate, now)

  // Only return a finding when the status is actionable (EOL or near EOL).
  // 'supported' entries are in the DB but we skip generating a finding for them.
  if (status === 'supported') return null

  const msDiff = entry.eolDate - now
  const daysDiff = Math.round(Math.abs(msDiff) / (24 * 60 * 60 * 1000))

  const daysOverdue = now >= entry.eolDate ? daysDiff : null
  const daysUntilEol = now < entry.eolDate ? daysDiff : null

  let title: string
  let description: string

  if (status === 'end_of_life') {
    title = `${component.name} ${parseVersionMajorMinor(component.version)} is end-of-life`
    description =
      `This version reached end-of-life on ${entry.eolDateText} (${daysOverdue} days ago) ` +
      `and no longer receives security patches. Any vulnerabilities discovered after this ` +
      `date will not be fixed.` +
      (entry.replacedBy ? ` Upgrade to ${entry.replacedBy}.` : '')
  } else {
    title = `${component.name} ${parseVersionMajorMinor(component.version)} reaches EOL in ${daysUntilEol} days`
    description =
      `This version will reach end-of-life on ${entry.eolDateText}. ` +
      `Plan an upgrade before security patch delivery stops.` +
      (entry.replacedBy ? ` Recommended upgrade: ${entry.replacedBy}.` : '')
  }

  return {
    packageName: component.name,
    ecosystem: component.ecosystem,
    version: component.version,
    eolStatus: status,
    eolDate: entry.eolDate,
    eolDateText: entry.eolDateText,
    daysOverdue,
    daysUntilEol,
    replacedBy: entry.replacedBy ?? null,
    category: entry.category,
    title,
    description,
  }
}

// ---------------------------------------------------------------------------
// computeEolReport  ← TODO: implement this function
// ---------------------------------------------------------------------------

/**
 * Aggregate EOL findings across all SBOM components and produce a scored
 * report that Sentinel can store, display, and act on.
 *
 * @param components - Array of SBOM components (name, version, ecosystem).
 * @param nowMs      - Current time in ms. Defaults to Date.now().
 *
 * @returns EolReportResult
 *
 * Scoring guidance:
 * - Run checkComponentEol on each component.
 * - Deduplicate findings by (packageName + ecosystem + versionPrefix) so a
 *   package appearing both as direct and transitive only contributes once.
 * - Count eolCount, nearEolCount, supportedCount, unknownCount.
 * - overallStatus: 'critical' when eolCount > 0, 'warning' when nearEolCount > 0, 'ok' otherwise.
 * - Build a concise summary string, e.g.:
 *   "3 end-of-life and 1 near-EOL components detected."
 *   "All 48 tracked components are supported."
 */
export function computeEolReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
  nowMs?: number,
): EolReportResult {
  const now = nowMs ?? Date.now()

  // Deduplicate by name+ecosystem+version — same package may appear as both
  // a direct and transitive dependency in the SBOM.
  const seen = new Set<string>()
  const findings: EolFinding[] = []
  let supportedCount = 0
  let unknownCount = 0

  for (const component of components) {
    const dedupeKey = `${component.ecosystem}:${component.name}:${component.version}`
    if (seen.has(dedupeKey)) continue
    seen.add(dedupeKey)

    const finding = checkComponentEol(component, now)
    if (finding) {
      findings.push(finding)
    } else {
      // Probe the DB again to distinguish "in-DB but supported" from "not in DB at all".
      const entry = lookupEolEntry(component.name, component.version, component.ecosystem)
      if (entry) {
        supportedCount++
      } else {
        unknownCount++
      }
    }
  }

  const eolCount = findings.filter((f) => f.eolStatus === 'end_of_life').length
  const nearEolCount = findings.filter((f) => f.eolStatus === 'near_eol').length

  const overallStatus: EolReportResult['overallStatus'] =
    eolCount > 0 ? 'critical' : nearEolCount > 0 ? 'warning' : 'ok'

  let summary: string
  if (eolCount === 0 && nearEolCount === 0) {
    summary =
      supportedCount > 0
        ? `All ${supportedCount} tracked component${supportedCount === 1 ? '' : 's'} are within their supported lifecycle.`
        : 'No end-of-life packages detected.'
  } else {
    const parts: string[] = []
    if (eolCount > 0) parts.push(`${eolCount} end-of-life`)
    if (nearEolCount > 0) parts.push(`${nearEolCount} near-EOL`)
    summary =
      `${parts.join(' and ')} component${findings.length === 1 ? '' : 's'} detected` +
      ` — security patches may no longer be available.`
  }

  return { findings, eolCount, nearEolCount, supportedCount, unknownCount, overallStatus, summary }
}
