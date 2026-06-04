/**
 * WS-48 — License Compliance & Risk Scanner: pure computation library.
 *
 * Scans SBOM component license declarations and flags packages whose
 * licenses carry legal or commercial risk in a proprietary codebase:
 *
 *   strong_copyleft   (GPL-2.0/3.0, AGPL-3.0, SSPL-1.0, OSL-3.0)  → critical
 *   weak_copyleft     (LGPL, MPL-2.0, EPL-1/2, EUPL-1.1, CDDL-1.0) → high
 *   proprietary_restricted (BUSL-1.1, Elastic-2.0)                   → high
 *   unrecognized_license   (custom string, not in DB)                 → medium
 *   unknown_license        (absent / null / empty field)              → medium
 *
 * Strong copyleft is critical because including even a transitive GPL-3.0
 * or AGPL-3.0 dependency in a distributed or SaaS product typically requires
 * the entire combined work to be released under the same license — a
 * showstopper for commercial products.
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LicenseType =
  | 'permissive'
  | 'weak_copyleft'
  | 'strong_copyleft'
  | 'proprietary'
  | 'unknown'

export type LicenseRisk = 'critical' | 'high' | 'medium' | 'low' | 'none'

export type LicenseRiskSignal =
  | 'strong_copyleft'
  | 'weak_copyleft'
  | 'proprietary_restricted'
  | 'unrecognized_license'
  | 'unknown_license'

type LicenseDatabaseEntry = {
  type: LicenseType
  riskLevel: LicenseRisk
}

export type LicenseFinding = {
  packageName: string
  ecosystem: string
  version: string
  /** Canonical SPDX identifier, or 'unknown' when not recognised. */
  spdxId: string
  licenseType: LicenseType
  riskLevel: LicenseRisk
  riskSignal: LicenseRiskSignal
  description: string
}

export type LicenseScanInput = {
  name: string
  ecosystem: string
  version: string
  license?: string | null
}

export type LicenseComplianceResult = {
  findings: LicenseFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** Total number of components evaluated. */
  totalScanned: number
  /** Components with no license field or an unrecognised string. */
  unknownLicenseCount: number
  overallRisk: LicenseRisk
  /**
   * Normalised SPDX ID → component count across the full scanned set
   * (including permissive entries — useful for licence audits).
   */
  licenseBreakdown: Record<string, number>
  summary: string
}

// ---------------------------------------------------------------------------
// License database (~70 entries)
// ---------------------------------------------------------------------------

export const LICENSE_DATABASE: Record<string, LicenseDatabaseEntry> = {
  // ── Permissive (risk: none) ───────────────────────────────────────────────
  'MIT': { type: 'permissive', riskLevel: 'none' },
  'MIT-0': { type: 'permissive', riskLevel: 'none' },
  'Apache-2.0': { type: 'permissive', riskLevel: 'none' },
  'BSD-2-Clause': { type: 'permissive', riskLevel: 'none' },
  'BSD-3-Clause': { type: 'permissive', riskLevel: 'none' },
  'BSD-4-Clause': { type: 'permissive', riskLevel: 'none' },
  'ISC': { type: 'permissive', riskLevel: 'none' },
  'Unlicense': { type: 'permissive', riskLevel: 'none' },
  'CC0-1.0': { type: 'permissive', riskLevel: 'none' },
  'CC-BY-4.0': { type: 'permissive', riskLevel: 'none' },
  'PSF-2.0': { type: 'permissive', riskLevel: 'none' },
  'Python-2.0': { type: 'permissive', riskLevel: 'none' },
  'Zlib': { type: 'permissive', riskLevel: 'none' },
  'libpng': { type: 'permissive', riskLevel: 'none' },
  'WTFPL': { type: 'permissive', riskLevel: 'none' },
  '0BSD': { type: 'permissive', riskLevel: 'none' },
  'AFL-2.1': { type: 'permissive', riskLevel: 'none' },
  'AFL-3.0': { type: 'permissive', riskLevel: 'none' },
  'Artistic-2.0': { type: 'permissive', riskLevel: 'none' },
  'Ruby': { type: 'permissive', riskLevel: 'none' },
  'BSL-1.0': { type: 'permissive', riskLevel: 'none' },
  'X11': { type: 'permissive', riskLevel: 'none' },
  'MS-PL': { type: 'permissive', riskLevel: 'none' },
  'IJG': { type: 'permissive', riskLevel: 'none' },
  'NTP': { type: 'permissive', riskLevel: 'none' },
  'OpenSSL': { type: 'permissive', riskLevel: 'none' },
  'NCSA': { type: 'permissive', riskLevel: 'none' },
  'W3C': { type: 'permissive', riskLevel: 'none' },
  'PostgreSQL': { type: 'permissive', riskLevel: 'none' },
  'PHP-3.0': { type: 'permissive', riskLevel: 'none' },
  'PHP-3.01': { type: 'permissive', riskLevel: 'none' },
  'JSON': { type: 'permissive', riskLevel: 'none' },
  'curl': { type: 'permissive', riskLevel: 'none' },
  // Deprecated SPDX but still permissive (risk: low — triggers a documentation note)
  'Apache-1.1': { type: 'permissive', riskLevel: 'low' },
  'Artistic-1.0': { type: 'permissive', riskLevel: 'low' },
  'GPL-1.0': { type: 'strong_copyleft', riskLevel: 'critical' }, // Old but still viral

  // ── Weak copyleft (risk: high) ────────────────────────────────────────────
  'LGPL-2.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-2.0-only': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-2.0-or-later': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-2.1': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-2.1-only': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-2.1-or-later': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-3.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-3.0-only': { type: 'weak_copyleft', riskLevel: 'high' },
  'LGPL-3.0-or-later': { type: 'weak_copyleft', riskLevel: 'high' },
  'MPL-2.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'MPL-1.1': { type: 'weak_copyleft', riskLevel: 'high' },
  'EUPL-1.1': { type: 'weak_copyleft', riskLevel: 'high' },
  'CPL-1.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'EPL-1.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'EPL-2.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'CDDL-1.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'CC-BY-SA-4.0': { type: 'weak_copyleft', riskLevel: 'high' },
  'MS-RL': { type: 'weak_copyleft', riskLevel: 'high' },
  'CECILL-2.1': { type: 'weak_copyleft', riskLevel: 'high' },
  'OSL-2.0': { type: 'weak_copyleft', riskLevel: 'high' },

  // ── Strong copyleft (risk: critical) ─────────────────────────────────────
  'GPL-2.0': { type: 'strong_copyleft', riskLevel: 'critical' },
  'GPL-2.0-only': { type: 'strong_copyleft', riskLevel: 'critical' },
  'GPL-2.0-or-later': { type: 'strong_copyleft', riskLevel: 'critical' },
  'GPL-3.0': { type: 'strong_copyleft', riskLevel: 'critical' },
  'GPL-3.0-only': { type: 'strong_copyleft', riskLevel: 'critical' },
  'GPL-3.0-or-later': { type: 'strong_copyleft', riskLevel: 'critical' },
  'AGPL-3.0': { type: 'strong_copyleft', riskLevel: 'critical' },
  'AGPL-3.0-only': { type: 'strong_copyleft', riskLevel: 'critical' },
  'AGPL-3.0-or-later': { type: 'strong_copyleft', riskLevel: 'critical' },
  'OSL-3.0': { type: 'strong_copyleft', riskLevel: 'critical' },
  'OSL-2.1': { type: 'strong_copyleft', riskLevel: 'critical' },
  'EUPL-1.2': { type: 'strong_copyleft', riskLevel: 'critical' },
  'RPL-1.5': { type: 'strong_copyleft', riskLevel: 'critical' },
  'SSPL-1.0': { type: 'strong_copyleft', riskLevel: 'critical' },
  'SISSL': { type: 'strong_copyleft', riskLevel: 'critical' },
  'Sleepycat': { type: 'strong_copyleft', riskLevel: 'critical' },

  // ── Proprietary / source-available with use restrictions (risk: high) ─────
  'BUSL-1.1': { type: 'proprietary', riskLevel: 'high' },
  'Elastic-2.0': { type: 'proprietary', riskLevel: 'high' },
  'NPOSL-3.0': { type: 'proprietary', riskLevel: 'high' },
  'Commons-Clause': { type: 'proprietary', riskLevel: 'high' },
}

// ---------------------------------------------------------------------------
// Common non-SPDX aliases (normalised before DB lookup)
// ---------------------------------------------------------------------------

/**
 * Maps colloquial or historically common license strings to their canonical
 * SPDX identifier. Keys are lower-cased for case-insensitive matching.
 */
export const SPDX_ALIASES: Record<string, string> = {
  'gplv2': 'GPL-2.0',
  'gplv3': 'GPL-3.0',
  'gpl2': 'GPL-2.0',
  'gpl3': 'GPL-3.0',
  'lgplv2': 'LGPL-2.1',
  'lgplv3': 'LGPL-3.0',
  'lgpl2': 'LGPL-2.1',
  'lgpl3': 'LGPL-3.0',
  'agplv3': 'AGPL-3.0',
  'agpl3': 'AGPL-3.0',
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'isc license': 'ISC',
  'apache license 2.0': 'Apache-2.0',
  'apache 2.0': 'Apache-2.0',
  'apache2': 'Apache-2.0',
  'apache-2': 'Apache-2.0',
  'bsd': 'BSD-3-Clause',
  'bsd2': 'BSD-2-Clause',
  'bsd3': 'BSD-3-Clause',
  '2-clause bsd': 'BSD-2-Clause',
  '3-clause bsd': 'BSD-3-Clause',
  'simplified bsd': 'BSD-2-Clause',
  'new bsd': 'BSD-3-Clause',
  'cc0': 'CC0-1.0',
  'public domain': 'Unlicense',
  'unlicensed': 'Unlicense',
  'mpl-2': 'MPL-2.0',
  'mozilla public license 2.0': 'MPL-2.0',
  'eclipse public license': 'EPL-2.0',
  'epl': 'EPL-2.0',
}

// ---------------------------------------------------------------------------
// Risk ordering
// ---------------------------------------------------------------------------

const RISK_RANK: Record<LicenseRisk, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Normalise and look up a license string in the database.
 * Returns the DB entry or undefined when unrecognised.
 */
function lookupLicense(raw: string): { spdxId: string; entry: LicenseDatabaseEntry } | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined

  // 1. Try exact match (case-preserving)
  if (trimmed in LICENSE_DATABASE) {
    return { spdxId: trimmed, entry: LICENSE_DATABASE[trimmed]! }
  }

  // 2. Try case-insensitive exact match
  const lower = trimmed.toLowerCase()
  for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
    if (key.toLowerCase() === lower) {
      return { spdxId: key, entry }
    }
  }

  // 3. Try alias table
  const aliased = SPDX_ALIASES[lower]
  if (aliased && aliased in LICENSE_DATABASE) {
    return { spdxId: aliased, entry: LICENSE_DATABASE[aliased]! }
  }

  return undefined
}

/**
 * Resolve a possibly compound license expression (e.g. "MIT AND GPL-3.0" or
 * "Apache-2.0 OR MIT") by splitting on connectors and taking the worst
 * (highest-risk) component. This is conservative: "MIT OR GPL-3.0" yields
 * critical because a downstream auditor will flag the GPL-3.0 option even
 * if the user chose MIT.
 */
function resolveCompoundLicense(
  raw: string,
): { spdxId: string; entry: LicenseDatabaseEntry } | undefined {
  // Strip outer parentheses
  const stripped = raw.replace(/^\(+/, '').replace(/\)+$/, '').trim()

  // Split on connectors
  const parts = stripped.split(/\s+(AND|OR|WITH)\s+/i).filter((p) => !/^(AND|OR|WITH)$/i.test(p))

  if (parts.length <= 1) {
    return lookupLicense(stripped)
  }

  let worst: { spdxId: string; entry: LicenseDatabaseEntry } | undefined
  for (const part of parts) {
    const resolved = lookupLicense(part.trim())
    if (!resolved) continue
    if (
      !worst ||
      RISK_RANK[resolved.entry.riskLevel] > RISK_RANK[worst.entry.riskLevel]
    ) {
      worst = resolved
    }
  }
  return worst
}

function describeRiskSignal(signal: LicenseRiskSignal, spdxId: string): string {
  switch (signal) {
    case 'strong_copyleft':
      return `${spdxId} is a strong copyleft license. Including this dependency in a commercial product typically requires releasing the entire combined work under the same terms — legal review required.`
    case 'weak_copyleft':
      return `${spdxId} is a weak copyleft license. Modifications to the licensed files must be released under the same terms; proprietary code that only links to the library may be exempt, but legal review is recommended.`
    case 'proprietary_restricted':
      return `${spdxId} imposes commercial use restrictions. Review the license terms before deploying this dependency in a production or commercial context.`
    case 'unrecognized_license':
      return `License "${spdxId}" is not a recognised SPDX identifier. Risk cannot be assessed automatically — manual legal review is required.`
    case 'unknown_license':
      return 'No license information is declared for this package. Risk cannot be assessed — assume unknown and request clarification from the package maintainer.'
  }
}

function worstRisk(risks: LicenseRisk[]): LicenseRisk {
  let best: LicenseRisk = 'none'
  for (const r of risks) {
    if (RISK_RANK[r] > RISK_RANK[best]) best = r
  }
  return best
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan SBOM components for license compliance risk.
 *
 * @param components — Minimal component records from the SBOM snapshot.
 * @returns A `LicenseComplianceResult` with per-package findings and
 *          aggregate counts suitable for persistence and dashboard display.
 */
export function computeLicenseCompliance(
  components: LicenseScanInput[],
): LicenseComplianceResult {
  if (components.length === 0) {
    return {
      findings: [],
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      totalScanned: 0,
      unknownLicenseCount: 0,
      overallRisk: 'none',
      licenseBreakdown: {},
      summary: 'No SBOM components found. License compliance scan skipped.',
    }
  }

  const findings: LicenseFinding[] = []
  const licenseBreakdown: Record<string, number> = {}
  let unknownLicenseCount = 0

  for (const component of components) {
    const rawLicense = component.license

    // ── No license declared ───────────────────────────────────────────────
    if (rawLicense == null || rawLicense.trim() === '') {
      unknownLicenseCount++
      const spdxId = 'unknown'
      licenseBreakdown[spdxId] = (licenseBreakdown[spdxId] ?? 0) + 1
      findings.push({
        packageName: component.name,
        ecosystem: component.ecosystem,
        version: component.version,
        spdxId,
        licenseType: 'unknown',
        riskLevel: 'medium',
        riskSignal: 'unknown_license',
        description: describeRiskSignal('unknown_license', spdxId),
      })
      continue
    }

    // ── Resolve the license string ────────────────────────────────────────
    const resolved = resolveCompoundLicense(rawLicense)

    if (!resolved) {
      // Unrecognised / custom license string
      unknownLicenseCount++
      const displayId = rawLicense.trim().slice(0, 64)
      licenseBreakdown['unknown'] = (licenseBreakdown['unknown'] ?? 0) + 1
      findings.push({
        packageName: component.name,
        ecosystem: component.ecosystem,
        version: component.version,
        spdxId: displayId,
        licenseType: 'unknown',
        riskLevel: 'medium',
        riskSignal: 'unrecognized_license',
        description: describeRiskSignal('unrecognized_license', displayId),
      })
      continue
    }

    const { spdxId, entry } = resolved
    licenseBreakdown[spdxId] = (licenseBreakdown[spdxId] ?? 0) + 1

    // Only create findings for packages with non-zero risk.
    if (entry.riskLevel === 'none') continue

    const signal: LicenseRiskSignal =
      entry.type === 'strong_copyleft'
        ? 'strong_copyleft'
        : entry.type === 'weak_copyleft'
          ? 'weak_copyleft'
          : entry.type === 'proprietary'
            ? 'proprietary_restricted'
            : 'unrecognized_license'

    findings.push({
      packageName: component.name,
      ecosystem: component.ecosystem,
      version: component.version,
      spdxId,
      licenseType: entry.type,
      riskLevel: entry.riskLevel,
      riskSignal: signal,
      description: describeRiskSignal(signal, spdxId),
    })
  }

  // ── Sort findings: critical → high → medium → low ──────────────────────
  const SEVERITY_ORDER: Record<LicenseRisk, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    none: 4,
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.riskLevel] - SEVERITY_ORDER[b.riskLevel])

  // ── Aggregate counts ───────────────────────────────────────────────────
  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length

  const overallRisk = worstRisk(findings.map((f) => f.riskLevel))

  // ── Build summary ──────────────────────────────────────────────────────
  const summary = buildSummary({
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalScanned: components.length,
    unknownLicenseCount,
    overallRisk,
  })

  return {
    findings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalScanned: components.length,
    unknownLicenseCount,
    overallRisk,
    licenseBreakdown,
    summary,
  }
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildSummary(stats: {
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalScanned: number
  unknownLicenseCount: number
  overallRisk: LicenseRisk
}): string {
  const { criticalCount, highCount, mediumCount, lowCount, totalScanned, unknownLicenseCount } =
    stats

  if (criticalCount === 0 && highCount === 0 && mediumCount === 0 && lowCount === 0) {
    if (unknownLicenseCount > 0) {
      return `${unknownLicenseCount} of ${totalScanned} packages have no declared license. All recognised licenses are permissive.`
    }
    return `All ${totalScanned} packages use permissive licenses. No license compliance issues found.`
  }

  const parts: string[] = []
  if (criticalCount > 0)
    parts.push(
      `${criticalCount} critical (strong copyleft — immediate legal review required)`,
    )
  if (highCount > 0) parts.push(`${highCount} high (weak copyleft or proprietary-restricted)`)
  if (mediumCount > 0) parts.push(`${mediumCount} medium (unknown or unrecognised license)`)
  if (lowCount > 0) parts.push(`${lowCount} low (deprecated SPDX identifier)`)

  return `License compliance issues detected across ${totalScanned} scanned packages: ${parts.join('; ')}.`
}
