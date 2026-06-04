// EPSS Score Enrichment — pure library (zero Convex imports).
//
// The Exploit Prediction Scoring System (EPSS) from FIRST.org assigns a daily
// probability score (0.0–1.0) to every CVE indicating the likelihood of
// exploitation in the wild within the next 30 days.  It is the forward-looking
// complement to CISA KEV (which confirms past exploitation).
//
// API endpoint (no key required):
//   https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXX,CVE-YYYY-YYYY
//   Accepts up to 100 comma-separated CVE IDs per request.
//
// Risk classification thresholds (calibrated against FIRST.org percentile
// distribution):
//   critical : score ≥ 0.50  — actively weaponised / top-tier exploitation
//   high     : score ≥ 0.20  — likely exploited soon (active public tooling)
//   medium   : score ≥ 0.05  — moderate risk (PoC exists / niche targeting)
//   low      : score <  0.05 — limited exploitation activity observed

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type EpssEntry = {
  /** Normalised uppercase CVE identifier, e.g. "CVE-2021-44228" */
  cveId: string
  /** Exploitation probability in the next 30 days (0.0–1.0) */
  epssScore: number
  /** Rank among all scored CVEs (0.0–1.0, higher = more dangerous than peers) */
  epssPercentile: number
  /** Score publication date "YYYY-MM-DD" */
  date: string
}

export type EpssRiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type EpssEnrichedCve = {
  cveId: string
  epssScore: number
  epssPercentile: number
  epssRiskLevel: EpssRiskLevel
  /** Package name from the matched breach disclosure, when known */
  packageName?: string
}

export type EpssSummary = {
  totalQueried: number
  enrichedCount: number
  criticalRiskCount: number // ≥ 0.50
  highRiskCount: number // ≥ 0.20
  mediumRiskCount: number // ≥ 0.05
  lowRiskCount: number // < 0.05
  avgScore: number
  /** Top 10 by score descending */
  topCves: EpssEnrichedCve[]
  summary: string
}

/** Minimal breach disclosure fields needed for CVE extraction / enrichment. */
export type MinimalDisclosure = {
  sourceRef: string
  aliases: string[]
  packageName?: string
}

// ---------------------------------------------------------------------------
// classifyEpssRisk
// ---------------------------------------------------------------------------

/**
 * Map a raw EPSS score (0.0–1.0) to a named risk level.
 * Scores are clamped before classification so out-of-range values are safe.
 */
export function classifyEpssRisk(score: number): EpssRiskLevel {
  const s = Math.min(1, Math.max(0, score))
  if (s >= 0.5) return 'critical'
  if (s >= 0.2) return 'high'
  if (s >= 0.05) return 'medium'
  return 'low'
}

// ---------------------------------------------------------------------------
// parseEpssApiResponse
// ---------------------------------------------------------------------------

/**
 * Parse the JSON body returned by the FIRST.org EPSS API v3.
 *
 * Returns an empty array when the `data` field is present but empty.
 * Returns null only when the response is structurally invalid (non-object,
 * missing `data` array, etc.).  Individual malformed entries are silently
 * skipped rather than causing the entire parse to fail.
 */
export function parseEpssApiResponse(json: unknown): EpssEntry[] | null {
  if (!json || typeof json !== 'object') return null
  const raw = json as Record<string, unknown>

  // The FIRST.org API always returns a `data` array when the request succeeds.
  if (!Array.isArray(raw['data'])) return null

  const entries: EpssEntry[] = []

  for (const item of raw['data']) {
    if (!item || typeof item !== 'object') continue
    const entry = item as Record<string, unknown>

    const cveId = String(entry['cve'] ?? '').trim().toUpperCase()
    if (!cveId.startsWith('CVE-')) continue

    const rawEpss = String(entry['epss'] ?? '')
    const rawPercentile = String(entry['percentile'] ?? '')
    const epssScore = parseFloat(rawEpss)
    const epssPercentile = parseFloat(rawPercentile)

    if (Number.isNaN(epssScore) || Number.isNaN(epssPercentile)) continue

    entries.push({
      cveId,
      epssScore: Math.min(1, Math.max(0, epssScore)),
      epssPercentile: Math.min(1, Math.max(0, epssPercentile)),
      date: String(entry['date'] ?? ''),
    })
  }

  return entries
}

// ---------------------------------------------------------------------------
// extractCveIds
// ---------------------------------------------------------------------------

/**
 * Collect a deduplicated, uppercase set of CVE IDs from an array of
 * breach disclosures.  Looks at both `sourceRef` and `aliases` so that
 * disclosures ingested from non-CVE primary sources (OSV, npm advisory, etc.)
 * are still covered when they carry CVE alias references.
 */
export function extractCveIds(disclosures: MinimalDisclosure[]): string[] {
  const seen = new Set<string>()

  for (const disc of disclosures) {
    const candidates = [disc.sourceRef, ...disc.aliases]
    for (const ref of candidates) {
      const upper = ref.trim().toUpperCase()
      if (upper.startsWith('CVE-')) seen.add(upper)
    }
  }

  return Array.from(seen)
}

// ---------------------------------------------------------------------------
// buildEpssEnrichmentMap
// ---------------------------------------------------------------------------

/**
 * Build a CVE-ID → EpssEntry lookup map from a flat array of parsed entries.
 * Keys are normalised to uppercase so lookups can be case-insensitive.
 */
export function buildEpssEnrichmentMap(entries: EpssEntry[]): Map<string, EpssEntry> {
  const map = new Map<string, EpssEntry>()
  for (const entry of entries) {
    map.set(entry.cveId.toUpperCase(), entry)
  }
  return map
}

// ---------------------------------------------------------------------------
// enrichDisclosureWithEpss
// ---------------------------------------------------------------------------

/**
 * Find the EPSS entry for a disclosure by checking `sourceRef` then
 * `aliases` in order.  Returns the first match, or null if the disclosure
 * has no CVE ID present in the enrichment map.
 */
export function enrichDisclosureWithEpss(
  disclosure: MinimalDisclosure,
  epssMap: Map<string, EpssEntry>,
): EpssEntry | null {
  const candidates = [disclosure.sourceRef, ...disclosure.aliases]
  for (const ref of candidates) {
    const upper = ref.trim().toUpperCase()
    const entry = epssMap.get(upper)
    if (entry) return entry
  }
  return null
}

// ---------------------------------------------------------------------------
// buildEpssSummary
// ---------------------------------------------------------------------------

/**
 * Aggregate per-CVE enrichment results into a tenant-level summary suitable
 * for persistence and dashboard display.
 *
 * @param enriched - All CVEs that were successfully scored
 * @param totalQueried - Total CVE IDs that were sent to the EPSS API
 */
export function buildEpssSummary(
  enriched: EpssEnrichedCve[],
  totalQueried: number,
): EpssSummary {
  const criticalRiskCount = enriched.filter(c => c.epssRiskLevel === 'critical').length
  const highRiskCount = enriched.filter(c => c.epssRiskLevel === 'high').length
  const mediumRiskCount = enriched.filter(c => c.epssRiskLevel === 'medium').length
  const lowRiskCount = enriched.filter(c => c.epssRiskLevel === 'low').length

  const avgScore =
    enriched.length > 0
      ? enriched.reduce((sum, c) => sum + c.epssScore, 0) / enriched.length
      : 0

  // Top 10 by EPSS score descending
  const topCves = [...enriched]
    .sort((a, b) => b.epssScore - a.epssScore)
    .slice(0, 10)

  // Human-readable summary
  const highRiskParts: string[] = []
  if (criticalRiskCount > 0) highRiskParts.push(`${criticalRiskCount} critical-risk`)
  if (highRiskCount > 0) highRiskParts.push(`${highRiskCount} high-risk`)

  const summary =
    enriched.length === 0
      ? `No CVEs enriched — ${totalQueried} queried but none returned EPSS scores.`
      : highRiskParts.length > 0
        ? `${enriched.length}/${totalQueried} CVEs enriched with EPSS scores. ${highRiskParts.join(', ')} CVEs require immediate attention.`
        : `${enriched.length}/${totalQueried} CVEs enriched. No elevated-risk EPSS scores detected.`

  return {
    totalQueried,
    enrichedCount: enriched.length,
    criticalRiskCount,
    highRiskCount,
    mediumRiskCount,
    lowRiskCount,
    avgScore,
    topCves,
    summary,
  }
}
