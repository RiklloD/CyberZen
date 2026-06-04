// CISA Known Exploited Vulnerabilities (KEV) catalog — pure parser.
//
// The CISA KEV catalog is publicly available (no API key required) at:
//   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//
// Cross-referencing breach disclosures' CVE IDs against the CISA KEV catalog
// confirms active exploitation in the wild — the strongest signal for
// prioritising remediation.  A CISA KEV match changes the classification from
// "known vulnerability" to "actively weaponised vulnerability."

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

export type CisaKevEntry = {
  cveId: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string   // "YYYY-MM-DD"
  shortDescription: string
  requiredAction: string
  dueDate: string     // "YYYY-MM-DD" — CISA-mandated federal remediation deadline
  knownRansomwareCampaignUse: 'Known' | 'Unknown'
  notes: string
}

export type CisaKevCatalog = {
  catalogVersion: string
  dateReleased: string
  count: number
  entries: CisaKevEntry[]
}

export type CisaKevSummary = {
  totalEntries: number
  ransomwareRelated: number   // knownRansomwareCampaignUse === 'Known'
  recentEntries: number       // dateAdded within the last 30 days
  hasHighPriorityEntries: boolean  // any entry that is both ransomware + recent
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse the raw JSON from the CISA KEV feed URL.
 * Returns null when the payload is malformed or missing.
 */
export function parseCisaKevResponse(json: unknown): CisaKevCatalog | null {
  if (!json || typeof json !== 'object') return null
  const raw = json as Record<string, unknown>

  if (!Array.isArray(raw.vulnerabilities)) return null

  const entries: CisaKevEntry[] = []

  for (const v of raw.vulnerabilities) {
    if (!v || typeof v !== 'object') continue
    const entry = v as Record<string, unknown>

    const cveId = String(entry.cveID ?? '').trim()
    if (!cveId.startsWith('CVE-')) continue

    entries.push({
      cveId,
      vendorProject: String(entry.vendorProject ?? ''),
      product: String(entry.product ?? ''),
      vulnerabilityName: String(entry.vulnerabilityName ?? ''),
      dateAdded: String(entry.dateAdded ?? ''),
      shortDescription: String(entry.shortDescription ?? ''),
      requiredAction: String(entry.requiredAction ?? ''),
      dueDate: String(entry.dueDate ?? ''),
      knownRansomwareCampaignUse:
        entry.knownRansomwareCampaignUse === 'Known' ? 'Known' : 'Unknown',
      notes: String(entry.notes ?? ''),
    })
  }

  return {
    catalogVersion: String(raw.catalogVersion ?? ''),
    dateReleased: String(raw.dateReleased ?? ''),
    count: entries.length,
    entries,
  }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/**
 * Cross-reference a list of CVE IDs against the catalog.
 * Matching is case-insensitive.
 */
export function matchCisaKevToCveList(
  catalog: CisaKevCatalog,
  cveIds: string[],
): CisaKevEntry[] {
  if (cveIds.length === 0) return []
  const normalised = new Set(cveIds.map((id) => id.trim().toUpperCase()))
  return catalog.entries.filter((e) => normalised.has(e.cveId.toUpperCase()))
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/**
 * Assign a Sentinel severity to a KEV entry.
 *
 * CISA KEV implies exploitation is occurring — floor is "high".
 * Ransomware-linked entries are always "critical".
 * Overdue entries (dueDate < referenceDate) are also "critical".
 */
export function cisaKevToSeverity(
  entry: CisaKevEntry,
  referenceDate?: string,
): 'critical' | 'high' | 'medium' | 'low' {
  if (entry.knownRansomwareCampaignUse === 'Known') return 'critical'
  if (entry.dueDate && referenceDate && entry.dueDate < referenceDate) return 'critical'
  return 'high'
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

/**
 * Build a dashboard-ready summary from the catalog.
 * referenceDate defaults to today (YYYY-MM-DD).
 */
export function buildCisaKevSummary(
  catalog: CisaKevCatalog,
  referenceDate?: string,
): CisaKevSummary {
  const ref = referenceDate ?? new Date().toISOString().slice(0, 10)

  // Compute the cutoff date 30 days before the reference
  const d = new Date(ref)
  d.setDate(d.getDate() - 30)
  const cutoff = d.toISOString().slice(0, 10)

  let ransomwareRelated = 0
  let recentEntries = 0

  for (const entry of catalog.entries) {
    if (entry.knownRansomwareCampaignUse === 'Known') ransomwareRelated++
    if (entry.dateAdded >= cutoff) recentEntries++
  }

  return {
    totalEntries: catalog.entries.length,
    ransomwareRelated,
    recentEntries,
    hasHighPriorityEntries: ransomwareRelated > 0 && recentEntries > 0,
  }
}
