import { describe, expect, it } from 'vitest'
import {
  buildEpssEnrichmentMap,
  buildEpssSummary,
  classifyEpssRisk,
  enrichDisclosureWithEpss,
  extractCveIds,
  parseEpssApiResponse,
  type EpssEnrichedCve,
  type EpssEntry,
} from './epssEnrichment'

// ---------------------------------------------------------------------------
// classifyEpssRisk
// ---------------------------------------------------------------------------

describe('classifyEpssRisk', () => {
  it('returns critical for score exactly 0.5', () => {
    expect(classifyEpssRisk(0.5)).toBe('critical')
  })

  it('returns critical for score above 0.5', () => {
    expect(classifyEpssRisk(0.97546)).toBe('critical')
  })

  it('returns high for score exactly 0.2', () => {
    expect(classifyEpssRisk(0.2)).toBe('high')
  })

  it('returns high for score between 0.2 and 0.5', () => {
    expect(classifyEpssRisk(0.35)).toBe('high')
  })

  it('returns medium for score exactly 0.05', () => {
    expect(classifyEpssRisk(0.05)).toBe('medium')
  })

  it('returns medium for score between 0.05 and 0.2', () => {
    expect(classifyEpssRisk(0.12)).toBe('medium')
  })

  it('returns low for score below 0.05', () => {
    expect(classifyEpssRisk(0.03)).toBe('low')
  })

  it('returns low for score of exactly 0', () => {
    expect(classifyEpssRisk(0)).toBe('low')
  })

  it('clamps scores above 1.0 to critical', () => {
    expect(classifyEpssRisk(1.5)).toBe('critical')
  })

  it('clamps negative scores to low', () => {
    expect(classifyEpssRisk(-0.1)).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// parseEpssApiResponse
// ---------------------------------------------------------------------------

describe('parseEpssApiResponse', () => {
  it('returns null for null input', () => {
    expect(parseEpssApiResponse(null)).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseEpssApiResponse('string')).toBeNull()
    expect(parseEpssApiResponse(42)).toBeNull()
  })

  it('returns null when data field is missing', () => {
    expect(parseEpssApiResponse({ status: 'OK' })).toBeNull()
  })

  it('returns empty array for empty data array', () => {
    const result = parseEpssApiResponse({ status: 'OK', data: [] })
    expect(result).toEqual([])
  })

  it('parses a realistic FIRST.org API response', () => {
    const json = {
      status: 'OK',
      'status-code': 200,
      data: [
        { cve: 'CVE-2021-44228', epss: '0.97546', percentile: '0.99998', date: '2024-01-15' },
        { cve: 'CVE-2023-12345', epss: '0.02300', percentile: '0.71234', date: '2024-01-15' },
      ],
    }
    const result = parseEpssApiResponse(json)
    expect(result).toHaveLength(2)
    expect(result![0].cveId).toBe('CVE-2021-44228')
    expect(result![0].epssScore).toBeCloseTo(0.97546)
    expect(result![0].epssPercentile).toBeCloseTo(0.99998)
    expect(result![0].date).toBe('2024-01-15')
  })

  it('normalises CVE IDs to uppercase', () => {
    const json = { data: [{ cve: 'cve-2021-44228', epss: '0.5', percentile: '0.9', date: '' }] }
    const result = parseEpssApiResponse(json)
    expect(result![0].cveId).toBe('CVE-2021-44228')
  })

  it('skips entries with non-CVE identifiers', () => {
    const json = {
      data: [
        { cve: 'GHSA-1234-5678', epss: '0.5', percentile: '0.9', date: '' },
        { cve: 'CVE-2022-99999', epss: '0.1', percentile: '0.5', date: '' },
      ],
    }
    const result = parseEpssApiResponse(json)
    expect(result).toHaveLength(1)
    expect(result![0].cveId).toBe('CVE-2022-99999')
  })

  it('skips entries with unparseable scores', () => {
    const json = {
      data: [
        { cve: 'CVE-2022-11111', epss: 'not-a-number', percentile: '0.5', date: '' },
        { cve: 'CVE-2022-22222', epss: '0.3', percentile: '0.7', date: '' },
      ],
    }
    const result = parseEpssApiResponse(json)
    expect(result).toHaveLength(1)
    expect(result![0].cveId).toBe('CVE-2022-22222')
  })

  it('clamps parsed scores to [0, 1]', () => {
    const json = {
      data: [{ cve: 'CVE-2022-33333', epss: '1.5', percentile: '-0.1', date: '' }],
    }
    const result = parseEpssApiResponse(json)
    expect(result![0].epssScore).toBe(1)
    expect(result![0].epssPercentile).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// extractCveIds
// ---------------------------------------------------------------------------

describe('extractCveIds', () => {
  it('returns empty array for empty disclosures', () => {
    expect(extractCveIds([])).toEqual([])
  })

  it('extracts CVE from sourceRef', () => {
    const result = extractCveIds([{ sourceRef: 'CVE-2021-44228', aliases: [] }])
    expect(result).toContain('CVE-2021-44228')
  })

  it('extracts CVE from aliases when sourceRef is not a CVE', () => {
    const result = extractCveIds([
      { sourceRef: 'GHSA-jfh8-c2jp-hdpw', aliases: ['CVE-2021-44228', 'GHSA-xyz'] },
    ])
    expect(result).toContain('CVE-2021-44228')
    expect(result).not.toContain('GHSA-jfh8-c2jp-hdpw')
    expect(result).not.toContain('GHSA-xyz')
  })

  it('deduplicates the same CVE appearing in multiple disclosures', () => {
    const disclosures = [
      { sourceRef: 'CVE-2021-44228', aliases: [] },
      { sourceRef: 'GHSA-abc', aliases: ['CVE-2021-44228'] },
    ]
    const result = extractCveIds(disclosures)
    expect(result.filter(id => id === 'CVE-2021-44228')).toHaveLength(1)
  })

  it('normalises CVE IDs to uppercase', () => {
    const result = extractCveIds([{ sourceRef: 'cve-2021-44228', aliases: [] }])
    expect(result).toContain('CVE-2021-44228')
    expect(result).not.toContain('cve-2021-44228')
  })

  it('skips refs that do not start with CVE-', () => {
    const result = extractCveIds([{ sourceRef: 'GHSA-1234', aliases: ['OSV-2021-123'] }])
    expect(result).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// buildEpssEnrichmentMap
// ---------------------------------------------------------------------------

describe('buildEpssEnrichmentMap', () => {
  it('returns empty map for empty input', () => {
    const map = buildEpssEnrichmentMap([])
    expect(map.size).toBe(0)
  })

  it('stores a single entry indexed by CVE ID', () => {
    const entry: EpssEntry = { cveId: 'CVE-2021-44228', epssScore: 0.97, epssPercentile: 0.99, date: '2024-01-01' }
    const map = buildEpssEnrichmentMap([entry])
    expect(map.get('CVE-2021-44228')).toBe(entry)
  })

  it('stores multiple entries without collision', () => {
    const entries: EpssEntry[] = [
      { cveId: 'CVE-2021-44228', epssScore: 0.97, epssPercentile: 0.99, date: '' },
      { cveId: 'CVE-2023-00001', epssScore: 0.03, epssPercentile: 0.40, date: '' },
    ]
    const map = buildEpssEnrichmentMap(entries)
    expect(map.size).toBe(2)
    expect(map.get('CVE-2021-44228')!.epssScore).toBe(0.97)
    expect(map.get('CVE-2023-00001')!.epssScore).toBe(0.03)
  })

  it('normalises map keys to uppercase', () => {
    const entry: EpssEntry = { cveId: 'cve-2021-44228', epssScore: 0.5, epssPercentile: 0.9, date: '' }
    const map = buildEpssEnrichmentMap([entry])
    expect(map.get('CVE-2021-44228')).toBeDefined()
    expect(map.get('cve-2021-44228')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// enrichDisclosureWithEpss
// ---------------------------------------------------------------------------

describe('enrichDisclosureWithEpss', () => {
  const epssEntry: EpssEntry = { cveId: 'CVE-2021-44228', epssScore: 0.97, epssPercentile: 0.99, date: '' }
  const epssMap = new Map([['CVE-2021-44228', epssEntry]])

  it('returns null when disclosure has no matching CVE', () => {
    const result = enrichDisclosureWithEpss({ sourceRef: 'GHSA-xyz', aliases: [] }, epssMap)
    expect(result).toBeNull()
  })

  it('matches via sourceRef', () => {
    const result = enrichDisclosureWithEpss({ sourceRef: 'CVE-2021-44228', aliases: [] }, epssMap)
    expect(result).toBe(epssEntry)
  })

  it('matches via aliases when sourceRef has no match', () => {
    const result = enrichDisclosureWithEpss(
      { sourceRef: 'GHSA-jfh8-c2jp-hdpw', aliases: ['CVE-2021-44228'] },
      epssMap,
    )
    expect(result).toBe(epssEntry)
  })

  it('is case-insensitive in lookup', () => {
    const result = enrichDisclosureWithEpss(
      { sourceRef: 'cve-2021-44228', aliases: [] },
      epssMap,
    )
    expect(result).toBe(epssEntry)
  })

  it('returns first alias match when multiple aliases present', () => {
    const secondEntry: EpssEntry = { cveId: 'CVE-2022-99999', epssScore: 0.1, epssPercentile: 0.5, date: '' }
    const mapWithTwo = new Map([
      ['CVE-2021-44228', epssEntry],
      ['CVE-2022-99999', secondEntry],
    ])
    const result = enrichDisclosureWithEpss(
      { sourceRef: 'GHSA-abc', aliases: ['CVE-2021-44228', 'CVE-2022-99999'] },
      mapWithTwo,
    )
    expect(result).toBe(epssEntry) // first match wins
  })

  it('returns null for empty map', () => {
    const result = enrichDisclosureWithEpss({ sourceRef: 'CVE-2021-44228', aliases: [] }, new Map())
    expect(result).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// buildEpssSummary
// ---------------------------------------------------------------------------

describe('buildEpssSummary', () => {
  it('returns zero counts and empty topCves for empty enriched list', () => {
    const result = buildEpssSummary([], 10)
    expect(result.enrichedCount).toBe(0)
    expect(result.criticalRiskCount).toBe(0)
    expect(result.highRiskCount).toBe(0)
    expect(result.mediumRiskCount).toBe(0)
    expect(result.lowRiskCount).toBe(0)
    expect(result.avgScore).toBe(0)
    expect(result.topCves).toHaveLength(0)
    expect(result.totalQueried).toBe(10)
  })

  it('counts risk levels correctly', () => {
    const enriched: EpssEnrichedCve[] = [
      { cveId: 'CVE-A', epssScore: 0.8, epssPercentile: 0.99, epssRiskLevel: 'critical' },
      { cveId: 'CVE-B', epssScore: 0.3, epssPercentile: 0.85, epssRiskLevel: 'high' },
      { cveId: 'CVE-C', epssScore: 0.08, epssPercentile: 0.60, epssRiskLevel: 'medium' },
      { cveId: 'CVE-D', epssScore: 0.01, epssPercentile: 0.20, epssRiskLevel: 'low' },
    ]
    const result = buildEpssSummary(enriched, 4)
    expect(result.criticalRiskCount).toBe(1)
    expect(result.highRiskCount).toBe(1)
    expect(result.mediumRiskCount).toBe(1)
    expect(result.lowRiskCount).toBe(1)
  })

  it('calculates correct average score', () => {
    const enriched: EpssEnrichedCve[] = [
      { cveId: 'CVE-A', epssScore: 0.8, epssPercentile: 0.99, epssRiskLevel: 'critical' },
      { cveId: 'CVE-B', epssScore: 0.2, epssPercentile: 0.70, epssRiskLevel: 'high' },
    ]
    const result = buildEpssSummary(enriched, 2)
    expect(result.avgScore).toBeCloseTo(0.5)
  })

  it('returns topCves sorted by score descending', () => {
    const enriched: EpssEnrichedCve[] = [
      { cveId: 'CVE-A', epssScore: 0.1, epssPercentile: 0.5, epssRiskLevel: 'medium' },
      { cveId: 'CVE-B', epssScore: 0.9, epssPercentile: 0.99, epssRiskLevel: 'critical' },
      { cveId: 'CVE-C', epssScore: 0.5, epssPercentile: 0.95, epssRiskLevel: 'critical' },
    ]
    const result = buildEpssSummary(enriched, 3)
    expect(result.topCves[0].cveId).toBe('CVE-B')
    expect(result.topCves[1].cveId).toBe('CVE-C')
    expect(result.topCves[2].cveId).toBe('CVE-A')
  })

  it('caps topCves at 10 entries', () => {
    const enriched: EpssEnrichedCve[] = Array.from({ length: 15 }, (_, i) => ({
      cveId: `CVE-2023-${String(i).padStart(5, '0')}`,
      epssScore: i / 14,
      epssPercentile: i / 14,
      epssRiskLevel: 'low' as const,
    }))
    const result = buildEpssSummary(enriched, 15)
    expect(result.topCves).toHaveLength(10)
  })

  it('includes risk counts in summary text when critical or high present', () => {
    const enriched: EpssEnrichedCve[] = [
      { cveId: 'CVE-A', epssScore: 0.8, epssPercentile: 0.99, epssRiskLevel: 'critical' },
    ]
    const result = buildEpssSummary(enriched, 5)
    expect(result.summary).toContain('critical-risk')
  })

  it('omits risk warning from summary when only low scores present', () => {
    const enriched: EpssEnrichedCve[] = [
      { cveId: 'CVE-A', epssScore: 0.02, epssPercentile: 0.3, epssRiskLevel: 'low' },
    ]
    const result = buildEpssSummary(enriched, 1)
    expect(result.summary).not.toContain('critical-risk')
    expect(result.summary).not.toContain('high-risk')
  })
})
