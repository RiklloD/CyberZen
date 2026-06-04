/// <reference types="vite/client" />
// WS-43 — Known CVE Version Range Scanner: unit tests.

import { describe, expect, test } from 'vitest'
import {
  KNOWN_CVE_DATABASE,
  checkComponentCves,
  compareVersionTuples,
  computeCveReport,
  cvssToRiskLevel,
  isVersionVulnerable,
  parseVersionTuple,
} from './cveVersionScanner'

// ---------------------------------------------------------------------------
// parseVersionTuple
// ---------------------------------------------------------------------------

describe('parseVersionTuple', () => {
  test('parses standard semver', () => {
    expect(parseVersionTuple('4.17.20')).toEqual([4, 17, 20])
    expect(parseVersionTuple('2.15.0')).toEqual([2, 15, 0])
  })

  test('strips leading v prefix', () => {
    expect(parseVersionTuple('v1.2.3')).toEqual([1, 2, 3])
    expect(parseVersionTuple('V2.0.0')).toEqual([2, 0, 0])
  })

  test('handles two-part version', () => {
    expect(parseVersionTuple('1.2')).toEqual([1, 2, 0])
    expect(parseVersionTuple('3.0')).toEqual([3, 0, 0])
  })

  test('handles major-only version', () => {
    expect(parseVersionTuple('2')).toEqual([2, 0, 0])
  })

  test('strips Maven qualifiers (.RELEASE, .SNAPSHOT)', () => {
    expect(parseVersionTuple('5.3.17.RELEASE')).toEqual([5, 3, 17])
    expect(parseVersionTuple('2.15.0.SNAPSHOT')).toEqual([2, 15, 0])
  })

  test('strips PyPI pre-release suffixes', () => {
    expect(parseVersionTuple('3.1.2rc1')).toEqual([3, 1, 2])
    expect(parseVersionTuple('10.2.0a1')).toEqual([10, 2, 0])
    expect(parseVersionTuple('2.31.0.post1')).toEqual([2, 31, 0])
  })

  test('returns null for unparseable strings', () => {
    expect(parseVersionTuple('latest')).toBeNull()
    expect(parseVersionTuple('*')).toBeNull()
    expect(parseVersionTuple('')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// compareVersionTuples
// ---------------------------------------------------------------------------

describe('compareVersionTuples', () => {
  test('returns 0 for equal tuples', () => {
    expect(compareVersionTuples([1, 2, 3], [1, 2, 3])).toBe(0)
  })

  test('returns -1 when a < b (major differs)', () => {
    expect(compareVersionTuples([1, 9, 9], [2, 0, 0])).toBe(-1)
  })

  test('returns 1 when a > b (minor differs)', () => {
    expect(compareVersionTuples([5, 3, 18], [5, 3, 17])).toBe(1)
  })

  test('returns -1 when patch differs', () => {
    expect(compareVersionTuples([4, 17, 20], [4, 17, 21])).toBe(-1)
  })

  test('handles zero padding correctly', () => {
    expect(compareVersionTuples([2, 0, 0], [2, 0, 1])).toBe(-1)
    expect(compareVersionTuples([2, 1, 0], [2, 0, 9])).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// isVersionVulnerable
// ---------------------------------------------------------------------------

describe('isVersionVulnerable', () => {
  test('returns true when installed is below threshold (patch)', () => {
    expect(isVersionVulnerable('4.17.20', '4.17.21')).toBe(true)
  })

  test('returns false when installed equals threshold (at fix version)', () => {
    expect(isVersionVulnerable('4.17.21', '4.17.21')).toBe(false)
  })

  test('returns false when installed is above threshold', () => {
    expect(isVersionVulnerable('5.0.0', '4.17.21')).toBe(false)
  })

  test('returns true for the classic Log4Shell scenario', () => {
    expect(isVersionVulnerable('2.14.1', '2.15.0')).toBe(true)
    expect(isVersionVulnerable('2.0.0', '2.15.0')).toBe(true)
  })

  test('returns false for patched Log4j', () => {
    expect(isVersionVulnerable('2.15.0', '2.15.0')).toBe(false)
    expect(isVersionVulnerable('2.17.1', '2.15.0')).toBe(false)
  })

  test('returns null when installed version is unparseable', () => {
    expect(isVersionVulnerable('latest', '1.0.0')).toBeNull()
    expect(isVersionVulnerable('*', '1.0.0')).toBeNull()
  })

  test('returns null when threshold version is unparseable', () => {
    expect(isVersionVulnerable('1.0.0', 'N/A')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// cvssToRiskLevel
// ---------------------------------------------------------------------------

describe('cvssToRiskLevel', () => {
  test('maps CVSS 10.0 to critical', () => {
    expect(cvssToRiskLevel(10.0)).toBe('critical')
  })

  test('maps CVSS 9.0 to critical', () => {
    expect(cvssToRiskLevel(9.0)).toBe('critical')
  })

  test('maps CVSS 8.9 to high', () => {
    expect(cvssToRiskLevel(8.9)).toBe('high')
  })

  test('maps CVSS 7.0 to high', () => {
    expect(cvssToRiskLevel(7.0)).toBe('high')
  })

  test('maps CVSS 6.9 to medium', () => {
    expect(cvssToRiskLevel(6.9)).toBe('medium')
  })

  test('maps CVSS 4.0 to medium', () => {
    expect(cvssToRiskLevel(4.0)).toBe('medium')
  })

  test('maps CVSS 3.9 to low', () => {
    expect(cvssToRiskLevel(3.9)).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// checkComponentCves
// ---------------------------------------------------------------------------

describe('checkComponentCves', () => {
  test('returns empty array for a package not in the database', () => {
    const result = checkComponentCves({ name: 'express', version: '4.18.0', ecosystem: 'npm' })
    expect(result).toHaveLength(0)
  })

  test('returns empty array when installed version is at or above fix', () => {
    const result = checkComponentCves({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' })
    expect(result).toHaveLength(0)
  })

  test('detects lodash CVE-2021-23337 for an affected version', () => {
    const result = checkComponentCves({ name: 'lodash', version: '4.17.20', ecosystem: 'npm' })
    expect(result.length).toBeGreaterThanOrEqual(1)
    const cve = result.find((f) => f.cveId === 'CVE-2021-23337')
    expect(cve).toBeDefined()
    expect(cve!.riskLevel).toBe('high')
    expect(cve!.minimumSafeVersion).toBe('4.17.21')
  })

  test('detects Log4Shell (CVE-2021-44228) for affected log4j-core', () => {
    const result = checkComponentCves({
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.1',
      ecosystem: 'maven',
    })
    const log4shell = result.find((f) => f.cveId === 'CVE-2021-44228')
    expect(log4shell).toBeDefined()
    expect(log4shell!.riskLevel).toBe('critical')
    expect(log4shell!.cvss).toBe(10.0)
  })

  test('is safe when log4j-core is patched past both log4shell CVEs', () => {
    const result = checkComponentCves({
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.17.1',
      ecosystem: 'maven',
    })
    expect(result).toHaveLength(0)
  })

  test('detects multiple CVEs for a package with several entries', () => {
    // log4j-core has CVE-2021-44228 (< 2.15.0) AND CVE-2021-45046 (< 2.16.0)
    const result = checkComponentCves({
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.1',
      ecosystem: 'maven',
    })
    expect(result.length).toBeGreaterThanOrEqual(2)
    const ids = result.map((f) => f.cveId)
    expect(ids).toContain('CVE-2021-44228')
    expect(ids).toContain('CVE-2021-45046')
  })

  test('is case-insensitive for ecosystem and package name', () => {
    const lower = checkComponentCves({ name: 'lodash', version: '4.17.20', ecosystem: 'npm' })
    const upper = checkComponentCves({ name: 'Lodash', version: '4.17.20', ecosystem: 'NPM' })
    expect(upper.length).toBe(lower.length)
  })

  test('returns null result for unparseable installed version (skip, not error)', () => {
    const result = checkComponentCves({ name: 'lodash', version: 'latest', ecosystem: 'npm' })
    expect(result).toHaveLength(0)
  })

  test('finding includes cveId, cvss, minimumSafeVersion, description, evidence', () => {
    const result = checkComponentCves({ name: 'vm2', version: '3.9.16', ecosystem: 'npm' })
    expect(result.length).toBeGreaterThanOrEqual(1)
    const f = result[0]
    expect(f.cveId).toBe('CVE-2023-29017')
    expect(f.cvss).toBe(9.8)
    expect(f.minimumSafeVersion).toBe('3.9.17')
    expect(f.description).toBeTruthy()
    expect(f.evidence).toContain('cve=CVE-2023-29017')
  })

  test('detects pypi werkzeug CVE-2024-34069 for affected version', () => {
    const result = checkComponentCves({ name: 'werkzeug', version: '2.3.8', ecosystem: 'pypi' })
    const cve = result.find((f) => f.cveId === 'CVE-2024-34069')
    expect(cve).toBeDefined()
    expect(cve!.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// computeCveReport
// ---------------------------------------------------------------------------

describe('computeCveReport', () => {
  test('returns none overallRisk for a clean list', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ]
    const report = computeCveReport(components)
    expect(report.overallRisk).toBe('none')
    expect(report.totalVulnerable).toBe(0)
  })

  test('detects critical finding and sets overallRisk to critical', () => {
    const components = [
      { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' },
    ]
    const report = computeCveReport(components)
    expect(report.overallRisk).toBe('critical')
    expect(report.criticalCount).toBeGreaterThanOrEqual(1)
  })

  test('findings are sorted by CVSS descending', () => {
    const components = [
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },          // CVSS 7.2
      { name: 'minimist', version: '1.2.5', ecosystem: 'npm' },          // CVSS 9.8
      { name: 'path-parse', version: '1.0.6', ecosystem: 'npm' },        // CVSS 5.3
    ]
    const report = computeCveReport(components)
    expect(report.findings.length).toBeGreaterThanOrEqual(3)
    expect(report.findings[0].cvss).toBeGreaterThanOrEqual(report.findings[1].cvss)
    expect(report.findings[1].cvss).toBeGreaterThanOrEqual(report.findings[2].cvss)
  })

  test('deduplicates identical components before scanning', () => {
    const components = [
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    ]
    const report = computeCveReport(components)
    const lodashFindings = report.findings.filter((f) => f.packageName === 'lodash')
    // Should only appear once despite duplicate input
    expect(lodashFindings.length).toBeLessThanOrEqual(3) // at most the actual CVEs for lodash
    // Count is not doubled
    const unique = new Set(lodashFindings.map((f) => f.cveId))
    expect(lodashFindings.length).toBe(unique.size)
  })

  test('deduplication is case-insensitive for ecosystem', () => {
    const components = [
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.20', ecosystem: 'NPM' },
    ]
    const report = computeCveReport(components)
    const lodashFindings = report.findings.filter((f) => f.packageName === 'lodash')
    const unique = new Set(lodashFindings.map((f) => f.cveId))
    expect(lodashFindings.length).toBe(unique.size)
  })

  test('handles empty component list gracefully', () => {
    const report = computeCveReport([])
    expect(report.findings).toHaveLength(0)
    expect(report.overallRisk).toBe('none')
    expect(report.totalVulnerable).toBe(0)
    expect(report.criticalCount).toBe(0)
  })

  test('summary is clean when no CVEs matched', () => {
    const report = computeCveReport([])
    expect(report.summary).toBe('No known-CVE version matches detected.')
  })

  test('summary mentions CVE count and critical count', () => {
    const components = [
      { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' },
    ]
    const report = computeCveReport(components)
    expect(report.summary).toMatch(/CVE/)
    expect(report.summary).toMatch(/critical/)
  })

  test('multiple vulnerable components each contribute their findings', () => {
    const components = [
      { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      { name: 'minimist', version: '1.2.5', ecosystem: 'npm' },
      { name: 'qs', version: '6.7.2', ecosystem: 'npm' },
    ]
    const report = computeCveReport(components)
    expect(report.totalVulnerable).toBeGreaterThanOrEqual(3)
    expect(report.findings.length).toBeGreaterThanOrEqual(3)
  })
})

// ---------------------------------------------------------------------------
// Database integrity
// ---------------------------------------------------------------------------

describe('KNOWN_CVE_DATABASE integrity', () => {
  test('contains at least 25 entries', () => {
    expect(KNOWN_CVE_DATABASE.length).toBeGreaterThanOrEqual(25)
  })

  test('every entry has a valid CVE ID format', () => {
    for (const entry of KNOWN_CVE_DATABASE) {
      expect(entry.cveId, `bad CVE ID: ${entry.cveId}`).toMatch(/^CVE-\d{4}-\d+$/)
    }
  })

  test('every entry has a positive CVSS score ≤ 10.0', () => {
    for (const entry of KNOWN_CVE_DATABASE) {
      expect(entry.cvss, `bad CVSS for ${entry.cveId}`).toBeGreaterThan(0)
      expect(entry.cvss, `bad CVSS for ${entry.cveId}`).toBeLessThanOrEqual(10.0)
    }
  })

  test('every minimumSafeVersion is parseable', () => {
    for (const entry of KNOWN_CVE_DATABASE) {
      const tuple = parseVersionTuple(entry.minimumSafeVersion)
      expect(tuple, `unparseable minimumSafeVersion for ${entry.cveId}: ${entry.minimumSafeVersion}`).not.toBeNull()
    }
  })

  test('Log4Shell (CVE-2021-44228) is present with correct metadata', () => {
    const entry = KNOWN_CVE_DATABASE.find((e) => e.cveId === 'CVE-2021-44228')
    expect(entry).toBeDefined()
    expect(entry!.cvss).toBe(10.0)
    expect(entry!.minimumSafeVersion).toBe('2.15.0')
    expect(entry!.ecosystem).toBe('maven')
  })
})
