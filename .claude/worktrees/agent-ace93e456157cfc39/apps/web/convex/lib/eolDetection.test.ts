/// <reference types="vite/client" />
// WS-38 — Dependency & Runtime End-of-Life (EOL) Detection: unit tests.

import { describe, expect, test } from 'vitest'
import {
  EOL_DATABASE,
  NEAR_EOL_WINDOW_MS,
  checkComponentEol,
  classifyEolStatus,
  computeEolReport,
  lookupEolEntry,
  parseVersionMajorMinor,
  versionMatchesPrefix,
} from './eolDetection'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** 30 days in ms */
const DAY_MS = 24 * 60 * 60 * 1000

/** A fixed "now" well past 2026 for deterministic tests. */
const NOW = Date.UTC(2026, 3, 22) // 2026-04-22

// ---------------------------------------------------------------------------
// versionMatchesPrefix
// ---------------------------------------------------------------------------

describe('versionMatchesPrefix', () => {
  test('empty prefix matches any version', () => {
    expect(versionMatchesPrefix('3.0.0', '')).toBe(true)
    expect(versionMatchesPrefix('1.2.3', '')).toBe(true)
  })

  test('exact match', () => {
    expect(versionMatchesPrefix('14', '14')).toBe(true)
    expect(versionMatchesPrefix('2.7', '2.7')).toBe(true)
  })

  test('prefix with major segment', () => {
    expect(versionMatchesPrefix('14.21.3', '14')).toBe(true)
    expect(versionMatchesPrefix('14.0.0', '14')).toBe(true)
  })

  test('prefix with major.minor segment', () => {
    expect(versionMatchesPrefix('2.7.18', '2.7')).toBe(true)
    expect(versionMatchesPrefix('3.8.0', '3.8')).toBe(true)
  })

  test('does NOT match a different major version', () => {
    expect(versionMatchesPrefix('141.0.0', '14')).toBe(false)
    expect(versionMatchesPrefix('2.17.3', '2.7')).toBe(false)
  })

  test('does NOT match when version is shorter than prefix', () => {
    expect(versionMatchesPrefix('3', '3.8')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// parseVersionMajorMinor
// ---------------------------------------------------------------------------

describe('parseVersionMajorMinor', () => {
  test('extracts major.minor from three-part version', () => {
    expect(parseVersionMajorMinor('14.21.3')).toBe('14.21')
    expect(parseVersionMajorMinor('3.8.0')).toBe('3.8')
  })

  test('returns major.minor from two-part version', () => {
    expect(parseVersionMajorMinor('2.7')).toBe('2.7')
  })

  test('returns major alone when only one part', () => {
    expect(parseVersionMajorMinor('3')).toBe('3')
  })

  test('handles whitespace', () => {
    expect(parseVersionMajorMinor('  16.0.0  ')).toBe('16.0')
  })
})

// ---------------------------------------------------------------------------
// classifyEolStatus
// ---------------------------------------------------------------------------

describe('classifyEolStatus', () => {
  test('returns "end_of_life" when now is past EOL date', () => {
    const eolDate = NOW - 10 * DAY_MS // 10 days ago
    expect(classifyEolStatus(eolDate, NOW)).toBe('end_of_life')
  })

  test('returns "end_of_life" exactly at EOL date', () => {
    expect(classifyEolStatus(NOW, NOW)).toBe('end_of_life')
  })

  test('returns "near_eol" within NEAR_EOL_WINDOW_MS', () => {
    const eolDate = NOW + 30 * DAY_MS // 30 days from now (well within 90-day window)
    expect(classifyEolStatus(eolDate, NOW)).toBe('near_eol')
  })

  test('returns "supported" when far from EOL', () => {
    const eolDate = NOW + 200 * DAY_MS // 200 days from now
    expect(classifyEolStatus(eolDate, NOW)).toBe('supported')
  })

  test('returns "unknown" for null EOL date', () => {
    expect(classifyEolStatus(null, NOW)).toBe('unknown')
  })

  test('boundary: just outside near-EOL window is "supported"', () => {
    const eolDate = NOW + NEAR_EOL_WINDOW_MS + 1
    expect(classifyEolStatus(eolDate, NOW)).toBe('supported')
  })

  test('boundary: exactly at near-EOL window start is "near_eol"', () => {
    const eolDate = NOW + NEAR_EOL_WINDOW_MS
    expect(classifyEolStatus(eolDate, NOW)).toBe('near_eol')
  })
})

// ---------------------------------------------------------------------------
// lookupEolEntry
// ---------------------------------------------------------------------------

describe('lookupEolEntry', () => {
  test('finds Node.js v14 EOL entry', () => {
    const entry = lookupEolEntry('node', '14.21.3', 'npm')
    expect(entry).not.toBeNull()
    expect(entry?.versionPrefix).toBe('14')
    expect(entry?.eolDateText).toBe('2023-04-30')
  })

  test('finds Django 2.2 EOL entry', () => {
    const entry = lookupEolEntry('django', '2.2.28', 'pypi')
    expect(entry).not.toBeNull()
    expect(entry?.versionPrefix).toBe('2.2')
  })

  test('finds python 2.7 EOL entry', () => {
    const entry = lookupEolEntry('python', '2.7.18', 'pypi')
    expect(entry).not.toBeNull()
    expect(entry?.eolDateText).toBe('2020-01-01')
  })

  test('returns null for supported Node.js version (20)', () => {
    const entry = lookupEolEntry('node', '20.11.0', 'npm')
    expect(entry).toBeNull()
  })

  test('returns null for unknown package', () => {
    const entry = lookupEolEntry('totally-unknown-pkg', '1.0.0', 'npm')
    expect(entry).toBeNull()
  })

  test('returns null for wrong ecosystem', () => {
    // node is in npm, not pypi
    const entry = lookupEolEntry('node', '14.21.3', 'pypi')
    expect(entry).toBeNull()
  })

  test('is case-insensitive for package name', () => {
    const entry = lookupEolEntry('Node', '14.0.0', 'npm')
    expect(entry).not.toBeNull()
  })

  test('prefers more specific prefix (2.7 over 2 if both existed)', () => {
    // Django has '2.2' and '1' prefixes — '2.2' should win for '2.2.28'
    const entry = lookupEolEntry('django', '2.2.28', 'pypi')
    expect(entry?.versionPrefix).toBe('2.2')
  })

  test('finds deprecated request package (empty prefix)', () => {
    const entry = lookupEolEntry('request', '2.88.2', 'npm')
    expect(entry).not.toBeNull()
    expect(entry?.versionPrefix).toBe('')
  })
})

// ---------------------------------------------------------------------------
// checkComponentEol
// ---------------------------------------------------------------------------

describe('checkComponentEol', () => {
  test('returns null for a supported package not in database', () => {
    const result = checkComponentEol({ name: 'express', version: '4.18.0', ecosystem: 'npm' }, NOW)
    expect(result).toBeNull()
  })

  test('returns EOL finding for Node.js 14', () => {
    const result = checkComponentEol({ name: 'node', version: '14.21.3', ecosystem: 'npm' }, NOW)
    expect(result).not.toBeNull()
    expect(result?.eolStatus).toBe('end_of_life')
    expect(result?.packageName).toBe('node')
    expect(result?.daysOverdue).toBeGreaterThan(0)
    expect(result?.daysUntilEol).toBeNull()
  })

  test('returns near_eol finding for PHP 8.1 when close to EOL', () => {
    // PHP 8.1 EOL is 2025-12-31; our NOW is 2026-04-22, so it's already EOL
    const result = checkComponentEol({ name: 'php', version: '8.1.0', ecosystem: 'runtime' }, NOW)
    expect(result).not.toBeNull()
    expect(result?.eolStatus).toBe('end_of_life')
  })

  test('returns near_eol when within 30 days of EOL', () => {
    // Construct a NOW that is 30 days before PHP 8.1 EOL (2025-12-31)
    const php81Eol = Date.UTC(2025, 11, 31)
    const near = php81Eol - 30 * DAY_MS
    const result = checkComponentEol({ name: 'php', version: '8.1.0', ecosystem: 'runtime' }, near)
    expect(result).not.toBeNull()
    expect(result?.eolStatus).toBe('near_eol')
    expect(result?.daysUntilEol).toBeGreaterThan(0)
    expect(result?.daysOverdue).toBeNull()
  })

  test('returns null for supported Node.js 20', () => {
    const result = checkComponentEol({ name: 'node', version: '20.10.0', ecosystem: 'npm' }, NOW)
    expect(result).toBeNull()
  })

  test('includes replacedBy in finding', () => {
    const result = checkComponentEol({ name: 'node', version: '14.0.0', ecosystem: 'npm' }, NOW)
    expect(result?.replacedBy).toBe('Node.js 20 LTS')
  })

  test('title mentions package name and version', () => {
    const result = checkComponentEol({ name: 'node', version: '14.21.3', ecosystem: 'npm' }, NOW)
    expect(result?.title).toContain('node')
    expect(result?.title).toContain('14.21')
  })

  test('description mentions EOL date', () => {
    const result = checkComponentEol({ name: 'node', version: '14.21.3', ecosystem: 'npm' }, NOW)
    expect(result?.description).toContain('2023-04-30')
  })
})

// ---------------------------------------------------------------------------
// computeEolReport
// ---------------------------------------------------------------------------

describe('computeEolReport', () => {
  test('returns ok status and zero counts for empty component list', () => {
    const report = computeEolReport([], NOW)
    expect(report.overallStatus).toBe('ok')
    expect(report.eolCount).toBe(0)
    expect(report.nearEolCount).toBe(0)
    expect(report.findings).toHaveLength(0)
  })

  test('returns ok status when all components are supported or unknown', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    ]
    const report = computeEolReport(components, NOW)
    expect(report.overallStatus).toBe('ok')
    expect(report.eolCount).toBe(0)
  })

  test('returns critical status when any component is EOL', () => {
    const components = [
      { name: 'node', version: '14.21.3', ecosystem: 'npm' },
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
    ]
    const report = computeEolReport(components, NOW)
    expect(report.overallStatus).toBe('critical')
    expect(report.eolCount).toBe(1)
  })

  test('returns warning status when only near_eol components present', () => {
    // Use a NOW just before PHP 8.1 EOL (within 30 days)
    const php81Eol = Date.UTC(2025, 11, 31)
    const nearNow = php81Eol - 30 * DAY_MS
    const components = [
      { name: 'php', version: '8.1.0', ecosystem: 'runtime' },
    ]
    const report = computeEolReport(components, nearNow)
    expect(report.overallStatus).toBe('warning')
    expect(report.nearEolCount).toBe(1)
    expect(report.eolCount).toBe(0)
  })

  test('includes findings array with detail for each EOL hit', () => {
    const components = [
      { name: 'node', version: '14.0.0', ecosystem: 'npm' },
      { name: 'django', version: '2.2.28', ecosystem: 'pypi' },
    ]
    const report = computeEolReport(components, NOW)
    expect(report.findings.length).toBeGreaterThanOrEqual(2)
    const names = report.findings.map((f) => f.packageName)
    expect(names).toContain('node')
    expect(names).toContain('django')
  })

  test('deduplicates repeated components', () => {
    // Same package appearing twice (direct + transitive) should produce one finding.
    const components = [
      { name: 'node', version: '14.0.0', ecosystem: 'npm' },
      { name: 'node', version: '14.0.0', ecosystem: 'npm' },
    ]
    const report = computeEolReport(components, NOW)
    expect(report.eolCount).toBe(1)
    expect(report.findings).toHaveLength(1)
  })

  test('counts unknownCount for packages not in EOL database', () => {
    const components = [
      { name: 'some-unknown-pkg', version: '1.0.0', ecosystem: 'npm' },
      { name: 'another-one', version: '2.0.0', ecosystem: 'npm' },
    ]
    const report = computeEolReport(components, NOW)
    expect(report.unknownCount).toBe(2)
  })

  test('summary string is non-empty', () => {
    const report = computeEolReport([], NOW)
    expect(report.summary).toBeTruthy()
    expect(typeof report.summary).toBe('string')
  })

  test('critical overrides warning when both EOL and near-EOL present', () => {
    const php81Eol = Date.UTC(2025, 11, 31)
    const nearNow = php81Eol - 30 * DAY_MS // near PHP 8.1 EOL
    const components = [
      { name: 'node', version: '14.0.0', ecosystem: 'npm' },  // already EOL at any time
      { name: 'php', version: '8.1.0', ecosystem: 'runtime' }, // near-EOL at nearNow
    ]
    const report = computeEolReport(components, nearNow)
    expect(report.overallStatus).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// EOL_DATABASE sanity
// ---------------------------------------------------------------------------

describe('EOL_DATABASE integrity', () => {
  test('all records have non-empty ecosystem and name', () => {
    for (const entry of EOL_DATABASE) {
      expect(entry.ecosystem).toBeTruthy()
      expect(entry.name).toBeTruthy()
    }
  })

  test('all EOL dates are valid timestamps', () => {
    for (const entry of EOL_DATABASE) {
      expect(Number.isFinite(entry.eolDate)).toBe(true)
      expect(entry.eolDate).toBeGreaterThan(0)
    }
  })

  test('eolDateText matches human-readable pattern', () => {
    const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/
    for (const entry of EOL_DATABASE) {
      expect(entry.eolDateText).toMatch(ISO_DATE)
    }
  })
})
