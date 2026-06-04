/// <reference types="vite/client" />
// WS-39 — Open-Source Package Abandonment Detector: unit tests.

import { describe, expect, test } from 'vitest'
import {
  ABANDONED_DATABASE,
  checkPackageAbandonment,
  classifyOverallRisk,
  computeAbandonmentReport,
  lookupAbandonedRecord,
  versionMatchesPrefix,
} from './abandonmentDetection'

// ---------------------------------------------------------------------------
// versionMatchesPrefix
// ---------------------------------------------------------------------------

describe('versionMatchesPrefix', () => {
  test('empty prefix matches any version', () => {
    expect(versionMatchesPrefix('1.0.0', '')).toBe(true)
    expect(versionMatchesPrefix('3.14.159', '')).toBe(true)
  })

  test('exact match', () => {
    expect(versionMatchesPrefix('2', '2')).toBe(true)
    expect(versionMatchesPrefix('1.1', '1.1')).toBe(true)
  })

  test('prefix matches full semver with trailing segments', () => {
    expect(versionMatchesPrefix('0.6.5', '0')).toBe(true)
    expect(versionMatchesPrefix('2.0.0', '2')).toBe(true)
  })

  test('does NOT match different major version', () => {
    expect(versionMatchesPrefix('10.0.0', '1')).toBe(false)
    expect(versionMatchesPrefix('20.0.0', '2')).toBe(false)
  })

  test('does NOT match when version is shorter than prefix', () => {
    expect(versionMatchesPrefix('1', '1.1')).toBe(false)
  })

  test('trimming whitespace still matches', () => {
    expect(versionMatchesPrefix('  0.6.5  ', '0')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// lookupAbandonedRecord
// ---------------------------------------------------------------------------

describe('lookupAbandonedRecord', () => {
  test('finds supply-chain-compromised event-stream', () => {
    const rec = lookupAbandonedRecord('event-stream', '3.3.6', 'npm')
    expect(rec).not.toBeNull()
    expect(rec?.reason).toBe('supply_chain_compromised')
    expect(rec?.riskLevel).toBe('critical')
  })

  test('finds ua-parser-js only for v0 prefix', () => {
    const hit = lookupAbandonedRecord('ua-parser-js', '0.7.28', 'npm')
    expect(hit).not.toBeNull()
    expect(hit?.riskLevel).toBe('critical')
  })

  test('does NOT flag ua-parser-js 1.x (clean release)', () => {
    const miss = lookupAbandonedRecord('ua-parser-js', '1.0.2', 'npm')
    expect(miss).toBeNull()
  })

  test('finds archived request package (empty prefix)', () => {
    const rec = lookupAbandonedRecord('request', '2.88.2', 'npm')
    expect(rec).not.toBeNull()
    expect(rec?.reason).toBe('archived')
    expect(rec?.riskLevel).toBe('high')
  })

  test('finds pycrypto in pypi ecosystem', () => {
    const rec = lookupAbandonedRecord('pycrypto', '2.6.1', 'pypi')
    expect(rec).not.toBeNull()
    expect(rec?.riskLevel).toBe('high')
  })

  test('returns null for unknown package', () => {
    const rec = lookupAbandonedRecord('definitely-not-a-real-package', '1.0.0', 'npm')
    expect(rec).toBeNull()
  })

  test('returns null for wrong ecosystem', () => {
    // request is npm, not pypi
    const rec = lookupAbandonedRecord('request', '2.88.2', 'pypi')
    expect(rec).toBeNull()
  })

  test('is case-insensitive for package name', () => {
    const rec = lookupAbandonedRecord('Event-Stream', '3.3.6', 'npm')
    expect(rec).not.toBeNull()
  })

  test('finds mock v1 for pypi (version-prefixed)', () => {
    const rec = lookupAbandonedRecord('mock', '1.0.1', 'pypi')
    expect(rec).not.toBeNull()
    expect(rec?.reason).toBe('superseded')
    expect(rec?.versionPrefix).toBe('1')
  })

  test('finds mock v2 for pypi (version-prefixed)', () => {
    const rec = lookupAbandonedRecord('mock', '2.0.0', 'pypi')
    expect(rec).not.toBeNull()
    expect(rec?.versionPrefix).toBe('2')
  })

  test('does NOT find mock v3 for pypi (no matching prefix)', () => {
    const rec = lookupAbandonedRecord('mock', '3.0.0', 'pypi')
    expect(rec).toBeNull()
  })

  test('prefers longer prefix (more specific) on tie', () => {
    // cryptiles v3 has specific versionPrefix '3'; a hypothetical '' entry would lose
    const rec = lookupAbandonedRecord('cryptiles', '3.1.2', 'npm')
    expect(rec).not.toBeNull()
    expect(rec?.versionPrefix).toBe('3')
  })
})

// ---------------------------------------------------------------------------
// checkPackageAbandonment
// ---------------------------------------------------------------------------

describe('checkPackageAbandonment', () => {
  test('returns null for package not in database', () => {
    const result = checkPackageAbandonment({
      name: 'express',
      version: '4.18.0',
      ecosystem: 'npm',
    })
    expect(result).toBeNull()
  })

  test('returns critical finding for event-stream', () => {
    const result = checkPackageAbandonment({
      name: 'event-stream',
      version: '3.3.6',
      ecosystem: 'npm',
    })
    expect(result).not.toBeNull()
    expect(result?.riskLevel).toBe('critical')
    expect(result?.reason).toBe('supply_chain_compromised')
    expect(result?.packageName).toBe('event-stream')
    expect(result?.ecosystem).toBe('npm')
    expect(result?.version).toBe('3.3.6')
  })

  test('title mentions supply-chain attack for compromised packages', () => {
    const result = checkPackageAbandonment({
      name: 'event-stream',
      version: '3.3.6',
      ecosystem: 'npm',
    })
    expect(result?.title).toContain('supply-chain attack')
  })

  test('title says "officially deprecated" for officially_deprecated packages', () => {
    const result = checkPackageAbandonment({
      name: 'tslint',
      version: '5.20.1',
      ecosystem: 'npm',
    })
    expect(result?.title).toContain('officially deprecated')
    expect(result?.riskLevel).toBe('medium')
  })

  test('title says "archived" for archived packages', () => {
    const result = checkPackageAbandonment({
      name: 'request',
      version: '2.88.2',
      ecosystem: 'npm',
    })
    expect(result?.title).toContain('archived')
  })

  test('title says "superseded" for superseded packages', () => {
    const result = checkPackageAbandonment({
      name: 'node-uuid',
      version: '1.4.8',
      ecosystem: 'npm',
    })
    expect(result?.title).toContain('superseded')
    expect(result?.riskLevel).toBe('low')
    expect(result?.replacedBy).toContain('uuid')
  })

  test('description includes replacedBy when present', () => {
    const result = checkPackageAbandonment({
      name: 'tslint',
      version: '5.0.0',
      ecosystem: 'npm',
    })
    expect(result?.description).toContain('ESLint')
  })

  test('returns high finding for phantomjs', () => {
    const result = checkPackageAbandonment({
      name: 'phantomjs',
      version: '2.1.1',
      ecosystem: 'npm',
    })
    expect(result?.riskLevel).toBe('high')
    expect(result?.reason).toBe('unmaintained')
  })
})

// ---------------------------------------------------------------------------
// classifyOverallRisk
// ---------------------------------------------------------------------------

describe('classifyOverallRisk', () => {
  test('returns critical when criticalCount > 0', () => {
    expect(classifyOverallRisk(1, 0, 0, 0)).toBe('critical')
    expect(classifyOverallRisk(3, 5, 2, 1)).toBe('critical')
  })

  test('returns high when no critical but highCount > 0', () => {
    expect(classifyOverallRisk(0, 2, 0, 0)).toBe('high')
  })

  test('returns medium when no critical/high but mediumCount > 0', () => {
    expect(classifyOverallRisk(0, 0, 4, 0)).toBe('medium')
  })

  test('returns low when only lowCount > 0', () => {
    expect(classifyOverallRisk(0, 0, 0, 3)).toBe('low')
  })

  test('returns none when all counts are zero', () => {
    expect(classifyOverallRisk(0, 0, 0, 0)).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// computeAbandonmentReport
// ---------------------------------------------------------------------------

describe('computeAbandonmentReport', () => {
  test('returns clean report for empty component list', () => {
    const report = computeAbandonmentReport([])
    expect(report.overallRisk).toBe('none')
    expect(report.totalAbandoned).toBe(0)
    expect(report.findings).toHaveLength(0)
    expect(report.criticalCount).toBe(0)
    expect(report.highCount).toBe(0)
    expect(report.mediumCount).toBe(0)
    expect(report.lowCount).toBe(0)
  })

  test('returns clean report when no abandoned packages present', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
      { name: 'fastapi', version: '0.100.0', ecosystem: 'pypi' },
    ]
    const report = computeAbandonmentReport(components)
    expect(report.overallRisk).toBe('none')
    expect(report.totalAbandoned).toBe(0)
  })

  test('returns critical overall risk when event-stream is present', () => {
    const components = [
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' },
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
    ]
    const report = computeAbandonmentReport(components)
    expect(report.overallRisk).toBe('critical')
    expect(report.criticalCount).toBe(1)
    expect(report.totalAbandoned).toBe(1)
  })

  test('includes all risk levels in per-level counts', () => {
    const components = [
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' },   // critical
      { name: 'request', version: '2.88.2', ecosystem: 'npm' },       // high
      { name: 'tslint', version: '5.20.0', ecosystem: 'npm' },        // medium
      { name: 'node-uuid', version: '1.4.8', ecosystem: 'npm' },      // low
    ]
    const report = computeAbandonmentReport(components)
    expect(report.criticalCount).toBe(1)
    expect(report.highCount).toBe(1)
    expect(report.mediumCount).toBe(1)
    expect(report.lowCount).toBe(1)
    expect(report.totalAbandoned).toBe(4)
  })

  test('deduplicates repeated components', () => {
    const components = [
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' },
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' }, // duplicate
    ]
    const report = computeAbandonmentReport(components)
    expect(report.criticalCount).toBe(1)
    expect(report.findings).toHaveLength(1)
  })

  test('does not deduplicate same name but different version', () => {
    const components = [
      { name: 'mock', version: '1.0.1', ecosystem: 'pypi' },
      { name: 'mock', version: '2.0.0', ecosystem: 'pypi' },
    ]
    const report = computeAbandonmentReport(components)
    expect(report.findings).toHaveLength(2)
    expect(report.lowCount).toBe(2)
  })

  test('summary is non-empty string', () => {
    const report = computeAbandonmentReport([])
    expect(typeof report.summary).toBe('string')
    expect(report.summary.length).toBeGreaterThan(0)
  })

  test('summary mentions "No abandoned" when all packages are clean', () => {
    const report = computeAbandonmentReport([
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
    ])
    expect(report.summary).toContain('No abandoned')
  })

  test('summary lists supply-chain-compromised count when critical findings present', () => {
    const components = [
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' },
      { name: 'flatmap-stream', version: '0.1.1', ecosystem: 'npm' },
    ]
    const report = computeAbandonmentReport(components)
    expect(report.summary).toContain('supply-chain-compromised')
    expect(report.criticalCount).toBe(2)
  })

  test('critical risk overrides lower risk levels', () => {
    const components = [
      { name: 'event-stream', version: '3.3.6', ecosystem: 'npm' },   // critical
      { name: 'tslint', version: '5.0.0', ecosystem: 'npm' },         // medium
    ]
    const report = computeAbandonmentReport(components)
    expect(report.overallRisk).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// ABANDONED_DATABASE integrity
// ---------------------------------------------------------------------------

describe('ABANDONED_DATABASE integrity', () => {
  test('all records have non-empty ecosystem and name', () => {
    for (const entry of ABANDONED_DATABASE) {
      expect(entry.ecosystem).toBeTruthy()
      expect(entry.name).toBeTruthy()
    }
  })

  test('all riskLevel values are valid', () => {
    const VALID_LEVELS = new Set(['critical', 'high', 'medium', 'low'])
    for (const entry of ABANDONED_DATABASE) {
      expect(VALID_LEVELS.has(entry.riskLevel)).toBe(true)
    }
  })

  test('all reason values are valid', () => {
    const VALID_REASONS = new Set([
      'supply_chain_compromised',
      'officially_deprecated',
      'archived',
      'superseded',
      'unmaintained',
    ])
    for (const entry of ABANDONED_DATABASE) {
      expect(VALID_REASONS.has(entry.reason)).toBe(true)
    }
  })

  test('abandonedSince dates match YYYY-MM-DD format when present', () => {
    const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/
    for (const entry of ABANDONED_DATABASE) {
      if (entry.abandonedSince !== null) {
        expect(entry.abandonedSince).toMatch(ISO_DATE)
      }
    }
  })

  test('all notes are non-empty strings', () => {
    for (const entry of ABANDONED_DATABASE) {
      expect(typeof entry.notes).toBe('string')
      expect(entry.notes.length).toBeGreaterThan(0)
    }
  })
})
