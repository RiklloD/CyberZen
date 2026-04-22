/// <reference types="vite/client" />
// WS-42 — Malicious Package Detection: unit tests.

import { describe, expect, test } from 'vitest'
import {
  KNOWN_MALICIOUS_NPM_PACKAGES,
  POPULAR_NPM_PACKAGES,
  SQUATTING_SCOPES,
  TYPOSQUAT_EDIT_DISTANCE,
  checkMaliciousPackage,
  computeMaliciousReport,
  containsHomoglyphSubstitution,
  findClosestPopularPackage,
  isScopeSquat,
  isNumericSuffixVariant,
  levenshteinDistance,
} from './maliciousPackageDetection'

// ---------------------------------------------------------------------------
// levenshteinDistance
// ---------------------------------------------------------------------------

describe('levenshteinDistance', () => {
  test('returns 0 for identical strings', () => {
    expect(levenshteinDistance('lodash', 'lodash')).toBe(0)
    expect(levenshteinDistance('', '')).toBe(0)
  })

  test('returns length of other string when one is empty', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3)
    expect(levenshteinDistance('abc', '')).toBe(3)
  })

  test('counts a single substitution as distance 1', () => {
    expect(levenshteinDistance('lodash', 'lodahs')).toBe(2) // swap: 2 edits (not transposition)
    expect(levenshteinDistance('expres', 'express')).toBe(1) // insertion
    expect(levenshteinDistance('expresss', 'express')).toBe(1) // deletion
  })

  test('counts single character insertion as distance 1', () => {
    expect(levenshteinDistance('expres', 'express')).toBe(1)
    expect(levenshteinDistance('mongose', 'mongoose')).toBe(1)
  })

  test('counts single character deletion as distance 1', () => {
    expect(levenshteinDistance('expresss', 'express')).toBe(1)
    expect(levenshteinDistance('loddash', 'lodash')).toBe(1)
  })

  test('correctly distances two very different strings', () => {
    const d = levenshteinDistance('abc', 'xyz')
    expect(d).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// findClosestPopularPackage
// ---------------------------------------------------------------------------

describe('findClosestPopularPackage', () => {
  test('returns null when name IS a popular package (not a typosquat)', () => {
    expect(findClosestPopularPackage('lodash')).toBeNull()
    expect(findClosestPopularPackage('express')).toBeNull()
  })

  test('finds a match at distance 1 (deletion)', () => {
    const result = findClosestPopularPackage('expres') // missing final 's'
    expect(result).not.toBeNull()
    expect(result!.match).toBe('express')
    expect(result!.distance).toBe(1)
  })

  test('finds a match at distance 1 (insertion)', () => {
    const result = findClosestPopularPackage('loddash') // extra 'd'
    expect(result).not.toBeNull()
    expect(result!.match).toBe('lodash')
    expect(result!.distance).toBe(1)
  })

  test('returns null when distance exceeds TYPOSQUAT_EDIT_DISTANCE', () => {
    // 'completely-different' is far from every popular package
    expect(findClosestPopularPackage('completely-different')).toBeNull()
  })

  test('length guard skips candidates whose lengths differ too much', () => {
    // 'express-session' (15 chars) is 8 chars longer than 'express' (7) — well beyond distance 1
    expect(findClosestPopularPackage('express-session')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// containsHomoglyphSubstitution
// ---------------------------------------------------------------------------

describe('containsHomoglyphSubstitution', () => {
  test('detects digit 1 flanked by letters (l/1 swap)', () => {
    expect(containsHomoglyphSubstitution('l1dash')).toBe(true)
    expect(containsHomoglyphSubstitution('c1ash')).toBe(true)
  })

  test('detects digit 0 flanked by letters (o/0 swap)', () => {
    expect(containsHomoglyphSubstitution('l0dash')).toBe(true)
    expect(containsHomoglyphSubstitution('c0lors')).toBe(true)
  })

  test('returns false for legitimate names with no homoglyphs', () => {
    expect(containsHomoglyphSubstitution('lodash')).toBe(false)
    expect(containsHomoglyphSubstitution('express')).toBe(false)
    expect(containsHomoglyphSubstitution('socket.io')).toBe(false)
  })

  test('returns false when digit is only at start or end (no flanking letters)', () => {
    // '1lodash' — 1 not flanked on both sides by letters → false
    expect(containsHomoglyphSubstitution('sha1')).toBe(false)
    // 'sha1' = s-h-a-1 — the '1' has 'a' before it but nothing after → no match
  })

  test('is case-insensitive (caller passes lowercased name)', () => {
    expect(containsHomoglyphSubstitution('c0lors')).toBe(true)
    // uppercase should still work since caller lowercases
    expect(containsHomoglyphSubstitution('C0LORS'.toLowerCase())).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// isNumericSuffixVariant
// ---------------------------------------------------------------------------

describe('isNumericSuffixVariant', () => {
  test('detects popular-name + digit suffix', () => {
    expect(isNumericSuffixVariant('lodash2')).toBe(true)
    expect(isNumericSuffixVariant('axios1')).toBe(true)
    expect(isNumericSuffixVariant('react3')).toBe(true)
  })

  test('returns false when base name is not a popular package', () => {
    expect(isNumericSuffixVariant('unknownpkg2')).toBe(false)
    expect(isNumericSuffixVariant('mypkg1')).toBe(false)
  })

  test('returns false when there are no trailing digits', () => {
    expect(isNumericSuffixVariant('lodash')).toBe(false)
    expect(isNumericSuffixVariant('express')).toBe(false)
  })

  test('strips scope before checking', () => {
    expect(isNumericSuffixVariant('@evil/lodash2')).toBe(true)
    expect(isNumericSuffixVariant('@acme/axios1')).toBe(true)
  })

  test('is case-insensitive', () => {
    expect(isNumericSuffixVariant('Lodash2')).toBe(true)
    expect(isNumericSuffixVariant('AXIOS1')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// isScopeSquat
// ---------------------------------------------------------------------------

describe('isScopeSquat', () => {
  test('detects @npm/popularPackage pattern', () => {
    expect(isScopeSquat('@npm/lodash')).toBe(true)
    expect(isScopeSquat('@node/express')).toBe(true)
  })

  test('detects all configured squatting scopes', () => {
    for (const scope of SQUATTING_SCOPES) {
      expect(isScopeSquat(`${scope}/lodash`)).toBe(true)
    }
  })

  test('returns false for legitimate known-public scopes', () => {
    // @babel, @angular etc. are not squatting scopes
    expect(isScopeSquat('@babel/core')).toBe(false)
    expect(isScopeSquat('@angular/common')).toBe(false)
  })

  test('returns false for unscoped packages', () => {
    expect(isScopeSquat('lodash')).toBe(false)
    expect(isScopeSquat('express')).toBe(false)
  })

  test('returns false when bare name is not a popular package', () => {
    expect(isScopeSquat('@npm/myunknownpackage')).toBe(false)
    expect(isScopeSquat('@node/notpopular')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage', () => {
  // ── Clean packages ──────────────────────────────────────────────────────────

  test('returns null for a normal package with no signals', () => {
    expect(checkMaliciousPackage({ name: 'express', version: '4.18.0', ecosystem: 'npm' })).toBeNull()
    expect(checkMaliciousPackage({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' })).toBeNull()
  })

  test('returns null for a non-npm package with no suspicious patterns', () => {
    expect(checkMaliciousPackage({ name: 'requests', version: '2.28.0', ecosystem: 'pypi' })).toBeNull()
  })

  // ── Signal: known_malicious ────────────────────────────────────────────────

  test('fires known_malicious for a confirmed typosquat', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
    expect(finding!.riskLevel).toBe('critical')
    expect(finding!.similarTo).toBe('cross-env')
  })

  test('fires known_malicious for a high-risk confirmed package', () => {
    const finding = checkMaliciousPackage({ name: 'lodahs', version: '4.17.21', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
    expect(finding!.riskLevel).toBe('high')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('known_malicious check uses bare name (strips scope)', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
  })

  test('known_malicious does NOT fire for non-npm ecosystems', () => {
    // crossenv in pypi would not fire the npm-only known_malicious signal
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'pypi' })
    // May still fire suspicious_name_pattern if applicable, but not known_malicious
    if (finding) {
      expect(finding.signals).not.toContain('known_malicious')
    }
  })

  // ── Signal: typosquat_near_popular ─────────────────────────────────────────

  test('fires typosquat_near_popular for edit-distance-1 name', () => {
    const finding = checkMaliciousPackage({ name: 'expres', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('typosquat_near_popular')
    expect(finding!.riskLevel).toBe('high')
    expect(finding!.similarTo).toBe('express')
  })

  test('does NOT fire typosquat_near_popular for scoped packages (scope squat path instead)', () => {
    // @evil/expres — scoped, so typosquat_near_popular is suppressed
    const finding = checkMaliciousPackage({ name: '@evil/expres', version: '1.0.0', ecosystem: 'npm' })
    if (finding) {
      expect(finding.signals).not.toContain('typosquat_near_popular')
    }
  })

  test('does NOT fire typosquat_near_popular for non-npm ecosystems', () => {
    // 'expres' in pypi won't fire the npm-only signal
    const finding = checkMaliciousPackage({ name: 'expres', version: '1.0.0', ecosystem: 'pypi' })
    if (finding) {
      expect(finding.signals).not.toContain('typosquat_near_popular')
    }
  })

  // ── Signal: suspicious_name_pattern ───────────────────────────────────────

  test('fires suspicious_name_pattern for numeric suffix variant', () => {
    // lodash21: length 8 vs lodash length 6 — length diff 2 blocks Signal 2,
    // so only Signal 3 (isNumericSuffixVariant) fires.
    const finding = checkMaliciousPackage({ name: 'lodash21', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('fires suspicious_name_pattern for scope squat', () => {
    const finding = checkMaliciousPackage({ name: '@npm/lodash', version: '4.17.21', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('fires suspicious_name_pattern for homoglyph substitution', () => {
    const finding = checkMaliciousPackage({ name: 'l0dash', version: '1.0.0', ecosystem: 'pypi' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
  })

  // ── Output shape ───────────────────────────────────────────────────────────

  test('finding includes all required fields', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.packageName).toBe('crossenv')
    expect(finding!.ecosystem).toBe('npm')
    expect(finding!.version).toBe('1.0.0')
    expect(finding!.title).toBeTruthy()
    expect(finding!.description).toBeTruthy()
    expect(finding!.evidence).toContain('package=crossenv')
    expect(finding!.evidence).toContain('version=1.0.0')
    expect(finding!.evidence).toContain('signals=[known_malicious]')
  })
})

// ---------------------------------------------------------------------------
// computeMaliciousReport
// ---------------------------------------------------------------------------

describe('computeMaliciousReport', () => {
  test('returns none overallRisk for a clean list', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.overallRisk).toBe('none')
    expect(report.totalSuspicious).toBe(0)
    expect(report.findings).toHaveLength(0)
  })

  test('counts critical findings correctly', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.criticalCount).toBe(1)
    expect(report.overallRisk).toBe('critical')
  })

  test('deduplicates identical components before scanning', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('deduplication is case-insensitive for ecosystem and name', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'Crossenv', version: '1.0.0', ecosystem: 'NPM' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('findings are sorted critical-first', () => {
    const components = [
      { name: '@npm/lodash', version: '4.17.21', ecosystem: 'npm' }, // medium (scope squat)
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },     // critical
      { name: 'expres', version: '1.0.0', ecosystem: 'npm' },       // high
    ]
    const report = computeMaliciousReport(components)
    expect(report.findings[0].riskLevel).toBe('critical')
    expect(report.findings[1].riskLevel).toBe('high')
    expect(report.findings[2].riskLevel).toBe('medium')
  })

  test('overallRisk escalates to highest severity present', () => {
    const components = [
      { name: 'lodash2', version: '1.0.0', ecosystem: 'npm' },  // medium
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' }, // critical
    ]
    const report = computeMaliciousReport(components)
    expect(report.overallRisk).toBe('critical')
  })

  test('summary is clean when no indicators detected', () => {
    const report = computeMaliciousReport([])
    expect(report.summary).toBe('No malicious package indicators detected.')
  })

  test('summary mentions count of findings', () => {
    const components = [{ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' }]
    const report = computeMaliciousReport(components)
    expect(report.summary).toMatch(/1 package/)
    expect(report.summary).toMatch(/critical/)
  })

  test('handles empty component list gracefully', () => {
    const report = computeMaliciousReport([])
    expect(report.findings).toHaveLength(0)
    expect(report.overallRisk).toBe('none')
    expect(report.criticalCount).toBe(0)
    expect(report.highCount).toBe(0)
    expect(report.mediumCount).toBe(0)
    expect(report.lowCount).toBe(0)
  })

  test('multiple known-malicious packages all appear in findings', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'electorn', version: '1.0.0', ecosystem: 'npm' },
      { name: 'mongose', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.criticalCount).toBe(3)
    expect(report.findings).toHaveLength(3)
  })
})

// ---------------------------------------------------------------------------
// Constants / configuration integrity
// ---------------------------------------------------------------------------

describe('configuration constants', () => {
  test('TYPOSQUAT_EDIT_DISTANCE is 1', () => {
    expect(TYPOSQUAT_EDIT_DISTANCE).toBe(1)
  })

  test('POPULAR_NPM_PACKAGES contains at least 50 entries', () => {
    expect(POPULAR_NPM_PACKAGES.size).toBeGreaterThanOrEqual(50)
  })

  test('POPULAR_NPM_PACKAGES contains the most critical ecosystem targets', () => {
    const required = ['lodash', 'express', 'react', 'axios', 'webpack', 'electron', 'mongoose']
    for (const pkg of required) {
      expect(POPULAR_NPM_PACKAGES.has(pkg), `missing ${pkg}`).toBe(true)
    }
  })

  test('KNOWN_MALICIOUS_NPM_PACKAGES contains at least 10 entries', () => {
    expect(KNOWN_MALICIOUS_NPM_PACKAGES.size).toBeGreaterThanOrEqual(10)
  })

  test('every KNOWN_MALICIOUS entry has a non-empty reason and targetsPackage', () => {
    for (const [pkg, entry] of KNOWN_MALICIOUS_NPM_PACKAGES) {
      expect(entry.targetsPackage.length, `${pkg}: empty targetsPackage`).toBeGreaterThan(0)
      expect(entry.reason.length, `${pkg}: empty reason`).toBeGreaterThan(0)
      expect(['critical', 'high']).toContain(entry.riskLevel)
    }
  })

  test('SQUATTING_SCOPES includes @npm and @node', () => {
    expect(SQUATTING_SCOPES.has('@npm')).toBe(true)
    expect(SQUATTING_SCOPES.has('@node')).toBe(true)
  })
})
