/// <reference types="vite/client" />
// WS-41 — Dependency Confusion Attack Detector: unit tests.

import { describe, expect, test } from 'vitest'
import {
  EXTREME_VERSION_THRESHOLD,
  HIGH_VERSION_THRESHOLD,
  INTERNAL_NAME_PATTERNS,
  KNOWN_PUBLIC_NPM_SCOPES,
  MEDIUM_VERSION_THRESHOLD,
  checkConfusionAttack,
  computeConfusionReport,
  isKnownPublicNpmScope,
  looksLikeInternalPackage,
  parseMajorVersion,
  parseNpmScope,
} from './confusionAttackDetection'

// ---------------------------------------------------------------------------
// parseNpmScope
// ---------------------------------------------------------------------------

describe('parseNpmScope', () => {
  test('extracts scope from scoped package name', () => {
    expect(parseNpmScope('@babel/core')).toBe('@babel')
  })

  test('extracts scope case-insensitively (preserves original casing)', () => {
    // scope is sliced as-is; isKnownPublicNpmScope handles lowercasing
    expect(parseNpmScope('@Babel/core')).toBe('@babel')
  })

  test('returns null for unscoped package', () => {
    expect(parseNpmScope('express')).toBeNull()
  })

  test('returns null for bare @', () => {
    expect(parseNpmScope('@')).toBeNull()
  })

  test('returns null for @/ edge case', () => {
    expect(parseNpmScope('@/bare')).toBeNull()
  })

  test('handles nested scope correctly', () => {
    expect(parseNpmScope('@aws-sdk/client-s3')).toBe('@aws-sdk')
  })
})

// ---------------------------------------------------------------------------
// isKnownPublicNpmScope
// ---------------------------------------------------------------------------

describe('isKnownPublicNpmScope', () => {
  test('returns true for a core known scope', () => {
    expect(isKnownPublicNpmScope('@babel')).toBe(true)
  })

  test('returns true for @types', () => {
    expect(isKnownPublicNpmScope('@types')).toBe(true)
  })

  test('returns true for @aws-sdk', () => {
    expect(isKnownPublicNpmScope('@aws-sdk')).toBe(true)
  })

  test('is case-insensitive', () => {
    expect(isKnownPublicNpmScope('@BABEL')).toBe(true)
    expect(isKnownPublicNpmScope('@Babel')).toBe(true)
  })

  test('returns false for an unknown scope', () => {
    expect(isKnownPublicNpmScope('@my-internal-company')).toBe(false)
  })

  test('returns false for a fabricated scope that resembles a known one', () => {
    expect(isKnownPublicNpmScope('@babel-evil')).toBe(false)
    expect(isKnownPublicNpmScope('@jestjs')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// parseMajorVersion
// ---------------------------------------------------------------------------

describe('parseMajorVersion', () => {
  test('parses a standard semver string', () => {
    expect(parseMajorVersion('4.18.0')).toBe(4)
  })

  test('parses a v-prefixed version string', () => {
    expect(parseMajorVersion('v1.2.3')).toBe(1)
  })

  test('parses a partial version (major only)', () => {
    expect(parseMajorVersion('9999')).toBe(9999)
  })

  test('parses a two-part version (major.minor)', () => {
    expect(parseMajorVersion('18.2')).toBe(18)
  })

  test('returns null for non-numeric version strings', () => {
    expect(parseMajorVersion('latest')).toBeNull()
    expect(parseMajorVersion('*')).toBeNull()
    expect(parseMajorVersion('')).toBeNull()
  })

  test('trims surrounding whitespace before parsing', () => {
    expect(parseMajorVersion('  3.0.0  ')).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// looksLikeInternalPackage
// ---------------------------------------------------------------------------

describe('looksLikeInternalPackage', () => {
  test('matches prefix pattern "internal-"', () => {
    expect(looksLikeInternalPackage('internal-api-client')).toBe(true)
  })

  test('matches suffix pattern "-internal"', () => {
    expect(looksLikeInternalPackage('auth-service-internal')).toBe(true)
  })

  test('matches prefix pattern "corp-"', () => {
    expect(looksLikeInternalPackage('corp-utils')).toBe(true)
  })

  test('matches prefix within scoped package (bare name after /)', () => {
    expect(looksLikeInternalPackage('@acme/internal-payments')).toBe(true)
  })

  test('returns false for a normal public package name', () => {
    expect(looksLikeInternalPackage('express')).toBe(false)
    expect(looksLikeInternalPackage('@babel/core')).toBe(false)
  })

  test('matches case-insensitively', () => {
    expect(looksLikeInternalPackage('INTERNAL-tool')).toBe(true)
    expect(looksLikeInternalPackage('auth-PRIVATE')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// checkConfusionAttack
// ---------------------------------------------------------------------------

describe('checkConfusionAttack', () => {
  // ── No signal ──────────────────────────────────────────────────────────────

  test('returns null for a normal public package at normal version', () => {
    expect(checkConfusionAttack({ name: 'express', version: '4.18.0', ecosystem: 'npm' })).toBeNull()
  })

  test('returns null when version is unparseable', () => {
    expect(checkConfusionAttack({ name: 'express', version: 'latest', ecosystem: 'npm' })).toBeNull()
  })

  // ── Signal: extreme_version ─────────────────────────────────────────────

  test('fires extreme_version signal at EXTREME_VERSION_THRESHOLD', () => {
    const finding = checkConfusionAttack({
      name: 'lodash',
      version: `${EXTREME_VERSION_THRESHOLD}.0.0`,
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('extreme_version')
    expect(finding!.riskLevel).toBe('critical')
  })

  test('fires extreme_version signal in non-npm ecosystems too', () => {
    const finding = checkConfusionAttack({
      name: 'requests',
      version: '9999.0.0',
      ecosystem: 'pypi',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('extreme_version')
    expect(finding!.riskLevel).toBe('critical')
  })

  test('does NOT fire extreme_version just below threshold', () => {
    const finding = checkConfusionAttack({
      name: 'lodash',
      version: `${EXTREME_VERSION_THRESHOLD - 1}.0.0`,
      ecosystem: 'npm',
    })
    // May still fire other signals if version ≥ HIGH_VERSION_THRESHOLD,
    // but extreme_version should not be in the list
    if (finding) {
      expect(finding.signals).not.toContain('extreme_version')
    }
  })

  // ── Signal: high_version_unknown_scope ──────────────────────────────────

  test('fires high_version_unknown_scope for unknown npm scope at high version', () => {
    const finding = checkConfusionAttack({
      name: '@acme-corp/payments',
      version: `${HIGH_VERSION_THRESHOLD}.0.0`,
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('high_version_unknown_scope')
  })

  test('does NOT fire high_version_unknown_scope for a known public scope', () => {
    const finding = checkConfusionAttack({
      name: '@babel/core',
      version: '999.0.0',
      ecosystem: 'npm',
    })
    // Should not fire scoped signal (may fire extreme_version though)
    if (finding) {
      expect(finding.signals).not.toContain('high_version_unknown_scope')
    }
  })

  test('does NOT fire high_version_unknown_scope in non-npm ecosystem', () => {
    const finding = checkConfusionAttack({
      name: '@acme/tool',
      version: '500.0.0',
      ecosystem: 'pypi',
    })
    if (finding) {
      expect(finding.signals).not.toContain('high_version_unknown_scope')
    }
  })

  // ── Signal: high_version_internal_name ──────────────────────────────────

  test('fires high_version_internal_name for internal-pattern name at medium version', () => {
    const finding = checkConfusionAttack({
      name: 'internal-auth',
      version: `${MEDIUM_VERSION_THRESHOLD}.0.0`,
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('high_version_internal_name')
  })

  test('fires high_version_internal_name across ecosystems', () => {
    const finding = checkConfusionAttack({
      name: 'corp-billing',
      version: '75.0.0',
      ecosystem: 'maven',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('high_version_internal_name')
  })

  test('does NOT fire high_version_internal_name just below MEDIUM threshold', () => {
    const finding = checkConfusionAttack({
      name: 'internal-auth',
      version: `${MEDIUM_VERSION_THRESHOLD - 1}.0.0`,
      ecosystem: 'npm',
    })
    if (finding) {
      expect(finding.signals).not.toContain('high_version_internal_name')
    }
  })

  // ── Risk level classification ─────────────────────────────────────────────

  test('classifies high_version_unknown_scope at ≥500 as high risk', () => {
    const finding = checkConfusionAttack({
      name: '@acme-corp/payments',
      version: '500.0.0',
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.riskLevel).toBe('high')
  })

  test('classifies high_version_unknown_scope below 500 as medium risk', () => {
    const finding = checkConfusionAttack({
      name: '@acme-corp/payments',
      version: '150.0.0',
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.riskLevel).toBe('medium')
  })

  test('classifies high_version_internal_name at ≥HIGH_VERSION_THRESHOLD as high risk', () => {
    const finding = checkConfusionAttack({
      name: 'internal-billing',
      version: `${HIGH_VERSION_THRESHOLD}.0.0`,
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.riskLevel).toBe('high')
  })

  // ── Output shape ──────────────────────────────────────────────────────────

  test('finding includes packageName, ecosystem, version, evidence', () => {
    const finding = checkConfusionAttack({
      name: 'internal-api',
      version: '99.0.0',
      ecosystem: 'npm',
    })
    expect(finding).not.toBeNull()
    expect(finding!.packageName).toBe('internal-api')
    expect(finding!.ecosystem).toBe('npm')
    expect(finding!.version).toBe('99.0.0')
    expect(finding!.evidence).toContain('package=internal-api')
    expect(finding!.evidence).toContain('version=99.0.0')
    expect(finding!.title).toBeTruthy()
    expect(finding!.description).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// computeConfusionReport
// ---------------------------------------------------------------------------

describe('computeConfusionReport', () => {
  test('returns none overall risk and zero counts for a clean list', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ]
    const report = computeConfusionReport(components)
    expect(report.overallRisk).toBe('none')
    expect(report.totalSuspicious).toBe(0)
    expect(report.findings).toHaveLength(0)
    expect(report.criticalCount).toBe(0)
    expect(report.highCount).toBe(0)
    expect(report.mediumCount).toBe(0)
  })

  test('counts critical findings correctly', () => {
    const components = [
      { name: 'innocent', version: '1.0.0', ecosystem: 'npm' },
      { name: 'evil-package', version: '9999.0.1', ecosystem: 'npm' },
    ]
    const report = computeConfusionReport(components)
    expect(report.criticalCount).toBe(1)
    expect(report.overallRisk).toBe('critical')
  })

  test('deduplicates identical components before scanning', () => {
    const components = [
      { name: 'internal-auth', version: '99.0.0', ecosystem: 'npm' },
      { name: 'internal-auth', version: '99.0.0', ecosystem: 'npm' }, // duplicate
    ]
    const report = computeConfusionReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('deduplicated count does not include duplicates (case-insensitive)', () => {
    const components = [
      { name: 'Internal-Auth', version: '99.0.0', ecosystem: 'NPM' },
      { name: 'internal-auth', version: '99.0.0', ecosystem: 'npm' },
    ]
    const report = computeConfusionReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('overallRisk escalates to highest severity present', () => {
    const components = [
      { name: '@acme/payments', version: '200.0.0', ecosystem: 'npm' }, // medium
      { name: 'malicious', version: '9000.0.0', ecosystem: 'npm' },     // critical
    ]
    const report = computeConfusionReport(components)
    expect(report.overallRisk).toBe('critical')
  })

  test('overallRisk is high when only high findings present', () => {
    const components = [
      { name: '@acme/payments', version: '500.0.0', ecosystem: 'npm' }, // high
    ]
    const report = computeConfusionReport(components)
    expect(report.overallRisk).toBe('high')
  })

  test('summary string mentions count of findings', () => {
    const components = [
      { name: 'internal-auth', version: '9999.0.0', ecosystem: 'npm' },
    ]
    const report = computeConfusionReport(components)
    expect(report.summary).toMatch(/1 package/)
  })

  test('summary is "No dependency confusion indicators detected." for clean list', () => {
    const report = computeConfusionReport([])
    expect(report.summary).toBe('No dependency confusion indicators detected.')
  })

  test('handles empty component list gracefully', () => {
    const report = computeConfusionReport([])
    expect(report.findings).toHaveLength(0)
    expect(report.overallRisk).toBe('none')
    expect(report.totalSuspicious).toBe(0)
  })

  test('multiple distinct findings are all included in findings array', () => {
    const components = [
      { name: 'internal-auth', version: '9999.0.0', ecosystem: 'npm' },
      { name: '@evil-corp/tool', version: '500.0.0', ecosystem: 'npm' },
      { name: 'corp-billing', version: '75.0.0', ecosystem: 'pypi' },
    ]
    const report = computeConfusionReport(components)
    expect(report.findings.length).toBeGreaterThanOrEqual(3)
    expect(report.criticalCount).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// Constants / configuration integrity
// ---------------------------------------------------------------------------

describe('configuration constants', () => {
  test('EXTREME_VERSION_THRESHOLD is >= 9000', () => {
    expect(EXTREME_VERSION_THRESHOLD).toBeGreaterThanOrEqual(9000)
  })

  test('HIGH_VERSION_THRESHOLD is less than EXTREME_VERSION_THRESHOLD', () => {
    expect(HIGH_VERSION_THRESHOLD).toBeLessThan(EXTREME_VERSION_THRESHOLD)
  })

  test('MEDIUM_VERSION_THRESHOLD is less than HIGH_VERSION_THRESHOLD', () => {
    expect(MEDIUM_VERSION_THRESHOLD).toBeLessThan(HIGH_VERSION_THRESHOLD)
  })

  test('KNOWN_PUBLIC_NPM_SCOPES contains at least the most common ecosystem scopes', () => {
    const required = ['@babel', '@types', '@jest', '@aws-sdk', '@mui', '@angular', '@vue']
    for (const scope of required) {
      expect(KNOWN_PUBLIC_NPM_SCOPES.has(scope), `missing scope ${scope}`).toBe(true)
    }
  })

  test('INTERNAL_NAME_PATTERNS is a non-empty array of RegExp objects', () => {
    expect(Array.isArray(INTERNAL_NAME_PATTERNS)).toBe(true)
    expect(INTERNAL_NAME_PATTERNS.length).toBeGreaterThan(0)
    for (const re of INTERNAL_NAME_PATTERNS) {
      expect(re).toBeInstanceOf(RegExp)
    }
  })
})
