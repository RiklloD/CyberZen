// WS-31 — Dependency License Compliance Engine: unit tests
/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  DEFAULT_COMMERCIAL_POLICY,
  assessComponentLicense,
  classifyLicense,
  computeLicenseCompliance,
  lookupStaticLicense,
  type LicensePolicy,
} from './licenseCompliance'

// ---------------------------------------------------------------------------
// classifyLicense
// ---------------------------------------------------------------------------

describe('classifyLicense', () => {
  it('classifies MIT as permissive', () => {
    expect(classifyLicense('MIT')).toBe('permissive')
  })

  it('classifies Apache-2.0 as permissive', () => {
    expect(classifyLicense('Apache-2.0')).toBe('permissive')
  })

  it('classifies BSD-3-Clause as permissive', () => {
    expect(classifyLicense('BSD-3-Clause')).toBe('permissive')
  })

  it('classifies ISC as permissive', () => {
    expect(classifyLicense('ISC')).toBe('permissive')
  })

  it('classifies LGPL-2.1 as weak_copyleft', () => {
    expect(classifyLicense('LGPL-2.1')).toBe('weak_copyleft')
  })

  it('classifies MPL-2.0 as weak_copyleft', () => {
    expect(classifyLicense('MPL-2.0')).toBe('weak_copyleft')
  })

  it('classifies GPL-2.0 as strong_copyleft', () => {
    expect(classifyLicense('GPL-2.0')).toBe('strong_copyleft')
  })

  it('classifies GPL-3.0-only as strong_copyleft', () => {
    expect(classifyLicense('GPL-3.0-only')).toBe('strong_copyleft')
  })

  it('classifies AGPL-3.0 as network_copyleft', () => {
    expect(classifyLicense('AGPL-3.0')).toBe('network_copyleft')
  })

  it('classifies SSPL-1.0 as network_copyleft', () => {
    expect(classifyLicense('SSPL-1.0')).toBe('network_copyleft')
  })

  it('classifies Proprietary as proprietary', () => {
    expect(classifyLicense('Proprietary')).toBe('proprietary')
  })

  it('classifies empty string as unknown', () => {
    expect(classifyLicense('')).toBe('unknown')
  })

  it('classifies unrecognised string as unknown', () => {
    expect(classifyLicense('ACME-Custom-License-1.0')).toBe('unknown')
  })

  it('handles SPDX OR expression — takes most permissive', () => {
    expect(classifyLicense('MIT OR Apache-2.0')).toBe('permissive')
  })

  it('handles mixed OR expression — takes most permissive side', () => {
    expect(classifyLicense('GPL-2.0 OR MIT')).toBe('permissive')
  })

  it('is case-insensitive', () => {
    expect(classifyLicense('mit')).toBe('permissive')
    expect(classifyLicense('agpl-3.0')).toBe('network_copyleft')
  })

  it('uses AGPL substring heuristic for non-SPDX strings', () => {
    expect(classifyLicense('GNU AFFERO GENERAL PUBLIC LICENSE')).toBe('network_copyleft')
  })

  it('uses GPL substring heuristic', () => {
    expect(classifyLicense('GNU General Public License v3')).toBe('strong_copyleft')
  })
})

// ---------------------------------------------------------------------------
// lookupStaticLicense
// ---------------------------------------------------------------------------

describe('lookupStaticLicense', () => {
  it('returns MIT for react (npm)', () => {
    expect(lookupStaticLicense('react', 'npm')).toBe('MIT')
  })

  it('returns BSD-3-Clause for django (pypi)', () => {
    expect(lookupStaticLicense('django', 'pypi')).toBe('BSD-3-Clause')
  })

  it('returns Apache-2.0 for boto3 (pypi)', () => {
    expect(lookupStaticLicense('boto3', 'pypi')).toBe('Apache-2.0')
  })

  it('returns MIT for serde (cargo)', () => {
    const result = lookupStaticLicense('serde', 'cargo')
    expect(result).toContain('MIT')
  })

  it('returns MIT for gin (go)', () => {
    expect(lookupStaticLicense('github.com/gin-gonic/gin', 'go')).toBe('MIT')
  })

  it('returns null for an unknown package', () => {
    expect(lookupStaticLicense('my-internal-package', 'npm')).toBeNull()
  })

  it('returns null for an unknown ecosystem', () => {
    expect(lookupStaticLicense('react', 'ruby')).toBeNull()
  })

  it('is case-insensitive for ecosystem name', () => {
    expect(lookupStaticLicense('react', 'NPM')).toBe('MIT')
  })
})

// ---------------------------------------------------------------------------
// assessComponentLicense
// ---------------------------------------------------------------------------

describe('assessComponentLicense', () => {
  it('uses static DB for well-known packages', () => {
    const result = assessComponentLicense({ name: 'react', ecosystem: 'npm' })
    expect(result.resolvedLicense).toBe('MIT')
    expect(result.source).toBe('static_db')
    expect(result.category).toBe('permissive')
    expect(result.outcome).toBe('allowed')
  })

  it('uses provided license when not in static DB', () => {
    const result = assessComponentLicense({
      name: 'my-lib',
      ecosystem: 'npm',
      knownLicense: 'MIT',
    })
    expect(result.source).toBe('provided')
    expect(result.category).toBe('permissive')
  })

  it('marks outcome as blocked for AGPL package', () => {
    const result = assessComponentLicense({
      name: 'agpl-lib',
      ecosystem: 'npm',
      knownLicense: 'AGPL-3.0',
    })
    expect(result.category).toBe('network_copyleft')
    expect(result.outcome).toBe('blocked')
  })

  it('marks outcome as warn for GPL package under commercial policy', () => {
    const result = assessComponentLicense({
      name: 'gpl-lib',
      ecosystem: 'npm',
      knownLicense: 'GPL-3.0',
    })
    expect(result.outcome).toBe('blocked')
  })

  it('marks outcome as warn for LGPL package', () => {
    const result = assessComponentLicense({
      name: 'lgpl-lib',
      ecosystem: 'npm',
      knownLicense: 'LGPL-2.1',
    })
    expect(result.outcome).toBe('warn')
  })

  it('marks outcome as warn for unknown license', () => {
    const result = assessComponentLicense({
      name: 'mystery-lib',
      ecosystem: 'npm',
    })
    expect(result.category).toBe('unknown')
    expect(result.outcome).toBe('warn')
    expect(result.source).toBe('unknown')
  })

  it('static DB takes precedence over provided license', () => {
    // react is MIT in DB; even if caller passes GPL it should use DB value
    const result = assessComponentLicense({
      name: 'react',
      ecosystem: 'npm',
      knownLicense: 'GPL-3.0',
    })
    expect(result.resolvedLicense).toBe('MIT')
    expect(result.source).toBe('static_db')
    expect(result.outcome).toBe('allowed')
  })

  it('respects a custom policy', () => {
    const strictPolicy: LicensePolicy = {
      ...DEFAULT_COMMERCIAL_POLICY,
      unknown: 'blocked',
    }
    const result = assessComponentLicense(
      { name: 'mystery-lib', ecosystem: 'npm' },
      strictPolicy,
    )
    expect(result.outcome).toBe('blocked')
  })
})

// ---------------------------------------------------------------------------
// computeLicenseCompliance
// ---------------------------------------------------------------------------

describe('computeLicenseCompliance', () => {
  it('returns fully compliant when all components are permissive', () => {
    const components = [
      { name: 'react', ecosystem: 'npm' },
      { name: 'express', ecosystem: 'npm' },
      { name: 'lodash', ecosystem: 'npm' },
    ]
    const result = computeLicenseCompliance(components)
    expect(result.overallLevel).toBe('compliant')
    expect(result.blockedCount).toBe(0)
    expect(result.warnCount).toBe(0)
    expect(result.complianceScore).toBe(100)
  })

  it('returns non_compliant when an AGPL component is present', () => {
    const components = [
      { name: 'react', ecosystem: 'npm' },
      { name: 'agpl-app', ecosystem: 'npm', knownLicense: 'AGPL-3.0' },
    ]
    const result = computeLicenseCompliance(components)
    expect(result.overallLevel).toBe('non_compliant')
    expect(result.blockedCount).toBe(1)
    expect(result.complianceScore).toBeLessThan(100)
  })

  it('returns caution when only warnings present', () => {
    const components = [
      { name: 'react', ecosystem: 'npm' },
      { name: 'psycopg2', ecosystem: 'pypi' }, // LGPL → warn
    ]
    const result = computeLicenseCompliance(components)
    expect(result.overallLevel).toBe('caution')
    expect(result.blockedCount).toBe(0)
    expect(result.warnCount).toBeGreaterThan(0)
  })

  it('score decreases 20 per blocked and 5 per warn', () => {
    const components = [
      { name: 'gpl-lib', ecosystem: 'npm', knownLicense: 'GPL-3.0' }, // blocked
      { name: 'lgpl-lib', ecosystem: 'npm', knownLicense: 'LGPL-2.1' }, // warn
    ]
    const result = computeLicenseCompliance(components)
    // 100 - 1×20 - 1×5 = 75
    expect(result.complianceScore).toBe(75)
  })

  it('score is floored at 0 for many violations', () => {
    const components = Array.from({ length: 10 }, (_, i) => ({
      name: `agpl-${i}`,
      ecosystem: 'npm',
      knownLicense: 'AGPL-3.0',
    }))
    const result = computeLicenseCompliance(components)
    expect(result.complianceScore).toBe(0)
  })

  it('handles empty component list gracefully', () => {
    const result = computeLicenseCompliance([])
    expect(result.overallLevel).toBe('compliant')
    expect(result.summary).toMatch(/no components/i)
    expect(result.complianceScore).toBe(100)
  })

  it('counts unknown licenses correctly', () => {
    const components = [
      { name: 'mystery-a', ecosystem: 'npm' },
      { name: 'mystery-b', ecosystem: 'npm' },
      { name: 'react', ecosystem: 'npm' },
    ]
    const result = computeLicenseCompliance(components)
    expect(result.unknownCount).toBe(2)
  })

  it('allowedCount only counts permissive outcomes', () => {
    const components = [
      { name: 'react', ecosystem: 'npm' }, // allowed
      { name: 'lgpl-lib', ecosystem: 'npm', knownLicense: 'LGPL-2.1' }, // warn
    ]
    const result = computeLicenseCompliance(components)
    expect(result.allowedCount).toBe(1)
  })

  it('summary mentions blocked count when violations exist', () => {
    const components = [
      { name: 'gpl-lib', ecosystem: 'npm', knownLicense: 'GPL-3.0' },
    ]
    const result = computeLicenseCompliance(components)
    expect(result.summary).toMatch(/blocked/i)
  })

  it('summary says fully compliant when all allowed', () => {
    const components = [
      { name: 'react', ecosystem: 'npm' },
    ]
    const result = computeLicenseCompliance(components)
    expect(result.summary).toMatch(/fully compliant/i)
  })
})
