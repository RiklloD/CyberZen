import { describe, expect, it } from 'vitest'
import { analyzeSupplyChain } from './supplyChainIntel'
import type { SupplyChainComponentInput } from './supplyChainIntel'

const base: SupplyChainComponentInput = {
  name: 'safe-package',
  version: '1.0.0',
  ecosystem: 'npm',
  layer: 'runtime',
  isDirect: true,
  trustScore: 80,
  hasKnownVulnerabilities: false,
  dependents: [],
}

describe('analyzeSupplyChain', () => {
  it('returns low risk for an empty component set', () => {
    const analysis = analyzeSupplyChain([])
    expect(analysis.overallRiskScore).toBe(0)
    expect(analysis.riskLevel).toBe('low')
    expect(analysis.flaggedComponents).toHaveLength(0)
    expect(analysis.summary).toContain('No components')
  })

  it('returns low risk for clean well-known packages', () => {
    const analysis = analyzeSupplyChain([
      { ...base, name: 'express' },
      { ...base, name: 'lodash', isDirect: false },
    ])
    expect(analysis.overallRiskScore).toBe(0)
    expect(analysis.flaggedComponents).toHaveLength(0)
    expect(analysis.summary).toContain('healthy')
  })

  // ── Typosquat detection ─────────────────────────────────────────────────

  it('detects a 1-edit typosquat of a well-known npm package', () => {
    // 'lodahs' → 'lodash': swap 's' and 'h' = 1 edit
    const analysis = analyzeSupplyChain([{ ...base, name: 'lodahs' }])
    expect(analysis.typosquatCandidates).toContain('lodahs')
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'typosquat_risk'),
    ).toBe(true)
  })

  it('detects a 2-edit typosquat of a well-known npm package', () => {
    // 'reqact' → 'react': 2 edits
    const analysis = analyzeSupplyChain([{ ...base, name: 'reqact' }])
    expect(analysis.typosquatCandidates).toContain('reqact')
  })

  it('does not flag exact matches as typosquats', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'react' }])
    expect(analysis.typosquatCandidates).not.toContain('react')
  })

  it('detects pypi typosquat', () => {
    // 'requsets' is 2 edits from 'requests'
    const analysis = analyzeSupplyChain([
      { ...base, name: 'requsets', ecosystem: 'pypi' },
    ])
    expect(analysis.typosquatCandidates).toContain('requsets')
  })

  // ── Suspicious names ────────────────────────────────────────────────────

  it('flags a single-character package name', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'x' }])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'suspicious_name'),
    ).toBe(true)
  })

  it('flags a two-character package name', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'ab' }])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'suspicious_name'),
    ).toBe(true)
  })

  it('flags a random hex-string package name', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'a1b2c3d4e5f6' }])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'suspicious_name'),
    ).toBe(true)
  })

  // ── Vulnerable direct dep ───────────────────────────────────────────────

  it('flags a direct dependency with known vulnerabilities', () => {
    const analysis = analyzeSupplyChain([
      { ...base, name: 'vulnerable-lib', hasKnownVulnerabilities: true },
    ])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'vulnerable_direct'),
    ).toBe(true)
    expect(analysis.flaggedComponents[0].riskScore).toBeGreaterThanOrEqual(35)
  })

  it('does not add vulnerable_direct for transitive vulnerable deps', () => {
    // Transitive vulnerabilities are already accounted for in trustScore;
    // the supply-chain signal only flags direct deps to avoid false positives.
    const analysis = analyzeSupplyChain([
      {
        ...base,
        name: 'transitive-vuln',
        isDirect: false,
        hasKnownVulnerabilities: true,
      },
    ])
    const signal = analysis.flaggedComponents.find((c) => c.name === 'transitive-vuln')
    expect(signal?.signals.some((s) => s.kind === 'vulnerable_direct')).toBeFalsy()
  })

  // ── Untrusted direct dep ────────────────────────────────────────────────

  it('flags a direct dependency with trust score below 40', () => {
    const analysis = analyzeSupplyChain([
      { ...base, name: 'untrusted-pkg', trustScore: 25 },
    ])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'untrusted_direct_dep'),
    ).toBe(true)
  })

  it('does not flag a trusted direct dependency', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'trusted-pkg', trustScore: 90 }])
    expect(analysis.flaggedComponents).toHaveLength(0)
  })

  // ── High blast radius ───────────────────────────────────────────────────

  it('flags components with 5 or more dependents', () => {
    const analysis = analyzeSupplyChain([
      {
        ...base,
        name: 'shared-core',
        dependents: ['svc-a', 'svc-b', 'svc-c', 'svc-d', 'svc-e'],
      },
    ])
    expect(
      analysis.flaggedComponents[0].signals.some((s) => s.kind === 'high_blast_radius'),
    ).toBe(true)
  })

  it('does not flag components with fewer than 5 dependents', () => {
    const analysis = analyzeSupplyChain([
      { ...base, name: 'small-dep', dependents: ['svc-a', 'svc-b'] },
    ])
    expect(analysis.flaggedComponents).toHaveLength(0)
  })

  // ── Chain depth ─────────────────────────────────────────────────────────

  it('reports higher chain depth when transitive:direct ratio is large', () => {
    const components: SupplyChainComponentInput[] = [
      { ...base, name: 'direct-dep', isDirect: true },
      ...Array.from({ length: 25 }, (_, i) => ({
        ...base,
        name: `transitive-${i}`,
        isDirect: false,
      })),
    ]
    const analysis = analyzeSupplyChain(components)
    expect(analysis.deepChainDepth).toBeGreaterThanOrEqual(4)
  })

  // ── Overall risk score ──────────────────────────────────────────────────

  it('overall risk score is 0 when no components are flagged', () => {
    const analysis = analyzeSupplyChain([{ ...base, name: 'express' }])
    expect(analysis.overallRiskScore).toBe(0)
  })

  it('overall risk score reflects flagged component proportion', () => {
    // 1 flagged out of 10 should give a lower score than 5 flagged out of 10
    const clean = Array.from({ length: 9 }, (_, i) => ({
      ...base,
      name: `safe-pkg-${i}`,
    }))

    const oneRisky = analyzeSupplyChain([
      ...clean,
      { ...base, name: 'lodahs' }, // typosquat of lodash
    ])
    const fiveRisky = analyzeSupplyChain([
      ...clean.slice(0, 5),
      { ...base, name: 'lodahs' },
      { ...base, name: 'expres' },
      { ...base, name: 'ax' },     // short name
      { ...base, name: 'vuln-a', hasKnownVulnerabilities: true },
      { ...base, name: 'vuln-b', trustScore: 15 },
    ])

    expect(fiveRisky.overallRiskScore).toBeGreaterThan(oneRisky.overallRiskScore)
  })
})
