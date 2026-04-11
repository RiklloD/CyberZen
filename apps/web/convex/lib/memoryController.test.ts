import { describe, expect, it } from 'vitest'
import {
  aggregateFindingMemory,
  type FindingMemoryInput,
} from './memoryController'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const base: FindingMemoryInput = {
  vulnClass: 'sql_injection',
  severity: 'high',
  source: 'semantic_fingerprint',
  status: 'open',
  validationStatus: 'pending',
  affectedPackages: ['sqlalchemy'],
  confidence: 0.9,
  businessImpactScore: 50,
}

// ---------------------------------------------------------------------------
// Empty-findings case
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — empty findings', () => {
  it('returns an all-zero record with a no-findings summary', () => {
    const result = aggregateFindingMemory({ findings: [] })
    expect(result.totalFindingsAnalyzed).toBe(0)
    expect(result.recurringVulnClasses).toHaveLength(0)
    expect(result.falsePositiveRate).toBe(0)
    expect(result.highConfidenceClasses).toHaveLength(0)
    expect(result.packageRiskMap).toEqual({})
    expect(result.dominantSeverity).toBe('low')
    expect(result.resolvedCount).toBe(0)
    expect(result.openCount).toBe(0)
    expect(result.summary).toContain('No findings recorded')
  })
})

// ---------------------------------------------------------------------------
// Single-class recurring case
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — single recurring class', () => {
  const findings: FindingMemoryInput[] = [
    { ...base, vulnClass: 'sql_injection', severity: 'critical' },
    { ...base, vulnClass: 'sql_injection', severity: 'high' },
    { ...base, vulnClass: 'sql_injection', severity: 'medium' },
    { ...base, vulnClass: 'xss', severity: 'low' },
  ]

  it('ranks recurring classes by count descending', () => {
    const result = aggregateFindingMemory({ findings })
    expect(result.recurringVulnClasses[0].vulnClass).toBe('sql_injection')
    expect(result.recurringVulnClasses[0].count).toBe(3)
    expect(result.recurringVulnClasses[1].vulnClass).toBe('xss')
    expect(result.recurringVulnClasses[1].count).toBe(1)
  })

  it('computes avgSeverityWeight correctly for mixed severities', () => {
    const result = aggregateFindingMemory({ findings })
    const sqlClass = result.recurringVulnClasses[0]
    // (critical=1.0 + high=0.75 + medium=0.5) / 3 ≈ 0.75
    expect(sqlClass.avgSeverityWeight).toBeCloseTo(0.75, 5)
  })

  it('sets totalFindingsAnalyzed correctly', () => {
    const result = aggregateFindingMemory({ findings })
    expect(result.totalFindingsAnalyzed).toBe(4)
  })

  it('includes the top class in the summary', () => {
    const result = aggregateFindingMemory({ findings })
    expect(result.summary).toContain('sql injection')
    expect(result.summary).toContain('3')
  })
})

// ---------------------------------------------------------------------------
// False-positive-heavy case
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — false positive heavy', () => {
  const findings: FindingMemoryInput[] = [
    { ...base, validationStatus: 'unexploitable' },
    { ...base, validationStatus: 'unexploitable' },
    { ...base, validationStatus: 'unexploitable' },
    { ...base, validationStatus: 'validated' },
  ]

  it('computes falsePositiveRate as fraction of unexploitable findings', () => {
    const result = aggregateFindingMemory({ findings })
    // 3 of 4 are unexploitable → 0.75
    expect(result.falsePositiveRate).toBeCloseTo(0.75, 5)
  })

  it('reports 0 false positives when none are unexploitable', () => {
    const clean = [
      { ...base, validationStatus: 'validated' },
      { ...base, validationStatus: 'likely_exploitable' },
    ]
    const result = aggregateFindingMemory({ findings: clean })
    expect(result.falsePositiveRate).toBe(0)
  })

  it('includes false positive rate in the summary', () => {
    const result = aggregateFindingMemory({ findings })
    expect(result.summary).toContain('75%')
  })
})

// ---------------------------------------------------------------------------
// High-confidence classes
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — high confidence classes', () => {
  it('includes a class where mean confidence > 0.8', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, vulnClass: 'rce', confidence: 0.95 },
      { ...base, vulnClass: 'rce', confidence: 0.9 },
      { ...base, vulnClass: 'ssrf', confidence: 0.6 },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(result.highConfidenceClasses).toContain('rce')
    expect(result.highConfidenceClasses).not.toContain('ssrf')
  })

  it('does not include a class at exactly 0.8', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, vulnClass: 'border_case', confidence: 0.8 },
    ]
    const result = aggregateFindingMemory({ findings })
    // 0.8 is NOT > 0.8
    expect(result.highConfidenceClasses).not.toContain('border_case')
  })
})

// ---------------------------------------------------------------------------
// Multi-package risk map case
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — package risk map', () => {
  it('computes mean businessImpactScore per package', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, affectedPackages: ['flask'], businessImpactScore: 80 },
      { ...base, affectedPackages: ['flask'], businessImpactScore: 60 },
      { ...base, affectedPackages: ['requests'], businessImpactScore: 40 },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(result.packageRiskMap['flask']).toBe(70)     // (80+60)/2
    expect(result.packageRiskMap['requests']).toBe(40)
  })

  it('normalizes package names to lowercase', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, affectedPackages: ['Flask', 'FLASK'], businessImpactScore: 50 },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(result.packageRiskMap['flask']).toBe(50)
  })

  it('handles scoped npm packages by stripping the leading @', () => {
    const findings: FindingMemoryInput[] = [
      {
        ...base,
        affectedPackages: ['@angular/core'],
        businessImpactScore: 60,
      },
    ]
    const result = aggregateFindingMemory({ findings })
    // '@angular/core' → 'angular_core'
    expect(result.packageRiskMap['angular_core']).toBe(60)
  })

  it('skips empty package names', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, affectedPackages: ['', '  '], businessImpactScore: 50 },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(Object.keys(result.packageRiskMap)).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Status counts
// ---------------------------------------------------------------------------

describe('aggregateFindingMemory — status counts', () => {
  it('counts resolved and merged as resolvedCount', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, status: 'resolved' },
      { ...base, status: 'merged' },
      { ...base, status: 'open' },
      { ...base, status: 'pr_opened' },
      { ...base, status: 'accepted_risk' },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(result.resolvedCount).toBe(2)
    expect(result.openCount).toBe(2)
  })

  it('identifies dominant severity correctly', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, severity: 'critical' },
      { ...base, severity: 'critical' },
      { ...base, severity: 'high' },
      { ...base, severity: 'medium' },
    ]
    const result = aggregateFindingMemory({ findings })
    expect(result.dominantSeverity).toBe('critical')
  })

  it('falls back to low for informational-only severities', () => {
    const findings: FindingMemoryInput[] = [
      { ...base, severity: 'informational' },
      { ...base, severity: 'informational' },
    ]
    const result = aggregateFindingMemory({ findings })
    // 'informational' is not in the valid set → falls back to 'low'
    expect(result.dominantSeverity).toBe('low')
  })
})
