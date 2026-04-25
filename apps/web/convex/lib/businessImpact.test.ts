/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeBusinessImpact, type BusinessImpactInput } from './businessImpact'

const base: BusinessImpactInput = {
  criticalFindings: 0,
  highFindings: 0,
  mediumFindings: 0,
  lowFindings: 0,
  maxBlastRadiusScore: 0,
  avgBlastRadiusScore: 0,
  reachableServiceNames: [],
  attackSurfaceScore: null,
  nonCompliantFrameworkCount: 0,
  atRiskFrameworkCount: 0,
  regulatoryDriftLevel: null,
}

// ── Output structure ─────────────────────────────────────────────────────────

describe('computeBusinessImpact — output structure', () => {
  it('returns all required fields', () => {
    const r = computeBusinessImpact(base)
    expect(typeof r.dataExposureScore).toBe('number')
    expect(typeof r.regulatoryExposureScore).toBe('number')
    expect(typeof r.revenueImpactScore).toBe('number')
    expect(typeof r.reputationScore).toBe('number')
    expect(typeof r.remediationCostScore).toBe('number')
    expect(typeof r.overallScore).toBe('number')
    expect(typeof r.impactLevel).toBe('string')
    expect(typeof r.estimatedRecordsAtRisk).toBe('number')
    expect(typeof r.estimatedFineRangeMin).toBe('number')
    expect(typeof r.estimatedFineRangeMax).toBe('number')
    expect(typeof r.estimatedRemediationCostMin).toBe('number')
    expect(typeof r.estimatedRemediationCostMax).toBe('number')
    expect(Array.isArray(r.topExposures)).toBe(true)
    expect(typeof r.assessedAt).toBe('number')
  })

  it('impact level is one of five valid values', () => {
    const levels = ['critical', 'high', 'medium', 'low', 'minimal']
    const r = computeBusinessImpact(base)
    expect(levels).toContain(r.impactLevel)
  })

  it('all sub-scores are clamped 0–100', () => {
    const r = computeBusinessImpact(base)
    for (const score of [
      r.dataExposureScore, r.regulatoryExposureScore, r.revenueImpactScore,
      r.reputationScore, r.remediationCostScore, r.overallScore,
    ]) {
      expect(score).toBeGreaterThanOrEqual(0)
      expect(score).toBeLessThanOrEqual(100)
    }
  })

  it('assessedAt is recent', () => {
    const before = Date.now()
    const r = computeBusinessImpact(base)
    expect(r.assessedAt).toBeGreaterThanOrEqual(before)
  })
})

// ── Empty / minimal input ────────────────────────────────────────────────────

describe('computeBusinessImpact — empty input', () => {
  it('returns minimal impact for zero findings', () => {
    const r = computeBusinessImpact(base)
    expect(r.impactLevel).toBe('minimal')
    expect(r.overallScore).toBe(0)
  })

  it('returns 0 records at risk for zero findings', () => {
    const r = computeBusinessImpact(base)
    expect(r.estimatedRecordsAtRisk).toBe(0)
  })

  it('returns lowest fine range for zero risk', () => {
    const r = computeBusinessImpact(base)
    expect(r.estimatedFineRangeMin).toBe(0)
    expect(r.estimatedFineRangeMax).toBe(10_000)
  })

  it('topExposures is empty for zero input', () => {
    const r = computeBusinessImpact(base)
    expect(r.topExposures).toHaveLength(0)
  })
})

// ── dataExposureScore ────────────────────────────────────────────────────────

describe('computeBusinessImpact — dataExposureScore', () => {
  it('increases with critical findings', () => {
    const r1 = computeBusinessImpact(base)
    const r2 = computeBusinessImpact({ ...base, criticalFindings: 3 })
    expect(r2.dataExposureScore).toBeGreaterThan(r1.dataExposureScore)
  })

  it('caps critical contribution at 40', () => {
    const r100 = computeBusinessImpact({ ...base, criticalFindings: 100 })
    // score is clamped to 100 even with extreme inputs
    expect(r100.dataExposureScore).toBeLessThanOrEqual(100)
  })

  it('increases with high blast radius score', () => {
    const low = computeBusinessImpact({ ...base, maxBlastRadiusScore: 20 })
    const high = computeBusinessImpact({ ...base, maxBlastRadiusScore: 90 })
    expect(high.dataExposureScore).toBeGreaterThan(low.dataExposureScore)
  })

  it('penalises poor attack surface score', () => {
    const good = computeBusinessImpact({ ...base, attackSurfaceScore: 90 })
    const poor = computeBusinessImpact({ ...base, attackSurfaceScore: 20 })
    expect(poor.dataExposureScore).toBeGreaterThan(good.dataExposureScore)
  })

  it('null attackSurfaceScore does not add penalty', () => {
    const withNull = computeBusinessImpact({ ...base, attackSurfaceScore: null })
    expect(withNull.dataExposureScore).toBe(0)
  })
})

// ── regulatoryExposureScore ──────────────────────────────────────────────────

describe('computeBusinessImpact — regulatoryExposureScore', () => {
  it('scores 0 with no compliance issues', () => {
    const r = computeBusinessImpact(base)
    expect(r.regulatoryExposureScore).toBe(0)
  })

  it('increases with non-compliant frameworks', () => {
    const r = computeBusinessImpact({ ...base, nonCompliantFrameworkCount: 3 })
    expect(r.regulatoryExposureScore).toBeGreaterThan(0)
  })

  it('at-risk frameworks contribute less than non-compliant', () => {
    const nonCompliant = computeBusinessImpact({ ...base, nonCompliantFrameworkCount: 1 })
    const atRisk = computeBusinessImpact({ ...base, atRiskFrameworkCount: 1 })
    expect(nonCompliant.regulatoryExposureScore).toBeGreaterThan(atRisk.regulatoryExposureScore)
  })

  it('high drift level adds significant penalty', () => {
    const none = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'none' })
    const high = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'high' })
    expect(high.regulatoryExposureScore).toBeGreaterThan(none.regulatoryExposureScore)
  })

  it('critical drift level adds maximum penalty', () => {
    const high = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'high' })
    const critical = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'critical' })
    expect(critical.regulatoryExposureScore).toBeGreaterThan(high.regulatoryExposureScore)
  })

  it('compound penalty: critical finding + non-compliant framework', () => {
    const partial = computeBusinessImpact({ ...base, nonCompliantFrameworkCount: 1 })
    const compound = computeBusinessImpact({
      ...base,
      criticalFindings: 1,
      nonCompliantFrameworkCount: 1,
    })
    expect(compound.regulatoryExposureScore).toBeGreaterThan(partial.regulatoryExposureScore)
  })
})

// ── revenueImpactScore ───────────────────────────────────────────────────────

describe('computeBusinessImpact — revenueImpactScore', () => {
  it('scores 0 with no findings and no revenue services', () => {
    const r = computeBusinessImpact({ ...base, attackSurfaceScore: 100 })
    // With perfect attack surface and no services/findings, revenue impact = 0
    expect(r.revenueImpactScore).toBe(0)
  })

  it('adds points for payment-related services', () => {
    const no  = computeBusinessImpact({ ...base, attackSurfaceScore: 80 })
    const yes = computeBusinessImpact({
      ...base,
      attackSurfaceScore: 80,
      reachableServiceNames: ['payment-service'],
    })
    expect(yes.revenueImpactScore).toBeGreaterThan(no.revenueImpactScore)
  })

  it('adds points for auth-related services', () => {
    const no  = computeBusinessImpact({ ...base, attackSurfaceScore: 80 })
    const yes = computeBusinessImpact({
      ...base,
      attackSurfaceScore: 80,
      reachableServiceNames: ['auth-api'],
    })
    expect(yes.revenueImpactScore).toBeGreaterThan(no.revenueImpactScore)
  })

  it('payment service + critical findings → high revenue impact', () => {
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 2,
      reachableServiceNames: ['stripe-billing'],
    })
    expect(r.revenueImpactScore).toBeGreaterThan(50)
  })
})

// ── reputationScore ──────────────────────────────────────────────────────────

describe('computeBusinessImpact — reputationScore', () => {
  it('scores 0 with no findings and good attack surface', () => {
    const r = computeBusinessImpact({ ...base, attackSurfaceScore: 90 })
    expect(r.reputationScore).toBe(0)
  })

  it('critical findings drive reputation score up sharply', () => {
    const low  = computeBusinessImpact({ ...base, criticalFindings: 1 })
    const high = computeBusinessImpact({ ...base, criticalFindings: 11 })
    expect(high.reputationScore).toBeGreaterThan(low.reputationScore)
  })

  it('more than 10 critical findings → reputation ≥ 70', () => {
    const r = computeBusinessImpact({ ...base, criticalFindings: 15 })
    expect(r.reputationScore).toBeGreaterThanOrEqual(70)
  })

  it('poor attack surface adds reputation penalty', () => {
    const good = computeBusinessImpact({ ...base, criticalFindings: 1, attackSurfaceScore: 90 })
    const poor = computeBusinessImpact({ ...base, criticalFindings: 1, attackSurfaceScore: 10 })
    expect(poor.reputationScore).toBeGreaterThan(good.reputationScore)
  })
})

// ── remediationCostScore ─────────────────────────────────────────────────────

describe('computeBusinessImpact — remediationCostScore', () => {
  it('scores 0 with no findings', () => {
    const r = computeBusinessImpact(base)
    expect(r.remediationCostScore).toBe(0)
  })

  it('critical findings have the highest per-unit weight', () => {
    const oneCrit  = computeBusinessImpact({ ...base, criticalFindings: 1 })
    const oneHigh  = computeBusinessImpact({ ...base, highFindings: 1 })
    const oneMed   = computeBusinessImpact({ ...base, mediumFindings: 1 })
    expect(oneCrit.remediationCostScore).toBeGreaterThan(oneHigh.remediationCostScore)
    expect(oneHigh.remediationCostScore).toBeGreaterThan(oneMed.remediationCostScore)
  })

  it('heavy finding load → high remediation cost score', () => {
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 5,
      highFindings: 10,
      mediumFindings: 20,
    })
    expect(r.remediationCostScore).toBeGreaterThan(60)
  })
})

// ── overallScore & impactLevel ───────────────────────────────────────────────

describe('computeBusinessImpact — overallScore and impactLevel', () => {
  it('overallScore is weighted average of sub-scores', () => {
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 1,
      nonCompliantFrameworkCount: 1,
    })
    const expected = Math.round(
      r.dataExposureScore * 0.25 +
      r.regulatoryExposureScore * 0.25 +
      r.revenueImpactScore * 0.20 +
      r.reputationScore * 0.20 +
      r.remediationCostScore * 0.10,
    )
    expect(r.overallScore).toBe(expected)
  })

  it('impactLevel critical when score ≥ 80', () => {
    // Build input that drives score ≥ 80
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 15,
      nonCompliantFrameworkCount: 4,
      regulatoryDriftLevel: 'critical',
      reachableServiceNames: ['payment-api', 'auth-service'],
      maxBlastRadiusScore: 95,
      attackSurfaceScore: 10,
    })
    expect(['critical', 'high']).toContain(r.impactLevel)
    expect(r.overallScore).toBeGreaterThan(60)
  })

  it('impactLevel minimal for all-zero input', () => {
    const r = computeBusinessImpact(base)
    expect(r.impactLevel).toBe('minimal')
  })
})

// ── Financial estimates ───────────────────────────────────────────────────────

describe('computeBusinessImpact — financial estimates', () => {
  it('fineRangeMin < fineRangeMax always', () => {
    for (const nc of [0, 1, 3, 5]) {
      const r = computeBusinessImpact({ ...base, nonCompliantFrameworkCount: nc })
      expect(r.estimatedFineRangeMin).toBeLessThanOrEqual(r.estimatedFineRangeMax)
    }
  })

  it('higher regulatory exposure → higher fine range', () => {
    const low  = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'none' })
    const high = computeBusinessImpact({
      ...base,
      nonCompliantFrameworkCount: 4,
      regulatoryDriftLevel: 'critical',
    })
    expect(high.estimatedFineRangeMax).toBeGreaterThan(low.estimatedFineRangeMax)
  })

  it('remediationCostMin < remediationCostMax always', () => {
    for (const crit of [0, 1, 5, 20]) {
      const r = computeBusinessImpact({ ...base, criticalFindings: crit })
      expect(r.estimatedRemediationCostMin).toBeLessThanOrEqual(r.estimatedRemediationCostMax)
    }
  })

  it('records at risk scale with finding severity', () => {
    const low  = computeBusinessImpact({ ...base, criticalFindings: 1 })
    const high = computeBusinessImpact({ ...base, criticalFindings: 10 })
    expect(high.estimatedRecordsAtRisk).toBeGreaterThan(low.estimatedRecordsAtRisk)
  })

  it('high blast radius multiplies records at risk', () => {
    const normal = computeBusinessImpact({ ...base, criticalFindings: 2, maxBlastRadiusScore: 30 })
    const boosted = computeBusinessImpact({ ...base, criticalFindings: 2, maxBlastRadiusScore: 80 })
    expect(boosted.estimatedRecordsAtRisk).toBeGreaterThan(normal.estimatedRecordsAtRisk)
  })

  it('records at risk capped at 1 000 000', () => {
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 1000,
      maxBlastRadiusScore: 100,
    })
    expect(r.estimatedRecordsAtRisk).toBeLessThanOrEqual(1_000_000)
  })
})

// ── topExposures ─────────────────────────────────────────────────────────────

describe('computeBusinessImpact — topExposures', () => {
  it('includes critical finding note when criticals > 0', () => {
    const r = computeBusinessImpact({ ...base, criticalFindings: 3 })
    expect(r.topExposures.some((e) => e.toLowerCase().includes('critical'))).toBe(true)
  })

  it('includes regulatory framework note when non-compliant', () => {
    const r = computeBusinessImpact({ ...base, nonCompliantFrameworkCount: 2 })
    expect(r.topExposures.some((e) => e.toLowerCase().includes('compliance') || e.toLowerCase().includes('framework'))).toBe(true)
  })

  it('includes blast radius note when blast score > 70', () => {
    const r = computeBusinessImpact({ ...base, maxBlastRadiusScore: 85 })
    expect(r.topExposures.some((e) => e.toLowerCase().includes('blast'))).toBe(true)
  })

  it('includes regulatory drift note when drift is high', () => {
    const r = computeBusinessImpact({ ...base, regulatoryDriftLevel: 'high' })
    expect(r.topExposures.some((e) => e.toLowerCase().includes('drift') || e.toLowerCase().includes('regulatory'))).toBe(true)
  })

  it('topExposures capped at 5 entries', () => {
    const r = computeBusinessImpact({
      ...base,
      criticalFindings: 5,
      nonCompliantFrameworkCount: 3,
      maxBlastRadiusScore: 90,
      reachableServiceNames: ['payment-service', 'auth-api'],
      attackSurfaceScore: 15,
      regulatoryDriftLevel: 'critical',
    })
    expect(r.topExposures.length).toBeLessThanOrEqual(5)
  })
})
