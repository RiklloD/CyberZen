import { describe, it, expect } from 'vitest'
import {
  computeRepositoryHealthScore,
  scoreToGrade,
  CATEGORY_WEIGHTS,
  CATEGORY_LABELS,
  type HealthCategory,
  type HealthGrade,
} from './repositoryHealthScore'

// ---------------------------------------------------------------------------
// Constants integrity
// ---------------------------------------------------------------------------

describe('CATEGORY_WEIGHTS', () => {
  it('weights sum to 1.0', () => {
    const sum = Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0)
    expect(sum).toBeCloseTo(1.0, 10)
  })

  it('has exactly 7 categories', () => {
    expect(Object.keys(CATEGORY_WEIGHTS)).toHaveLength(7)
  })

  it('all weights are positive', () => {
    for (const w of Object.values(CATEGORY_WEIGHTS)) {
      expect(w).toBeGreaterThan(0)
    }
  })

  it('supply_chain has highest weight (25%)', () => {
    expect(CATEGORY_WEIGHTS.supply_chain).toBe(0.25)
  })

  it('sbom_quality has lowest weight (5%)', () => {
    expect(CATEGORY_WEIGHTS.sbom_quality).toBe(0.05)
  })
})

describe('CATEGORY_LABELS', () => {
  it('has a label for every weight category', () => {
    for (const key of Object.keys(CATEGORY_WEIGHTS)) {
      expect(CATEGORY_LABELS[key as HealthCategory]).toBeDefined()
      expect(typeof CATEGORY_LABELS[key as HealthCategory]).toBe('string')
    }
  })
})

// ---------------------------------------------------------------------------
// scoreToGrade
// ---------------------------------------------------------------------------

describe('scoreToGrade', () => {
  it.each([
    [100, 'A'], [95, 'A'], [90, 'A'],
    [89, 'B'], [80, 'B'], [75, 'B'],
    [74, 'C'], [65, 'C'], [60, 'C'],
    [59, 'D'], [50, 'D'], [40, 'D'],
    [39, 'F'], [20, 'F'], [0, 'F'],
  ] as [number, HealthGrade][])('score %d → grade %s', (score, expected) => {
    expect(scoreToGrade(score)).toBe(expected)
  })
})

// ---------------------------------------------------------------------------
// Clean / empty inputs
// ---------------------------------------------------------------------------

describe('clean inputs (no risk detected)', () => {
  const report = computeRepositoryHealthScore({})

  it('overall score is 100', () => {
    // No data = no penalties. SBOM quality defaults to 75 (no data fallback),
    // so overall won't be 100. Let's compute the exact expected value.
    // All categories = 100 except sbom_quality = 75 (default when no data).
    // Weighted: 0.25*100 + 0.20*100 + 0.15*100 + 0.15*100 + 0.10*100 + 0.10*100 + 0.05*75
    //         = 25 + 20 + 15 + 15 + 10 + 10 + 3.75 = 98.75 → rounds to 99
    expect(report.overallScore).toBe(99)
  })

  it('overall grade is A', () => {
    expect(report.overallGrade).toBe('A')
  })

  it('returns 7 categories', () => {
    expect(report.categories).toHaveLength(7)
  })

  it('all penalty-based categories score 100', () => {
    const penaltyCats = report.categories.filter(c => c.category !== 'sbom_quality')
    for (const cat of penaltyCats) {
      expect(cat.score).toBe(100)
    }
  })

  it('sbom_quality defaults to 75 when no data', () => {
    const sbom = report.categories.find(c => c.category === 'sbom_quality')!
    expect(sbom.score).toBe(75)
  })

  it('trend is "new" when no previous score', () => {
    expect(report.trend).toBe('new')
  })

  it('topRisks is empty for clean input', () => {
    expect(report.topRisks).toHaveLength(0)
  })

  it('summary mentions grade A', () => {
    expect(report.summary).toContain('grade A')
  })
})

// ---------------------------------------------------------------------------
// Supply chain category
// ---------------------------------------------------------------------------

describe('supply chain scoring', () => {
  it('uses supplyChainScore directly', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 60 })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.score).toBe(60)
  })

  it('adds signal when score < 50', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 30 })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.signals).toEqual(
      expect.arrayContaining([expect.stringContaining('critically low')])
    )
  })

  it('adds signal when score < 75', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 65 })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.signals).toEqual(
      expect.arrayContaining([expect.stringContaining('needs improvement')])
    )
  })

  it('critical risk overrides score to max 25', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 80, supplyChainRisk: 'critical' })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.score).toBe(25)
  })

  it('high risk overrides score to max 50', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 80, supplyChainRisk: 'high' })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.score).toBe(50)
  })

  it('high risk does not increase a lower score', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 30, supplyChainRisk: 'high' })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.score).toBe(30)
  })
})

// ---------------------------------------------------------------------------
// Vulnerability management category
// ---------------------------------------------------------------------------

describe('vulnerability management scoring', () => {
  it('1 critical CVE deducts 20 points', () => {
    const report = computeRepositoryHealthScore({ cveCriticalCount: 1 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(80)
  })

  it('CVE critical penalty caps at 60', () => {
    const report = computeRepositoryHealthScore({ cveCriticalCount: 10 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    // 10 * 20 = 200, capped at 60 → 100 - 60 = 40
    expect(cat.score).toBe(40)
  })

  it('1 high CVE deducts 10 points', () => {
    const report = computeRepositoryHealthScore({ cveHighCount: 1 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(90)
  })

  it('CVE high penalty caps at 30', () => {
    const report = computeRepositoryHealthScore({ cveHighCount: 10 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(70)
  })

  it('critical and high CVEs stack', () => {
    const report = computeRepositoryHealthScore({ cveCriticalCount: 2, cveHighCount: 2 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    // 2*20 + 2*10 = 60 → 100 - 60 = 40
    expect(cat.score).toBe(40)
  })

  it('1 EOL critical deducts 15 points', () => {
    const report = computeRepositoryHealthScore({ eolCriticalCount: 1 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(85)
  })

  it('EOL critical penalty caps at 45', () => {
    const report = computeRepositoryHealthScore({ eolCriticalCount: 10 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(55)
  })

  it('abandonment critical deducts 15 each, capped at 30', () => {
    const report = computeRepositoryHealthScore({ abandonmentCriticalCount: 5 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    // 5*15 = 75, capped at 30 → 100 - 30 = 70
    expect(cat.score).toBe(70)
  })

  it('all vulnerability sources stack to floor at 0', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: 5,     // -60 (capped)
      cveHighCount: 5,          // -30 (capped)
      eolCriticalCount: 5,      // -45 (capped)
      abandonmentCriticalCount: 5, // -30 (capped)
    })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    // 100 - 60 - 30 - 45 - 30 = -65 → clamped to 0
    expect(cat.score).toBe(0)
    expect(cat.grade).toBe('F')
  })

  it('pluralizes CVE signal correctly for 1 vs many', () => {
    const single = computeRepositoryHealthScore({ cveCriticalCount: 1 })
    const multi = computeRepositoryHealthScore({ cveCriticalCount: 3 })
    const singleCat = single.categories.find(c => c.category === 'vulnerability_management')!
    const multiCat = multi.categories.find(c => c.category === 'vulnerability_management')!
    expect(singleCat.signals[0]).not.toContain('CVEs')
    expect(multiCat.signals[0]).toContain('CVEs')
  })
})

// ---------------------------------------------------------------------------
// Code security category
// ---------------------------------------------------------------------------

describe('code security scoring', () => {
  it('1 critical secret deducts 20 points', () => {
    const report = computeRepositoryHealthScore({ secretCriticalCount: 1 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    expect(cat.score).toBe(80)
  })

  it('secret critical penalty caps at 60', () => {
    const report = computeRepositoryHealthScore({ secretCriticalCount: 5 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 5*20 = 100, capped at 60 → 100 - 60 = 40
    expect(cat.score).toBe(40)
  })

  it('high secrets deduct 10 each, capped at 30', () => {
    const report = computeRepositoryHealthScore({ secretHighCount: 5 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 5*10 = 50, capped at 30 → 100 - 30 = 70
    expect(cat.score).toBe(70)
  })

  it('crypto critical deducts 15 each, capped at 45', () => {
    const report = computeRepositoryHealthScore({ cryptoCriticalCount: 4 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 4*15 = 60, capped at 45 → 100 - 45 = 55
    expect(cat.score).toBe(55)
  })

  it('crypto high deducts 8 each, capped at 24', () => {
    const report = computeRepositoryHealthScore({ cryptoHighCount: 5 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 5*8 = 40, capped at 24 → 100 - 24 = 76
    expect(cat.score).toBe(76)
  })

  it('IaC critical deducts 15 each, capped at 30', () => {
    const report = computeRepositoryHealthScore({ iacCriticalCount: 3 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 3*15 = 45, capped at 30 → 100 - 30 = 70
    expect(cat.score).toBe(70)
  })

  it('CI/CD critical deducts 15 each, capped at 30', () => {
    const report = computeRepositoryHealthScore({ cicdCriticalCount: 3 })
    const cat = report.categories.find(c => c.category === 'code_security')!
    // 3*15 = 45, capped at 30 → 100 - 30 = 70
    expect(cat.score).toBe(70)
  })

  it('all code security penalties stack and floor at 0', () => {
    const report = computeRepositoryHealthScore({
      secretCriticalCount: 5,  // -60
      secretHighCount: 5,       // -30
      cryptoCriticalCount: 5,   // -45
      cryptoHighCount: 5,       // -24
      iacCriticalCount: 5,      // -30
      cicdCriticalCount: 5,     // -30
    })
    const cat = report.categories.find(c => c.category === 'code_security')!
    expect(cat.score).toBe(0)
    expect(cat.grade).toBe('F')
  })
})

// ---------------------------------------------------------------------------
// Compliance category
// ---------------------------------------------------------------------------

describe('compliance scoring', () => {
  it('non_compliant status sets base score to 20', () => {
    const report = computeRepositoryHealthScore({ complianceOverallStatus: 'non_compliant' })
    const cat = report.categories.find(c => c.category === 'compliance')!
    expect(cat.score).toBe(20)
  })

  it('at_risk status sets base score to 55', () => {
    const report = computeRepositoryHealthScore({ complianceOverallStatus: 'at_risk' })
    const cat = report.categories.find(c => c.category === 'compliance')!
    expect(cat.score).toBe(55)
  })

  it('compliant status keeps score at 100', () => {
    const report = computeRepositoryHealthScore({ complianceOverallStatus: 'compliant' })
    const cat = report.categories.find(c => c.category === 'compliance')!
    expect(cat.score).toBe(100)
  })

  it('critical gaps deduct 10 each, capped at 30', () => {
    const report = computeRepositoryHealthScore({ complianceCriticalGaps: 5 })
    const cat = report.categories.find(c => c.category === 'compliance')!
    // 100 - min(5*10, 30) = 70
    expect(cat.score).toBe(70)
  })

  it('high gaps deduct 5 each, capped at 20', () => {
    const report = computeRepositoryHealthScore({ complianceHighGaps: 6 })
    const cat = report.categories.find(c => c.category === 'compliance')!
    // 100 - min(6*5, 20) = 80
    expect(cat.score).toBe(80)
  })

  it('at_risk + gaps stack penalties', () => {
    const report = computeRepositoryHealthScore({
      complianceOverallStatus: 'at_risk',
      complianceCriticalGaps: 2,
      complianceHighGaps: 3,
    })
    const cat = report.categories.find(c => c.category === 'compliance')!
    // 55 - 20 - 15 = 20
    expect(cat.score).toBe(20)
  })
})

// ---------------------------------------------------------------------------
// Container security category
// ---------------------------------------------------------------------------

describe('container security scoring', () => {
  it('1 critical container issue deducts 20', () => {
    const report = computeRepositoryHealthScore({ containerCriticalCount: 1 })
    const cat = report.categories.find(c => c.category === 'container_security')!
    expect(cat.score).toBe(80)
  })

  it('container critical penalty caps at 60', () => {
    const report = computeRepositoryHealthScore({ containerCriticalCount: 5 })
    const cat = report.categories.find(c => c.category === 'container_security')!
    // 5*20 = 100, capped at 60 → 100 - 60 = 40
    expect(cat.score).toBe(40)
  })

  it('1 high container issue deducts 10', () => {
    const report = computeRepositoryHealthScore({ containerHighCount: 1 })
    const cat = report.categories.find(c => c.category === 'container_security')!
    expect(cat.score).toBe(90)
  })

  it('container high penalty caps at 30', () => {
    const report = computeRepositoryHealthScore({ containerHighCount: 5 })
    const cat = report.categories.find(c => c.category === 'container_security')!
    expect(cat.score).toBe(70)
  })
})

// ---------------------------------------------------------------------------
// License risk category
// ---------------------------------------------------------------------------

describe('license risk scoring', () => {
  it('1 critical license (strong copyleft) deducts 20', () => {
    const report = computeRepositoryHealthScore({ licenseCriticalCount: 1 })
    const cat = report.categories.find(c => c.category === 'license_risk')!
    expect(cat.score).toBe(80)
    expect(cat.signals[0]).toContain('copyleft')
  })

  it('license critical penalty caps at 60', () => {
    const report = computeRepositoryHealthScore({ licenseCriticalCount: 5 })
    const cat = report.categories.find(c => c.category === 'license_risk')!
    expect(cat.score).toBe(40)
  })

  it('license high penalty caps at 30', () => {
    const report = computeRepositoryHealthScore({ licenseHighCount: 5 })
    const cat = report.categories.find(c => c.category === 'license_risk')!
    expect(cat.score).toBe(70)
  })

  it('critical + high licenses stack', () => {
    const report = computeRepositoryHealthScore({ licenseCriticalCount: 2, licenseHighCount: 2 })
    const cat = report.categories.find(c => c.category === 'license_risk')!
    // 100 - 40 - 20 = 40
    expect(cat.score).toBe(40)
  })
})

// ---------------------------------------------------------------------------
// SBOM quality category
// ---------------------------------------------------------------------------

describe('SBOM quality scoring', () => {
  it('uses sbomQualityScore directly when provided', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 85 })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.score).toBe(85)
  })

  it('falls back to grade mapping when only grade provided', () => {
    const excellent = computeRepositoryHealthScore({ sbomQualityGrade: 'excellent' })
    const good = computeRepositoryHealthScore({ sbomQualityGrade: 'good' })
    const fair = computeRepositoryHealthScore({ sbomQualityGrade: 'fair' })
    const poor = computeRepositoryHealthScore({ sbomQualityGrade: 'poor' })
    expect(excellent.categories.find(c => c.category === 'sbom_quality')!.score).toBe(100)
    expect(good.categories.find(c => c.category === 'sbom_quality')!.score).toBe(80)
    expect(fair.categories.find(c => c.category === 'sbom_quality')!.score).toBe(55)
    expect(poor.categories.find(c => c.category === 'sbom_quality')!.score).toBe(25)
  })

  it('sbomQualityScore takes precedence over grade', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 50, sbomQualityGrade: 'excellent' })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.score).toBe(50)
  })

  it('defaults to 75 when neither score nor grade provided', () => {
    const report = computeRepositoryHealthScore({})
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.score).toBe(75)
  })

  it('generates signal when SBOM quality is poor (<40)', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 30 })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.signals).toEqual(
      expect.arrayContaining([expect.stringContaining('poor')])
    )
  })

  it('generates signal when SBOM quality is fair (40-59)', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 50 })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.signals).toEqual(
      expect.arrayContaining([expect.stringContaining('fair')])
    )
  })

  it('no signal when SBOM quality ≥ 60', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 80 })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.signals).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Weighted average correctness
// ---------------------------------------------------------------------------

describe('weighted average', () => {
  it('computes correct overall score from known category scores', () => {
    // Scenario: supply_chain=50, vulnerability=80, code_security=70,
    // compliance=60, container=90, license=40, sbom_quality=100
    const report = computeRepositoryHealthScore({
      supplyChainScore: 50,      // → 50
      cveCriticalCount: 1,       // → 80
      secretCriticalCount: 1, cryptoHighCount: 1, // secrets: -20, crypto: -8 → 72 (not 70 exactly)
      complianceOverallStatus: 'at_risk', complianceCriticalGaps: 0, // → 55 (not 60)
      containerHighCount: 1,     // → 90
      licenseCriticalCount: 3,   // → 40
      sbomQualityScore: 100,     // → 100
    })
    // Let me compute the exact values:
    // supply_chain: score=50, weight=0.25 → 12.5
    // vulnerability_management: 100 - 20 = 80, weight=0.20 → 16
    // code_security: 100 - 20 - 8 = 72, weight=0.15 → 10.8
    // compliance: 55, weight=0.15 → 8.25
    // container_security: 90, weight=0.10 → 9
    // license_risk: 100 - 60 = 40, weight=0.10 → 4
    // sbom_quality: 100, weight=0.05 → 5
    // Total = 12.5 + 16 + 10.8 + 8.25 + 9 + 4 + 5 = 65.55 → rounds to 66
    expect(report.overallScore).toBe(66)
    expect(report.overallGrade).toBe('C')
  })

  it('overall score floors at 0', () => {
    const report = computeRepositoryHealthScore({
      supplyChainScore: 0,
      supplyChainRisk: 'critical',
      cveCriticalCount: 10,
      cveHighCount: 10,
      eolCriticalCount: 10,
      abandonmentCriticalCount: 10,
      secretCriticalCount: 10,
      secretHighCount: 10,
      cryptoCriticalCount: 10,
      cryptoHighCount: 10,
      iacCriticalCount: 10,
      cicdCriticalCount: 10,
      complianceOverallStatus: 'non_compliant',
      complianceCriticalGaps: 10,
      complianceHighGaps: 10,
      containerCriticalCount: 10,
      containerHighCount: 10,
      licenseCriticalCount: 10,
      licenseHighCount: 10,
      sbomQualityScore: 0,
    })
    // All categories should be 0 or near-0
    expect(report.overallScore).toBeGreaterThanOrEqual(0)
    expect(report.overallGrade).toBe('F')
  })

  it('each category includes its weight', () => {
    const report = computeRepositoryHealthScore({})
    for (const cat of report.categories) {
      expect(cat.weight).toBe(CATEGORY_WEIGHTS[cat.category])
    }
  })

  it('each category includes the correct label', () => {
    const report = computeRepositoryHealthScore({})
    for (const cat of report.categories) {
      expect(cat.label).toBe(CATEGORY_LABELS[cat.category])
    }
  })
})

// ---------------------------------------------------------------------------
// Trend detection
// ---------------------------------------------------------------------------

describe('trend detection', () => {
  it('returns "new" when previousOverallScore is null', () => {
    const report = computeRepositoryHealthScore({ previousOverallScore: null })
    expect(report.trend).toBe('new')
  })

  it('returns "new" when previousOverallScore is undefined', () => {
    const report = computeRepositoryHealthScore({})
    expect(report.trend).toBe('new')
  })

  it('returns "improving" when score increases by ≥5', () => {
    // Clean inputs → ~99. If previous was 90, delta = +9 → improving
    const report = computeRepositoryHealthScore({ previousOverallScore: 90 })
    expect(report.trend).toBe('improving')
  })

  it('returns "declining" when score decreases by ≥5', () => {
    // Force low score (~66), previous was 90
    const report = computeRepositoryHealthScore({
      supplyChainScore: 50,
      cveCriticalCount: 1,
      previousOverallScore: 90,
    })
    expect(report.trend).toBe('declining')
  })

  it('returns "stable" when score delta is within ±4', () => {
    // Clean inputs → 99. Previous = 97, delta = +2 → stable
    const report = computeRepositoryHealthScore({ previousOverallScore: 97 })
    expect(report.trend).toBe('stable')
  })

  it('exactly +5 delta is "improving"', () => {
    const report = computeRepositoryHealthScore({ previousOverallScore: 94 })
    // Clean → 99, delta = +5
    expect(report.trend).toBe('improving')
  })

  it('exactly -5 delta is "declining"', () => {
    // Need score of exactly X and previous of X+5
    // With sbomQualityScore: 100, all clean → overall = 100
    // previous = 105 won't work (>100). Let's use a setup that gives ~80
    const report = computeRepositoryHealthScore({
      supplyChainScore: 60,
      sbomQualityScore: 100,
      previousOverallScore: 95, // actual score will be ~90
    })
    // Need to verify what score we get. supply_chain=60(w=0.25)=15, rest 100:
    // 15 + 20 + 15 + 15 + 10 + 10 + 5 = 90
    // delta = 90 - 95 = -5 → declining
    expect(report.trend).toBe('declining')
  })
})

// ---------------------------------------------------------------------------
// Top risks
// ---------------------------------------------------------------------------

describe('top risks', () => {
  it('returns max 5 risks', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: 1,
      cveHighCount: 1,
      eolCriticalCount: 1,
      abandonmentCriticalCount: 1,
      secretCriticalCount: 1,
      secretHighCount: 1,
      cryptoCriticalCount: 1,
      containerCriticalCount: 1,
      licenseCriticalCount: 1,
    })
    expect(report.topRisks.length).toBeLessThanOrEqual(5)
  })

  it('empty for clean inputs', () => {
    const report = computeRepositoryHealthScore({})
    expect(report.topRisks).toHaveLength(0)
  })

  it('signals from lowest-scoring categories come first', () => {
    // Make supply_chain very low and vulnerability only slightly low
    const report = computeRepositoryHealthScore({
      supplyChainScore: 10,       // score = 10 (very bad)
      cveCriticalCount: 1,        // score = 80 (mild)
    })
    // supply_chain (10) < vulnerability (80), so supply chain signal comes first
    expect(report.topRisks[0]).toContain('Supply chain')
  })

  it('all signals from a category are grouped', () => {
    // Code security with both secrets and crypto issues
    const report = computeRepositoryHealthScore({
      secretCriticalCount: 1,
      cryptoCriticalCount: 1,
    })
    const codeSecSignals = report.topRisks.filter(
      r => r.includes('secret') || r.includes('crypto')
    )
    // Both should be present (from same category)
    expect(codeSecSignals.length).toBeGreaterThanOrEqual(2)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('grade A: mentions "Excellent" and no critical issues', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 100 })
    expect(report.summary).toContain('Excellent')
    expect(report.summary).toContain('No critical issues')
  })

  it('grade A + improving trend mentions improvement', () => {
    const report = computeRepositoryHealthScore({
      sbomQualityScore: 100,
      previousOverallScore: 90,
    })
    expect(report.summary).toContain('improving')
  })

  it('grade A + stable trend mentions stable', () => {
    const report = computeRepositoryHealthScore({
      sbomQualityScore: 100,
      previousOverallScore: 99,
    })
    expect(report.summary).toContain('stable')
  })

  it('non-A grade mentions top risk', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: 30 })
    // Grade will be B or lower with supply chain bringing it down
    // Actually: supply_chain=30 → 0.25*30 = 7.5, rest=100 except sbom=75
    // 7.5 + 20 + 15 + 15 + 10 + 10 + 3.75 = 81.25 → 81, grade B
    expect(report.summary).toContain('Supply chain')
  })

  it('declining trend mentions "declining"', () => {
    const report = computeRepositoryHealthScore({
      supplyChainScore: 30,
      previousOverallScore: 95,
    })
    expect(report.summary).toContain('declining')
  })

  it('summary always includes score and grade', () => {
    const report = computeRepositoryHealthScore({ cveCriticalCount: 2 })
    expect(report.summary).toMatch(/\d+\/100/)
    expect(report.summary).toMatch(/grade [A-F]/)
  })
})

// ---------------------------------------------------------------------------
// Null/undefined handling
// ---------------------------------------------------------------------------

describe('null/undefined input handling', () => {
  it('null values are treated as 0 for count fields', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: null,
      cveHighCount: null,
      eolCriticalCount: null,
    })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(cat.score).toBe(100)
  })

  it('null supplyChainScore defaults to 100', () => {
    const report = computeRepositoryHealthScore({ supplyChainScore: null })
    const cat = report.categories.find(c => c.category === 'supply_chain')!
    expect(cat.score).toBe(100)
  })

  it('null sbomQualityScore falls through to grade then default', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: null, sbomQualityGrade: 'fair' })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    // sbomQualityScore is null → check sbomQualityGrade → fair → 55
    // But wait — the code checks `input.sbomQualityScore != null` first.
    // null != null is false, so it enters the else branch → gradeMap['fair'] = 55
    expect(cat.score).toBe(55)
  })
})

// ---------------------------------------------------------------------------
// Category-level grades
// ---------------------------------------------------------------------------

describe('per-category grades', () => {
  it('each category has a valid grade', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: 2,
      secretCriticalCount: 1,
      complianceOverallStatus: 'at_risk',
    })
    const validGrades: HealthGrade[] = ['A', 'B', 'C', 'D', 'F']
    for (const cat of report.categories) {
      expect(validGrades).toContain(cat.grade)
    }
  })

  it('category grade matches score threshold', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: 2, // vuln score = 60 → grade C
    })
    const vuln = report.categories.find(c => c.category === 'vulnerability_management')!
    expect(vuln.score).toBe(60)
    expect(vuln.grade).toBe('C')
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('edge cases', () => {
  it('zero counts produce no penalties', () => {
    const report = computeRepositoryHealthScore({
      cveCriticalCount: 0,
      cveHighCount: 0,
      secretCriticalCount: 0,
      containerCriticalCount: 0,
      licenseCriticalCount: 0,
    })
    const vuln = report.categories.find(c => c.category === 'vulnerability_management')!
    const code = report.categories.find(c => c.category === 'code_security')!
    expect(vuln.score).toBe(100)
    expect(code.score).toBe(100)
  })

  it('unknown compliance status treated as compliant (100)', () => {
    const report = computeRepositoryHealthScore({ complianceOverallStatus: 'some_unknown_status' })
    const cat = report.categories.find(c => c.category === 'compliance')!
    expect(cat.score).toBe(100)
  })

  it('unknown SBOM quality grade defaults to 75', () => {
    const report = computeRepositoryHealthScore({ sbomQualityGrade: 'unknown_grade' })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.score).toBe(75)
  })

  it('very large counts still clamp category to 0', () => {
    const report = computeRepositoryHealthScore({ cveCriticalCount: 1000, cveHighCount: 1000 })
    const cat = report.categories.find(c => c.category === 'vulnerability_management')!
    // crit capped at 60, high capped at 30, EOL/aband = 0 → 100 - 60 - 30 = 10
    expect(cat.score).toBe(10)
    // But overall still floors at 0 if we add more:
    const report2 = computeRepositoryHealthScore({
      cveCriticalCount: 1000, cveHighCount: 1000,
      eolCriticalCount: 1000, abandonmentCriticalCount: 1000,
    })
    const cat2 = report2.categories.find(c => c.category === 'vulnerability_management')!
    // 100 - 60 - 30 - 45 - 30 = -65 → 0
    expect(cat2.score).toBe(0)
  })

  it('sbomQualityScore is clamped to [0, 100]', () => {
    const report = computeRepositoryHealthScore({ sbomQualityScore: 150 })
    const cat = report.categories.find(c => c.category === 'sbom_quality')!
    expect(cat.score).toBe(100)
  })
})
