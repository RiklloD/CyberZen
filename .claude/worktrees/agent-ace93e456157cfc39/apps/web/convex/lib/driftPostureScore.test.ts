import { describe, expect, it } from 'vitest'
import {
  DRIFT_CATEGORY_WEIGHTS,
  type DriftPostureScannerInputs,
  computeDriftPostureScore,
  detectTrend,
  scoreToGrade,
} from './driftPostureScore'

// ---------------------------------------------------------------------------
// scoreToGrade
// ---------------------------------------------------------------------------

describe('scoreToGrade', () => {
  it('returns A for 90', () => expect(scoreToGrade(90)).toBe('A'))
  it('returns A for 100', () => expect(scoreToGrade(100)).toBe('A'))
  it('returns B for 75', () => expect(scoreToGrade(75)).toBe('B'))
  it('returns B for 89', () => expect(scoreToGrade(89)).toBe('B'))
  it('returns C for 60', () => expect(scoreToGrade(60)).toBe('C'))
  it('returns C for 74', () => expect(scoreToGrade(74)).toBe('C'))
  it('returns D for 40', () => expect(scoreToGrade(40)).toBe('D'))
  it('returns D for 59', () => expect(scoreToGrade(59)).toBe('D'))
  it('returns F for 39', () => expect(scoreToGrade(39)).toBe('F'))
  it('returns F for 0', () => expect(scoreToGrade(0)).toBe('F'))
})

// ---------------------------------------------------------------------------
// detectTrend
// ---------------------------------------------------------------------------

describe('detectTrend', () => {
  it('returns new when no previous score', () => expect(detectTrend(80, null)).toBe('new'))
  it('returns new when previous is undefined', () => expect(detectTrend(80, undefined)).toBe('new'))
  it('returns improving when delta >= 5', () => expect(detectTrend(85, 80)).toBe('improving'))
  it('returns improving for exactly 5 delta', () => expect(detectTrend(75, 70)).toBe('improving'))
  it('returns stable when delta is 0', () => expect(detectTrend(80, 80)).toBe('stable'))
  it('returns stable for delta of 4', () => expect(detectTrend(84, 80)).toBe('stable'))
  it('returns stable for delta of -4', () => expect(detectTrend(76, 80)).toBe('stable'))
  it('returns degrading when delta <= -5', () => expect(detectTrend(75, 80)).toBe('degrading'))
  it('returns degrading for exactly -5 delta', () => expect(detectTrend(70, 75)).toBe('degrading'))
})

// ---------------------------------------------------------------------------
// DRIFT_CATEGORY_WEIGHTS
// ---------------------------------------------------------------------------

describe('DRIFT_CATEGORY_WEIGHTS', () => {
  it('all weights sum to 1.0', () => {
    const total = Object.values(DRIFT_CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0)
    expect(total).toBeCloseTo(1.0, 5)
  })
  it('has 8 categories', () => {
    expect(Object.keys(DRIFT_CATEGORY_WEIGHTS)).toHaveLength(8)
  })
  it('application_security has highest weight at 22%', () => {
    expect(DRIFT_CATEGORY_WEIGHTS.application_security).toBe(0.22)
  })
  it('endpoint_device has lowest weight at 5%', () => {
    expect(DRIFT_CATEGORY_WEIGHTS.endpoint_device).toBe(0.05)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — all-clean input
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — all scanners clean', () => {
  const cleanInputs: DriftPostureScannerInputs = {
    ws60_riskScore: 0, ws60_riskLevel: 'none',
    ws61_riskScore: 0, ws61_riskLevel: 'none',
    ws62_riskScore: 0, ws62_riskLevel: 'none',
    ws63_riskScore: 0, ws63_riskLevel: 'none',
    ws64_riskScore: 0, ws64_riskLevel: 'none',
    ws65_riskScore: 0, ws65_riskLevel: 'none',
    ws66_riskScore: 0, ws66_riskLevel: 'none',
    ws67_riskScore: 0, ws67_riskLevel: 'none',
    ws68_riskScore: 0, ws68_riskLevel: 'none',
    ws69_riskScore: 0, ws69_riskLevel: 'none',
    ws70_riskScore: 0, ws70_riskLevel: 'none',
    ws71_riskScore: 0, ws71_riskLevel: 'none',
    ws72_riskScore: 0, ws72_riskLevel: 'none',
    ws73_riskScore: 0, ws73_riskLevel: 'none',
    ws74_riskScore: 0, ws74_riskLevel: 'none',
    ws75_riskScore: 0, ws75_riskLevel: 'none',
    ws76_riskScore: 0, ws76_riskLevel: 'none',
    ws77_riskScore: 0, ws77_riskLevel: 'none',
    ws78_riskScore: 0, ws78_riskLevel: 'none',
    ws79_riskScore: 0, ws79_riskLevel: 'none',
    ws80_riskScore: 0, ws80_riskLevel: 'none',
    ws81_riskScore: 0, ws81_riskLevel: 'none',
    ws82_riskScore: 0, ws82_riskLevel: 'none',
    ws83_riskScore: 0, ws83_riskLevel: 'none',
    ws84_riskScore: 0, ws84_riskLevel: 'none',
    ws85_riskScore: 0, ws85_riskLevel: 'none',
    ws86_riskScore: 0, ws86_riskLevel: 'none',
    ws87_riskScore: 0, ws87_riskLevel: 'none',
    ws88_riskScore: 0, ws88_riskLevel: 'none',
    ws89_riskScore: 0, ws89_riskLevel: 'none',
    ws90_riskScore: 0, ws90_riskLevel: 'none',
    ws91_riskScore: 0, ws91_riskLevel: 'none',
    ws92_riskScore: 0, ws92_riskLevel: 'none',
    ws93_riskScore: 0, ws93_riskLevel: 'none',
    ws94_riskScore: 0, ws94_riskLevel: 'none',
    ws95_riskScore: 0, ws95_riskLevel: 'none',
    ws101_riskScore: 0, ws101_riskLevel: 'none',
    ws103_riskScore: 0, ws103_riskLevel: 'none',
    ws105_riskScore: 0, ws105_riskLevel: 'none',
    ws107_riskScore: 0, ws107_riskLevel: 'none',
    ws109_riskScore: 0, ws109_riskLevel: 'none',
  }

  it('produces overall score of 100', () => {
    expect(computeDriftPostureScore(cleanInputs).overallScore).toBe(100)
  })
  it('grades as A', () => {
    expect(computeDriftPostureScore(cleanInputs).overallGrade).toBe('A')
  })
  it('all category scores are 100', () => {
    const report = computeDriftPostureScore(cleanInputs)
    for (const cat of report.categoryScores) {
      expect(cat.score).toBe(100)
    }
  })
  it('trend is new when no previous score', () => {
    expect(computeDriftPostureScore(cleanInputs).trend).toBe('new')
  })
  it('all workstreams scanned is 41', () => {
    expect(computeDriftPostureScore(cleanInputs).totalWorkstreamsScanned).toBe(41)
  })
  it('zero critical drift categories', () => {
    expect(computeDriftPostureScore(cleanInputs).criticalDriftCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — all missing input
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — no data', () => {
  it('defaults to score 100 (no risk detected)', () => {
    expect(computeDriftPostureScore({}).overallScore).toBe(100)
  })
  it('grades as A with no data', () => {
    expect(computeDriftPostureScore({}).overallGrade).toBe('A')
  })
  it('zero workstreams scanned', () => {
    expect(computeDriftPostureScore({}).totalWorkstreamsScanned).toBe(0)
  })
  it('trend is new with no previous', () => {
    expect(computeDriftPostureScore({}).trend).toBe('new')
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — single critical scanner
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — single critical scanner in infrastructure', () => {
  const inputs: DriftPostureScannerInputs = {
    ws62_riskScore: 100, ws62_riskLevel: 'critical',  // Cloud security critical
  }

  it('caps infrastructure category at 30', () => {
    const report = computeDriftPostureScore(inputs)
    const infra = report.categoryScores.find((c) => c.category === 'infrastructure')!
    expect(infra.score).toBeLessThanOrEqual(30)
  })
  it('marks infrastructure worstRiskLevel as critical', () => {
    const report = computeDriftPostureScore(inputs)
    const infra = report.categoryScores.find((c) => c.category === 'infrastructure')!
    expect(infra.worstRiskLevel).toBe('critical')
  })
  it('overall score drops below 90 due to infrastructure penalty', () => {
    expect(computeDriftPostureScore(inputs).overallScore).toBeLessThan(90)
  })
  it('criticalDriftCount is 1', () => {
    expect(computeDriftPostureScore(inputs).criticalDriftCount).toBe(1)
  })
  it('infra category grade is F when capped at 30', () => {
    const report = computeDriftPostureScore(inputs)
    const infra = report.categoryScores.find((c) => c.category === 'infrastructure')!
    expect(infra.grade).toBe('F')
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — high severity cap
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — high severity cap', () => {
  const inputs: DriftPostureScannerInputs = {
    ws67_riskScore: 80, ws67_riskLevel: 'high',  // Runtime security high
  }

  it('caps runtime category at 60 on high finding', () => {
    const report = computeDriftPostureScore(inputs)
    const runtime = report.categoryScores.find((c) => c.category === 'runtime_policy')!
    expect(runtime.score).toBeLessThanOrEqual(60)
  })
  it('worstRiskLevel is high in runtime_policy', () => {
    const report = computeDriftPostureScore(inputs)
    const runtime = report.categoryScores.find((c) => c.category === 'runtime_policy')!
    expect(runtime.worstRiskLevel).toBe('high')
  })
  it('highDriftCount is 1', () => {
    expect(computeDriftPostureScore(inputs).highDriftCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — multiple categories with mixed severity
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — mixed severity across categories', () => {
  const inputs: DriftPostureScannerInputs = {
    // App security — high
    ws60_riskScore: 70, ws60_riskLevel: 'high',
    ws65_riskScore: 50, ws65_riskLevel: 'medium',
    // Identity — critical
    ws70_riskScore: 100, ws70_riskLevel: 'critical',
    // Infrastructure — low risk
    ws62_riskScore: 20, ws62_riskLevel: 'low',
    ws63_riskScore: 10, ws63_riskLevel: 'low',
  }

  it('identity_access score is capped at 30 due to critical ws70', () => {
    const report = computeDriftPostureScore(inputs)
    const identity = report.categoryScores.find((c) => c.category === 'identity_access')!
    expect(identity.score).toBeLessThanOrEqual(30)
  })
  it('application_security score is capped at 60 due to high ws60', () => {
    const report = computeDriftPostureScore(inputs)
    const appSec = report.categoryScores.find((c) => c.category === 'application_security')!
    expect(appSec.score).toBeLessThanOrEqual(60)
  })
  it('infrastructure score reflects averaged low risk', () => {
    const report = computeDriftPostureScore(inputs)
    const infra = report.categoryScores.find((c) => c.category === 'infrastructure')!
    // avg riskScore = (20+10)/2 = 15, security score = 85
    expect(infra.score).toBe(85)
  })
  it('criticalDriftCount is 1', () => {
    expect(computeDriftPostureScore(inputs).criticalDriftCount).toBe(1)
  })
  it('highDriftCount is at least 1', () => {
    expect(computeDriftPostureScore(inputs).highDriftCount).toBeGreaterThanOrEqual(1)
  })
  it('overall score is below 90', () => {
    expect(computeDriftPostureScore(inputs).overallScore).toBeLessThan(90)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — trend calculation
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — trend', () => {
  const baseClean: DriftPostureScannerInputs = {
    ws60_riskScore: 0, ws60_riskLevel: 'none',
  }

  it('trend is improving when current is 5+ higher', () => {
    const report = computeDriftPostureScore(baseClean, 85)
    expect(report.trend).toBe('improving')
  })
  it('trend is stable when delta is within ±4', () => {
    const report = computeDriftPostureScore(baseClean, 98)
    expect(report.trend).toBe('stable')
  })
  it('trend is degrading when current is 5+ lower', () => {
    // Push riskScore high in all major categories to drive overall below previous
    const inputs: DriftPostureScannerInputs = {
      ws60_riskScore: 80, ws60_riskLevel: 'high',
      ws62_riskScore: 80, ws62_riskLevel: 'high',
      ws67_riskScore: 80, ws67_riskLevel: 'high',
      ws70_riskScore: 80, ws70_riskLevel: 'high',
    }
    const report = computeDriftPostureScore(inputs, 95)
    expect(report.trend).toBe('degrading')
  })
  it('trend is new with no previous score', () => {
    const report = computeDriftPostureScore(baseClean, null)
    expect(report.trend).toBe('new')
  })
  it('uses inputs.previousOverallScore if second arg is not provided', () => {
    const inputs: DriftPostureScannerInputs = {
      ws60_riskScore: 0, ws60_riskLevel: 'none',
      previousOverallScore: 70,
    }
    const report = computeDriftPostureScore(inputs)
    // overall score = 100 (all else clean), delta = 30 → improving
    expect(report.trend).toBe('improving')
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — grade boundaries
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — grade F scenario', () => {
  const inputs: DriftPostureScannerInputs = {
    ws60_riskScore: 100, ws60_riskLevel: 'critical',
    ws62_riskScore: 100, ws62_riskLevel: 'critical',
    ws67_riskScore: 100, ws67_riskLevel: 'critical',
    ws70_riskScore: 100, ws70_riskLevel: 'critical',
    ws77_riskScore: 100, ws77_riskLevel: 'critical',
    ws71_riskScore: 100, ws71_riskLevel: 'critical',
    ws84_riskScore: 100, ws84_riskLevel: 'critical',
    ws95_riskScore: 100, ws95_riskLevel: 'critical',
  }

  it('overall grade is F under maximum drift', () => {
    expect(computeDriftPostureScore(inputs).overallGrade).toBe('F')
  })
  it('overall score is below 40 under maximum drift', () => {
    expect(computeDriftPostureScore(inputs).overallScore).toBeLessThan(40)
  })
  it('criticalDriftCount covers all 8 categories', () => {
    expect(computeDriftPostureScore(inputs).criticalDriftCount).toBe(8)
  })
  it('summary mentions critical', () => {
    expect(computeDriftPostureScore(inputs).summary.toLowerCase()).toContain('critical')
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — topRisks selection
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — topRisks', () => {
  const inputs: DriftPostureScannerInputs = {
    ws60_riskScore: 90, ws60_riskLevel: 'critical',  // app sec critical
    ws70_riskScore: 80, ws70_riskLevel: 'high',       // identity high
  }

  it('topRisks is an array', () => {
    expect(Array.isArray(computeDriftPostureScore(inputs).topRisks)).toBe(true)
  })
  it('topRisks contains at most 5 items', () => {
    expect(computeDriftPostureScore(inputs).topRisks.length).toBeLessThanOrEqual(5)
  })
  it('topRisks is empty when all clean', () => {
    const clean: DriftPostureScannerInputs = {
      ws60_riskScore: 0, ws60_riskLevel: 'none',
    }
    expect(computeDriftPostureScore(clean).topRisks).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — output shape
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — output shape', () => {
  const report = computeDriftPostureScore({})

  it('has overallScore as number', () => expect(typeof report.overallScore).toBe('number'))
  it('has overallGrade as string', () => expect(typeof report.overallGrade).toBe('string'))
  it('has trend as string', () => expect(typeof report.trend).toBe('string'))
  it('has 8 categoryScores', () => expect(report.categoryScores).toHaveLength(8))
  it('has totalWorkstreamsScanned as number', () => expect(typeof report.totalWorkstreamsScanned).toBe('number'))
  it('has criticalDriftCount as number', () => expect(typeof report.criticalDriftCount).toBe('number'))
  it('has highDriftCount as number', () => expect(typeof report.highDriftCount).toBe('number'))
  it('has topRisks as array', () => expect(Array.isArray(report.topRisks)).toBe(true))
  it('has summary as non-empty string', () => {
    expect(typeof report.summary).toBe('string')
    expect(report.summary.length).toBeGreaterThan(0)
  })
  it('each categoryScore has required fields', () => {
    for (const cat of report.categoryScores) {
      expect(typeof cat.category).toBe('string')
      expect(typeof cat.label).toBe('string')
      expect(typeof cat.score).toBe('number')
      expect(typeof cat.weight).toBe('number')
      expect(typeof cat.grade).toBe('string')
      expect(typeof cat.workstreamsScanned).toBe('number')
      expect(typeof cat.worstRiskLevel).toBe('string')
      expect(Array.isArray(cat.signals)).toBe(true)
    }
  })
  it('overallScore is within 0–100', () => {
    expect(report.overallScore).toBeGreaterThanOrEqual(0)
    expect(report.overallScore).toBeLessThanOrEqual(100)
  })
  it('category scores are within 0–100', () => {
    for (const cat of report.categoryScores) {
      expect(cat.score).toBeGreaterThanOrEqual(0)
      expect(cat.score).toBeLessThanOrEqual(100)
    }
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — weighted average correctness
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — weighted average', () => {
  it('overall score matches expected weighted average for known inputs', () => {
    // Only feed one scanner per category with known riskScore=0 → secScore=100
    // All categories should score 100, weighted average = 100
    const inputs: DriftPostureScannerInputs = {
      ws60_riskScore: 0, ws60_riskLevel: 'none',   // app_sec
      ws62_riskScore: 0, ws62_riskLevel: 'none',   // infra
      ws67_riskScore: 0, ws67_riskLevel: 'none',   // runtime
      ws69_riskScore: 0, ws69_riskLevel: 'none',   // identity
      ws77_riskScore: 0, ws77_riskLevel: 'none',   // platform
      ws71_riskScore: 0, ws71_riskLevel: 'none',   // observability
      ws84_riskScore: 0, ws84_riskLevel: 'none',   // network
      ws95_riskScore: 0, ws95_riskLevel: 'none',   // endpoint
    }
    expect(computeDriftPostureScore(inputs).overallScore).toBe(100)
  })

  it('partial scanner data: missing categories default to 100 and preserve score', () => {
    // Only app_sec (22% weight) is risky: riskScore=100 → secScore=0
    const inputs: DriftPostureScannerInputs = {
      ws60_riskScore: 100, ws60_riskLevel: 'high',
    }
    const report = computeDriftPostureScore(inputs)
    // app_sec: 100-100=0, capped at min(0,60)=0; others: 100
    // overall ≈ 0.22*0 + 0.78*100 = 78
    expect(report.overallScore).toBeGreaterThan(70)
    expect(report.overallScore).toBeLessThan(90)
  })
})

// ---------------------------------------------------------------------------
// computeDriftPostureScore — workstreamsScanned per category
// ---------------------------------------------------------------------------

describe('computeDriftPostureScore — workstreamsScanned', () => {
  it('application_security scans 5 workstreams when all provided', () => {
    const inputs: DriftPostureScannerInputs = {
      ws60_riskScore: 0, ws60_riskLevel: 'none',
      ws61_riskScore: 0, ws61_riskLevel: 'none',
      ws65_riskScore: 0, ws65_riskLevel: 'none',
      ws75_riskScore: 0, ws75_riskLevel: 'none',
      ws76_riskScore: 0, ws76_riskLevel: 'none',
    }
    const report = computeDriftPostureScore(inputs)
    const appSec = report.categoryScores.find((c) => c.category === 'application_security')!
    expect(appSec.workstreamsScanned).toBe(5)
  })
  it('endpoint_device scans 6 workstreams when all provided', () => {
    const inputs: DriftPostureScannerInputs = {
      ws74_riskScore: 0, ws74_riskLevel: 'none',
      ws89_riskScore: 0, ws89_riskLevel: 'none',
      ws91_riskScore: 0, ws91_riskLevel: 'none',
      ws92_riskScore: 0, ws92_riskLevel: 'none',
      ws93_riskScore: 0, ws93_riskLevel: 'none',
      ws95_riskScore: 0, ws95_riskLevel: 'none',
    }
    const report = computeDriftPostureScore(inputs)
    const ep = report.categoryScores.find((c) => c.category === 'endpoint_device')!
    expect(ep.workstreamsScanned).toBe(6)
  })
  it('category with no data shows 0 workstreams scanned', () => {
    const report = computeDriftPostureScore({})
    for (const cat of report.categoryScores) {
      expect(cat.workstreamsScanned).toBe(0)
    }
  })
})
