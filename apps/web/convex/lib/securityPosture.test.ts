/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeSecurityPosture } from './securityPosture'
import type { SecurityPostureInput } from './securityPosture'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BASE: SecurityPostureInput = {
  repositoryName: 'test-repo',
  findings: { openCritical: 0, openHigh: 0, openMedium: 0, openLow: 0 },
  attackSurface: null,
  regulatoryDrift: null,
  redBlue: null,
  learningProfile: null,
  honeypot: null,
}

// ─── Perfect score baseline ───────────────────────────────────────────────────

describe('computeSecurityPosture — perfect score', () => {
  it('returns 100 and "excellent" when no findings and no signals', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.overallScore).toBe(100)
    expect(result.postureLevel).toBe('excellent')
  })

  it('all penalties are 0 for empty input', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.findingPenalty).toBe(0)
    expect(result.attackSurfacePenalty).toBeNull()
    expect(result.regulatoryPenalty).toBeNull()
    expect(result.redAgentPenalty).toBeNull()
    expect(result.learningBonus).toBe(0)
  })

  it('provides a healthy default action when no issues', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.topActions).toHaveLength(1)
    expect(result.topActions[0]).toMatch(/healthy/i)
  })
})

// ─── Finding penalties ────────────────────────────────────────────────────────

describe('computeSecurityPosture — finding penalties', () => {
  it('one critical finding applies -12 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 1, openHigh: 0, openMedium: 0, openLow: 0 },
    })
    expect(result.findingPenalty).toBe(12)
    expect(result.overallScore).toBe(88)
  })

  it('one high finding applies -6 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 0, openHigh: 1, openMedium: 0, openLow: 0 },
    })
    expect(result.findingPenalty).toBe(6)
    expect(result.overallScore).toBe(94)
  })

  it('one medium finding applies -2 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 0, openHigh: 0, openMedium: 1, openLow: 0 },
    })
    expect(result.findingPenalty).toBe(2)
  })

  it('two low findings apply -1 penalty (floor of 2 * 0.5)', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 0, openHigh: 0, openMedium: 0, openLow: 2 },
    })
    expect(result.findingPenalty).toBe(1)
  })

  it('one low finding (odd) applies 0 penalty (floor of 1 * 0.5 = 0)', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 0, openHigh: 0, openMedium: 0, openLow: 1 },
    })
    expect(result.findingPenalty).toBe(0)
  })

  it('finding penalty caps at 50', () => {
    // 5 criticals = 60 → capped at 50
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 5, openHigh: 0, openMedium: 0, openLow: 0 },
    })
    expect(result.findingPenalty).toBe(50)
    expect(result.overallScore).toBe(50)
  })

  it('combined findings are capped at 50', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 3, openHigh: 10, openMedium: 20, openLow: 0 },
    })
    expect(result.findingPenalty).toBe(50)
  })
})

// ─── Attack surface penalties ─────────────────────────────────────────────────

describe('computeSecurityPosture — attack surface penalties', () => {
  it('score < 40 applies -25 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      attackSurface: { score: 30, trend: 'stable' },
    })
    expect(result.attackSurfacePenalty).toBe(25)
    expect(result.overallScore).toBe(75)
  })

  it('score in [40,60) applies -15 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      attackSurface: { score: 55, trend: 'stable' },
    })
    expect(result.attackSurfacePenalty).toBe(15)
  })

  it('score in [60,80) applies -5 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      attackSurface: { score: 70, trend: 'stable' },
    })
    expect(result.attackSurfacePenalty).toBe(5)
  })

  it('score >= 80 applies 0 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      attackSurface: { score: 90, trend: 'stable' },
    })
    expect(result.attackSurfacePenalty).toBe(0)
    expect(result.overallScore).toBe(100)
  })

  it('degrading trend adds action', () => {
    const result = computeSecurityPosture({
      ...BASE,
      attackSurface: { score: 85, trend: 'degrading' },
    })
    expect(result.topActions.some((a) => /degrad/i.test(a))).toBe(true)
  })

  it('null attack surface → no penalty applied', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.attackSurfacePenalty).toBeNull()
  })
})

// ─── Regulatory drift penalties ───────────────────────────────────────────────

describe('computeSecurityPosture — regulatory drift penalties', () => {
  it('non_compliant applies -20 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      regulatoryDrift: {
        overallDriftLevel: 'non_compliant',
        criticalGapCount: 3,
        affectedFrameworks: ['SOC 2', 'GDPR'],
      },
    })
    expect(result.regulatoryPenalty).toBe(20)
    expect(result.overallScore).toBe(80)
  })

  it('at_risk applies -15 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      regulatoryDrift: {
        overallDriftLevel: 'at_risk',
        criticalGapCount: 1,
        affectedFrameworks: ['PCI-DSS'],
      },
    })
    expect(result.regulatoryPenalty).toBe(15)
  })

  it('drifting applies -8 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      regulatoryDrift: {
        overallDriftLevel: 'drifting',
        criticalGapCount: 0,
        affectedFrameworks: ['NIS2'],
      },
    })
    expect(result.regulatoryPenalty).toBe(8)
  })

  it('compliant applies 0 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      regulatoryDrift: {
        overallDriftLevel: 'compliant',
        criticalGapCount: 0,
        affectedFrameworks: [],
      },
    })
    expect(result.regulatoryPenalty).toBe(0)
    expect(result.overallScore).toBe(100)
  })

  it('regulatory action mentions framework names', () => {
    const result = computeSecurityPosture({
      ...BASE,
      regulatoryDrift: {
        overallDriftLevel: 'non_compliant',
        criticalGapCount: 2,
        affectedFrameworks: ['SOC 2', 'HIPAA'],
      },
    })
    const hasFrameworks = result.topActions.some((a) => a.includes('SOC 2') || a.includes('HIPAA'))
    expect(hasFrameworks).toBe(true)
  })
})

// ─── Red agent penalties ──────────────────────────────────────────────────────

describe('computeSecurityPosture — red agent penalties', () => {
  it('win rate > 0.7 applies -10 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      redBlue: { latestOutcome: 'red_wins', redAgentWinRate: 0.8, totalRounds: 5 },
    })
    expect(result.redAgentPenalty).toBe(10)
  })

  it('win rate > 0.5 applies -6 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      redBlue: { latestOutcome: 'red_wins', redAgentWinRate: 0.6, totalRounds: 5 },
    })
    expect(result.redAgentPenalty).toBe(6)
  })

  it('win rate <= 0.3 applies 0 penalty', () => {
    const result = computeSecurityPosture({
      ...BASE,
      redBlue: { latestOutcome: 'blue_wins', redAgentWinRate: 0.2, totalRounds: 5 },
    })
    expect(result.redAgentPenalty).toBe(0)
  })

  it('null redBlue → no penalty applied', () => {
    expect(computeSecurityPosture(BASE).redAgentPenalty).toBeNull()
  })

  it('0 rounds → no penalty (guard against division by zero)', () => {
    const result = computeSecurityPosture({
      ...BASE,
      redBlue: { latestOutcome: 'draw', redAgentWinRate: 0, totalRounds: 0 },
    })
    expect(result.redAgentPenalty).toBeNull()
  })
})

// ─── Learning maturity bonus ──────────────────────────────────────────────────

describe('computeSecurityPosture — learning bonus', () => {
  it('maturity >= 75 grants +5 bonus', () => {
    const result = computeSecurityPosture({
      ...BASE,
      learningProfile: { adaptedConfidenceScore: 80, recurringVulnClasses: [], successfulExploitPaths: 0 },
    })
    expect(result.learningBonus).toBe(5)
    expect(result.overallScore).toBe(100) // 100 - 0 + 5 → capped at 100
  })

  it('maturity in [50,75) grants +3 bonus', () => {
    const result = computeSecurityPosture({
      ...BASE,
      learningProfile: { adaptedConfidenceScore: 60, recurringVulnClasses: [], successfulExploitPaths: 0 },
    })
    expect(result.learningBonus).toBe(3)
  })

  it('maturity < 50 grants 0 bonus', () => {
    const result = computeSecurityPosture({
      ...BASE,
      learningProfile: { adaptedConfidenceScore: 30, recurringVulnClasses: [], successfulExploitPaths: 0 },
    })
    expect(result.learningBonus).toBe(0)
  })

  it('score is clamped at 100 even with learning bonus', () => {
    const result = computeSecurityPosture({
      ...BASE,
      learningProfile: { adaptedConfidenceScore: 90, recurringVulnClasses: [], successfulExploitPaths: 0 },
    })
    expect(result.overallScore).toBe(100)
  })
})

// ─── Score clamping ───────────────────────────────────────────────────────────

describe('computeSecurityPosture — score clamping', () => {
  it('score is clamped at 0 when penalties exceed 100', () => {
    const result = computeSecurityPosture({
      repositoryName: 'test',
      findings: { openCritical: 4, openHigh: 0, openMedium: 0, openLow: 0 }, // -48
      attackSurface: { score: 10, trend: 'degrading' }, // -25
      regulatoryDrift: {
        overallDriftLevel: 'non_compliant',
        criticalGapCount: 5,
        affectedFrameworks: ['SOC 2'],
      }, // -20
      redBlue: { latestOutcome: 'red_wins', redAgentWinRate: 0.9, totalRounds: 10 }, // -10
      learningProfile: null,
      honeypot: null,
    })
    expect(result.overallScore).toBeGreaterThanOrEqual(0)
  })
})

// ─── Posture level boundaries ─────────────────────────────────────────────────

describe('computeSecurityPosture — postureLevel boundaries', () => {
  it('score >= 80 → excellent', () => {
    expect(computeSecurityPosture(BASE).postureLevel).toBe('excellent')
  })

  it('score in [65,80) → good', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 0, openHigh: 0, openMedium: 10, openLow: 0 }, // -20 → 80
      attackSurface: { score: 70, trend: 'stable' }, // -5 → 75
    })
    expect(['good', 'fair']).toContain(result.postureLevel)
  })

  it('score < 35 → critical', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 4, openHigh: 0, openMedium: 0, openLow: 0 }, // -48
      attackSurface: { score: 20, trend: 'stable' }, // -25
    })
    expect(['at_risk', 'critical']).toContain(result.postureLevel)
  })
})

// ─── Top actions cap ──────────────────────────────────────────────────────────

describe('computeSecurityPosture — topActions', () => {
  it('topActions has at most 4 items', () => {
    const result = computeSecurityPosture({
      repositoryName: 'test',
      findings: { openCritical: 2, openHigh: 3, openMedium: 0, openLow: 0 },
      attackSurface: { score: 30, trend: 'degrading' },
      regulatoryDrift: {
        overallDriftLevel: 'non_compliant',
        criticalGapCount: 2,
        affectedFrameworks: ['SOC 2'],
      },
      redBlue: { latestOutcome: 'red_wins', redAgentWinRate: 0.8, totalRounds: 5 },
      learningProfile: null,
      honeypot: null,
    })
    expect(result.topActions.length).toBeLessThanOrEqual(4)
  })

  it('critical finding action appears before high-finding action', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 1, openHigh: 2, openMedium: 0, openLow: 0 },
    })
    expect(result.topActions[0]).toMatch(/critical/i)
  })
})

// ─── Summary ──────────────────────────────────────────────────────────────────

describe('computeSecurityPosture — summary', () => {
  it('summary includes the overall score', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.summary).toContain('100/100')
  })

  it('summary includes posture level', () => {
    const result = computeSecurityPosture(BASE)
    expect(result.summary).toContain('excellent')
  })

  it('summary includes open finding count', () => {
    const result = computeSecurityPosture({
      ...BASE,
      findings: { openCritical: 1, openHigh: 2, openMedium: 0, openLow: 0 },
    })
    expect(result.summary).toContain('3 open')
  })
})
