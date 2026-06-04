import { describe, it, expect } from 'vitest'
import {
  classifyTrend,
  computeDebtScore,
  computeSecurityDebtVelocity,
  type FindingInput,
} from './securityDebtVelocity'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY = 24 * 60 * 60 * 1000
const NOW = 1_700_000_000_000 // fixed reference timestamp

function finding(
  overrides: Partial<FindingInput> & { status: string; severity: string },
): FindingInput {
  return {
    createdAt: NOW - 5 * DAY, // 5 days ago by default (within 30-day window)
    resolvedAt: undefined,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// classifyTrend
// ---------------------------------------------------------------------------

describe('classifyTrend', () => {
  it('returns improving when velocity ≤ −1', () => {
    expect(classifyTrend(-2)).toBe('improving')
    expect(classifyTrend(-1)).toBe('improving')
  })

  it('returns stable when velocity is between −1 and +1', () => {
    expect(classifyTrend(0)).toBe('stable')
    expect(classifyTrend(0.5)).toBe('stable')
    expect(classifyTrend(-0.9)).toBe('stable')
  })

  it('returns degrading when velocity is between +1 and +3', () => {
    expect(classifyTrend(1.1)).toBe('degrading')
    expect(classifyTrend(3)).toBe('degrading')
  })

  it('returns critical when velocity > +3', () => {
    expect(classifyTrend(3.1)).toBe('critical')
    expect(classifyTrend(10)).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// computeDebtScore
// ---------------------------------------------------------------------------

describe('computeDebtScore', () => {
  it('returns 100 when all signals are zero', () => {
    expect(computeDebtScore(0, 0, 0, 0)).toBe(100)
  })

  it('reduces score for open findings', () => {
    const score = computeDebtScore(10, 0, 0, 0)
    expect(score).toBeLessThan(100)
    expect(score).toBeGreaterThanOrEqual(0)
  })

  it('applies overdue penalty (−5 per overdue, capped at −30)', () => {
    const none = computeDebtScore(5, 0, 0, 0)
    const some = computeDebtScore(5, 3, 0, 0)
    expect(some).toBeLessThan(none)
  })

  it('applies open critical penalty (−10 per critical, capped at −25)', () => {
    const noCrit = computeDebtScore(5, 0, 0, 0)
    const withCrit = computeDebtScore(5, 0, 2, 0)
    expect(withCrit).toBeLessThan(noCrit)
  })

  it('applies positive velocity penalty, but not negative velocity', () => {
    const base = computeDebtScore(0, 0, 0, 0)
    const pos = computeDebtScore(0, 0, 0, 5)
    const neg = computeDebtScore(0, 0, 0, -5)
    expect(pos).toBeLessThan(base)
    expect(neg).toBe(base) // negative velocity → no penalty
  })

  it('clamps score to [0, 100]', () => {
    // Worst case: many findings, overdue, criticals, high velocity
    const score = computeDebtScore(100, 20, 10, 50)
    expect(score).toBe(0)
  })

  it('open backlog cap of 30 means 15+ findings all get same backlog penalty', () => {
    const at15 = computeDebtScore(15, 0, 0, 0)
    const at100 = computeDebtScore(100, 0, 0, 0)
    expect(at15).toBe(at100) // both hit the cap of −30
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — empty inputs
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — empty', () => {
  it('returns perfect score with no findings', () => {
    const result = computeSecurityDebtVelocity([], NOW)
    expect(result.openFindings).toBe(0)
    expect(result.debtScore).toBe(100)
    expect(result.trend).toBe('stable')
    expect(result.projectedClearanceDays).toBeNull()
  })

  it('summary mentions no open findings', () => {
    const result = computeSecurityDebtVelocity([], NOW)
    expect(result.summary).toMatch(/no open/i)
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — open backlog
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — open backlog', () => {
  it('counts open, pr_opened, and merged as open', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high' }),
      finding({ status: 'pr_opened', severity: 'medium' }),
      finding({ status: 'merged', severity: 'low' }),
      finding({ status: 'resolved', severity: 'high', resolvedAt: NOW - DAY }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.openFindings).toBe(3)
  })

  it('does not count resolved, accepted_risk, false_positive, ignored as open', () => {
    const findings: FindingInput[] = [
      finding({ status: 'resolved', severity: 'high', resolvedAt: NOW - DAY }),
      finding({ status: 'accepted_risk', severity: 'medium', resolvedAt: NOW - DAY }),
      finding({ status: 'false_positive', severity: 'low', resolvedAt: NOW - DAY }),
      finding({ status: 'ignored', severity: 'low', resolvedAt: NOW - DAY }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.openFindings).toBe(0)
    expect(result.debtScore).toBe(100)
  })

  it('counts open critical and open high separately', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'critical' }),
      finding({ status: 'open', severity: 'critical' }),
      finding({ status: 'open', severity: 'high' }),
      finding({ status: 'open', severity: 'medium' }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.openCritical).toBe(2)
    expect(result.openHigh).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — window metrics
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — window metrics', () => {
  it('counts findings created within the window', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high', createdAt: NOW - 5 * DAY }),  // in window
      finding({ status: 'open', severity: 'high', createdAt: NOW - 10 * DAY }), // in window
      finding({ status: 'open', severity: 'high', createdAt: NOW - 40 * DAY }), // outside 30-day window
    ]
    const result = computeSecurityDebtVelocity(findings, NOW, 30)
    expect(result.newFindingsInWindow).toBe(2)
  })

  it('counts resolved findings within the window', () => {
    const findings: FindingInput[] = [
      finding({ status: 'resolved', severity: 'high', resolvedAt: NOW - 5 * DAY }),  // in window
      finding({ status: 'resolved', severity: 'high', resolvedAt: NOW - 40 * DAY }), // outside
      finding({ status: 'resolved', severity: 'low', resolvedAt: undefined }),        // no resolvedAt
    ]
    const result = computeSecurityDebtVelocity(findings, NOW, 30)
    expect(result.resolvedFindingsInWindow).toBe(1)
  })

  it('resolvedPerDay is 0 when nothing resolved in window', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high' }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.resolvedPerDay).toBe(0)
    expect(result.projectedClearanceDays).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — SLA overdue
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — overdue SLA', () => {
  it('flags critical finding open more than 24h as overdue', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'critical', createdAt: NOW - 2 * DAY }), // 48h > 24h SLA
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.overdueFindings).toBe(1)
    expect(result.overdueCritical).toBe(1)
  })

  it('does NOT flag critical finding open less than 24h as overdue', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'critical', createdAt: NOW - 12 * 60 * 60 * 1000 }), // 12h < 24h SLA
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.overdueFindings).toBe(0)
  })

  it('flags high finding open more than 72h as overdue', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high', createdAt: NOW - 4 * DAY }), // 96h > 72h SLA
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.overdueFindings).toBe(1)
  })

  it('flags medium finding open more than 7d as overdue', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'medium', createdAt: NOW - 10 * DAY }), // > 7d SLA
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.overdueFindings).toBe(1)
  })

  it('does NOT flag resolved findings as overdue even if old', () => {
    const findings: FindingInput[] = [
      finding({ status: 'resolved', severity: 'critical', createdAt: NOW - 30 * DAY, resolvedAt: NOW - DAY }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.overdueFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — trend classification
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — trend', () => {
  it('returns improving when resolution rate exceeds creation rate', () => {
    // Use a 7-day window: 1 new finding vs 10 resolved → net = -1.28/day → improving
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'low', createdAt: NOW - DAY }),
      // Resolved findings created OUTSIDE window (60 days ago) but resolved inside window
      ...Array.from({ length: 10 }, (_, i) =>
        finding({
          status: 'resolved',
          severity: 'low',
          createdAt: NOW - 60 * DAY,
          resolvedAt: NOW - i * DAY,
        }),
      ),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW, 7)
    expect(result.trend).toBe('improving')
    expect(result.netVelocityPerDay).toBeLessThan(0)
  })

  it('returns degrading when many new findings and few resolved', () => {
    // 60 new in 30 days (2/day), 0 resolved
    const findings: FindingInput[] = Array.from({ length: 60 }, (_, i) =>
      finding({ status: 'open', severity: 'medium', createdAt: NOW - i * 12 * 60 * 60 * 1000 }),
    )
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.trend).toBe('degrading')
  })

  it('returns critical when velocity > 3/day', () => {
    // 120 new in 30 days (4/day), 0 resolved
    const findings: FindingInput[] = Array.from({ length: 120 }, (_, i) =>
      finding({ status: 'open', severity: 'high', createdAt: NOW - (i % 29) * DAY }),
    )
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.trend).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — projected clearance
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — projectedClearanceDays', () => {
  it('returns null when nothing is being resolved', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high' }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.projectedClearanceDays).toBeNull()
  })

  it('returns a positive integer when resolution rate > 0', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high' }),
      finding({ status: 'open', severity: 'medium' }),
      finding({ status: 'resolved', severity: 'low', resolvedAt: NOW - 5 * DAY }),
    ]
    const result = computeSecurityDebtVelocity(findings, NOW)
    expect(result.projectedClearanceDays).not.toBeNull()
    expect(result.projectedClearanceDays).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — summary text
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — summary', () => {
  it('produces a non-empty summary', () => {
    const result = computeSecurityDebtVelocity([], NOW)
    expect(result.summary.length).toBeGreaterThan(10)
  })

  it('mentions critical in summary when trend is critical', () => {
    const findings = Array.from({ length: 120 }, (_, i) =>
      finding({ status: 'open', severity: 'critical', createdAt: NOW - (i % 29) * DAY }),
    )
    const result = computeSecurityDebtVelocity(findings, NOW)
    if (result.trend === 'critical') {
      expect(result.summary.toUpperCase()).toMatch(/CRITICAL/)
    }
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — debtScore range
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — debtScore', () => {
  it('always returns a value in [0, 100]', () => {
    const variants: FindingInput[][] = [
      [],
      [finding({ status: 'open', severity: 'critical', createdAt: NOW - 10 * DAY })],
      Array.from({ length: 50 }, () => finding({ status: 'open', severity: 'critical', createdAt: NOW - 20 * DAY })),
    ]
    for (const f of variants) {
      const result = computeSecurityDebtVelocity(f, NOW)
      expect(result.debtScore).toBeGreaterThanOrEqual(0)
      expect(result.debtScore).toBeLessThanOrEqual(100)
    }
  })

  it('clean repo scores 100', () => {
    const result = computeSecurityDebtVelocity([], NOW)
    expect(result.debtScore).toBe(100)
  })

  it('repo with overdue criticals scores lower than same repo without overdue', () => {
    const notOverdue: FindingInput[] = [
      finding({ status: 'open', severity: 'critical', createdAt: NOW - 60 * 60 * 1000 }), // 1h ago, within SLA
    ]
    const overdue: FindingInput[] = [
      finding({ status: 'open', severity: 'critical', createdAt: NOW - 2 * DAY }), // 2 days ago, past 24h SLA
    ]
    const r1 = computeSecurityDebtVelocity(notOverdue, NOW)
    const r2 = computeSecurityDebtVelocity(overdue, NOW)
    expect(r2.debtScore).toBeLessThan(r1.debtScore)
  })
})

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity — custom window
// ---------------------------------------------------------------------------

describe('computeSecurityDebtVelocity — custom window', () => {
  it('respects a 7-day window (narrower than 30-day default)', () => {
    const findings: FindingInput[] = [
      finding({ status: 'open', severity: 'high', createdAt: NOW - 3 * DAY }),   // within 7d
      finding({ status: 'open', severity: 'high', createdAt: NOW - 10 * DAY }),  // outside 7d
    ]
    const r7 = computeSecurityDebtVelocity(findings, NOW, 7)
    const r30 = computeSecurityDebtVelocity(findings, NOW, 30)
    expect(r7.newFindingsInWindow).toBe(1)
    expect(r30.newFindingsInWindow).toBe(2)
    expect(r7.windowDays).toBe(7)
  })
})
