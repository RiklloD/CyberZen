import { describe, expect, it } from 'vitest'
import {
  analystConfidenceMultiplier,
  analystFpRate,
  computeTriageSummary,
  triageActionToStatus,
  type TriageEvent,
} from './findingTriage'

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

function makeEvent(
  action: TriageEvent['action'],
  overrides: Partial<TriageEvent> = {},
): TriageEvent {
  return { action, createdAt: Date.now(), ...overrides }
}

// ---------------------------------------------------------------------------
// triageActionToStatus
// ---------------------------------------------------------------------------

describe('triageActionToStatus', () => {
  it('mark_false_positive → false_positive', () => {
    expect(triageActionToStatus('mark_false_positive')).toBe('false_positive')
  })

  it('mark_accepted_risk → accepted_risk', () => {
    expect(triageActionToStatus('mark_accepted_risk')).toBe('accepted_risk')
  })

  it('reopen → open', () => {
    expect(triageActionToStatus('reopen')).toBe('open')
  })

  it('ignore → ignored', () => {
    expect(triageActionToStatus('ignore')).toBe('ignored')
  })

  it('add_note → null (no status change)', () => {
    expect(triageActionToStatus('add_note')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// computeTriageSummary — empty log
// ---------------------------------------------------------------------------

describe('computeTriageSummary — empty log', () => {
  it('returns sensible defaults when no events exist', () => {
    const summary = computeTriageSummary([])
    expect(summary.totalEvents).toBe(0)
    expect(summary.isReviewed).toBe(false)
    expect(summary.falsePositiveCount).toBe(0)
    expect(summary.isFalsePositive).toBe(false)
    expect(summary.notes).toHaveLength(0)
    expect(summary.lastStatusAction).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// computeTriageSummary — single events
// ---------------------------------------------------------------------------

describe('computeTriageSummary — single events', () => {
  it('single FP mark → isFalsePositive=true, falsePositiveCount=1', () => {
    const summary = computeTriageSummary([makeEvent('mark_false_positive')])
    expect(summary.isFalsePositive).toBe(true)
    expect(summary.falsePositiveCount).toBe(1)
    expect(summary.isReviewed).toBe(true)
    expect(summary.lastStatusAction).toBe('mark_false_positive')
  })

  it('add_note only → isReviewed=false (notes do not count as review)', () => {
    const summary = computeTriageSummary([makeEvent('add_note', { note: 'looks suspicious' })])
    expect(summary.isReviewed).toBe(false)
    expect(summary.isFalsePositive).toBe(false)
    expect(summary.notes).toEqual(['looks suspicious'])
  })

  it('ignore marks finding without counting as FP', () => {
    const summary = computeTriageSummary([makeEvent('ignore')])
    expect(summary.lastStatusAction).toBe('ignore')
    expect(summary.isFalsePositive).toBe(false)
    expect(summary.falsePositiveCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// computeTriageSummary — last action wins
// ---------------------------------------------------------------------------

describe('computeTriageSummary — last action semantics', () => {
  it('FP then reopen → isFalsePositive=false', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { createdAt: 1000 }),
      makeEvent('reopen', { createdAt: 2000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.isFalsePositive).toBe(false)
    expect(summary.lastStatusAction).toBe('reopen')
    expect(summary.falsePositiveCount).toBe(1)   // still counted historically
  })

  it('multiple FP markings accumulate falsePositiveCount', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { createdAt: 1000 }),
      makeEvent('reopen', { createdAt: 2000 }),
      makeEvent('mark_false_positive', { createdAt: 3000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.isFalsePositive).toBe(true)
    expect(summary.falsePositiveCount).toBe(2)
  })

  it('lastActedAt reflects the most recent status-changing event', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { createdAt: 1000 }),
      makeEvent('reopen', { createdAt: 5000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.lastActedAt).toBe(5000)
  })

  it('add_note interspersed does not affect lastStatusAction', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { createdAt: 1000 }),
      makeEvent('add_note', { createdAt: 2000, note: 'confirmed with team' }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.lastStatusAction).toBe('mark_false_positive')
    expect(summary.isFalsePositive).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// computeTriageSummary — notes collection
// ---------------------------------------------------------------------------

describe('computeTriageSummary — notes', () => {
  it('collects notes from all event types', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { note: 'not exploitable in our config', createdAt: 1000 }),
      makeEvent('add_note', { note: 'verified with security team', createdAt: 2000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.notes).toHaveLength(2)
    expect(summary.notes).toContain('not exploitable in our config')
    expect(summary.notes).toContain('verified with security team')
  })

  it('trims whitespace from notes and skips empty notes', () => {
    const events: TriageEvent[] = [
      makeEvent('add_note', { note: '  ', createdAt: 1000 }),
      makeEvent('add_note', { note: '  valid note  ', createdAt: 2000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.notes).toHaveLength(1)
    expect(summary.notes[0]).toBe('valid note')
  })

  it('lastAnalyst tracks the analyst from the last status action', () => {
    const events: TriageEvent[] = [
      makeEvent('mark_false_positive', { analyst: 'alice@example.com', createdAt: 1000 }),
      makeEvent('reopen', { analyst: 'bob@example.com', createdAt: 2000 }),
    ]
    const summary = computeTriageSummary(events)
    expect(summary.lastAnalyst).toBe('bob@example.com')
  })
})

// ---------------------------------------------------------------------------
// analystFpRate
// ---------------------------------------------------------------------------

describe('analystFpRate', () => {
  it('returns 0 when no reviewed findings', () => {
    expect(analystFpRate([])).toBe(0)
    expect(analystFpRate([{ isReviewed: false, isFalsePositive: false }])).toBe(0)
  })

  it('returns 1.0 when all reviewed findings are FP', () => {
    const summaries = [
      { isReviewed: true, isFalsePositive: true },
      { isReviewed: true, isFalsePositive: true },
    ]
    expect(analystFpRate(summaries)).toBe(1)
  })

  it('returns 0.5 when half of reviewed findings are FP', () => {
    const summaries = [
      { isReviewed: true, isFalsePositive: true },
      { isReviewed: true, isFalsePositive: false },
    ]
    expect(analystFpRate(summaries)).toBe(0.5)
  })

  it('ignores unreviewed findings in the rate calculation', () => {
    const summaries = [
      { isReviewed: true, isFalsePositive: true },
      { isReviewed: false, isFalsePositive: false },  // not reviewed
    ]
    expect(analystFpRate(summaries)).toBe(1)  // 1/1 reviewed are FP
  })
})

// ---------------------------------------------------------------------------
// analystConfidenceMultiplier
// ---------------------------------------------------------------------------

describe('analystConfidenceMultiplier', () => {
  it('returns 1.0 for 0% FP rate (no analyst feedback yet)', () => {
    expect(analystConfidenceMultiplier(0)).toBe(1.0)
  })

  it('returns 0.4 at 100% FP rate (all findings false positive)', () => {
    expect(analystConfidenceMultiplier(1)).toBeCloseTo(0.25, 2)
  })

  it('decreases monotonically as FP rate increases', () => {
    const m0 = analystConfidenceMultiplier(0)
    const m25 = analystConfidenceMultiplier(0.25)
    const m50 = analystConfidenceMultiplier(0.5)
    const m75 = analystConfidenceMultiplier(0.75)
    const m100 = analystConfidenceMultiplier(1)
    expect(m0).toBeGreaterThan(m25)
    expect(m25).toBeGreaterThan(m50)
    expect(m50).toBeGreaterThan(m75)
    expect(m75).toBeGreaterThan(m100)
  })

  it('clamps at 0 FP rate for negative inputs', () => {
    expect(analystConfidenceMultiplier(-0.5)).toBe(analystConfidenceMultiplier(0))
  })

  it('clamps at 100% FP rate for inputs > 1', () => {
    expect(analystConfidenceMultiplier(1.5)).toBe(analystConfidenceMultiplier(1))
  })
})
