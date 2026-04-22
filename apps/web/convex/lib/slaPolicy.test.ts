import { describe, expect, it } from 'vitest'
import {
  DEFAULT_SLA_POLICY,
  assessSlaFinding,
  computeSlaDeadline,
  computeSlaSummary,
  getSlaThresholdHours,
  type SlaFindingAssessment,
} from './slaPolicy'

const H = (hours: number) => hours * 3_600_000 // hours → ms

// ── getSlaThresholdHours ──────────────────────────────────────────────────────

describe('getSlaThresholdHours', () => {
  it('returns 24h for critical', () => {
    expect(getSlaThresholdHours('critical', DEFAULT_SLA_POLICY)).toBe(24)
  })
  it('returns 72h for high', () => {
    expect(getSlaThresholdHours('high', DEFAULT_SLA_POLICY)).toBe(72)
  })
  it('returns 168h for medium', () => {
    expect(getSlaThresholdHours('medium', DEFAULT_SLA_POLICY)).toBe(168)
  })
  it('returns 720h for low', () => {
    expect(getSlaThresholdHours('low', DEFAULT_SLA_POLICY)).toBe(720)
  })
  it('returns null for informational', () => {
    expect(getSlaThresholdHours('informational', DEFAULT_SLA_POLICY)).toBeNull()
  })
})

// ── computeSlaDeadline ────────────────────────────────────────────────────────

describe('computeSlaDeadline', () => {
  const BASE = 1_700_000_000_000

  it('critical deadline = openedAt + 24 hours', () => {
    expect(computeSlaDeadline(BASE, 'critical', DEFAULT_SLA_POLICY)).toBe(
      BASE + H(24),
    )
  })
  it('high deadline = openedAt + 72 hours', () => {
    expect(computeSlaDeadline(BASE, 'high', DEFAULT_SLA_POLICY)).toBe(
      BASE + H(72),
    )
  })
  it('informational has no deadline', () => {
    expect(
      computeSlaDeadline(BASE, 'informational', DEFAULT_SLA_POLICY),
    ).toBeNull()
  })
})

// ── assessSlaFinding — inactive statuses ──────────────────────────────────────

describe('assessSlaFinding — inactive statuses are not_applicable', () => {
  const BASE = 1_700_000_000_000
  const now = BASE + H(10)

  it('resolved → not_applicable with null deadline/remaining/percent', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'resolved',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: now,
    })
    expect(r.slaStatus).toBe('not_applicable')
    expect(r.deadlineAt).toBeNull()
    expect(r.hoursRemaining).toBeNull()
    expect(r.percentElapsed).toBeNull()
  })

  it('accepted_risk → not_applicable', () => {
    expect(
      assessSlaFinding({
        findingId: 'f1',
        severity: 'high',
        status: 'accepted_risk',
        openedAt: BASE,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      }).slaStatus,
    ).toBe('not_applicable')
  })

  it('false_positive → not_applicable', () => {
    expect(
      assessSlaFinding({
        findingId: 'f1',
        severity: 'high',
        status: 'false_positive',
        openedAt: BASE,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      }).slaStatus,
    ).toBe('not_applicable')
  })

  it('ignored → not_applicable', () => {
    expect(
      assessSlaFinding({
        findingId: 'f1',
        severity: 'medium',
        status: 'ignored',
        openedAt: BASE,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      }).slaStatus,
    ).toBe('not_applicable')
  })

  it('informational severity + open status → not_applicable', () => {
    expect(
      assessSlaFinding({
        findingId: 'f1',
        severity: 'informational',
        status: 'open',
        openedAt: BASE,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      }).slaStatus,
    ).toBe('not_applicable')
  })
})

// ── assessSlaFinding — active statuses ───────────────────────────────────────

describe('assessSlaFinding — active findings', () => {
  const BASE = 1_700_000_000_000

  it('critical open finding at 10% elapsed is within_sla', () => {
    const now = BASE + H(2.4) // 2.4 / 24 = 10%
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: now,
    })
    expect(r.slaStatus).toBe('within_sla')
    expect(r.deadlineAt).toBe(BASE + H(24))
    expect(r.hoursRemaining).toBeCloseTo(21.6)
    expect(r.percentElapsed).toBeCloseTo(0.1)
  })

  it('high finding at 80% elapsed is approaching_sla', () => {
    const now = BASE + H(57.6) // 57.6 / 72 = 80%
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'high',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: now,
    })
    expect(r.slaStatus).toBe('approaching_sla')
    expect(r.percentElapsed).toBeCloseTo(0.8)
  })

  it('medium finding past deadline is breached_sla', () => {
    const now = BASE + H(200) // 200h > 168h threshold
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'medium',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: now,
    })
    expect(r.slaStatus).toBe('breached_sla')
    expect(r.hoursRemaining).toBeNull()
  })

  it('pr_opened status counts as active (within_sla)', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'pr_opened',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(1),
    })
    expect(r.slaStatus).toBe('within_sla')
  })

  it('merged status counts as active (within_sla)', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'high',
      status: 'merged',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(1),
    })
    expect(r.slaStatus).toBe('within_sla')
  })

  it('hoursRemaining is null when breached', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(100),
    })
    expect(r.hoursRemaining).toBeNull()
  })

  it('hoursRemaining > 0 when within SLA', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(10),
    })
    expect(r.hoursRemaining).toBeGreaterThan(0)
  })

  it('percentElapsed is 0 at exactly openedAt', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE,
    })
    expect(r.percentElapsed).toBe(0)
    expect(r.slaStatus).toBe('within_sla')
  })

  it('percentElapsed is 1.0 at exact deadline → breached_sla', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(24), // exactly at deadline
    })
    expect(r.percentElapsed).toBe(1.0)
    // nowMs >= deadlineAt → breached
    expect(r.slaStatus).toBe('breached_sla')
  })

  it('hoursElapsed accumulates correctly for a breached finding', () => {
    const r = assessSlaFinding({
      findingId: 'f1',
      severity: 'critical',
      status: 'open',
      openedAt: BASE,
      policy: DEFAULT_SLA_POLICY,
      nowMs: BASE + H(48),
    })
    expect(r.hoursElapsed).toBeCloseTo(48)
  })
})

// ── computeSlaSummary ─────────────────────────────────────────────────────────

describe('computeSlaSummary', () => {
  const makeA = (
    slaStatus: SlaFindingAssessment['slaStatus'],
  ): SlaFindingAssessment => ({
    findingId: 'f',
    severity: 'high',
    status: 'open',
    openedAt: 0,
    deadlineAt: null,
    slaStatus,
    hoursElapsed: 0,
    hoursRemaining: null,
    percentElapsed: null,
  })

  it('empty assessments → totalTracked 0, complianceRate 1.0, mttrHours null', () => {
    const s = computeSlaSummary([], [])
    expect(s.totalTracked).toBe(0)
    expect(s.complianceRate).toBe(1.0)
    expect(s.mttrHours).toBeNull()
  })

  it('all within_sla → complianceRate 1.0', () => {
    const s = computeSlaSummary(
      [makeA('within_sla'), makeA('within_sla')],
      [],
    )
    expect(s.withinSla).toBe(2)
    expect(s.complianceRate).toBe(1.0)
  })

  it('all breached_sla → complianceRate 0.0', () => {
    const s = computeSlaSummary(
      [makeA('breached_sla'), makeA('breached_sla')],
      [],
    )
    expect(s.breachedSla).toBe(2)
    expect(s.complianceRate).toBe(0.0)
  })

  it('approaching_sla counts toward compliance numerator', () => {
    const s = computeSlaSummary(
      [makeA('within_sla'), makeA('approaching_sla'), makeA('breached_sla')],
      [],
    )
    expect(s.totalTracked).toBe(3)
    expect(s.complianceRate).toBeCloseTo(2 / 3)
  })

  it('not_applicable excluded from compliance denominator', () => {
    const s = computeSlaSummary(
      [makeA('within_sla'), makeA('not_applicable')],
      [],
    )
    expect(s.totalTracked).toBe(1)
    expect(s.notApplicable).toBe(1)
    expect(s.complianceRate).toBe(1.0)
  })

  it('counts each status bucket correctly', () => {
    const s = computeSlaSummary(
      [
        makeA('within_sla'),
        makeA('within_sla'),
        makeA('approaching_sla'),
        makeA('breached_sla'),
        makeA('not_applicable'),
      ],
      [],
    )
    expect(s.withinSla).toBe(2)
    expect(s.approachingSla).toBe(1)
    expect(s.breachedSla).toBe(1)
    expect(s.notApplicable).toBe(1)
  })

  it('no resolved findings → mttrHours null', () => {
    const s = computeSlaSummary([makeA('within_sla')], [])
    expect(s.mttrHours).toBeNull()
  })

  it('single resolved finding → mttrHours = hours to resolve', () => {
    const base = 1_700_000_000_000
    const s = computeSlaSummary([], [{ createdAt: base, resolvedAt: base + H(48) }])
    expect(s.mttrHours).toBeCloseTo(48)
  })

  it('multiple resolved findings → mttrHours = average', () => {
    const base = 1_700_000_000_000
    const s = computeSlaSummary([], [
      { createdAt: base, resolvedAt: base + H(24) },
      { createdAt: base, resolvedAt: base + H(48) },
    ])
    expect(s.mttrHours).toBeCloseTo(36)
  })
})
