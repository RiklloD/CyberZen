import { describe, expect, it } from 'vitest'
import {
  DEFAULT_ESCALATION_POLICY,
  assessEscalation,
  escalateSeverityForTrigger,
  getSeverityRank,
  type EscalationContext,
  type EscalationPolicy,
} from './escalationPolicy'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeCtx(overrides: Partial<EscalationContext> = {}): EscalationContext {
  return {
    currentSeverity: 'low',
    exploitAvailable: false,
    blastRadiusScore: -1,
    affectedRepoCount: 0,
    slaStatus: 'within_sla',
    ...overrides,
  }
}

// ─── getSeverityRank ──────────────────────────────────────────────────────────

describe('getSeverityRank', () => {
  it('returns 0 for informational', () => {
    expect(getSeverityRank('informational')).toBe(0)
  })

  it('returns 1 for low', () => {
    expect(getSeverityRank('low')).toBe(1)
  })

  it('returns 2 for medium', () => {
    expect(getSeverityRank('medium')).toBe(2)
  })

  it('returns 3 for high', () => {
    expect(getSeverityRank('high')).toBe(3)
  })

  it('returns 4 for critical', () => {
    expect(getSeverityRank('critical')).toBe(4)
  })

  it('produces a strictly ascending order across the severity ladder', () => {
    const ranks = (['informational', 'low', 'medium', 'high', 'critical'] as const).map(
      getSeverityRank,
    )
    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeGreaterThan(ranks[i - 1])
    }
  })
})

// ─── escalateSeverityForTrigger ───────────────────────────────────────────────

describe('escalateSeverityForTrigger — exploit_available (ceiling: critical)', () => {
  it('escalates low → medium', () => {
    expect(escalateSeverityForTrigger('low', 'exploit_available')).toBe('medium')
  })

  it('escalates medium → high', () => {
    expect(escalateSeverityForTrigger('medium', 'exploit_available')).toBe('high')
  })

  it('escalates high → critical (reaches ceiling)', () => {
    expect(escalateSeverityForTrigger('high', 'exploit_available')).toBe('critical')
  })

  it('leaves critical unchanged (already at ceiling)', () => {
    expect(escalateSeverityForTrigger('critical', 'exploit_available')).toBe('critical')
  })
})

describe('escalateSeverityForTrigger — blast_radius_critical (ceiling: high)', () => {
  it('escalates low → medium', () => {
    expect(escalateSeverityForTrigger('low', 'blast_radius_critical')).toBe('medium')
  })

  it('escalates medium → high (reaches ceiling)', () => {
    expect(escalateSeverityForTrigger('medium', 'blast_radius_critical')).toBe('high')
  })

  it('leaves high unchanged (already at ceiling)', () => {
    expect(escalateSeverityForTrigger('high', 'blast_radius_critical')).toBe('high')
  })

  it('leaves critical unchanged (above ceiling)', () => {
    expect(escalateSeverityForTrigger('critical', 'blast_radius_critical')).toBe('critical')
  })
})

describe('escalateSeverityForTrigger — cross_repo_spread (ceiling: high)', () => {
  it('escalates low → medium', () => {
    expect(escalateSeverityForTrigger('low', 'cross_repo_spread')).toBe('medium')
  })

  it('escalates medium → high (reaches ceiling)', () => {
    expect(escalateSeverityForTrigger('medium', 'cross_repo_spread')).toBe('high')
  })

  it('leaves high unchanged (at ceiling)', () => {
    expect(escalateSeverityForTrigger('high', 'cross_repo_spread')).toBe('high')
  })
})

describe('escalateSeverityForTrigger — blast_radius_high (ceiling: medium)', () => {
  it('escalates low → medium (reaches ceiling)', () => {
    expect(escalateSeverityForTrigger('low', 'blast_radius_high')).toBe('medium')
  })

  it('leaves medium unchanged (at ceiling)', () => {
    expect(escalateSeverityForTrigger('medium', 'blast_radius_high')).toBe('medium')
  })

  it('leaves high unchanged (above ceiling)', () => {
    expect(escalateSeverityForTrigger('high', 'blast_radius_high')).toBe('high')
  })
})

describe('escalateSeverityForTrigger — sla_breach (ceiling: medium)', () => {
  it('escalates low → medium (reaches ceiling)', () => {
    expect(escalateSeverityForTrigger('low', 'sla_breach')).toBe('medium')
  })

  it('leaves medium unchanged (at ceiling)', () => {
    expect(escalateSeverityForTrigger('medium', 'sla_breach')).toBe('medium')
  })

  it('leaves high unchanged (above ceiling)', () => {
    expect(escalateSeverityForTrigger('high', 'sla_breach')).toBe('high')
  })
})

// ─── assessEscalation — boundary conditions ───────────────────────────────────

describe('assessEscalation — boundary conditions', () => {
  it('never escalates informational findings regardless of all triggers', () => {
    const result = assessEscalation(
      makeCtx({
        currentSeverity: 'informational',
        exploitAvailable: true,
        blastRadiusScore: 95,
        affectedRepoCount: 10,
        slaStatus: 'breached_sla',
      }),
    )
    expect(result.shouldEscalate).toBe(false)
    expect(result.newSeverity).toBe('informational')
    expect(result.triggers).toHaveLength(0)
    expect(result.rationale).toHaveLength(0)
  })

  it('never escalates critical findings (already at maximum severity)', () => {
    const result = assessEscalation(
      makeCtx({
        currentSeverity: 'critical',
        exploitAvailable: true,
        blastRadiusScore: 95,
        affectedRepoCount: 10,
        slaStatus: 'breached_sla',
      }),
    )
    expect(result.shouldEscalate).toBe(false)
    expect(result.newSeverity).toBe('critical')
    expect(result.triggers).toHaveLength(0)
  })

  it('does not escalate when no triggers are active', () => {
    const result = assessEscalation(makeCtx({ currentSeverity: 'medium' }))
    expect(result.shouldEscalate).toBe(false)
    expect(result.newSeverity).toBe('medium')
    expect(result.currentSeverity).toBe('medium')
    expect(result.triggers).toHaveLength(0)
    expect(result.rationale).toHaveLength(0)
  })

  it('reflects currentSeverity in both currentSeverity and newSeverity when no escalation', () => {
    const result = assessEscalation(makeCtx({ currentSeverity: 'high' }))
    expect(result.currentSeverity).toBe('high')
    expect(result.newSeverity).toBe('high')
    expect(result.shouldEscalate).toBe(false)
  })
})

// ─── assessEscalation — exploit_available ────────────────────────────────────

describe('assessEscalation — exploit_available trigger', () => {
  it('escalates low → medium when exploit is available', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', exploitAvailable: true }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('medium')
    expect(result.triggers).toContain('exploit_available')
  })

  it('escalates medium → high when exploit is available', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', exploitAvailable: true }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('high')
  })

  it('escalates high → critical when exploit is available', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'high', exploitAvailable: true }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('critical')
  })

  it('does not escalate when exploitAvailable = false', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', exploitAvailable: false }),
    )
    expect(result.shouldEscalate).toBe(false)
  })
})

// ─── assessEscalation — blast radius triggers ─────────────────────────────────

describe('assessEscalation — blast_radius_critical trigger (score ≥ 80)', () => {
  it('activates blast_radius_critical when score equals the threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 80 }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.triggers).toContain('blast_radius_critical')
    expect(result.triggers).not.toContain('blast_radius_high')
  })

  it('escalates low → medium on blast_radius_critical', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 85 }),
    )
    expect(result.newSeverity).toBe('medium')
  })

  it('escalates medium → high on blast_radius_critical', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', blastRadiusScore: 90 }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('high')
  })

  it('does not escalate high (already at blast_radius_critical ceiling)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'high', blastRadiusScore: 95 }),
    )
    // blast_radius_critical ceiling is high; high >= high → no escalation from this trigger
    expect(result.shouldEscalate).toBe(false)
  })
})

describe('assessEscalation — blast_radius_high trigger (60 ≤ score < 80)', () => {
  it('activates blast_radius_high when score is at the lower threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 60 }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.triggers).toContain('blast_radius_high')
    expect(result.triggers).not.toContain('blast_radius_critical')
  })

  it('activates blast_radius_high for score just below the critical threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 79 }),
    )
    expect(result.triggers).toContain('blast_radius_high')
    expect(result.triggers).not.toContain('blast_radius_critical')
  })

  it('escalates low → medium on blast_radius_high', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 70 }),
    )
    expect(result.newSeverity).toBe('medium')
  })

  it('does not escalate medium (already at blast_radius_high ceiling)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', blastRadiusScore: 70 }),
    )
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate any blast trigger when score is below high threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 59 }),
    )
    expect(result.triggers).not.toContain('blast_radius_high')
    expect(result.triggers).not.toContain('blast_radius_critical')
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate any blast trigger when score is -1 (unknown)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: -1 }),
    )
    expect(result.triggers).not.toContain('blast_radius_high')
    expect(result.triggers).not.toContain('blast_radius_critical')
  })
})

// ─── assessEscalation — cross_repo_spread trigger ────────────────────────────

describe('assessEscalation — cross_repo_spread trigger', () => {
  it('activates when affectedRepoCount meets the threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 3 }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.triggers).toContain('cross_repo_spread')
  })

  it('escalates low → medium on cross_repo_spread', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 5 }),
    )
    expect(result.newSeverity).toBe('medium')
  })

  it('escalates medium → high on cross_repo_spread', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', affectedRepoCount: 5 }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('high')
  })

  it('does not escalate high (already at cross_repo_spread ceiling)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'high', affectedRepoCount: 10 }),
    )
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate when count is below threshold', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 2 }),
    )
    expect(result.triggers).not.toContain('cross_repo_spread')
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate when affectedRepoCount is 0', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 0 }),
    )
    expect(result.triggers).not.toContain('cross_repo_spread')
  })
})

// ─── assessEscalation — sla_breach trigger ───────────────────────────────────

describe('assessEscalation — sla_breach trigger', () => {
  it('activates on breached_sla and escalates low → medium', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', slaStatus: 'breached_sla' }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('medium')
    expect(result.triggers).toContain('sla_breach')
  })

  it('does not escalate medium (already at sla_breach ceiling)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', slaStatus: 'breached_sla' }),
    )
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate on approaching_sla (urgency only signals breach)', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', slaStatus: 'approaching_sla' }),
    )
    expect(result.triggers).not.toContain('sla_breach')
    expect(result.shouldEscalate).toBe(false)
  })

  it('does not activate on within_sla', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', slaStatus: 'within_sla' }),
    )
    expect(result.triggers).not.toContain('sla_breach')
  })

  it('does not activate on not_applicable', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', slaStatus: 'not_applicable' }),
    )
    expect(result.triggers).not.toContain('sla_breach')
  })
})

// ─── assessEscalation — multi-trigger resolution ─────────────────────────────

describe('assessEscalation — multi-trigger resolution', () => {
  it('highest-ceiling trigger wins when multiple are active on same severity', () => {
    // exploit (ceiling: critical) and sla_breach (ceiling: medium) both active on low
    // exploit proposes: low+1=medium; sla_breach proposes: low+1=medium (both at ceiling)
    // max = medium
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', exploitAvailable: true, slaStatus: 'breached_sla' }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('medium')
    expect(result.triggers).toContain('exploit_available')
    expect(result.triggers).toContain('sla_breach')
  })

  it('exploit elevates beyond sla_breach ceiling from medium', () => {
    // exploit (ceiling: critical) on medium → proposes high
    // sla_breach (ceiling: medium) on medium → at ceiling, proposes medium (no change)
    // max = high
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'medium', exploitAvailable: true, slaStatus: 'breached_sla' }),
    )
    expect(result.shouldEscalate).toBe(true)
    expect(result.newSeverity).toBe('high')
    expect(result.triggers).toContain('exploit_available')
    expect(result.triggers).toContain('sla_breach')
  })

  it('all triggers active on low → escalates to medium (each proposes +1 from low)', () => {
    const result = assessEscalation(
      makeCtx({
        currentSeverity: 'low',
        exploitAvailable: true,
        blastRadiusScore: 90,
        affectedRepoCount: 5,
        slaStatus: 'breached_sla',
      }),
    )
    expect(result.shouldEscalate).toBe(true)
    // All triggers propose medium from low (each is +1 from rank 1, capped at their ceiling)
    expect(result.newSeverity).toBe('medium')
    expect(result.triggers).toHaveLength(4) // exploit, blast_radius_critical, cross_repo, sla_breach
  })

  it('rationale includes entries for all active triggers when shouldEscalate=true', () => {
    const result = assessEscalation(
      makeCtx({
        currentSeverity: 'low',
        exploitAvailable: true,
        slaStatus: 'breached_sla',
      }),
    )
    expect(result.rationale).toHaveLength(2)
  })

  it('triggers and rationale are empty arrays when shouldEscalate = false', () => {
    const result = assessEscalation(makeCtx({ currentSeverity: 'low' }))
    expect(result.triggers).toEqual([])
    expect(result.rationale).toEqual([])
  })
})

// ─── assessEscalation — rationale content ────────────────────────────────────

describe('assessEscalation — rationale strings', () => {
  it('exploit_available rationale mentions public exploit', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', exploitAvailable: true }),
    )
    expect(result.rationale[0]).toContain('exploit')
  })

  it('blast_radius_critical rationale includes the actual impact score', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 88 }),
    )
    const blastRationale = result.rationale.find((r) => r.includes('88'))
    expect(blastRationale).toBeDefined()
  })

  it('blast_radius_high rationale includes the actual impact score', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 72 }),
    )
    const blastRationale = result.rationale.find((r) => r.includes('72'))
    expect(blastRationale).toBeDefined()
  })

  it('cross_repo_spread rationale includes the repository count', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 7 }),
    )
    const spreadRationale = result.rationale.find((r) => r.includes('7'))
    expect(spreadRationale).toBeDefined()
  })

  it('sla_breach rationale mentions SLA or deadline', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', slaStatus: 'breached_sla' }),
    )
    const slaRationale = result.rationale.find(
      (r) => r.toLowerCase().includes('sla') || r.toLowerCase().includes('deadline'),
    )
    expect(slaRationale).toBeDefined()
  })
})

// ─── assessEscalation — custom policy ────────────────────────────────────────

describe('assessEscalation — custom EscalationPolicy', () => {
  const strictPolicy: EscalationPolicy = {
    blastRadiusCriticalThreshold: 50,
    blastRadiusHighThreshold: 30,
    crossRepoSpreadThreshold: 2,
  }

  it('activates blast_radius_high at score 40 under a lower threshold policy', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 40 }),
      strictPolicy,
    )
    expect(result.triggers).toContain('blast_radius_high')
    expect(result.shouldEscalate).toBe(true)
  })

  it('activates blast_radius_critical at score 50 under a lower threshold policy', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 50 }),
      strictPolicy,
    )
    expect(result.triggers).toContain('blast_radius_critical')
    expect(result.triggers).not.toContain('blast_radius_high')
  })

  it('activates cross_repo_spread at count 2 under a lower threshold policy', () => {
    const result = assessEscalation(
      makeCtx({ currentSeverity: 'low', affectedRepoCount: 2 }),
      strictPolicy,
    )
    expect(result.triggers).toContain('cross_repo_spread')
  })

  it('default policy is used when no policy argument is provided', () => {
    // Score 79 is below the default critical threshold (80) but above high (60)
    const withDefault = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 79 }),
    )
    const withExplicit = assessEscalation(
      makeCtx({ currentSeverity: 'low', blastRadiusScore: 79 }),
      DEFAULT_ESCALATION_POLICY,
    )
    expect(withDefault.triggers).toEqual(withExplicit.triggers)
    expect(withDefault.newSeverity).toEqual(withExplicit.newSeverity)
  })
})
