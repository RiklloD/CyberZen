import { describe, expect, it } from 'vitest'
import {
  DEFAULT_AUTO_REMEDIATION_POLICY,
  isTierEligible,
  selectRemediationCandidates,
  type AutoRemediationPolicy,
} from './autoRemediation'

// ─── Helpers ─────────────────────────────────────────────────────────────────

type QueueEntry = {
  findingId: string
  title: string
  severity: string
  priorityTier: string
  priorityScore: number
}

function makeEntry(overrides: Partial<QueueEntry> = {}): QueueEntry {
  return {
    findingId: 'f1',
    title: 'Test finding',
    severity: 'critical',
    priorityTier: 'p0',
    priorityScore: 85,
    ...overrides,
  }
}

const ENABLED_POLICY: AutoRemediationPolicy = {
  enabled: true,
  tierThreshold: 'p0',
  maxConcurrentPrs: 3,
  allowedSeverities: ['critical', 'high'],
}

// ─── isTierEligible ───────────────────────────────────────────────────────────

describe('isTierEligible', () => {
  it('accepts p0 under p0 threshold', () => {
    expect(isTierEligible('p0', 'p0')).toBe(true)
  })

  it('rejects p1 under p0 threshold', () => {
    expect(isTierEligible('p1', 'p0')).toBe(false)
  })

  it('rejects p2 under p0 threshold', () => {
    expect(isTierEligible('p2', 'p0')).toBe(false)
  })

  it('rejects p3 under p0 threshold', () => {
    expect(isTierEligible('p3', 'p0')).toBe(false)
  })

  it('accepts p0 under p0_p1 threshold', () => {
    expect(isTierEligible('p0', 'p0_p1')).toBe(true)
  })

  it('accepts p1 under p0_p1 threshold', () => {
    expect(isTierEligible('p1', 'p0_p1')).toBe(true)
  })

  it('rejects p2 under p0_p1 threshold', () => {
    expect(isTierEligible('p2', 'p0_p1')).toBe(false)
  })

  it('rejects p3 under p0_p1 threshold', () => {
    expect(isTierEligible('p3', 'p0_p1')).toBe(false)
  })
})

// ─── selectRemediationCandidates — disabled policy ───────────────────────────

describe('selectRemediationCandidates — disabled policy', () => {
  it('returns policyDisabled=true when policy.enabled=false', () => {
    const result = selectRemediationCandidates(
      [makeEntry()],
      new Set(),
      0,
      DEFAULT_AUTO_REMEDIATION_POLICY,
    )
    expect(result.policyDisabled).toBe(true)
    expect(result.eligible).toHaveLength(0)
  })

  it('marks all findings as skipped with reason disabled', () => {
    const queue = [makeEntry({ findingId: 'f1' }), makeEntry({ findingId: 'f2' })]
    const result = selectRemediationCandidates(
      queue,
      new Set(),
      0,
      DEFAULT_AUTO_REMEDIATION_POLICY,
    )
    expect(result.skipped).toHaveLength(2)
    expect(result.skipped.every((s) => s.reason === 'disabled')).toBe(true)
  })

  it('returns empty eligible and empty skipped for empty queue when disabled', () => {
    const result = selectRemediationCandidates([], new Set(), 0)
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped).toHaveLength(0)
    expect(result.policyDisabled).toBe(true)
  })
})

// ─── selectRemediationCandidates — empty queue ───────────────────────────────

describe('selectRemediationCandidates — empty queue', () => {
  it('returns empty results for an empty queue when enabled', () => {
    const result = selectRemediationCandidates([], new Set(), 0, ENABLED_POLICY)
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped).toHaveLength(0)
    expect(result.policyDisabled).toBe(false)
  })
})

// ─── selectRemediationCandidates — already_has_pr ────────────────────────────

describe('selectRemediationCandidates — already_has_pr', () => {
  it('skips findings that already have an open PR', () => {
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1' })],
      new Set(['f1']),
      0,
      ENABLED_POLICY,
    )
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped[0].reason).toBe('already_has_pr')
  })

  it('only dispatches findings without PRs when some have PRs', () => {
    const queue = [
      makeEntry({ findingId: 'has-pr', priorityScore: 90 }),
      makeEntry({ findingId: 'no-pr', priorityScore: 80 }),
    ]
    const result = selectRemediationCandidates(
      queue,
      new Set(['has-pr']),
      0,
      ENABLED_POLICY,
    )
    expect(result.eligible).toHaveLength(1)
    expect(result.eligible[0].findingId).toBe('no-pr')
    expect(result.skipped[0].findingId).toBe('has-pr')
    expect(result.skipped[0].reason).toBe('already_has_pr')
  })
})

// ─── selectRemediationCandidates — tier filtering ────────────────────────────

describe('selectRemediationCandidates — tier filtering', () => {
  it('skips p1 findings under p0-only threshold', () => {
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', priorityTier: 'p1', priorityScore: 50 })],
      new Set(),
      0,
      ENABLED_POLICY,
    )
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped[0].reason).toBe('below_tier')
  })

  it('skips p2 and p3 findings under p0-only threshold', () => {
    const queue = [
      makeEntry({ findingId: 'f2', priorityTier: 'p2', priorityScore: 25 }),
      makeEntry({ findingId: 'f3', priorityTier: 'p3', priorityScore: 5 }),
    ]
    const result = selectRemediationCandidates(queue, new Set(), 0, ENABLED_POLICY)
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped).toHaveLength(2)
    expect(result.skipped.every((s) => s.reason === 'below_tier')).toBe(true)
  })

  it('accepts p1 under p0_p1 threshold', () => {
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, tierThreshold: 'p0_p1' }
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', priorityTier: 'p1', priorityScore: 50 })],
      new Set(),
      0,
      policy,
    )
    expect(result.eligible).toHaveLength(1)
  })

  it('still rejects p2 under p0_p1 threshold', () => {
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, tierThreshold: 'p0_p1' }
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', priorityTier: 'p2', priorityScore: 25 })],
      new Set(),
      0,
      policy,
    )
    expect(result.skipped[0].reason).toBe('below_tier')
  })
})

// ─── selectRemediationCandidates — severity filtering ────────────────────────

describe('selectRemediationCandidates — severity filtering', () => {
  it('skips medium severity finding when allowedSeverities=[critical,high]', () => {
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', severity: 'medium', priorityTier: 'p0' })],
      new Set(),
      0,
      ENABLED_POLICY,
    )
    expect(result.skipped[0].reason).toBe('below_severity')
  })

  it('skips low severity finding when allowedSeverities=[critical,high]', () => {
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', severity: 'low', priorityTier: 'p0' })],
      new Set(),
      0,
      ENABLED_POLICY,
    )
    expect(result.skipped[0].reason).toBe('below_severity')
  })

  it('accepts all severities when allowedSeverities is empty', () => {
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, allowedSeverities: [] }
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', severity: 'low', priorityTier: 'p0' })],
      new Set(),
      0,
      policy,
    )
    expect(result.eligible).toHaveLength(1)
  })

  it('accepts high severity under default allowed list', () => {
    const result = selectRemediationCandidates(
      [makeEntry({ findingId: 'f1', severity: 'high', priorityTier: 'p0' })],
      new Set(),
      0,
      ENABLED_POLICY,
    )
    expect(result.eligible).toHaveLength(1)
  })
})

// ─── selectRemediationCandidates — concurrency cap ───────────────────────────

describe('selectRemediationCandidates — concurrency cap', () => {
  it('caps eligible at maxConcurrentPrs when queue exceeds limit', () => {
    const queue = [
      makeEntry({ findingId: 'f1', priorityScore: 90 }),
      makeEntry({ findingId: 'f2', priorityScore: 80 }),
      makeEntry({ findingId: 'f3', priorityScore: 75 }),
      makeEntry({ findingId: 'f4', priorityScore: 72 }),
    ]
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, maxConcurrentPrs: 2 }
    const result = selectRemediationCandidates(queue, new Set(), 0, policy)
    expect(result.eligible).toHaveLength(2)
    expect(result.skipped.filter((s) => s.reason === 'concurrency_cap')).toHaveLength(2)
  })

  it('reduces available slots by currentOpenPrCount', () => {
    const queue = [
      makeEntry({ findingId: 'f1', priorityScore: 90 }),
      makeEntry({ findingId: 'f2', priorityScore: 80 }),
    ]
    // maxConcurrentPrs=3 but 2 already open → 1 slot available
    const result = selectRemediationCandidates(queue, new Set(), 2, ENABLED_POLICY)
    expect(result.eligible).toHaveLength(1)
    expect(result.eligible[0].findingId).toBe('f1')
    expect(result.skipped[0].reason).toBe('concurrency_cap')
  })

  it('dispatches nothing when currentOpenPrCount meets the cap', () => {
    const queue = [makeEntry({ findingId: 'f1', priorityScore: 90 })]
    const result = selectRemediationCandidates(queue, new Set(), 3, ENABLED_POLICY)
    expect(result.eligible).toHaveLength(0)
    expect(result.skipped[0].reason).toBe('concurrency_cap')
  })

  it('dispatches nothing when currentOpenPrCount exceeds the cap (over-provisioned)', () => {
    const queue = [makeEntry({ findingId: 'f1', priorityScore: 90 })]
    const result = selectRemediationCandidates(queue, new Set(), 10, ENABLED_POLICY)
    expect(result.eligible).toHaveLength(0)
  })

  it('respects maxConcurrentPrs=1 strictly', () => {
    const queue = [
      makeEntry({ findingId: 'f1', priorityScore: 90 }),
      makeEntry({ findingId: 'f2', priorityScore: 85 }),
      makeEntry({ findingId: 'f3', priorityScore: 80 }),
    ]
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, maxConcurrentPrs: 1 }
    const result = selectRemediationCandidates(queue, new Set(), 0, policy)
    expect(result.eligible).toHaveLength(1)
    expect(result.eligible[0].findingId).toBe('f1')
  })
})

// ─── selectRemediationCandidates — ordering ───────────────────────────────────

describe('selectRemediationCandidates — ordering', () => {
  it('selects the highest-priority findings first (queue is already sorted)', () => {
    const queue = [
      makeEntry({ findingId: 'high', priorityScore: 90 }),
      makeEntry({ findingId: 'mid', priorityScore: 75 }),
      makeEntry({ findingId: 'low', priorityScore: 71 }),
    ]
    const policy: AutoRemediationPolicy = { ...ENABLED_POLICY, maxConcurrentPrs: 2 }
    const result = selectRemediationCandidates(queue, new Set(), 0, policy)
    expect(result.eligible[0].findingId).toBe('high')
    expect(result.eligible[1].findingId).toBe('mid')
    expect(result.skipped[0].findingId).toBe('low')
  })
})

// ─── selectRemediationCandidates — combined filtering ────────────────────────

describe('selectRemediationCandidates — combined conditions', () => {
  it('handles a mix of all skip reasons correctly', () => {
    const queue = [
      makeEntry({ findingId: 'has-pr', priorityTier: 'p0', severity: 'critical' }),
      makeEntry({ findingId: 'wrong-tier', priorityTier: 'p1', severity: 'critical' }),
      makeEntry({ findingId: 'wrong-sev', priorityTier: 'p0', severity: 'low' }),
      makeEntry({ findingId: 'eligible-1', priorityTier: 'p0', severity: 'critical' }),
      makeEntry({ findingId: 'eligible-2', priorityTier: 'p0', severity: 'high' }),
      makeEntry({ findingId: 'cap-hit', priorityTier: 'p0', severity: 'critical' }),
    ]
    const policy: AutoRemediationPolicy = {
      ...ENABLED_POLICY,
      maxConcurrentPrs: 2,
      tierThreshold: 'p0',
      allowedSeverities: ['critical', 'high'],
    }
    const result = selectRemediationCandidates(queue, new Set(['has-pr']), 0, policy)
    expect(result.eligible).toHaveLength(2)
    expect(result.eligible[0].findingId).toBe('eligible-1')
    expect(result.eligible[1].findingId).toBe('eligible-2')

    const skipReasons = Object.fromEntries(
      result.skipped.map((s) => [s.findingId, s.reason]),
    )
    expect(skipReasons['has-pr']).toBe('already_has_pr')
    expect(skipReasons['wrong-tier']).toBe('below_tier')
    expect(skipReasons['wrong-sev']).toBe('below_severity')
    expect(skipReasons['cap-hit']).toBe('concurrency_cap')
  })

  it('preserves all eligible candidate fields in the output', () => {
    const entry = makeEntry({
      findingId: 'f1',
      title: 'SQL injection in login route',
      severity: 'critical',
      priorityTier: 'p0',
      priorityScore: 88,
    })
    const result = selectRemediationCandidates([entry], new Set(), 0, ENABLED_POLICY)
    expect(result.eligible[0]).toMatchObject({
      findingId: 'f1',
      title: 'SQL injection in login route',
      severity: 'critical',
      priorityTier: 'p0',
      priorityScore: 88,
    })
  })
})
