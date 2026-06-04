import { describe, expect, it } from 'vitest'
import {
  classifyPriorityTier,
  computeQueueSummary,
  computeRemediationScore,
  prioritizeRemediationQueue,
  type RemediationCandidate,
} from './remediationPriority'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeCandidate(
  overrides: Partial<RemediationCandidate> = {},
): RemediationCandidate {
  return {
    findingId: 'f1',
    title: 'Test finding',
    severity: 'medium',
    slaStatus: 'within_sla',
    blastRadiusScore: -1, // unknown
    exploitAvailable: false,
    validationStatus: 'pending',
    createdAt: 1_000_000,
    repositoryName: 'repo-a',
    affectedPackages: ['lodash'],
    ...overrides,
  }
}

// ─── computeRemediationScore ──────────────────────────────────────────────────

describe('computeRemediationScore', () => {
  it('returns 0 for a baseline candidate with no signals', () => {
    const { score, rationale } = computeRemediationScore(makeCandidate())
    // medium severity contributes 2 but is silent in rationale
    expect(score).toBe(2)
    expect(rationale).toHaveLength(0)
  })

  it('adds 40 for SLA breached', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ slaStatus: 'breached_sla', severity: 'low' }),
    )
    expect(score).toBe(40)
  })

  it('adds 25 for SLA approaching', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ slaStatus: 'approaching_sla', severity: 'low' }),
    )
    expect(score).toBe(25)
  })

  it('adds 20 for exploit available', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ exploitAvailable: true, severity: 'low' }),
    )
    expect(score).toBe(20)
  })

  it('adds 15 for validated status', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ validationStatus: 'validated', severity: 'low' }),
    )
    expect(score).toBe(15)
  })

  it('adds 15 for likely_exploitable status', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ validationStatus: 'likely_exploitable', severity: 'low' }),
    )
    expect(score).toBe(15)
  })

  it('does not add for unexploitable or dismissed', () => {
    expect(
      computeRemediationScore(
        makeCandidate({ validationStatus: 'unexploitable', severity: 'low' }),
      ).score,
    ).toBe(0)
    expect(
      computeRemediationScore(
        makeCandidate({ validationStatus: 'dismissed', severity: 'low' }),
      ).score,
    ).toBe(0)
  })

  it('adds 15 for very high blast radius (≥80)', () => {
    const { score, rationale } = computeRemediationScore(
      makeCandidate({ blastRadiusScore: 85, severity: 'low' }),
    )
    expect(score).toBe(15)
    expect(rationale).toContain('Very high blast radius (impact score 85)')
  })

  it('adds 10 for high blast radius (≥50)', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ blastRadiusScore: 65, severity: 'low' }),
    )
    expect(score).toBe(10)
  })

  it('adds 5 for moderate blast radius (≥20)', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ blastRadiusScore: 30, severity: 'low' }),
    )
    expect(score).toBe(5)
  })

  it('adds 0 for low blast radius (<20)', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ blastRadiusScore: 10, severity: 'low' }),
    )
    expect(score).toBe(0)
  })

  it('adds 0 for unknown blast radius (-1)', () => {
    const { score } = computeRemediationScore(
      makeCandidate({ blastRadiusScore: -1, severity: 'low' }),
    )
    expect(score).toBe(0)
  })

  it('adds 10 for critical severity', () => {
    const { score, rationale } = computeRemediationScore(
      makeCandidate({ severity: 'critical' }),
    )
    expect(score).toBe(10)
    expect(rationale).toContain('Critical severity')
  })

  it('adds 6 for high severity', () => {
    const { score } = computeRemediationScore(makeCandidate({ severity: 'high' }))
    expect(score).toBe(6)
  })

  it('adds 2 for medium severity silently (no rationale entry)', () => {
    const { score, rationale } = computeRemediationScore(
      makeCandidate({ severity: 'medium' }),
    )
    expect(score).toBe(2)
    expect(rationale).toHaveLength(0)
  })

  it('clamps score at 100 for a maxed-out candidate', () => {
    const { score } = computeRemediationScore(
      makeCandidate({
        slaStatus: 'breached_sla', // 40
        exploitAvailable: true, // 20
        validationStatus: 'validated', // 15
        blastRadiusScore: 95, // 15
        severity: 'critical', // 10
      }),
    )
    expect(score).toBe(100)
  })

  it('includes SLA breach rationale when breached', () => {
    const { rationale } = computeRemediationScore(
      makeCandidate({ slaStatus: 'breached_sla', severity: 'low' }),
    )
    expect(rationale[0]).toContain('breached')
  })
})

// ─── classifyPriorityTier ─────────────────────────────────────────────────────

describe('classifyPriorityTier', () => {
  it('returns p0 for score ≥ 70', () => {
    expect(classifyPriorityTier(70)).toBe('p0')
    expect(classifyPriorityTier(100)).toBe('p0')
  })

  it('returns p1 for score in [45, 70)', () => {
    expect(classifyPriorityTier(45)).toBe('p1')
    expect(classifyPriorityTier(69)).toBe('p1')
  })

  it('returns p2 for score in [20, 45)', () => {
    expect(classifyPriorityTier(20)).toBe('p2')
    expect(classifyPriorityTier(44)).toBe('p2')
  })

  it('returns p3 for score < 20', () => {
    expect(classifyPriorityTier(0)).toBe('p3')
    expect(classifyPriorityTier(19)).toBe('p3')
  })
})

// ─── prioritizeRemediationQueue ───────────────────────────────────────────────

describe('prioritizeRemediationQueue', () => {
  it('returns empty array for empty input', () => {
    expect(prioritizeRemediationQueue([])).toHaveLength(0)
  })

  it('sorts by priority score descending', () => {
    const queue = prioritizeRemediationQueue([
      makeCandidate({ findingId: 'low', severity: 'low' }),
      makeCandidate({ findingId: 'critical', severity: 'critical' }),
      makeCandidate({ findingId: 'high', severity: 'high' }),
    ])
    expect(queue[0].findingId).toBe('critical')
    expect(queue[1].findingId).toBe('high')
    expect(queue[2].findingId).toBe('low')
  })

  it('breaks score ties by createdAt ascending (oldest first)', () => {
    const queue = prioritizeRemediationQueue([
      makeCandidate({ findingId: 'newer', severity: 'low', createdAt: 2_000_000 }),
      makeCandidate({ findingId: 'older', severity: 'low', createdAt: 1_000_000 }),
    ])
    expect(queue[0].findingId).toBe('older')
    expect(queue[1].findingId).toBe('newer')
  })

  it('attaches the correct priority tier to each finding', () => {
    // P0: breached(40) + exploit(20) + critical(10) = 70
    // P1: approaching(25) + exploit(20) = 45 (exactly on boundary)
    // P2: validated(15) + critical(10) = 25
    // P3: low severity only = 0
    const queue = prioritizeRemediationQueue([
      makeCandidate({ findingId: 'p0', slaStatus: 'breached_sla', exploitAvailable: true, severity: 'critical' }),
      makeCandidate({ findingId: 'p1', slaStatus: 'approaching_sla', exploitAvailable: true, severity: 'low' }),
      makeCandidate({ findingId: 'p2', validationStatus: 'validated', severity: 'critical' }),
      makeCandidate({ findingId: 'p3', severity: 'low' }),
    ])
    expect(queue[0].priorityTier).toBe('p0')
    expect(queue[1].priorityTier).toBe('p1')
    expect(queue[2].priorityTier).toBe('p2')
    expect(queue[3].priorityTier).toBe('p3')
  })

  it('includes priorityRationale for each finding', () => {
    const queue = prioritizeRemediationQueue([
      makeCandidate({ slaStatus: 'breached_sla', severity: 'low' }),
    ])
    expect(queue[0].priorityRationale.length).toBeGreaterThan(0)
    expect(queue[0].priorityRationale[0]).toContain('breached')
  })

  it('preserves all original candidate fields', () => {
    const original = makeCandidate({
      findingId: 'test-id',
      title: 'My finding',
      affectedPackages: ['lodash', 'express'],
    })
    const [result] = prioritizeRemediationQueue([original])
    expect(result.findingId).toBe('test-id')
    expect(result.title).toBe('My finding')
    expect(result.affectedPackages).toEqual(['lodash', 'express'])
  })
})

// ─── computeQueueSummary ──────────────────────────────────────────────────────

describe('computeQueueSummary', () => {
  it('returns all zeros for an empty queue', () => {
    const summary = computeQueueSummary([])
    expect(summary.totalCandidates).toBe(0)
    expect(summary.p0Count).toBe(0)
    expect(summary.averageScore).toBe(0)
  })

  it('counts findings per tier correctly', () => {
    // Same scoring as the tier test above — one per tier
    const queue = prioritizeRemediationQueue([
      makeCandidate({ findingId: 'p0', slaStatus: 'breached_sla', exploitAvailable: true, severity: 'critical' }),
      makeCandidate({ findingId: 'p1', slaStatus: 'approaching_sla', exploitAvailable: true, severity: 'low' }),
      makeCandidate({ findingId: 'p2', validationStatus: 'validated', severity: 'critical' }),
      makeCandidate({ findingId: 'p3', severity: 'low' }),
    ])
    const summary = computeQueueSummary(queue)
    expect(summary.totalCandidates).toBe(4)
    expect(summary.p0Count).toBe(1)
    expect(summary.p1Count).toBe(1)
    expect(summary.p2Count).toBe(1)
    expect(summary.p3Count).toBe(1)
  })

  it('computes the average score correctly', () => {
    const queue = prioritizeRemediationQueue([
      makeCandidate({ slaStatus: 'breached_sla', severity: 'low' }), // 40
      makeCandidate({ severity: 'low' }), // 0
    ])
    const summary = computeQueueSummary(queue)
    expect(summary.averageScore).toBe(20) // (40 + 0) / 2
  })
})
