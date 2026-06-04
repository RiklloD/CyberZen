/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeLearningProfile } from './learningLoop'
import type { AttackSurfacePoint, FindingHistoryEntry, LearningLoopInput, RedBlueRoundEntry } from './learningLoop'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const EMPTY: LearningLoopInput = {
  findingHistory: [],
  redBlueRounds: [],
  attackSurfaceHistory: [],
}

function finding(
  vulnClass: string,
  validationStatus: string,
  severity: FindingHistoryEntry['severity'] = 'medium',
): FindingHistoryEntry {
  return { vulnClass, severity, status: 'open', validationStatus }
}

function round(outcome: RedBlueRoundEntry['roundOutcome'], chains: string[] = []): RedBlueRoundEntry {
  return { roundOutcome: outcome, exploitChains: chains }
}

function surfacePoint(score: number): AttackSurfacePoint {
  return { score }
}

// ─── Empty input ──────────────────────────────────────────────────────────────

describe('computeLearningProfile — empty input', () => {
  it('returns zero counts for empty input', () => {
    const result = computeLearningProfile(EMPTY)
    expect(result.totalFindingsAnalyzed).toBe(0)
    expect(result.totalRoundsAnalyzed).toBe(0)
    expect(result.recurringCount).toBe(0)
    expect(result.suppressedCount).toBe(0)
  })

  it('returns unknown trend when no history', () => {
    expect(computeLearningProfile(EMPTY).attackSurfaceTrend).toBe('unknown')
  })

  it('returns zero adapted confidence score for empty input', () => {
    expect(computeLearningProfile(EMPTY).adaptedConfidenceScore).toBe(0)
  })

  it('returns zero red agent win rate for no rounds', () => {
    expect(computeLearningProfile(EMPTY).redAgentWinRate).toBe(0)
  })

  it('returns empty exploit paths for no rounds', () => {
    expect(computeLearningProfile(EMPTY).successfulExploitPaths).toHaveLength(0)
  })
})

// ─── Vuln class classification ────────────────────────────────────────────────

describe('computeLearningProfile — vuln class classification', () => {
  it('single confirmed finding → not recurring, multiplier = 1.0', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [finding('sql_injection', 'validated')],
    })
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'sql_injection')!
    expect(pattern.isRecurring).toBe(false)
    expect(pattern.confidenceMultiplier).toBe(1.0)
  })

  it('two confirmed findings in same class → recurring', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('xss', 'validated'),
        finding('xss', 'likely_exploitable'),
      ],
    })
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'xss')!
    expect(pattern.isRecurring).toBe(true)
    // recurringCount lives on LearningProfileResult, not on VulnClassLearning
    expect((pattern as Record<string, unknown>).recurringCount).toBeUndefined()
  })

  it('multiplier = min(2.0, 1.0 + confirmedCount * 0.25) when recurring', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('xss', 'validated'),
        finding('xss', 'validated'),
        finding('xss', 'validated'),
        finding('xss', 'validated'),
      ],
    })
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'xss')!
    // 1.0 + 4 * 0.25 = 2.0
    expect(pattern.confidenceMultiplier).toBe(2.0)
  })

  it('multiplier caps at 2.0 for very many confirmed findings', () => {
    const findings = Array.from({ length: 20 }, () => finding('path_traversal', 'validated'))
    const result = computeLearningProfile({ ...EMPTY, findingHistory: findings })
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'path_traversal')!
    expect(pattern.confidenceMultiplier).toBe(2.0)
  })

  it('FP rate > 0.6 → suppressed, multiplier = 0.5', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('timing_attack', 'unexploitable'),
        finding('timing_attack', 'unexploitable'),
        finding('timing_attack', 'unexploitable'),
        finding('timing_attack', 'validated'),
      ],
    })
    // FP rate = 3/4 = 0.75 > 0.6
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'timing_attack')!
    expect(pattern.isSuppressed).toBe(true)
    expect(pattern.confidenceMultiplier).toBe(0.5)
  })

  it('FP rate exactly at threshold (0.6) → not suppressed', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('csrf', 'unexploitable'),
        finding('csrf', 'unexploitable'),
        finding('csrf', 'unexploitable'),
        finding('csrf', 'validated'),
        finding('csrf', 'validated'),
      ],
    })
    // FP rate = 3/5 = 0.6 — NOT > 0.6
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'csrf')!
    expect(pattern.isSuppressed).toBe(false)
  })

  it('pending/skipped findings count toward total but not confirmed or FP', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('open_redirect', 'pending'),
        finding('open_redirect', 'skipped'),
        finding('open_redirect', 'validated'),
      ],
    })
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'open_redirect')!
    expect(pattern.totalCount).toBe(3)
    expect(pattern.confirmedCount).toBe(1)
    expect(pattern.falsePositiveCount).toBe(0)
  })

  it('vuln class names are normalised (hyphens + spaces → underscores, lowercase)', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('SQL Injection', 'validated'),
        finding('sql-injection', 'validated'),
        finding('sql_injection', 'validated'),
      ],
    })
    // All three should merge into a single 'sql_injection' class
    const pattern = result.vulnClassPatterns.find((p) => p.vulnClass === 'sql_injection')
    expect(pattern).toBeDefined()
    expect(pattern!.totalCount).toBe(3)
    expect(pattern!.confirmedCount).toBe(3)
  })
})

// ─── recurringCount / suppressedCount ────────────────────────────────────────

describe('computeLearningProfile — aggregate counts', () => {
  it('recurringCount counts classes with isRecurring = true', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('xss', 'validated'),
        finding('xss', 'validated'),
        finding('sqli', 'validated'), // only 1 → not recurring
      ],
    })
    expect(result.recurringCount).toBe(1)
  })

  it('suppressedCount counts classes with isSuppressed = true', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('noise', 'unexploitable'),
        finding('noise', 'unexploitable'),
        finding('noise', 'unexploitable'),
        finding('real', 'validated'),
      ],
    })
    expect(result.suppressedCount).toBe(1)
  })
})

// ─── Proposal ordering ────────────────────────────────────────────────────────

describe('computeLearningProfile — vuln class ordering', () => {
  it('recurring classes appear before non-recurring', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('single', 'validated'),   // not recurring
        finding('double', 'validated'),
        finding('double', 'validated'),   // recurring
      ],
    })
    expect(result.vulnClassPatterns[0].vulnClass).toBe('double')
  })

  it('within recurring, higher confirmedCount appears first', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [
        finding('a', 'validated'), finding('a', 'validated'),              // 2 confirmed
        finding('b', 'validated'), finding('b', 'validated'), finding('b', 'validated'), // 3 confirmed
      ],
    })
    const recurring = result.vulnClassPatterns.filter((p) => p.isRecurring)
    expect(recurring[0].vulnClass).toBe('b')
  })
})

// ─── Red agent exploit paths ──────────────────────────────────────────────────

describe('computeLearningProfile — exploit paths', () => {
  it('collects exploit chains from red_wins rounds', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [
        round('red_wins', ['chain A', 'chain B']),
        round('blue_wins', ['chain C']),
      ],
    })
    expect(result.successfulExploitPaths).toContain('chain A')
    expect(result.successfulExploitPaths).toContain('chain B')
    expect(result.successfulExploitPaths).not.toContain('chain C')
  })

  it('deduplicates exploit chains across rounds', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [
        round('red_wins', ['chain A']),
        round('red_wins', ['chain A', 'chain B']),
      ],
    })
    expect(result.successfulExploitPaths.filter((c) => c === 'chain A')).toHaveLength(1)
  })

  it('draw rounds do not contribute exploit paths', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [round('draw', ['chain X'])],
    })
    expect(result.successfulExploitPaths).toHaveLength(0)
  })

  it('blank chains are filtered out', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [round('red_wins', ['  ', '', 'real chain'])],
    })
    expect(result.successfulExploitPaths).toEqual(['real chain'])
  })
})

// ─── Red agent win rate ───────────────────────────────────────────────────────

describe('computeLearningProfile — redAgentWinRate', () => {
  it('win rate = 0 when no rounds', () => {
    expect(computeLearningProfile(EMPTY).redAgentWinRate).toBe(0)
  })

  it('win rate = 1.0 when all rounds are red wins', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [round('red_wins'), round('red_wins')],
    })
    expect(result.redAgentWinRate).toBe(1.0)
  })

  it('win rate = 0.5 for one win one loss', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [round('red_wins'), round('blue_wins')],
    })
    expect(result.redAgentWinRate).toBe(0.5)
  })
})

// ─── Attack surface trend ─────────────────────────────────────────────────────

describe('computeLearningProfile — attackSurfaceTrend', () => {
  it('unknown when fewer than 3 data points', () => {
    expect(computeLearningProfile({ ...EMPTY, attackSurfaceHistory: [surfacePoint(70)] }).attackSurfaceTrend).toBe('unknown')
    expect(computeLearningProfile({ ...EMPTY, attackSurfaceHistory: [surfacePoint(70), surfacePoint(80)] }).attackSurfaceTrend).toBe('unknown')
  })

  it('improving when second half scores are significantly higher', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      attackSurfaceHistory: [surfacePoint(50), surfacePoint(55), surfacePoint(50), surfacePoint(70), surfacePoint(75), surfacePoint(80)],
    })
    expect(result.attackSurfaceTrend).toBe('improving')
  })

  it('degrading when second half scores are significantly lower', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      attackSurfaceHistory: [surfacePoint(80), surfacePoint(78), surfacePoint(82), surfacePoint(60), surfacePoint(55), surfacePoint(50)],
    })
    expect(result.attackSurfaceTrend).toBe('degrading')
  })

  it('stable when difference is within threshold', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      attackSurfaceHistory: [surfacePoint(70), surfacePoint(72), surfacePoint(71), surfacePoint(73), surfacePoint(70), surfacePoint(72)],
    })
    expect(result.attackSurfaceTrend).toBe('stable')
  })
})

// ─── Adapted confidence score ─────────────────────────────────────────────────

describe('computeLearningProfile — adaptedConfidenceScore', () => {
  it('increases with more confirmed findings', () => {
    const few = computeLearningProfile({
      ...EMPTY,
      findingHistory: [finding('xss', 'validated'), finding('xss', 'validated')],
    })
    const many = computeLearningProfile({
      ...EMPTY,
      findingHistory: Array.from({ length: 10 }, () => finding('xss', 'validated')),
    })
    expect(many.adaptedConfidenceScore).toBeGreaterThan(few.adaptedConfidenceScore)
  })

  it('increases with more adversarial rounds', () => {
    const few = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: [round('blue_wins')],
    })
    const many = computeLearningProfile({
      ...EMPTY,
      redBlueRounds: Array.from({ length: 10 }, () => round('blue_wins')),
    })
    expect(many.adaptedConfidenceScore).toBeGreaterThan(few.adaptedConfidenceScore)
  })

  it('caps at 100', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: Array.from({ length: 30 }, () => finding('sqli', 'validated')),
      redBlueRounds: Array.from({ length: 30 }, () => round('red_wins')),
    })
    expect(result.adaptedConfidenceScore).toBe(100)
  })
})

// ─── Summary ──────────────────────────────────────────────────────────────────

describe('computeLearningProfile — summary', () => {
  it('summary mentions total findings analyzed', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      findingHistory: [finding('xss', 'validated'), finding('sqli', 'validated')],
    })
    expect(result.summary).toContain('2')
  })

  it('summary mentions attack surface trend', () => {
    const result = computeLearningProfile({
      ...EMPTY,
      attackSurfaceHistory: [surfacePoint(50), surfacePoint(55), surfacePoint(80)],
    })
    expect(result.summary).toMatch(/improving|stable|degrading|insufficient/)
  })

  it('summary mentions learning maturity score', () => {
    const result = computeLearningProfile(EMPTY)
    expect(result.summary).toContain('0/100')
  })
})
