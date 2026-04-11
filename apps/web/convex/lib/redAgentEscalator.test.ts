/// <reference types="vite/client" />
import { describe, it, expect } from 'vitest'
import {
  escalateRedAgentRound,
  type FindingCandidate,
} from './redAgentEscalator'
import type { AdversarialRoundResult } from './redBlueSimulator'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeRound(
  overrides: Partial<AdversarialRoundResult> = {},
): AdversarialRoundResult {
  return {
    redStrategySummary: 'Targeting injection via api-gateway.',
    attackSurfaceCoverage: 70,
    simulatedFindingsGenerated: 3,
    blueDetectionScore: 30,
    exploitChains: ['lodash (score 85) → api-gateway'],
    roundOutcome: 'red_wins',
    confidenceGain: 8,
    summary: 'Round 1: Red Agent breached the surface.',
    ...overrides,
  }
}

const BASE_INPUT = {
  round: makeRound(),
  roundNumber: 1,
  repositoryName: 'acme/core',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function first(result: ReturnType<typeof escalateRedAgentRound>): FindingCandidate {
  if (result.candidates.length === 0) throw new Error('No candidates')
  return result.candidates[0]
}

// ---------------------------------------------------------------------------
// Empty / fallback chains
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — empty candidates', () => {
  it('returns no candidates when the only chain is the sentinel string', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        exploitChains: ['No high-confidence exploit chains identified this round'],
      }),
    })
    expect(result.candidates).toHaveLength(0)
  })

  it('returns no candidates when exploit chains array is empty', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: [] }),
    })
    expect(result.candidates).toHaveLength(0)
  })

  it('skips unrecognised chain formats silently', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['some unexpected format chain'] }),
    })
    expect(result.candidates).toHaveLength(0)
  })

  it('escalationSummary notes no parseable chains when candidates is empty', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: [] }),
    })
    expect(result.escalationSummary).toContain('no parseable exploit chains')
  })
})

// ---------------------------------------------------------------------------
// Package-based chains
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — package chains', () => {
  it('parses a package chain into a candidate', () => {
    const result = escalateRedAgentRound(BASE_INPUT)
    expect(result.candidates).toHaveLength(1)
  })

  it('sets vulnClass to vulnerable_dependency for package chains', () => {
    expect(first(escalateRedAgentRound(BASE_INPUT)).vulnClass).toBe(
      'vulnerable_dependency',
    )
  })

  it('extracts affectedPackages from chain', () => {
    expect(first(escalateRedAgentRound(BASE_INPUT)).affectedPackages).toEqual([
      'lodash',
    ])
  })

  it('extracts affectedServices from chain', () => {
    expect(first(escalateRedAgentRound(BASE_INPUT)).affectedServices).toEqual([
      'api-gateway',
    ])
  })

  it('title includes package and service names', () => {
    const title = first(escalateRedAgentRound(BASE_INPUT)).title
    expect(title).toContain('lodash')
    expect(title).toContain('api-gateway')
  })

  it('summary mentions round number and repository', () => {
    const { summary } = first(escalateRedAgentRound(BASE_INPUT))
    expect(summary).toContain('round 1')
    expect(summary).toContain('acme/core')
  })

  it('blastRadiusSummary contains package and service', () => {
    const { blastRadiusSummary } = first(escalateRedAgentRound(BASE_INPUT))
    expect(blastRadiusSummary).toContain('lodash')
    expect(blastRadiusSummary).toContain('api-gateway')
  })
})

// ---------------------------------------------------------------------------
// Depth-based chains
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — depth chains', () => {
  const depthInput = {
    ...BASE_INPUT,
    round: makeRound({
      exploitChains: [
        'Depth-3 transitive chain traversal targeting runtime layer',
      ],
    }),
  }

  it('parses a depth chain into a candidate', () => {
    expect(escalateRedAgentRound(depthInput).candidates).toHaveLength(1)
  })

  it('sets vulnClass to supply_chain_traversal for depth chains', () => {
    expect(first(escalateRedAgentRound(depthInput)).vulnClass).toBe(
      'supply_chain_traversal',
    )
  })

  it('has empty affectedPackages for depth chains', () => {
    expect(first(escalateRedAgentRound(depthInput)).affectedPackages).toEqual([])
  })

  it('sets affectedServices to the target layer', () => {
    expect(first(escalateRedAgentRound(depthInput)).affectedServices).toEqual([
      'runtime',
    ])
  })

  it('title includes depth and layer', () => {
    const title = first(escalateRedAgentRound(depthInput)).title
    expect(title).toContain('depth-3')
    expect(title).toContain('runtime layer')
  })

  it('blastRadiusSummary mentions depth and layer', () => {
    const { blastRadiusSummary } = first(escalateRedAgentRound(depthInput))
    expect(blastRadiusSummary).toContain('depth 3')
    expect(blastRadiusSummary).toContain('runtime')
  })
})

// ---------------------------------------------------------------------------
// Severity derivation
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — severity', () => {
  it('package score >= 80 → critical', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 80) → svc'] }),
    })
    expect(first(result).severity).toBe('critical')
  })

  it('package score 60–79 → high', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 60) → svc'] }),
    })
    expect(first(result).severity).toBe('high')
  })

  it('package score 40–59 → medium', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 40) → svc'] }),
    })
    expect(first(result).severity).toBe('medium')
  })

  it('package score < 40 → low', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 39) → svc'] }),
    })
    expect(first(result).severity).toBe('low')
  })

  it('depth chain uses coverage for severity (≥80 → critical)', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        attackSurfaceCoverage: 85,
        exploitChains: ['Depth-2 transitive chain traversal targeting data layer'],
      }),
    })
    expect(first(result).severity).toBe('critical')
  })

  it('depth chain uses coverage for severity (40–59 → medium)', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        attackSurfaceCoverage: 50,
        exploitChains: ['Depth-2 transitive chain traversal targeting data layer'],
      }),
    })
    expect(first(result).severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — confidence', () => {
  it('maps confidenceGain=10 to confidence=1', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ confidenceGain: 10 }),
    })
    expect(first(result).confidence).toBe(1)
  })

  it('maps confidenceGain=5 to confidence=0.5', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ confidenceGain: 5 }),
    })
    expect(first(result).confidence).toBe(0.5)
  })

  it('clamps low confidenceGain to minimum 0.3 (red_wins is meaningful signal)', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ confidenceGain: 0 }),
    })
    expect(first(result).confidence).toBe(0.3)
  })

  it('clamps confidence at 1.0 max', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ confidenceGain: 15 }), // hypothetically over-range
    })
    expect(first(result).confidence).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// businessImpactScore
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — businessImpactScore', () => {
  it('critical severity → businessImpactScore 88', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 90) → svc'] }),
    })
    expect(first(result).businessImpactScore).toBe(88)
  })

  it('high severity → businessImpactScore 72', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 65) → svc'] }),
    })
    expect(first(result).businessImpactScore).toBe(72)
  })

  it('medium severity → businessImpactScore 52', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 45) → svc'] }),
    })
    expect(first(result).businessImpactScore).toBe(52)
  })

  it('low severity → businessImpactScore 36', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({ exploitChains: ['pkg (score 30) → svc'] }),
    })
    expect(first(result).businessImpactScore).toBe(36)
  })
})

// ---------------------------------------------------------------------------
// Multiple chains
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — multiple chains', () => {
  it('produces one candidate per parseable chain', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        exploitChains: [
          'lodash (score 85) → api-gateway',
          'express (score 60) → auth-service',
          'Depth-2 transitive chain traversal targeting data layer',
        ],
      }),
    })
    expect(result.candidates).toHaveLength(3)
  })

  it('skips sentinel and keeps real chains in mixed list', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        exploitChains: [
          'lodash (score 85) → api-gateway',
          'No high-confidence exploit chains identified this round',
        ],
      }),
    })
    expect(result.candidates).toHaveLength(1)
    expect(result.candidates[0].affectedPackages).toEqual(['lodash'])
  })

  it('escalationSummary uses plural when multiple candidates', () => {
    const result = escalateRedAgentRound({
      ...BASE_INPUT,
      round: makeRound({
        exploitChains: [
          'pkg1 (score 80) → svc1',
          'pkg2 (score 70) → svc2',
        ],
      }),
    })
    expect(result.escalationSummary).toContain('2 exploit chains')
  })

  it('escalationSummary uses singular when one candidate', () => {
    const result = escalateRedAgentRound(BASE_INPUT)
    expect(result.escalationSummary).toContain('1 exploit chain')
    expect(result.escalationSummary).not.toContain('chains escalated')
    expect(result.escalationSummary).toContain('chain escalated')
  })
})

// ---------------------------------------------------------------------------
// escalationSummary
// ---------------------------------------------------------------------------

describe('escalateRedAgentRound — escalationSummary', () => {
  it('always mentions the repository name', () => {
    const result = escalateRedAgentRound(BASE_INPUT)
    expect(result.escalationSummary).toContain('acme/core')
  })

  it('always mentions the round number', () => {
    const result = escalateRedAgentRound({ ...BASE_INPUT, roundNumber: 7 })
    expect(result.escalationSummary).toContain('round 7')
  })
})
