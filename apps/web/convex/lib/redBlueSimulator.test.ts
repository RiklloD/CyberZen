import { describe, expect, it } from 'vitest'
import { simulateAdversarialRound } from './redBlueSimulator'
import type { RepositoryMemoryRecord } from './memoryController'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const emptyMemory: RepositoryMemoryRecord = {
  recurringVulnClasses: [],
  falsePositiveRate: 0,
  highConfidenceClasses: [],
  packageRiskMap: {},
  dominantSeverity: 'low',
  totalFindingsAnalyzed: 0,
  resolvedCount: 0,
  openCount: 0,
  summary: 'No findings recorded yet.',
}

const richMemory: RepositoryMemoryRecord = {
  recurringVulnClasses: [
    { vulnClass: 'sql_injection', count: 5, avgSeverityWeight: 0.9 },
    { vulnClass: 'xss', count: 2, avgSeverityWeight: 0.5 },
  ],
  falsePositiveRate: 0.1,
  highConfidenceClasses: ['sql_injection'],
  packageRiskMap: { sqlalchemy: 75, flask: 55, requests: 40 },
  dominantSeverity: 'high',
  totalFindingsAnalyzed: 7,
  resolvedCount: 2,
  openCount: 5,
  summary: '7 findings analyzed.',
}

const highBlast = {
  reachableServices: ['api-gateway', 'auth-service', 'payments-service'],
  exposedDataLayers: ['direct', 'transitive'],
  directExposureCount: 3,
  attackPathDepth: 2,
  riskTier: 'critical',
}

const lowBlast = {
  reachableServices: [],
  exposedDataLayers: ['transitive'],
  directExposureCount: 0,
  attackPathDepth: 1,
  riskTier: 'low',
}

// ---------------------------------------------------------------------------
// Null blast radius case
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — null blast radius', () => {
  it('handles null blast radius gracefully', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: null,
      openFindingCount: 0,
      roundNumber: 1,
      repositoryName: 'my-repo',
    })
    expect(result.attackSurfaceCoverage).toBe(0)
    // min(1, floor(0×0.3+1)) = 1
    expect(result.simulatedFindingsGenerated).toBe(1)
    // (1-0)×50 + 1×2 = 52
    expect(result.blueDetectionScore).toBe(52)
    expect(result.roundOutcome).toBe('draw')
    expect(result.summary).toContain('my-repo')
  })

  it('produces at least one exploit chain entry even with no data', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: null,
      openFindingCount: 0,
      roundNumber: 1,
      repositoryName: 'my-repo',
    })
    expect(result.exploitChains).toHaveLength(1)
    expect(result.exploitChains[0]).toContain('No high-confidence')
  })
})

// ---------------------------------------------------------------------------
// Empty memory case
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — empty memory', () => {
  it('produces a broad-spectrum recon strategy when memory is empty', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 5,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.redStrategySummary.toLowerCase()).toContain('broad-spectrum recon')
  })
})

// ---------------------------------------------------------------------------
// Red-wins case
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — red wins', () => {
  it('declares red_wins when coverage > 60 and detection < 40', () => {
    // High false positive rate → low blue detection
    // coverage = 3×15 + 3×5 + 2×10 + 20×2 = 45+15+20+40=120 → 100 (capped)
    const highFpMemory: RepositoryMemoryRecord = {
      ...emptyMemory,
      falsePositiveRate: 0.9, // very high → detection = (1-0.9)×50 + 1×2 = 7 → 7
    }
    const result = simulateAdversarialRound({
      repositoryMemory: highFpMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 20,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.attackSurfaceCoverage).toBeGreaterThan(60)
    expect(result.blueDetectionScore).toBeLessThan(40)
    expect(result.roundOutcome).toBe('red_wins')
  })

  it('awards positive confidence gain on red win', () => {
    const highFpMemory: RepositoryMemoryRecord = {
      ...emptyMemory,
      falsePositiveRate: 0.9,
    }
    const result = simulateAdversarialRound({
      repositoryMemory: highFpMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 20,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.confidenceGain).toBeGreaterThan(0)
    expect(result.roundOutcome).toBe('red_wins')
  })
})

// ---------------------------------------------------------------------------
// Blue-wins case
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — blue wins', () => {
  it('declares blue_wins when detection > 70', () => {
    // Low false positive rate (0) + many rounds → detection > 70
    // detection = (1-0)×50 + 25×2 = 50+50=100 → capped 100
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory, // falsePositiveRate=0
      blastRadiusSnapshot: lowBlast,
      openFindingCount: 0,
      roundNumber: 25,
      repositoryName: 'repo',
    })
    expect(result.blueDetectionScore).toBeGreaterThan(70)
    expect(result.roundOutcome).toBe('blue_wins')
  })

  it('detection score grows with round number', () => {
    const r1 = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: null,
      openFindingCount: 0,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    const r10 = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: null,
      openFindingCount: 0,
      roundNumber: 10,
      repositoryName: 'repo',
    })
    expect(r10.blueDetectionScore).toBeGreaterThan(r1.blueDetectionScore)
  })
})

// ---------------------------------------------------------------------------
// Draw case
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — draw', () => {
  it('declares a draw when neither win condition is met', () => {
    // coverage = 0×15 + 0 + 1×10 + 2×2 = 14 (not > 60)
    // detection = 1×50 + 1×2 = 52 (not > 70)
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: {
        ...lowBlast,
        directExposureCount: 0,
        reachableServices: [],
        attackPathDepth: 1,
      },
      openFindingCount: 2,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.roundOutcome).toBe('draw')
  })
})

// ---------------------------------------------------------------------------
// Exploit chain generation
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — exploit chains', () => {
  it('derives chains from packageRiskMap top entries', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: richMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 3,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    // Top packages: sqlalchemy(75), flask(55), requests(40)
    expect(result.exploitChains[0]).toContain('sqlalchemy')
    expect(result.exploitChains[0]).toContain('75')
    expect(result.exploitChains).toHaveLength(3) // 3 packages → 3 chains
  })

  it('links each chain to a reachable service from the blast radius', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: richMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 3,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.exploitChains[0]).toContain('api-gateway')
    expect(result.exploitChains[1]).toContain('auth-service')
  })

  it('caps exploit chains at 3 even with many packages', () => {
    const manyPackageMemory: RepositoryMemoryRecord = {
      ...richMemory,
      packageRiskMap: {
        pkg1: 90,
        pkg2: 80,
        pkg3: 70,
        pkg4: 60,
        pkg5: 50,
      },
    }
    const result = simulateAdversarialRound({
      repositoryMemory: manyPackageMemory,
      blastRadiusSnapshot: highBlast,
      openFindingCount: 5,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.exploitChains.length).toBeLessThanOrEqual(3)
  })
})

// ---------------------------------------------------------------------------
// Score formula verification
// ---------------------------------------------------------------------------

describe('simulateAdversarialRound — formula correctness', () => {
  it('computes attackSurfaceCoverage exactly per spec formula', () => {
    // direct=2, services=2, depth=2, findings=5
    // 2×15 + 2×5 + 2×10 + 5×2 = 30+10+20+10 = 70
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: {
        reachableServices: ['svc-a', 'svc-b'],
        exposedDataLayers: ['direct'],
        directExposureCount: 2,
        attackPathDepth: 2,
        riskTier: 'high',
      },
      openFindingCount: 5,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.attackSurfaceCoverage).toBe(70)
  })

  it('computes simulatedFindingsGenerated with critical risk bonus', () => {
    // floor(3 × 0.3 + 3) = floor(0.9 + 3) = floor(3.9) = 3
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: { ...highBlast, riskTier: 'critical' },
      openFindingCount: 3,
      roundNumber: 1,
      repositoryName: 'repo',
    })
    expect(result.simulatedFindingsGenerated).toBe(3)
  })

  it('includes round number in the summary', () => {
    const result = simulateAdversarialRound({
      repositoryMemory: emptyMemory,
      blastRadiusSnapshot: null,
      openFindingCount: 0,
      roundNumber: 7,
      repositoryName: 'sentinel-repo',
    })
    expect(result.summary).toContain('Round 7')
    expect(result.summary).toContain('sentinel-repo')
  })
})
