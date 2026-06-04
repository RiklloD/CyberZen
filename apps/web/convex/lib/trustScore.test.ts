// §4.4 — repositoryScore unit tests.

import { describe, expect, test } from 'vitest'
import {
  type RepositoryScoreInput,
  aggregateTrustScore,
  repositoryScore,
} from './trustScore'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convenience: build a perfect-input with overrides. */
function makeInput(overrides: Partial<RepositoryScoreInput> = {}): RepositoryScoreInput {
  return {
    health: 100,
    posture: 100,
    criticalFindings: 0,
    highFindings: 0,
    mediumFindings: 0,
    slaBreachRate: 0,
    learningConfidence: 100,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// repositoryScore — §4.4
// ---------------------------------------------------------------------------

describe('repositoryScore', () => {
  test('perfect inputs yield 100', () => {
    const result = repositoryScore(makeInput())
    expect(result.score).toBe(100)
  })

  test('all-zero inputs yield score based only on findingDensity', () => {
    const result = repositoryScore(makeInput({
      health: 0,
      posture: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      slaBreachRate: 1, // 100% breach rate → slaScore = 0
      learningConfidence: 0,
    }))
    // findingDensityScore = 100 - min(0, 100) = 100 → contributes 100×0.20 = 20
    expect(result.score).toBe(20)
  })

  test('truly all-zero including findings yields 0', () => {
    const result = repositoryScore(makeInput({
      health: 0,
      posture: 0,
      criticalFindings: 100, // findingDensityScore = 100 - 100 = 0
      highFindings: 0,
      mediumFindings: 0,
      slaBreachRate: 1, // slaScore = 0
      learningConfidence: 0,
    }))
    expect(result.score).toBe(0)
  })

  test('only health degrades score proportionally', () => {
    const perfect = repositoryScore(makeInput())
    const degraded = repositoryScore(makeInput({ health: 80 }))
    // health weight = 0.25; dropping 20 points → raw drops by 5
    expect(perfect.score - degraded.score).toBe(5)
  })

  test('findingDensityScore penalizes critical findings heavily', () => {
    const withCritical = repositoryScore(makeInput({ criticalFindings: 4 }))
    // 4 critical × 5 = 20 → findingDensityScore = 80
    // Weight 0.20 → drops 4 points from 100
    expect(withCritical.score).toBe(96)
    expect(withCritical.breakdown.findingDensityScore).toBe(80)
  })

  test('findingDensityScore clamps at 0 for many findings', () => {
    const result = repositoryScore(makeInput({
      criticalFindings: 20,
      highFindings: 10,
      mediumFindings: 30,
    }))
    // 20×5 + 10×2 + 30 = 150 → min(150,100) = 100 → score = 0
    expect(result.breakdown.findingDensityScore).toBe(0)
  })

  test('slaScore degrades linearly with breach rate', () => {
    const result = repositoryScore(makeInput({ slaBreachRate: 0.5 }))
    // slaScore = 100 - min(50, 100) = 50 → weight 0.20 → drops 10 from 100
    expect(result.breakdown.slaScore).toBe(50)
    expect(result.score).toBe(90)
  })

  test('slaScore clamps at 0 for 100% breach rate', () => {
    const result = repositoryScore(makeInput({ slaBreachRate: 1 }))
    expect(result.breakdown.slaScore).toBe(0)
  })

  test('slaScore handles breach rate > 1 gracefully', () => {
    const result = repositoryScore(makeInput({ slaBreachRate: 2 }))
    // min(200, 100) = 100 → slaScore = 0
    expect(result.breakdown.slaScore).toBe(0)
  })

  test('learningConfidence weight is 0.15', () => {
    const result = repositoryScore(makeInput({ learningConfidence: 0 }))
    // drops 100 × 0.15 = 15 from 100
    expect(result.score).toBe(85)
  })

  test('posture weight is 0.20', () => {
    const result = repositoryScore(makeInput({ posture: 50 }))
    // drops 50 × 0.20 = 10 from 100
    expect(result.score).toBe(90)
  })

  test('mixed realistic inputs produce expected score', () => {
    const result = repositoryScore(makeInput({
      health: 80,
      posture: 70,
      criticalFindings: 2,
      highFindings: 3,
      mediumFindings: 5,
      slaBreachRate: 0.1,
      learningConfidence: 60,
    }))
    // findingDensityScore = 100 - min(2×5 + 3×2 + 5, 100) = 100 - 21 = 79
    // slaScore = 100 - min(10, 100) = 90
    // raw = 80×0.25 + 70×0.20 + 79×0.20 + 90×0.20 + 60×0.15
    //     = 20 + 14 + 15.8 + 18 + 9 = 76.8 → round to 77
    expect(result.score).toBe(77)
    expect(result.breakdown.findingDensityScore).toBe(79)
    expect(result.breakdown.slaScore).toBe(90)
  })

  test('score is clamped to 0 for extremely bad inputs', () => {
    const result = repositoryScore({
      health: -50,
      posture: -20,
      criticalFindings: 100,
      highFindings: 100,
      mediumFindings: 100,
      slaBreachRate: 5,
      learningConfidence: -30,
    })
    expect(result.score).toBe(0)
  })

  test('score is clamped to 100 and does not exceed it', () => {
    const result = repositoryScore(makeInput({
      health: 110,
      posture: 120,
      learningConfidence: 200,
    }))
    expect(result.score).toBe(100)
  })

  test('high findings contribute 2 each to density penalty', () => {
    const result = repositoryScore(makeInput({ highFindings: 10 }))
    // 10 × 2 = 20 → findingDensityScore = 80 → drops 4
    expect(result.breakdown.findingDensityScore).toBe(80)
    expect(result.score).toBe(96)
  })

  test('medium findings contribute 1 each to density penalty', () => {
    const result = repositoryScore(makeInput({ mediumFindings: 30 }))
    // 30 × 1 = 30 → findingDensityScore = 70 → drops 6
    expect(result.breakdown.findingDensityScore).toBe(70)
    expect(result.score).toBe(94)
  })

  test('breakdown reflects all input factors', () => {
    const result = repositoryScore(makeInput({
      health: 90,
      posture: 80,
      learningConfidence: 70,
    }))
    expect(result.breakdown.health).toBe(90)
    expect(result.breakdown.posture).toBe(80)
    expect(result.breakdown.learningConfidence).toBe(70)
    expect(result.breakdown.findingDensityScore).toBe(100)
    expect(result.breakdown.slaScore).toBe(100)
  })
})

// ---------------------------------------------------------------------------
// aggregateTrustScore — existing function, basic smoke test
// ---------------------------------------------------------------------------

describe('aggregateTrustScore', () => {
  test('returns 100 for empty component list', () => {
    const result = aggregateTrustScore([])
    expect(result.repositoryScore).toBe(100)
    expect(result.directDepScore).toBe(100)
    expect(result.transitiveDepScore).toBe(100)
  })

  test('computes direct-weighted mean correctly', () => {
    const components = [
      { name: 'a', version: '1.0', ecosystem: 'npm', layer: 'app', isDirect: true, trustScore: 80, hasKnownVulnerabilities: false },
      { name: 'b', version: '1.0', ecosystem: 'npm', layer: 'app', isDirect: true, trustScore: 70, hasKnownVulnerabilities: false },
      { name: 'c', version: '1.0', ecosystem: 'npm', layer: 'lib', isDirect: false, trustScore: 50, hasKnownVulnerabilities: true },
    ]
    const result = aggregateTrustScore(components)
    // direct = mean(80,70) = 75, transitive = 50
    // (2*75 + 50)/3 = 66.67 → round to 67
    expect(result.repositoryScore).toBe(67)
    expect(result.directDepScore).toBe(75)
    expect(result.transitiveDepScore).toBe(50)
    expect(result.vulnerableComponentCount).toBe(1)
  })
})
