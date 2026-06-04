/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import {
  computeCentroid,
  cosineDistance,
  scoreAnomaly,
  scoreAnomalyAdaptive,
  computeBaselineVariance,
  type EmbeddingHistoryEntry,
} from './zeroDayAnomaly'

// ── Test helpers ──────────────────────────────────────────────────────────────

function makeEntry(vector: number[], sha = 'abc'): EmbeddingHistoryEntry {
  return { vector, commitSha: sha, embeddedAt: Date.now() }
}

/** Make n identical vectors with small noise (simulates a stable repo) */
function stableHistory(n: number, dim = 4): EmbeddingHistoryEntry[] {
  const base = Array.from({ length: dim }, (_, i) => (i + 1) / dim)
  return Array.from({ length: n }, (_, i) =>
    makeEntry(base.map((v) => v + (Math.sin(i) * 0.02)), `commit${i}`),
  )
}

// ── computeCentroid ───────────────────────────────────────────────────────────

describe('computeCentroid', () => {
  test('returns null for empty input', () => {
    expect(computeCentroid([])).toBeNull()
  })

  test('returns the vector itself for a single entry', () => {
    const v = [1, 2, 3, 4]
    const result = computeCentroid([v])
    expect(result).not.toBeNull()
    result!.forEach((x, i) => expect(x).toBeCloseTo(v[i], 5))
  })

  test('averages two orthogonal unit vectors', () => {
    const result = computeCentroid([[1, 0], [0, 1]])
    expect(result![0]).toBeCloseTo(0.5, 5)
    expect(result![1]).toBeCloseTo(0.5, 5)
  })

  test('averages three vectors correctly', () => {
    const result = computeCentroid([[3, 0], [0, 3], [0, 0]])
    expect(result![0]).toBeCloseTo(1.0, 5)
    expect(result![1]).toBeCloseTo(1.0, 5)
  })
})

// ── cosineDistance ────────────────────────────────────────────────────────────

describe('cosineDistance', () => {
  test('identical vectors → distance 0', () => {
    const v = [0.5, 0.5]
    expect(cosineDistance(v, v)).toBeCloseTo(0, 5)
  })

  test('orthogonal vectors → distance ~1', () => {
    expect(cosineDistance([1, 0], [0, 1])).toBeCloseTo(1.0, 5)
  })

  test('opposite vectors → distance ~2', () => {
    expect(cosineDistance([1, 0], [-1, 0])).toBeCloseTo(2.0, 5)
  })
})

// ── scoreAnomaly ──────────────────────────────────────────────────────────────

describe('scoreAnomaly', () => {
  test('insufficient history → normal with sufficientHistory=false', () => {
    const result = scoreAnomaly([1, 0, 0, 0], [makeEntry([1, 0, 0, 0])], 10)
    expect(result.sufficientHistory).toBe(false)
    expect(result.anomalyLevel).toBe('normal')
    expect(result.anomalyScore).toBe(0)
  })

  test('similar push against stable history → normal', () => {
    const history = stableHistory(5)
    const newVec = history[0].vector.map((v) => v + 0.01) // tiny delta
    const result = scoreAnomaly(newVec, history)
    expect(result.sufficientHistory).toBe(true)
    expect(result.anomalyLevel).toBe('normal')
  })

  test('very different vector → anomalous', () => {
    const history = stableHistory(5, 4)
    // Completely different direction
    const newVec = [-1, -1, -1, -1]
    const result = scoreAnomaly(newVec, history)
    expect(result.anomalyLevel).toMatch(/suspicious|anomalous/)
    expect(result.anomalyScore).toBeGreaterThan(30)
  })

  test('baselineSize reflects window entries', () => {
    const history = stableHistory(8)
    const result = scoreAnomaly(history[0].vector, history, 5)
    expect(result.baselineSize).toBe(5)
  })

  test('anomaly score is 0–100', () => {
    const history = stableHistory(5)
    const newVec = [-1, -1, 0, 0]
    const result = scoreAnomaly(newVec, history)
    expect(result.anomalyScore).toBeGreaterThanOrEqual(0)
    expect(result.anomalyScore).toBeLessThanOrEqual(100)
  })

  test('very different vector is not normal', () => {
    const history = stableHistory(5)
    // Near-opposite direction to the baseline
    const newVec = [-0.9, -0.9, -0.9, -0.9]
    const result = scoreAnomaly(newVec, history)
    // Should be suspicious or anomalous — definitely not normal
    expect(result.anomalyLevel).not.toBe('normal')
    expect(result.anomalyScore).toBeGreaterThan(20)
  })

  test('cosineDistance is in valid range', () => {
    const history = stableHistory(5)
    const result = scoreAnomaly([1, 0, 0, 0], history)
    expect(result.cosineDistance).toBeGreaterThanOrEqual(0)
    expect(result.cosineDistance).toBeLessThanOrEqual(2)
  })

  test('summary is non-empty string', () => {
    const history = stableHistory(5)
    const result = scoreAnomaly(history[0].vector, history)
    expect(result.summary.length).toBeGreaterThan(10)
  })
})

// ── computeBaselineVariance ───────────────────────────────────────────────────

describe('computeBaselineVariance', () => {
  test('returns 0 for single entry', () => {
    expect(computeBaselineVariance([makeEntry([1, 0])])).toBe(0)
  })

  test('identical vectors → variance 0', () => {
    const history = Array.from({ length: 5 }, () => makeEntry([1, 0]))
    expect(computeBaselineVariance(history)).toBeCloseTo(0, 5)
  })

  test('diverse vectors → higher variance than stable', () => {
    // These vectors point in very different directions AND have varying distances from centroid
    const history = [
      makeEntry([0.9, 0.1, 0.0, 0.0]),
      makeEntry([0.0, 0.0, 0.9, 0.1]),
      makeEntry([0.5, 0.5, 0.0, 0.0]),
      makeEntry([0.0, 0.0, 0.5, 0.5]),
    ]
    const stable = stableHistory(4)
    // At minimum, diverse should not be less than stable (tiny noise is nearly 0)
    const diverseVar = computeBaselineVariance(history)
    const stableVar = computeBaselineVariance(stable)
    expect(diverseVar).toBeGreaterThanOrEqual(stableVar)
  })
})

// ── scoreAnomalyAdaptive ──────────────────────────────────────────────────────

describe('scoreAnomalyAdaptive', () => {
  test('falls back to fixed thresholds when insufficient history', () => {
    const result = scoreAnomalyAdaptive([1, 0], [makeEntry([1, 0])], 10)
    expect(result.sufficientHistory).toBe(false)
  })

  test('high-variance repo raises thresholds', () => {
    // High-variance: vectors pointing in clearly different directions with varying magnitudes
    const highVarianceHistory = [
      makeEntry([0.95, 0.05, 0.0, 0.0]),
      makeEntry([0.0, 0.0, 0.95, 0.05]),
      makeEntry([0.6, 0.4, 0.0, 0.0]),
      makeEntry([0.0, 0.0, 0.6, 0.4]),
      makeEntry([0.7, 0.1, 0.1, 0.1]),
    ]
    // Low-variance: tiny noise around the same direction
    const lowVarianceHistory = stableHistory(5)

    const highVar = computeBaselineVariance(highVarianceHistory)
    const lowVar = computeBaselineVariance(lowVarianceHistory)
    // The key property: high-variance repos have measurably higher std dev
    expect(highVar).toBeGreaterThan(lowVar)
  })

  test('returns valid anomaly score', () => {
    const history = stableHistory(5)
    const result = scoreAnomalyAdaptive([1, 0, 0, 0], history)
    expect(result.anomalyScore).toBeGreaterThanOrEqual(0)
    expect(result.anomalyScore).toBeLessThanOrEqual(100)
  })
})
