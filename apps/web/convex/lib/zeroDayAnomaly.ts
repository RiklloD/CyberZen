/**
 * Zero-Day Anomaly Detection — spec §3.1.3
 *
 * "For novel vulnerability classes where no fingerprint exists yet, Sentinel
 * runs a continuous background analysis that flags code patterns that are
 * statistically anomalous relative to the historical safe baseline."
 *
 * Algorithm:
 *   1. Maintain a rolling baseline: the centroid (average vector) of the last
 *      N code context embeddings for a repository.
 *   2. When a new push embedding arrives, compute its cosine distance from
 *      the centroid.
 *   3. If distance > threshold → flag as anomalous ("requires investigation").
 *   4. Anomaly score is the cosine distance normalized to 0–100.
 *
 * This is behavioral anomaly detection at the code-semantic level:
 * the system doesn't know *what* changed, only *how much* the semantic
 * fingerprint of the code has shifted from its established baseline.
 *
 * Key insight: legitimate refactoring produces gradual drift. A sudden
 * large shift (new cryptographic logic, new network code, new deserialization)
 * is a statistical outlier worth investigating — especially if it wasn't
 * part of a tracked PR.
 */

import { cosineSimilarity } from './codeEmbedding'

// ── Types ─────────────────────────────────────────────────────────────────────

export type AnomalyScore = {
  /** 0–100. Higher = more anomalous vs historical baseline. */
  anomalyScore: number
  /** Cosine distance from baseline centroid (0 = identical, 2 = opposite). */
  cosineDistance: number
  /** Classification of the anomaly level. */
  anomalyLevel: 'normal' | 'watch' | 'suspicious' | 'anomalous'
  /** How many historical embeddings the baseline was computed from. */
  baselineSize: number
  /** Whether there's enough history to make a meaningful decision. */
  sufficientHistory: boolean
  /** Human-readable explanation. */
  summary: string
}

export type EmbeddingHistoryEntry = {
  vector: number[]
  commitSha: string
  embeddedAt: number
}

// ── Constants ─────────────────────────────────────────────────────────────────

/** Minimum number of historical embeddings before we trust the baseline. */
const MIN_BASELINE_SIZE = 3

/**
 * Anomaly threshold tuning.
 * cosineDistance = 1 - cosineSimilarity, so:
 *   0.0 = identical,  0.5 = orthogonal,  2.0 = opposite
 *
 * Typical values from experimentation:
 *   Normal push (bug fix, docstring) : distance 0.05–0.15
 *   Feature branch (new module)      : distance 0.15–0.35
 *   Suspicious (large new crypto/net): distance 0.35–0.60
 *   Anomalous (completely new code)  : distance > 0.60
 */
const THRESHOLDS = {
  watch: 0.20,
  suspicious: 0.35,
  anomalous: 0.55,
}

// ── Centroid computation ──────────────────────────────────────────────────────

/**
 * Compute the centroid (mean vector) of a set of embedding vectors.
 * All vectors must be the same dimensionality.
 */
export function computeCentroid(vectors: number[][]): number[] | null {
  if (vectors.length === 0) return null
  const dims = vectors[0].length
  if (dims === 0) return null

  const centroid = new Array<number>(dims).fill(0)
  for (const vec of vectors) {
    for (let i = 0; i < dims; i++) {
      centroid[i] += vec[i]
    }
  }
  const n = vectors.length
  return centroid.map((v) => v / n)
}

/**
 * Cosine distance = 1 - cosine similarity.
 * 0 = identical direction, 1 = orthogonal, 2 = opposite.
 */
export function cosineDistance(a: number[], b: number[]): number {
  return 1 - cosineSimilarity(a, b)
}

// ── Anomaly scoring ───────────────────────────────────────────────────────────

/**
 * Score a new embedding against historical baseline embeddings.
 *
 * @param newVector    The embedding of the latest code context.
 * @param history      Past embeddings (oldest first). Use last N only.
 * @param windowSize   How many recent embeddings to include in baseline.
 */
export function scoreAnomaly(
  newVector: number[],
  history: EmbeddingHistoryEntry[],
  windowSize = 10,
): AnomalyScore {
  const window = history.slice(-windowSize)

  if (window.length < MIN_BASELINE_SIZE) {
    return {
      anomalyScore: 0,
      cosineDistance: 0,
      anomalyLevel: 'normal',
      baselineSize: window.length,
      sufficientHistory: false,
      summary: `Insufficient history (${window.length}/${MIN_BASELINE_SIZE} embeddings) — need at least ${MIN_BASELINE_SIZE} prior pushes to establish a baseline.`,
    }
  }

  const centroid = computeCentroid(window.map((e) => e.vector))
  if (!centroid) {
    return {
      anomalyScore: 0,
      cosineDistance: 0,
      anomalyLevel: 'normal',
      baselineSize: 0,
      sufficientHistory: false,
      summary: 'Could not compute baseline centroid.',
    }
  }

  const distance = cosineDistance(newVector, centroid)

  // Normalize to 0–100 (distance 0 → score 0, distance ≥ 1 → score 100)
  const anomalyScore = Math.min(100, Math.round(distance * 100))

  const anomalyLevel: AnomalyScore['anomalyLevel'] =
    distance >= THRESHOLDS.anomalous ? 'anomalous'
    : distance >= THRESHOLDS.suspicious ? 'suspicious'
    : distance >= THRESHOLDS.watch ? 'watch'
    : 'normal'

  const summary = buildSummary(anomalyLevel, distance, window.length)

  return {
    anomalyScore,
    cosineDistance: Math.round(distance * 1000) / 1000,
    anomalyLevel,
    baselineSize: window.length,
    sufficientHistory: true,
    summary,
  }
}

function buildSummary(
  level: AnomalyScore['anomalyLevel'],
  distance: number,
  baselineSize: number,
): string {
  const distStr = distance.toFixed(3)
  switch (level) {
    case 'normal':
      return `Code change is within normal variance (distance ${distStr} from ${baselineSize}-push baseline). No anomaly detected.`
    case 'watch':
      return `Minor semantic drift detected (distance ${distStr}). Code changed more than usual — monitor if this continues across multiple pushes.`
    case 'suspicious':
      return `Significant semantic drift (distance ${distStr}) — this push introduces code patterns substantially different from the established baseline. Consider a security review of the changed files.`
    case 'anomalous':
      return `High anomaly score — semantic distance ${distStr} from ${baselineSize}-push baseline. This push looks statistically unlike the rest of the codebase history. Flag for manual investigation as a potential zero-day vulnerability class introduction.`
  }
}

// ── Adaptive baseline ─────────────────────────────────────────────────────────

/**
 * Compute per-commit variance to detect whether the repository has
 * inherently high churn (microservices with many small commits) vs
 * low churn (stable libraries). Adaptive thresholds prevent false
 * positive storms in high-velocity repositories.
 */
export function computeBaselineVariance(history: EmbeddingHistoryEntry[]): number {
  if (history.length < 2) return 0

  const centroid = computeCentroid(history.map((e) => e.vector))
  if (!centroid) return 0

  const distances = history.map((e) => cosineDistance(e.vector, centroid))
  const mean = distances.reduce((a, b) => a + b, 0) / distances.length
  const variance = distances.reduce((acc, d) => acc + (d - mean) ** 2, 0) / distances.length
  return Math.sqrt(variance) // standard deviation
}

/**
 * Adaptive anomaly scoring that accounts for repository-specific variance.
 * High-churn repos get higher thresholds to avoid alert fatigue.
 */
export function scoreAnomalyAdaptive(
  newVector: number[],
  history: EmbeddingHistoryEntry[],
  windowSize = 10,
): AnomalyScore {
  const window = history.slice(-windowSize)
  if (window.length < MIN_BASELINE_SIZE) {
    return scoreAnomaly(newVector, history, windowSize) // fall back to fixed
  }

  const stdDev = computeBaselineVariance(window)

  // Adapt thresholds: in high-variance repos, raise thresholds proportionally
  const adaptedThresholds = {
    watch: THRESHOLDS.watch + stdDev * 0.5,
    suspicious: THRESHOLDS.suspicious + stdDev * 1.0,
    anomalous: THRESHOLDS.anomalous + stdDev * 1.5,
  }

  const centroid = computeCentroid(window.map((e) => e.vector))!
  const distance = cosineDistance(newVector, centroid)
  const anomalyScore = Math.min(100, Math.round(distance * 100))

  const anomalyLevel: AnomalyScore['anomalyLevel'] =
    distance >= adaptedThresholds.anomalous ? 'anomalous'
    : distance >= adaptedThresholds.suspicious ? 'suspicious'
    : distance >= adaptedThresholds.watch ? 'watch'
    : 'normal'

  return {
    anomalyScore,
    cosineDistance: Math.round(distance * 1000) / 1000,
    anomalyLevel,
    baselineSize: window.length,
    sufficientHistory: true,
    summary: buildSummary(anomalyLevel, distance, window.length),
  }
}
