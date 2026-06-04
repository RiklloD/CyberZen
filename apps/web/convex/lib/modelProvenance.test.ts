/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeProvenanceScore, type ProvenanceChain } from './modelProvenance'

// ── Score bounds ────────────────────────────────────────────────────────────

describe('computeProvenanceScore — score bounds', () => {
  it('returns 0 when no components are present', () => {
    expect(computeProvenanceScore({})).toBe(0)
  })

  it('returns 100 when all components are present', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: true,
        trainingDataManifest: true,
        fineTuneAttestation: true,
        deploymentHashMatch: true,
        sbomPresent: true,
      }),
    ).toBe(100)
  })

  it('returns a number in [0, 100]', () => {
    const score = computeProvenanceScore({ sourceSignature: true, sbomPresent: true })
    expect(score).toBeGreaterThanOrEqual(0)
    expect(score).toBeLessThanOrEqual(100)
  })
})

// ── Individual components ───────────────────────────────────────────────────

describe('computeProvenanceScore — individual components', () => {
  it.each([
    ['sourceSignature', { sourceSignature: true }],
    ['trainingDataManifest', { trainingDataManifest: true }],
    ['fineTuneAttestation', { fineTuneAttestation: true }],
    ['deploymentHashMatch', { deploymentHashMatch: true }],
    ['sbomPresent', { sbomPresent: true }],
  ] as const)('adds 20 for %s alone', (_name, chain) => {
    expect(computeProvenanceScore(chain)).toBe(20)
  })
})

// ── Accumulation ────────────────────────────────────────────────────────────

describe('computeProvenanceScore — accumulation', () => {
  it('scores 40 with two components present', () => {
    expect(
      computeProvenanceScore({ sourceSignature: true, sbomPresent: true }),
    ).toBe(40)
  })

  it('scores 60 with three components present', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: true,
        trainingDataManifest: true,
        sbomPresent: true,
      }),
    ).toBe(60)
  })

  it('scores 80 with four components present', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: true,
        trainingDataManifest: true,
        fineTuneAttestation: true,
        sbomPresent: true,
      }),
    ).toBe(80)
  })
})

// ── Deployment hash mismatch cap ────────────────────────────────────────────

describe('computeProvenanceScore — deploymentHashMatch === false caps at 50', () => {
  it('caps at 50 when all components present but deployment hash mismatched', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: true,
        trainingDataManifest: true,
        fineTuneAttestation: true,
        deploymentHashMatch: false,
        sbomPresent: true,
      }),
    ).toBe(50)
  })

  it('caps at 50 when 3 other components present + hash mismatch', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: true,
        trainingDataManifest: true,
        fineTuneAttestation: true,
        deploymentHashMatch: false,
      }),
    ).toBe(50)
  })

  it('does not boost score when deploymentHashMatch is false (0 components = 0)', () => {
    expect(computeProvenanceScore({ deploymentHashMatch: false })).toBe(0)
  })

  it('still counts deploymentHashMatch=true as +20', () => {
    expect(computeProvenanceScore({ deploymentHashMatch: true })).toBe(20)
  })
})

// ── Undefined / missing fields treated as absent ────────────────────────────

describe('computeProvenanceScore — undefined fields', () => {
  it('treats undefined fields as absent (0 score)', () => {
    expect(
      computeProvenanceScore({
        sourceSignature: undefined,
        trainingDataManifest: undefined,
        fineTuneAttestation: undefined,
        deploymentHashMatch: undefined,
        sbomPresent: undefined,
      }),
    ).toBe(0)
  })

  it('treats missing fields as absent', () => {
    // Only one field set
    expect(computeProvenanceScore({ trainingDataManifest: true })).toBe(20)
  })
})
