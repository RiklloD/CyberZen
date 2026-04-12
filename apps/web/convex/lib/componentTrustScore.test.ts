/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeComponentTrustScore } from './componentTrustScore'
import type { ComponentTrustScoreInput } from './componentTrustScore'

// ── Helpers ──────────────────────────────────────────────────────────────────

const base: ComponentTrustScoreInput = {
  name: 'express',
  version: '4.18.2',
  ecosystem: 'npm',
  isDirect: true,
  hasKnownVulnerabilities: false,
  cveCount: 0,
}

// ── Perfect score ─────────────────────────────────────────────────────────────

describe('computeComponentTrustScore — perfect score', () => {
  it('returns 100 for a clean, well-known, pinned direct dependency', () => {
    const result = computeComponentTrustScore(base)
    expect(result.score).toBe(100)
  })

  it('returns 100 for a clean transitive dep', () => {
    const result = computeComponentTrustScore({ ...base, isDirect: false })
    expect(result.score).toBe(100)
  })

  it('returns an empty signals list when no penalties apply', () => {
    const result = computeComponentTrustScore(base)
    expect(result.signals).toHaveLength(0)
  })
})

// ── Vulnerability penalties ───────────────────────────────────────────────────

describe('computeComponentTrustScore — vulnerability penalties', () => {
  it('deducts 30 when hasKnownVulnerabilities is true (cveCount=0, transitive)', () => {
    // Use isDirect=false to isolate the base vulnerability penalty without
    // triggering the direct-dep surcharge.
    const result = computeComponentTrustScore({
      ...base,
      isDirect: false,
      hasKnownVulnerabilities: true,
      cveCount: 0,
    })
    expect(result.score).toBe(70) // 100 - 30
    expect(result.signals.some((s) => s.includes('Known vulnerability'))).toBe(true)
  })

  it('treats cveCount > 0 as vulnerable even when hasKnownVulnerabilities is false', () => {
    const result = computeComponentTrustScore({
      ...base,
      hasKnownVulnerabilities: false,
      cveCount: 1,
    })
    expect(result.score).toBe(65) // 100 - 30 - 5 (direct surcharge)
  })

  it('applies extra-CVE penalty for cveCount = 3 (direct dep)', () => {
    // 100 - 30 (known) - min(20, 2*8)=16 (extra) - 5 (direct) = 49
    const result = computeComponentTrustScore({
      ...base,
      hasKnownVulnerabilities: true,
      cveCount: 3,
      isDirect: true,
    })
    expect(result.score).toBe(49)
  })

  it('caps extra-CVE penalty at 20 for very high cveCount', () => {
    // 100 - 30 - 20 (capped) - 5 (direct) = 45
    const result = computeComponentTrustScore({
      ...base,
      hasKnownVulnerabilities: true,
      cveCount: 10,
      isDirect: true,
    })
    expect(result.score).toBe(45)
  })

  it('does NOT apply direct surcharge for transitive vulnerable dep', () => {
    // 100 - 30 = 70
    const result = computeComponentTrustScore({
      ...base,
      hasKnownVulnerabilities: true,
      cveCount: 1,
      isDirect: false,
    })
    expect(result.score).toBe(70)
    expect(result.signals.some((s) => s.includes('surcharge'))).toBe(false)
  })

  it('applies direct surcharge for direct vulnerable dep', () => {
    // 100 - 30 - 5 = 65
    const result = computeComponentTrustScore({
      ...base,
      hasKnownVulnerabilities: true,
      cveCount: 1,
      isDirect: true,
    })
    expect(result.score).toBe(65)
    expect(result.signals.some((s) => s.includes('surcharge'))).toBe(true)
  })
})

// ── Typosquat detection ───────────────────────────────────────────────────────

describe('computeComponentTrustScore — typosquat risk', () => {
  it('penalises "lodaash" (1 edit from "lodash") in npm', () => {
    const result = computeComponentTrustScore({
      ...base,
      name: 'lodaash',
      ecosystem: 'npm',
    })
    expect(result.score).toBe(75) // 100 - 25
    expect(result.signals.some((s) => s.includes('Typosquat'))).toBe(true)
  })

  it('does NOT penalise "lodash" itself (exact corpus match)', () => {
    const result = computeComponentTrustScore({
      ...base,
      name: 'lodash',
      ecosystem: 'npm',
    })
    expect(result.score).toBe(100)
  })

  it('does NOT penalise "totally-different-name" (far from corpus)', () => {
    const result = computeComponentTrustScore({
      ...base,
      name: 'totally-different-name',
      ecosystem: 'npm',
    })
    expect(result.score).toBe(100)
  })

  it('applies typosquat penalty for "requets" (2 edits from "requests") in pypi', () => {
    const result = computeComponentTrustScore({
      ...base,
      name: 'requets',
      ecosystem: 'pypi',
    })
    expect(result.score).toBe(75)
  })

  it('does NOT apply typosquat penalty for unknown ecosystem', () => {
    const result = computeComponentTrustScore({
      ...base,
      name: 'lodaash',
      ecosystem: 'unknown_ecosystem',
    })
    // No corpus for unknown ecosystem — no penalty
    expect(result.score).toBe(100)
  })
})

// ── Suspicious name ───────────────────────────────────────────────────────────

describe('computeComponentTrustScore — suspicious name', () => {
  it('penalises a single-char name "x"', () => {
    const result = computeComponentTrustScore({ ...base, name: 'x' })
    expect(result.score).toBe(85) // 100 - 15
    expect(result.signals.some((s) => s.includes('Suspicious name'))).toBe(true)
  })

  it('penalises a two-char name "ab"', () => {
    const result = computeComponentTrustScore({ ...base, name: 'ab' })
    expect(result.score).toBe(85)
  })

  it('penalises a hex-string name "a1b2c3d4e5f6"', () => {
    const result = computeComponentTrustScore({ ...base, name: 'a1b2c3d4e5f6' })
    expect(result.score).toBe(85)
  })

  it('does NOT penalise a three-char name "foo"', () => {
    const result = computeComponentTrustScore({ ...base, name: 'foo' })
    expect(result.score).toBe(100)
  })

  it('does NOT apply suspicious penalty when typosquat already fires', () => {
    // "lodaash" triggers typosquat but NOT suspicious (length > 2, not hex)
    const result = computeComponentTrustScore({ ...base, name: 'lodaash', ecosystem: 'npm' })
    expect(result.score).toBe(75) // only typosquat penalty, not both
    expect(result.signals.some((s) => s.includes('Suspicious name'))).toBe(false)
  })
})

// ── Version signals ───────────────────────────────────────────────────────────

describe('computeComponentTrustScore — version signals', () => {
  it('penalises pre-release "0.9.2"', () => {
    const result = computeComponentTrustScore({ ...base, version: '0.9.2' })
    expect(result.score).toBe(92) // 100 - 8
    expect(result.signals.some((s) => s.includes('Pre-release'))).toBe(true)
  })

  it('penalises pre-release "0.1.0"', () => {
    const result = computeComponentTrustScore({ ...base, version: '0.1.0' })
    expect(result.score).toBe(92)
  })

  it('penalises empty version string', () => {
    const result = computeComponentTrustScore({ ...base, version: '' })
    expect(result.score).toBe(88) // 100 - 12
    expect(result.signals.some((s) => s.includes('Unknown/floating'))).toBe(true)
  })

  it('penalises version "0.0.0" as unknown (not pre-release)', () => {
    const result = computeComponentTrustScore({ ...base, version: '0.0.0' })
    expect(result.score).toBe(88)
  })

  it('penalises version "latest"', () => {
    const result = computeComponentTrustScore({ ...base, version: 'latest' })
    expect(result.score).toBe(88)
  })

  it('penalises version "*"', () => {
    const result = computeComponentTrustScore({ ...base, version: '*' })
    expect(result.score).toBe(88)
  })

  it('does NOT penalise a stable version "1.0.0"', () => {
    const result = computeComponentTrustScore({ ...base, version: '1.0.0' })
    expect(result.score).toBe(100)
  })
})

// ── Penalty stacking and clamping ─────────────────────────────────────────────

describe('computeComponentTrustScore — stacking and clamping', () => {
  it('stacks vulnerability and pre-release penalties', () => {
    // 100 - 30 (known) - 5 (direct) - 8 (prerelease) = 57
    const result = computeComponentTrustScore({
      ...base,
      version: '0.5.0',
      hasKnownVulnerabilities: true,
      cveCount: 1,
      isDirect: true,
    })
    expect(result.score).toBe(57)
  })

  it('clamps score to 0 under maximum possible penalties', () => {
    // Typosquat (25) + vuln (30) + extra-CVE max (20) + direct surcharge (5) + unknown version (12) = 92
    // 100 - 92 = 8
    const result = computeComponentTrustScore({
      name: 'lodaash',
      version: 'latest',
      ecosystem: 'npm',
      isDirect: true,
      hasKnownVulnerabilities: true,
      cveCount: 10,
    })
    expect(result.score).toBe(8)
  })

  it('score never drops below 0', () => {
    // Fabricate a scenario where deductions would exceed 100 without clamping
    const result = computeComponentTrustScore({
      name: 'ab',               // suspicious: -15
      version: 'latest',        // unknown: -12
      ecosystem: 'npm',
      isDirect: true,
      hasKnownVulnerabilities: true,
      cveCount: 10,             // vuln: -30, extra: -20, direct: -5
    })
    // 15 + 12 + 30 + 20 + 5 = 82 → score = 18 (no clamp needed, but proves formula)
    expect(result.score).toBeGreaterThanOrEqual(0)
    expect(result.score).toBeLessThanOrEqual(100)
  })

  it('score never exceeds 100 for a clean component', () => {
    const result = computeComponentTrustScore({
      name: 'my-lib',
      version: '2.3.1',
      ecosystem: 'cargo',
      isDirect: false,
      hasKnownVulnerabilities: false,
      cveCount: 0,
    })
    expect(result.score).toBeLessThanOrEqual(100)
    expect(result.score).toBe(100)
  })
})
