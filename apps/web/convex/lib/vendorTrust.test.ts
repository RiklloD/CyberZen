/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeVendorRiskScore, type VendorRiskScoreInput } from '../vendorTrust'

const MS_PER_DAY = 86_400_000
const now = Date.now()

/** Helper: create a base input with zero risk signals. */
function base(overrides: Partial<VendorRiskScoreInput> = {}): VendorRiskScoreInput {
  return {
    scopes: [],
    breachCount: 0,
    advisoryCount: 0,
    lastUpdated: now,
    ...overrides,
  }
}

// ── Score bounds ────────────────────────────────────────────────────────────

describe('computeVendorRiskScore — score bounds', () => {
  it('returns 0 for a vendor with no risk signals', () => {
    expect(computeVendorRiskScore(base())).toBe(0)
  })

  it('never exceeds 100', () => {
    const input = base({
      scopes: ['repo', 'write:packages', 'admin:org', 'delete_repo', 'workflow'],
      breachCount: 10,
      advisoryCount: 50,
      lastUpdated: now - 365 * MS_PER_DAY, // very stale
    })
    expect(computeVendorRiskScore(input)).toBeLessThanOrEqual(100)
  })

  it('returns a number in [0, 100]', () => {
    const input = base({ breachCount: 2, advisoryCount: 5 })
    const score = computeVendorRiskScore(input)
    expect(score).toBeGreaterThanOrEqual(0)
    expect(score).toBeLessThanOrEqual(100)
  })
})

// ── Empty scopes ────────────────────────────────────────────────────────────

describe('computeVendorRiskScore — empty scopes', () => {
  it('adds 0 when scopes array is empty', () => {
    expect(computeVendorRiskScore(base({ scopes: [] }))).toBe(0)
  })

  it('ignores non-sensitive scopes', () => {
    expect(computeVendorRiskScore(base({ scopes: ['read:user', 'user:email'] }))).toBe(0)
  })
})

// ── Sensitive scopes ────────────────────────────────────────────────────────

describe('computeVendorRiskScore — sensitive scopes', () => {
  it('adds 25 for one sensitive scope', () => {
    expect(computeVendorRiskScore(base({ scopes: ['repo'] }))).toBe(25)
  })

  it('adds 50 for two sensitive scopes (capped at 50)', () => {
    expect(computeVendorRiskScore(base({ scopes: ['repo', 'write:packages'] }))).toBe(50)
  })

  it('caps sensitive scope contribution at 50 even with 5 scopes', () => {
    expect(
      computeVendorRiskScore(
        base({
          scopes: ['repo', 'write:packages', 'admin:org', 'delete_repo', 'workflow'],
        }),
      ),
    ).toBe(50)
  })

  it('handles mix of sensitive and non-sensitive scopes', () => {
    expect(
      computeVendorRiskScore(
        base({ scopes: ['read:user', 'repo', 'user:email'] }),
      ),
    ).toBe(25)
  })
})

// ── Breach count ────────────────────────────────────────────────────────────

describe('computeVendorRiskScore — breach count', () => {
  it('adds 10 per breach', () => {
    expect(computeVendorRiskScore(base({ breachCount: 1 }))).toBe(10)
    expect(computeVendorRiskScore(base({ breachCount: 2 }))).toBe(20)
    expect(computeVendorRiskScore(base({ breachCount: 3 }))).toBe(30)
  })

  it('caps breach contribution at 30', () => {
    expect(computeVendorRiskScore(base({ breachCount: 5 }))).toBe(30)
    expect(computeVendorRiskScore(base({ breachCount: 100 }))).toBe(30)
  })
})

// ── Advisory count ──────────────────────────────────────────────────────────

describe('computeVendorRiskScore — advisory count', () => {
  it('adds 2 per advisory', () => {
    expect(computeVendorRiskScore(base({ advisoryCount: 1 }))).toBe(2)
    expect(computeVendorRiskScore(base({ advisoryCount: 5 }))).toBe(10)
  })

  it('caps advisory contribution at 20', () => {
    expect(computeVendorRiskScore(base({ advisoryCount: 15 }))).toBe(20)
    expect(computeVendorRiskScore(base({ advisoryCount: 100 }))).toBe(20)
  })
})

// ── Staleness ───────────────────────────────────────────────────────────────

describe('computeVendorRiskScore — staleness', () => {
  it('adds 0 when lastUpdated is recent', () => {
    expect(computeVendorRiskScore(base({ lastUpdated: now }))).toBe(0)
  })

  it('adds 0 when lastUpdated is exactly 180 days ago (within tolerance)', () => {
    // Use a timestamp slightly inside the 180-day boundary to avoid
    // timing drift between test capture and function execution.
    const justInside = Date.now() - 180 * MS_PER_DAY + 1000
    expect(computeVendorRiskScore(base({ lastUpdated: justInside }))).toBe(0)
  })

  it('adds 10 when lastUpdated is over 180 days ago', () => {
    expect(computeVendorRiskScore(base({ lastUpdated: now - 181 * MS_PER_DAY }))).toBe(10)
  })

  it('adds 10 for a very stale vendor', () => {
    expect(computeVendorRiskScore(base({ lastUpdated: now - 365 * MS_PER_DAY }))).toBe(10)
  })
})

// ── Combined scenarios ──────────────────────────────────────────────────────

describe('computeVendorRiskScore — combined scenarios', () => {
  it('max breach + all sensitive scopes + max advisories + stale', () => {
    const score = computeVendorRiskScore(
      base({
        scopes: ['repo', 'write:packages', 'admin:org'],
        breachCount: 10,
        advisoryCount: 50,
        lastUpdated: now - 365 * MS_PER_DAY,
      }),
    )
    // 50 (scopes) + 30 (breach) + 20 (advisory) + 10 (stale) = 110 → capped 100
    expect(score).toBe(100)
  })

  it('moderate risk: 1 sensitive scope + 1 breach + 5 advisories', () => {
    const score = computeVendorRiskScore(
      base({
        scopes: ['repo'],
        breachCount: 1,
        advisoryCount: 5,
      }),
    )
    // 25 + 10 + 10 = 45
    expect(score).toBe(45)
  })

  it('low risk: 0 scopes + 0 breaches + 3 advisories', () => {
    expect(computeVendorRiskScore(base({ advisoryCount: 3 }))).toBe(6)
  })
})
