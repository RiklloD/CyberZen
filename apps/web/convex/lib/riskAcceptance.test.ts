import { describe, expect, it } from 'vitest'
import {
  computeAcceptanceSummary,
  computeExpiresAt,
  formatExpiryText,
  isExpired,
  isExpiringSoon,
} from './riskAcceptance'

const DAY = 24 * 3_600_000
const NOW = 1_700_000_000_000

// ── isExpired ─────────────────────────────────────────────────────────────────

describe('isExpired', () => {
  it('null expiresAt → false (permanent acceptance never expires)', () => {
    expect(isExpired({ expiresAt: null }, NOW)).toBe(false)
  })

  it('undefined expiresAt → false', () => {
    expect(isExpired({}, NOW)).toBe(false)
  })

  it('expiresAt in the future → false', () => {
    expect(isExpired({ expiresAt: NOW + DAY }, NOW)).toBe(false)
  })

  it('expiresAt exactly at now → true (boundary is inclusive)', () => {
    expect(isExpired({ expiresAt: NOW }, NOW)).toBe(true)
  })

  it('expiresAt in the past → true', () => {
    expect(isExpired({ expiresAt: NOW - DAY }, NOW)).toBe(true)
  })
})

// ── isExpiringSoon ────────────────────────────────────────────────────────────

describe('isExpiringSoon', () => {
  it('null expiresAt → false', () => {
    expect(isExpiringSoon({ expiresAt: null }, NOW)).toBe(false)
  })

  it('expiresAt more than 7 days away → false', () => {
    expect(isExpiringSoon({ expiresAt: NOW + 8 * DAY }, NOW)).toBe(false)
  })

  it('expiresAt 3 days away → true', () => {
    expect(isExpiringSoon({ expiresAt: NOW + 3 * DAY }, NOW)).toBe(true)
  })

  it('expiresAt already past → false (expired, not "soon")', () => {
    expect(isExpiringSoon({ expiresAt: NOW - DAY }, NOW)).toBe(false)
  })

  it('custom windowMs: expiresAt within window → true', () => {
    expect(isExpiringSoon({ expiresAt: NOW + DAY }, NOW, 2 * DAY)).toBe(true)
  })

  it('custom windowMs: expiresAt outside window → false', () => {
    expect(isExpiringSoon({ expiresAt: NOW + 3 * DAY }, NOW, 2 * DAY)).toBe(
      false,
    )
  })
})

// ── formatExpiryText ──────────────────────────────────────────────────────────

describe('formatExpiryText', () => {
  it('null → "permanent"', () => {
    expect(formatExpiryText(null, NOW)).toBe('permanent')
  })

  it('undefined → "permanent"', () => {
    expect(formatExpiryText(undefined, NOW)).toBe('permanent')
  })

  it('past → "expired"', () => {
    expect(formatExpiryText(NOW - DAY, NOW)).toBe('expired')
  })

  it('same day (< 24h remaining) → "expires today"', () => {
    expect(formatExpiryText(NOW + 12 * 3_600_000, NOW)).toBe('expires today')
  })

  it('exactly 1 day remaining → "expires tomorrow"', () => {
    expect(formatExpiryText(NOW + DAY + 3_600_000, NOW)).toBe(
      'expires tomorrow',
    )
  })

  it('5 days remaining → "expires in 5d"', () => {
    expect(formatExpiryText(NOW + 5 * DAY + 3_600_000, NOW)).toBe(
      'expires in 5d',
    )
  })
})

// ── computeExpiresAt ──────────────────────────────────────────────────────────

describe('computeExpiresAt', () => {
  it('30 days = createdAt + 30*24*3_600_000', () => {
    expect(computeExpiresAt(NOW, 30)).toBe(NOW + 30 * DAY)
  })

  it('90 days', () => {
    expect(computeExpiresAt(NOW, 90)).toBe(NOW + 90 * DAY)
  })
})

// ── computeAcceptanceSummary ──────────────────────────────────────────────────

describe('computeAcceptanceSummary', () => {
  it('empty records → all zeros', () => {
    const s = computeAcceptanceSummary([], NOW)
    expect(s.totalActive).toBe(0)
    expect(s.expiringSoon).toBe(0)
    expect(s.alreadyExpired).toBe(0)
    expect(s.permanent).toBe(0)
    expect(s.temporary).toBe(0)
  })

  it('revoked and expired records are not counted', () => {
    const records = [
      {
        level: 'permanent' as const,
        expiresAt: null,
        status: 'revoked' as const,
      },
      {
        level: 'temporary' as const,
        expiresAt: NOW - DAY,
        status: 'expired' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.totalActive).toBe(0)
  })

  it('permanent active acceptances counted correctly', () => {
    const records = [
      {
        level: 'permanent' as const,
        expiresAt: null,
        status: 'active' as const,
      },
      {
        level: 'permanent' as const,
        expiresAt: null,
        status: 'active' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.totalActive).toBe(2)
    expect(s.permanent).toBe(2)
    expect(s.temporary).toBe(0)
    expect(s.expiringSoon).toBe(0)
  })

  it('temporary expiring soon is counted', () => {
    const records = [
      {
        level: 'temporary' as const,
        expiresAt: NOW + 3 * DAY,
        status: 'active' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.expiringSoon).toBe(1)
    expect(s.temporary).toBe(1)
  })

  it('temporary already expired but still active is counted in alreadyExpired', () => {
    const records = [
      {
        level: 'temporary' as const,
        expiresAt: NOW - 3_600_000,
        status: 'active' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.alreadyExpired).toBe(1)
    expect(s.expiringSoon).toBe(0)
  })

  it('temporary far in future not expiring soon', () => {
    const records = [
      {
        level: 'temporary' as const,
        expiresAt: NOW + 30 * DAY,
        status: 'active' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.expiringSoon).toBe(0)
    expect(s.alreadyExpired).toBe(0)
    expect(s.temporary).toBe(1)
  })

  it('mixed permanent + temporary + revoked gives correct counts', () => {
    const records = [
      {
        level: 'permanent' as const,
        expiresAt: null,
        status: 'active' as const,
      },
      {
        level: 'temporary' as const,
        expiresAt: NOW + 2 * DAY,
        status: 'active' as const,
      },
      {
        level: 'temporary' as const,
        expiresAt: NOW + 20 * DAY,
        status: 'active' as const,
      },
      {
        level: 'permanent' as const,
        expiresAt: null,
        status: 'revoked' as const,
      },
    ]
    const s = computeAcceptanceSummary(records, NOW)
    expect(s.totalActive).toBe(3)
    expect(s.permanent).toBe(1)
    expect(s.temporary).toBe(2)
    expect(s.expiringSoon).toBe(1) // 2 DAY is within 7d window
  })
})
