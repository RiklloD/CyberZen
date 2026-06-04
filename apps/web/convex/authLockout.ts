import { mutation, query } from './_generated/server'
import { v } from 'convex/values'

const MAX_FAILURES = 5
const FAILURE_TTL_MS = 24 * 60 * 60 * 1000 // 24 h — reset counter if no failures for this long

function normalizeEmail(email: string) {
  return email.trim().toLowerCase()
}

function getLockoutDurationMs(lockCount: number): number {
  if (lockCount === 0) return 60 * 1000        // 1 min
  if (lockCount === 1) return 5 * 60 * 1000    // 5 min
  return 30 * 60 * 1000                         // 30 min
}

export const checkAuthLockout = query({
  args: { email: v.string() },
  returns: v.object({
    locked: v.boolean(),
    lockedUntil: v.optional(v.number()),
    attemptsRemaining: v.optional(v.number()),
  }),
  handler: async (ctx, { email }) => {
    const normalized = normalizeEmail(email)
    if (!normalized) return { locked: false }

    const lockout = await ctx.db
      .query('authLockouts')
      .withIndex('by_email', (q) => q.eq('email', normalized))
      .unique()

    if (!lockout) return { locked: false }

    const now = Date.now()

    if (lockout.lastFailedAt < now - FAILURE_TTL_MS) {
      return { locked: false }
    }

    if (lockout.lockedUntil && lockout.lockedUntil > now) {
      return { locked: true, lockedUntil: lockout.lockedUntil }
    }

    const attemptsRemaining = Math.max(0, MAX_FAILURES - lockout.failedAttempts)
    return { locked: false, attemptsRemaining }
  },
})

export const recordAuthFailure = mutation({
  args: { email: v.string() },
  returns: v.object({
    locked: v.boolean(),
    lockedUntil: v.optional(v.number()),
  }),
  handler: async (ctx, { email }) => {
    const normalized = normalizeEmail(email)
    if (!normalized) return { locked: false }

    const now = Date.now()

    const lockout = await ctx.db
      .query('authLockouts')
      .withIndex('by_email', (q) => q.eq('email', normalized))
      .unique()

    if (!lockout) {
      await ctx.db.insert('authLockouts', {
        email: normalized,
        failedAttempts: 1,
        lastFailedAt: now,
        lockCount: 0,
      })
      return { locked: false }
    }

    // Stale record — reset
    if (lockout.lastFailedAt < now - FAILURE_TTL_MS) {
      await ctx.db.patch(lockout._id, {
        failedAttempts: 1,
        lastFailedAt: now,
        lockedUntil: undefined,
        lockCount: 0,
      })
      return { locked: false }
    }

    // Already locked — just update timestamp, do not escalate
    if (lockout.lockedUntil && lockout.lockedUntil > now) {
      await ctx.db.patch(lockout._id, { lastFailedAt: now })
      return { locked: true, lockedUntil: lockout.lockedUntil }
    }

    const newAttempts = lockout.failedAttempts + 1

    if (newAttempts >= MAX_FAILURES) {
      const durationMs = getLockoutDurationMs(lockout.lockCount)
      const lockedUntil = now + durationMs
      await ctx.db.patch(lockout._id, {
        failedAttempts: newAttempts,
        lastFailedAt: now,
        lockedUntil,
        lockCount: lockout.lockCount + 1,
      })
      return { locked: true, lockedUntil }
    }

    await ctx.db.patch(lockout._id, {
      failedAttempts: newAttempts,
      lastFailedAt: now,
    })
    return { locked: false }
  },
})
