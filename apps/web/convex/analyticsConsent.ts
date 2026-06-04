// §B9 — Analytics Consent Management
//
//   getMyConsent    — query: returns the current user's analytics consent state
//   updateMyConsent — mutation: updates consent for the current user

import { v } from 'convex/values'
import { query, mutation } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

export const getMyConsent = query({
  args: {
    authToken: v.string(),
  },
  handler: async (ctx, args) => {
    if (!args.authToken) return null
    const { userId } = await requireSessionAuth(ctx, args.authToken)

    const record = await ctx.db
      .query('analyticsConsents')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()

    if (!record) return null
    return {
      consent: record.consent,
      consentedAt: record.consentedAt ?? null,
      updatedAt: record.updatedAt,
    }
  },
})

export const updateMyConsent = mutation({
  args: {
    authToken: v.string(),
    consent: v.boolean(),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireSessionAuth(ctx, args.authToken)
    const now = Date.now()

    const existing = await ctx.db
      .query('analyticsConsents')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()

    if (existing) {
      await ctx.db.patch(existing._id, {
        consent: args.consent,
        consentedAt: args.consent ? now : existing.consentedAt,
        updatedAt: now,
      })
    } else {
      await ctx.db.insert('analyticsConsents', {
        userId,
        consent: args.consent,
        consentedAt: args.consent ? now : undefined,
        updatedAt: now,
      })
    }
  },
})
