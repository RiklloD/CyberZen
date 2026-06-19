import { v } from 'convex/values'
import { mutation, query } from './_generated/server'
import type { Id } from './_generated/dataModel'
import { requireSessionAuth } from './lib/sessionAuth'

const SESSION_TTL_MS = 8 * 60 * 60 * 1000

function parseUserAgent(ua: string): { browser?: string; os?: string } {
  const browser = ua.includes('Firefox')
    ? 'Firefox'
    : ua.includes('Edg/')
      ? 'Edge'
      : ua.includes('Chrome')
        ? 'Chrome'
        : ua.includes('Safari')
          ? 'Safari'
          : undefined
  const os = ua.includes('Windows')
    ? 'Windows'
    : ua.includes('Mac OS')
      ? 'macOS'
      : ua.includes('Linux')
        ? 'Linux'
        : ua.includes('Android')
          ? 'Android'
          : ua.includes('iPhone') || ua.includes('iPad')
            ? 'iOS'
            : undefined
  return { browser, os }
}

export const trackSession = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    userAgent: v.optional(v.string()),
    ipAddress: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, userAgent, ipAddress }) => {
    const { userId, sessionId } = await requireSessionAuth(ctx, authToken)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const now = Date.now()
    const authSessionRef = sessionId as string

    const existing = await ctx.db
      .query('userSessions')
      .withIndex('by_auth_session', (q) => q.eq('authSessionRef', authSessionRef))
      .unique()

    const deviceInfo = userAgent ? parseUserAgent(userAgent) : {}

    if (existing) {
      await ctx.db.patch(existing._id, {
        lastSeenAt: now,
        isActive: true,
        expiresAt: now + SESSION_TTL_MS,
      })
    } else {
      await ctx.db.insert('userSessions', {
        userId,
        tenantId: tenant._id,
        authSessionRef,
        deviceInfo: {
          browser: deviceInfo.browser,
          os: deviceInfo.os,
          userAgent,
        },
        ipAddress,
        lastSeenAt: now,
        createdAt: now,
        expiresAt: now + SESSION_TTL_MS,
        isActive: true,
      })
    }

    return null
  },
})

export const listSessions = query({
  args: {
    authToken: v.optional(v.string()),
  },
  returns: v.array(
    v.object({
      _id: v.id('userSessions'),
      userId: v.id('users'),
      tenantId: v.id('tenants'),
      authSessionRef: v.string(),
      deviceInfo: v.object({
        browser: v.optional(v.string()),
        os: v.optional(v.string()),
        userAgent: v.optional(v.string()),
      }),
      ipAddress: v.optional(v.string()),
      lastSeenAt: v.number(),
      createdAt: v.number(),
      expiresAt: v.number(),
      isActive: v.boolean(),
      isCurrent: v.boolean(),
    }),
  ),
  handler: async (ctx, { authToken }) => {
    const { userId, sessionId } = await requireSessionAuth(ctx, authToken)

    const sessions = await ctx.db
      .query('userSessions')
      .withIndex('by_user_and_active', (q) =>
        q.eq('userId', userId).eq('isActive', true),
      )
      .take(50)

    const now = Date.now()
    const currentAuthSessionRef = sessionId as string

    return sessions
      .filter((s) => s.expiresAt > now)
      .map((s) => ({
        _id: s._id,
        userId: s.userId,
        tenantId: s.tenantId,
        authSessionRef: s.authSessionRef,
        deviceInfo: s.deviceInfo,
        ipAddress: s.ipAddress,
        lastSeenAt: s.lastSeenAt,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        isActive: s.isActive,
        isCurrent: s.authSessionRef === currentAuthSessionRef,
      }))
  },
})

export const revokeSession = mutation({
  args: {
    authToken: v.optional(v.string()),
    userSessionId: v.id('userSessions'),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, userSessionId }) => {
    const { userId, sessionId: currentSessionId } = await requireSessionAuth(
      ctx,
      authToken,
    )

    const session = await ctx.db.get(userSessionId)
    if (!session || session.userId !== userId) {
      throw new Error('Session not found')
    }

    if (session.authSessionRef === (currentSessionId as string)) {
      throw new Error(
        'Cannot revoke the current session. Sign out instead.',
      )
    }

    const authSessionId = session.authSessionRef as Id<'authSessions'>
    const authSession = await ctx.db.get(authSessionId)
    if (authSession) {
      await ctx.db.delete(authSessionId)
    }

    await ctx.db.patch(userSessionId, { isActive: false })

    return null
  },
})

export const revokeAllOtherSessions = mutation({
  args: {
    authToken: v.optional(v.string()),
  },
  returns: v.number(),
  handler: async (ctx, { authToken }) => {
    const { userId, sessionId: currentSessionId } = await requireSessionAuth(
      ctx,
      authToken,
    )

    const sessions = await ctx.db
      .query('userSessions')
      .withIndex('by_user_and_active', (q) =>
        q.eq('userId', userId).eq('isActive', true),
      )
      .take(50)

    let revoked = 0
    for (const session of sessions) {
      if (session.authSessionRef === (currentSessionId as string)) continue

      const authSessionId = session.authSessionRef as Id<'authSessions'>
      const authSession = await ctx.db.get(authSessionId)
      if (authSession) {
        await ctx.db.delete(authSessionId)
      }
      await ctx.db.patch(session._id, { isActive: false })
      revoked++
    }

    return revoked
  },
})

export const heartbeat = mutation({
  args: {
    authToken: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { authToken }) => {
    const { sessionId } = await requireSessionAuth(ctx, authToken)

    const authSessionRef = sessionId as string
    const now = Date.now()

    const userSession = await ctx.db
      .query('userSessions')
      .withIndex('by_auth_session', (q) => q.eq('authSessionRef', authSessionRef))
      .unique()

    if (userSession) {
      await ctx.db.patch(userSession._id, {
        lastSeenAt: now,
        expiresAt: now + SESSION_TTL_MS,
      })
    }

    return null
  },
})
