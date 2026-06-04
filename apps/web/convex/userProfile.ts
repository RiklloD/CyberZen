import { query } from './_generated/server'
import { v } from 'convex/values'

/**
 * Returns the current user's profile, workspace role, and GitHub
 * connection status.  Used by the sidebar user-profile button.
 */
export const getProfile = query({
  args: {},
  returns: v.union(
    v.null(),
    v.object({
      userId: v.id('users'),
      email: v.optional(v.string()),
      name: v.optional(v.string()),
      image: v.optional(v.string()),
      githubConnected: v.boolean(),
      githubLogin: v.optional(v.string()),
    }),
  ),
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity()
    if (!identity) return null

    const email = identity.email ?? undefined
    if (!email) return null

    const user = await ctx.db
      .query('users')
      .withIndex('email', (q) => q.eq('email', email))
      .first()

    if (!user) return null

    // Check for a stored GitHub API OAuth token.
    const githubToken = await ctx.db
      .query('userGithubTokens')
      .withIndex('by_user', (q) => q.eq('userId', user._id))
      .first()

    return {
      userId: user._id,
      email,
      name: identity.name ?? undefined,
      image: identity.pictureUrl ?? undefined,
      githubConnected: !!githubToken,
      githubLogin: githubToken?.login,
    }
  },
})
