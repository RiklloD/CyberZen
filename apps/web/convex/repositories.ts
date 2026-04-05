import { query } from './_generated/server'
import { v } from 'convex/values'

export const listByTenant = query({
  args: { tenantSlug: v.string() },
  returns: v.array(
    v.object({
      _id: v.id('repositories'),
      name: v.string(),
      fullName: v.string(),
      provider: v.string(),
      primaryLanguage: v.string(),
      defaultBranch: v.string(),
      latestCommitSha: v.optional(v.string()),
      lastScannedAt: v.optional(v.number()),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return []
    }

    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    return repositories.map((repository) => ({
      _id: repository._id,
      name: repository.name,
      fullName: repository.fullName,
      provider: repository.provider,
      primaryLanguage: repository.primaryLanguage,
      defaultBranch: repository.defaultBranch,
      latestCommitSha: repository.latestCommitSha,
      lastScannedAt: repository.lastScannedAt,
    }))
  },
})
