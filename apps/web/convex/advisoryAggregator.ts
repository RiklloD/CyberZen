import { ConvexError, v } from 'convex/values'
import { internalMutation } from './_generated/server'

const syncProviderSummary = v.object({
  queried: v.number(),
  fetched: v.number(),
  imported: v.number(),
  deduped: v.number(),
})

export const recordSyncRun = internalMutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    triggerType: v.union(v.literal('manual'), v.literal('scheduled')),
    status: v.union(
      v.literal('completed'),
      v.literal('skipped'),
      v.literal('failed'),
    ),
    packageCount: v.number(),
    lookbackHours: v.number(),
    github: syncProviderSummary,
    osv: syncProviderSummary,
    reason: v.optional(v.string()),
    startedAt: v.number(),
    completedAt: v.number(),
  },
  returns: v.id('advisorySyncRuns'),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new ConvexError('Tenant not found')
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new ConvexError('Repository not found')
    }

    return await ctx.db.insert('advisorySyncRuns', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      triggerType: args.triggerType,
      status: args.status,
      packageCount: args.packageCount,
      lookbackHours: args.lookbackHours,
      githubQueried: args.github.queried,
      githubFetched: args.github.fetched,
      githubImported: args.github.imported,
      githubDeduped: args.github.deduped,
      osvQueried: args.osv.queried,
      osvFetched: args.osv.fetched,
      osvImported: args.osv.imported,
      osvDeduped: args.osv.deduped,
      reason: args.reason,
      startedAt: args.startedAt,
      completedAt: args.completedAt,
    })
  },
})
