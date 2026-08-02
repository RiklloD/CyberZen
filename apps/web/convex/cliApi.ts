import { internalQuery } from './_generated/server'
import { v } from 'convex/values'

/** Internal data access used only by explicit, tenant-bound CLI HTTP routes. */
export const getRepositoryForTenant = internalQuery({
  args: {
    tenantId: v.id('tenants'),
    fullName: v.string(),
  },
  returns: v.any(),
  handler: async (ctx, { tenantId, fullName }) => {
    return await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenantId).eq('fullName', fullName),
      )
      .unique()
  },
})

export const getRepositoryMemorySummary = internalQuery({
  args: { repositoryId: v.id('repositories') },
  returns: v.object({
    version: v.number(),
    lastLearningAt: v.union(v.number(), v.null()),
    totalEpisodes: v.number(),
    totalPatterns: v.number(),
    predictionAccuracy: v.number(),
    coverageScore: v.number(),
  }),
  handler: async (ctx, { repositoryId }) => {
    const memory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', repositoryId))
      .unique()

    if (!memory) {
      return {
        version: 0,
        lastLearningAt: null,
        totalEpisodes: 0,
        totalPatterns: 0,
        predictionAccuracy: 0,
        coverageScore: 0,
      }
    }

    return {
      version: memory.version,
      lastLearningAt: memory.lastLearningAt ?? null,
      totalEpisodes: memory.memoryStats.totalEpisodes,
      totalPatterns: memory.memoryStats.totalPatterns,
      predictionAccuracy: memory.memoryStats.predictionAccuracy,
      coverageScore: memory.memoryStats.coverageScore,
    }
  },
})
