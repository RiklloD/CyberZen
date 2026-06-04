import { internalAction, query } from './_generated/server'
import { internal } from './_generated/api'
import { v } from 'convex/values'

// Get all active repositories that need learning cycles
export const getAllActiveRepositories = query({
  args: {},
  handler: async (ctx, args) => {
    return await ctx.db.query('repositories').collect()
  },
})

// Get all active tenants for cross-project learning
export const getAllActiveTenants = query({
  args: {},
  handler: async (ctx, args) => {
    return await ctx.db.query('tenants').collect()
  },
})

// Run learning cycles for all repositories
export const runAllLearningCycles = internalAction({
  args: {},
  handler: async (ctx, args) => {
    // Get all active repositories
    const repositories = await ctx.runQuery(internal.neuralMemoryScheduler.getAllActiveRepositories, {})

    console.log(`Neural Memory: Running learning cycles for ${repositories.length} repositories`)

    // Run learning cycle for each repository
    const learningPromises = repositories.map(async (repo) => {
      try {
        await ctx.runAction(internal.neuralMemory.runLearningCycle, {
          repositoryId: repo._id,
        })
        console.log(`Neural Memory: Learning cycle completed for repo ${repo.fullName}`)
      } catch (error) {
        console.error(`Neural Memory: Learning cycle failed for repo ${repo.fullName}:`, error)
      }
    })

    // Wait for all learning cycles to complete
    await Promise.allSettled(learningPromises)

    console.log(`Neural Memory: All learning cycles completed`)
  },
})

// Run cross-project learning for all tenants
export const runAllCrossProjectLearning = internalAction({
  args: {},
  handler: async (ctx, args) => {
    // Get all active tenants
    const tenants = await ctx.runQuery(internal.neuralMemoryScheduler.getAllActiveTenants, {})

    console.log(`Neural Memory: Running cross-project learning for ${tenants.length} tenants`)

    // Run cross-project learning for each tenant
    const crossProjectPromises = tenants.map(async (tenant) => {
      try {
        await ctx.runAction(internal.neuralMemory.runCrossProjectLearning, {
          tenantId: tenant._id,
        })
        console.log(`Neural Memory: Cross-project learning completed for tenant ${tenant.slug}`)
      } catch (error) {
        console.error(`Neural Memory: Cross-project learning failed for tenant ${tenant.slug}:`, error)
      }
    })

    // Wait for all cross-project learning to complete
    await Promise.allSettled(crossProjectPromises)

    console.log(`Neural Memory: All cross-project learning completed`)
  },
})

// Check which repositories have unprocessed episodes (for monitoring/debugging)
export const getRepositoriesWithUnprocessedEpisodes = query({
  args: {},
  handler: async (ctx, args) => {
    const repositories = await ctx.db.query('repositories').collect()
    const results = []

    for (const repo of repositories) {
      const unprocessedCount = await ctx.db
        .query('memoryEpisodes')
        .withIndex('by_processed', (q) => q.eq('processed', false))
        .filter((q) => q.eq(q.field('repositoryId'), repo._id))
        .collect()
        .then((episodes) => episodes.length)

      if (unprocessedCount > 0) {
        results.push({
          repositoryId: repo._id,
          repositoryName: repo.fullName,
          unprocessedCount,
        })
      }
    }

    return results
  },
})

// Get Neural Memory statistics across all tenants (for admin dashboard)
export const getGlobalNeuralMemoryStats = query({
  args: {},
  handler: async (ctx, args) => {
    const memories = await ctx.db.query('projectMemories').collect()
    const patterns = await ctx.db.query('memoryPatterns').collect()
    const predictions = await ctx.db.query('memoryPredictions').collect()
    const episodes = await ctx.db.query('memoryEpisodes').collect()

    return {
      totalProjects: memories.length,
      totalEpisodes: episodes.length,
      unprocessedEpisodes: episodes.filter(e => !e.processed).length,
      totalPatterns: patterns.length,
      activePatterns: patterns.filter(p => p.isActive).length,
      totalPredictions: predictions.length,
      activePredictions: predictions.filter(p => p.status === 'active').length,
      avgAccuracy: memories.reduce((sum, m) => sum + m.memoryStats.predictionAccuracy, 0) / memories.length || 0,
      avgCoverage: memories.reduce((sum, m) => sum + m.memoryStats.coverageScore, 0) / memories.length || 0,
    }
  },
})