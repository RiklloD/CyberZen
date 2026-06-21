import { v } from 'convex/values'
import { query, mutation, internalQuery, internalMutation, internalAction } from './_generated/server'
import type { QueryCtx, MutationCtx, ActionCtx } from './_generated/server'
import { api, internal } from './_generated/api'
import type { Doc, Id } from './_generated/dataModel'
import { requireSessionAuth } from './lib/sessionAuth'

// Helper to verify tenant membership and get user (Clerk-compliant via email index)
async function verifyTenantMembership(ctx: QueryCtx | MutationCtx, tenantId: Id<'tenants'>) {
  const { userId } = await requireSessionAuth(ctx)

  const user = await ctx.db.get(userId)
  if (!user) throw new Error('User not found')

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) => q.eq('tenantId', tenantId).eq('userId', user._id))
    .unique()
  if (!membership) throw new Error('Not authorized for this tenant')

  return { user, membership }
}

// ======================= QUERIES =======================

export const getProjectMemory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    let memory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .unique()

    // Create memory if doesn't exist
    if (!memory) {
      return {
        repositoryId: args.repositoryId,
        tenantId: repo.tenantId,
        version: 0,
        lastLearningAt: null,
        memoryStats: {
          totalEpisodes: 0,
          totalPatterns: 0,
          predictionAccuracy: 0,
          coverageScore: 0,
        },
      }
    }

    return memory
  },
})

export const getPatterns = query({
  args: {
    repositoryId: v.id('repositories'),
    type: v.optional(v.union(
      v.literal('recurring_vulnerability'),
      v.literal('recurring_fix'),
      v.literal('developer_pattern'),
      v.literal('temporal_pattern'),
      v.literal('dependency_risk'),
      v.literal('code_path_risk'),
      v.literal('false_positive_signal'),
    )),
    active: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    let query = ctx.db
      .query('memoryPatterns')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))

    const patterns = await query.collect()

    return patterns.filter(pattern => {
      if (args.type && pattern.patternType !== args.type) return false
      if (args.active !== undefined && pattern.isActive !== args.active) return false
      return true
    }).sort((a, b) => b.confidence - a.confidence)
  },
})

export const getPredictions = query({
  args: {
    repositoryId: v.id('repositories'),
    status: v.optional(v.union(
      v.literal('active'),
      v.literal('confirmed'),
      v.literal('disproved'),
      v.literal('expired'),
    )),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    let query = ctx.db
      .query('memoryPredictions')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))

    const predictions = await query.collect()

    return predictions
      .filter(pred => !args.status || pred.status === args.status)
      .sort((a, b) => b.confidence - a.confidence)
  },
})

export const getEpisodes = query({
  args: {
    repositoryId: v.id('repositories'),
    type: v.optional(v.union(
      v.literal('finding'),
      v.literal('breach'),
      v.literal('fix'),
      v.literal('gate_block'),
      v.literal('false_positive'),
      v.literal('scan_result'),
      v.literal('deployment'),
    )),
    limit: v.optional(v.number()),
    since: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    let query = ctx.db
      .query('memoryEpisodes')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .order('desc')

    const episodes = await query.take(args.limit || 100)

    return episodes.filter(episode => {
      if (args.type && episode.episodeType !== args.type) return false
      if (args.since && episode.timestamp < args.since) return false
      return true
    })
  },
})

export const getMemoryTimeline = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const patterns = await ctx.db
      .query('memoryPatterns')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .collect()

    const predictions = await ctx.db
      .query('memoryPredictions')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .collect()

    // Combine patterns and predictions into timeline events
    const events = [
      ...patterns.map(p => ({
        type: 'pattern_discovered' as const,
        timestamp: p.firstSeenAt,
        data: { name: p.name, patternType: p.patternType, confidence: p.confidence },
      })),
      ...predictions.map(p => ({
        type: 'prediction_made' as const,
        timestamp: p.createdAt,
        data: { title: p.title, predictionType: p.predictionType, confidence: p.confidence },
      })),
    ]

    return events.sort((a, b) => b.timestamp - a.timestamp)
  },
})

export const getMemoryInsights = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    await verifyTenantMembership(ctx, args.tenantId)

    // Get all patterns across tenant repos
    const patterns = await ctx.db
      .query('memoryPatterns')
      .withIndex('by_tenant', (q) => q.eq('tenantId', args.tenantId))
      .collect()

    // Group patterns by type and name to find shared ones
    const patternGroups = patterns.reduce((acc, pattern) => {
      const key = `${pattern.patternType}:${pattern.name}`
      if (!acc[key]) acc[key] = []
      acc[key].push(pattern)
      return acc
    }, {} as Record<string, typeof patterns>)

    const sharedPatterns = Object.entries(patternGroups)
      .filter(([, patterns]) => patterns.length >= 2)
      .map(([key, patterns]) => ({
        key,
        patternType: patterns[0].patternType,
        name: patterns[0].name,
        repoCount: patterns.length,
        avgConfidence: patterns.reduce((sum, p) => sum + p.confidence, 0) / patterns.length,
        repositories: patterns.map(p => p.repositoryId),
      }))

    return {
      totalRepos: new Set(patterns.map(p => p.repositoryId)).size,
      totalPatterns: patterns.length,
      sharedPatterns,
    }
  },
})

export const getMemoryInsightsBySlug = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    await verifyTenantMembership(ctx, tenant._id)

    const patterns = await ctx.db
      .query('memoryPatterns')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const patternGroups = patterns.reduce((acc, pattern) => {
      const key = `${pattern.patternType}:${pattern.name}`
      if (!acc[key]) acc[key] = []
      acc[key].push(pattern)
      return acc
    }, {} as Record<string, typeof patterns>)

    const sharedPatterns = Object.entries(patternGroups)
      .filter(([, ps]) => ps.length >= 2)
      .map(([, ps]) => ({
        patternType: ps[0].patternType,
        name: ps[0].name,
        severity: ps[0].severity,
        repoCount: ps.length,
        avgConfidence: ps.reduce((sum, p) => sum + p.confidence, 0) / ps.length,
      }))
      .sort((a, b) => b.repoCount - a.repoCount)

    const memories = await ctx.db
      .query('projectMemories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .collect()

    return {
      totalRepos: new Set(patterns.map(p => p.repositoryId)).size,
      totalPatterns: patterns.length,
      sharedPatterns,
      repoCoverage: memories.map(m => ({
        repositoryId: m.repositoryId,
        coverageScore: m.memoryStats.coverageScore,
        totalPatterns: m.memoryStats.totalPatterns,
        totalEpisodes: m.memoryStats.totalEpisodes,
      })),
    }
  },
})

export const getPredictionAccuracy = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const feedback = await ctx.db
      .query('memoryFeedback')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .collect()

    if (feedback.length === 0) {
      return { accuracy: 0, totalPredictions: 0, confirmed: 0, disproved: 0 }
    }

    const confirmed = feedback.filter(f => f.outcome === 'confirmed').length
    const disproved = feedback.filter(f => f.outcome === 'disproved').length
    const partial = feedback.filter(f => f.outcome === 'partial').length

    return {
      accuracy: (confirmed + partial * 0.5) / feedback.length,
      totalPredictions: feedback.length,
      confirmed,
      disproved,
      partial,
    }
  },
})

// ======================= MUTATIONS =======================

export const updateMemorySettings = mutation({
  args: {
    repositoryId: v.id('repositories'),
    settings: v.object({
      episodesBeforePattern: v.optional(v.number()),
      predictionHorizonDays: v.optional(v.number()),
      patternExpiryDays: v.optional(v.number()),
      enabledAlgorithms: v.optional(v.object({
        patternDetection: v.optional(v.boolean()),
        predictionGeneration: v.optional(v.boolean()),
        falsePositiveLearning: v.optional(v.boolean()),
        temporalAnalysis: v.optional(v.boolean()),
      })),
    }),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const memory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .unique()

    if (!memory) {
      await ctx.db.insert('projectMemories', {
        repositoryId: args.repositoryId,
        tenantId: repo.tenantId,
        version: 1,
        memoryStats: { totalEpisodes: 0, totalPatterns: 0, predictionAccuracy: 0, coverageScore: 0 },
        settings: args.settings,
      })
    } else {
      await ctx.db.patch(memory._id, { settings: args.settings })
    }

    return true
  },
})

export const recordEpisode = mutation({
  args: {
    repositoryId: v.id('repositories'),
    episodeType: v.union(
      v.literal('finding'),
      v.literal('breach'),
      v.literal('fix'),
      v.literal('gate_block'),
      v.literal('false_positive'),
      v.literal('scan_result'),
      v.literal('deployment'),
    ),
    payload: v.any(),
    sourceRef: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    // Get or create project memory
    const existingMemory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .unique()

    let memoryId: Id<'projectMemories'>
    let currentStats: { totalEpisodes: number; totalPatterns: number; predictionAccuracy: number; coverageScore: number }

    if (existingMemory) {
      memoryId = existingMemory._id
      currentStats = existingMemory.memoryStats
    } else {
      const emptyStats = { totalEpisodes: 0, totalPatterns: 0, predictionAccuracy: 0, coverageScore: 0 }
      memoryId = await ctx.db.insert('projectMemories', {
        repositoryId: args.repositoryId,
        tenantId: repo.tenantId,
        version: 1,
        lastLearningAt: undefined,
        memoryStats: emptyStats,
      })
      currentStats = emptyStats
    }

    // Extract simple features for embedding (not ML, just structured attributes)
    const embedding = extractFeatures(args.episodeType, args.payload)

    // Record the episode
    const episodeId = await ctx.db.insert('memoryEpisodes', {
      projectMemoryId: memoryId,
      tenantId: repo.tenantId,
      repositoryId: args.repositoryId,
      episodeType: args.episodeType,
      timestamp: Date.now(),
      payload: args.payload,
      embedding,
      sourceRef: args.sourceRef || `${args.episodeType}-${Date.now()}`,
      processed: false,
    })

    // Update episode count
    await ctx.db.patch(memoryId, {
      memoryStats: {
        ...currentStats,
        totalEpisodes: currentStats.totalEpisodes + 1,
      },
    })

    return episodeId
  },
})

export const submitFeedback = mutation({
  args: {
    predictionId: v.id('memoryPredictions'),
    outcome: v.union(v.literal('confirmed'), v.literal('disproved'), v.literal('partial')),
    actualEvent: v.string(),
  },
  handler: async (ctx, args) => {
    const prediction = await ctx.db.get(args.predictionId)
    if (!prediction) throw new Error('Prediction not found')

    await verifyTenantMembership(ctx, prediction.tenantId)

    // Calculate accuracy delta
    const accuracyDelta = args.outcome === 'confirmed' ? 0.1 :
                         args.outcome === 'partial' ? 0.05 : -0.1

    // Record feedback
    await ctx.db.insert('memoryFeedback', {
      tenantId: prediction.tenantId,
      repositoryId: prediction.repositoryId,
      predictionId: args.predictionId,
      outcome: args.outcome,
      actualEvent: args.actualEvent,
      feedbackAt: Date.now(),
      accuracyDelta,
    })

    // Update prediction status
    const newStatus = args.outcome === 'confirmed' ? 'confirmed' :
                     args.outcome === 'disproved' ? 'disproved' : prediction.status

    await ctx.db.patch(args.predictionId, {
      status: newStatus,
      outcome: args.actualEvent,
    })

    return true
  },
})

export const createUserPattern = mutation({
  args: {
    repositoryId: v.id('repositories'),
    patternData: v.object({
      patternType: v.union(
        v.literal('recurring_vulnerability'),
        v.literal('recurring_fix'),
        v.literal('developer_pattern'),
        v.literal('temporal_pattern'),
        v.literal('dependency_risk'),
        v.literal('code_path_risk'),
        v.literal('false_positive_signal'),
      ),
      name: v.string(),
      description: v.string(),
      severity: v.union(
        v.literal('critical'),
        v.literal('high'),
        v.literal('medium'),
        v.literal('low'),
        v.literal('informational'),
      ),
      attributes: v.any(),
    }),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    // Get or create project memory
    const existingMemory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .unique()

    let memoryId: Id<'projectMemories'>
    let currentStats: { totalEpisodes: number; totalPatterns: number; predictionAccuracy: number; coverageScore: number }

    if (existingMemory) {
      memoryId = existingMemory._id
      currentStats = existingMemory.memoryStats
    } else {
      const emptyStats = { totalEpisodes: 0, totalPatterns: 0, predictionAccuracy: 0, coverageScore: 0 }
      memoryId = await ctx.db.insert('projectMemories', {
        repositoryId: args.repositoryId,
        tenantId: repo.tenantId,
        version: 1,
        lastLearningAt: undefined,
        memoryStats: emptyStats,
      })
      currentStats = emptyStats
    }

    const patternId = await ctx.db.insert('memoryPatterns', {
      projectMemoryId: memoryId,
      tenantId: repo.tenantId,
      repositoryId: args.repositoryId,
      patternType: args.patternData.patternType,
      name: args.patternData.name,
      description: args.patternData.description,
      confidence: 0.5,
      frequency: 1,
      firstSeenAt: Date.now(),
      lastSeenAt: Date.now(),
      attributes: args.patternData.attributes,
      severity: args.patternData.severity,
      isActive: true,
      relatedPatternIds: [],
      createdBy: 'user',
    })

    // Update pattern count
    await ctx.db.patch(memoryId, {
      memoryStats: {
        ...currentStats,
        totalPatterns: currentStats.totalPatterns + 1,
      },
    })

    return patternId
  },
})

export const dismissPattern = mutation({
  args: {
    patternId: v.id('memoryPatterns'),
    dismissReason: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const pattern = await ctx.db.get(args.patternId)
    if (!pattern) throw new Error('Pattern not found')

    await verifyTenantMembership(ctx, pattern.tenantId)

    await ctx.db.patch(args.patternId, {
      isActive: false,
      dismissedAt: Date.now(),
      dismissReason: args.dismissReason || 'User dismissed',
    })

    return true
  },
})

export const addNote = mutation({
  args: {
    targetId: v.string(),
    targetType: v.union(
      v.literal('pattern'),
      v.literal('prediction'),
      v.literal('episode')
    ),
    repositoryId: v.id('repositories'),
    text: v.string(),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    const { user } = await verifyTenantMembership(ctx, repo.tenantId)

    return await ctx.db.insert('memoryNotes', {
      targetId: args.targetId,
      targetType: args.targetType,
      tenantId: repo.tenantId,
      repositoryId: args.repositoryId,
      text: args.text,
      authorId: user._id,
      createdAt: Date.now(),
    })
  },
})

export const deleteNote = mutation({
  args: { noteId: v.id('memoryNotes') },
  handler: async (ctx, args) => {
    const note = await ctx.db.get(args.noteId)
    if (!note) throw new Error('Note not found')

    const { user } = await verifyTenantMembership(ctx, note.tenantId)

    // Only allow author to delete their own note
    if (note.authorId !== user._id) {
      throw new Error('Not authorized to delete this note')
    }

    await ctx.db.delete(args.noteId)
    return true
  },
})

export const getNotes = query({
  args: {
    targetId: v.string(),
    targetType: v.union(
      v.literal('pattern'),
      v.literal('prediction'),
      v.literal('episode')
    ),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const notes = await ctx.db
      .query('memoryNotes')
      .withIndex('by_target', (q) => q.eq('targetId', args.targetId).eq('targetType', args.targetType))
      .collect()

    // Get author information
    const notesWithAuthors = await Promise.all(
      notes.map(async (note) => {
        const author = await ctx.db.get(note.authorId)
        return {
          ...note,
          authorName: author?.name || 'Unknown',
          authorEmail: author?.email || '',
        }
      })
    )

    return notesWithAuthors.sort((a, b) => b.createdAt - a.createdAt)
  },
})

export const resolvePrediction = mutation({
  args: {
    predictionId: v.id('memoryPredictions'),
    outcome: v.union(v.literal('confirmed'), v.literal('disproved'), v.literal('expired')),
    actualEvent: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const prediction = await ctx.db.get(args.predictionId)
    if (!prediction) throw new Error('Prediction not found')

    await verifyTenantMembership(ctx, prediction.tenantId)

    await ctx.db.patch(args.predictionId, {
      status: args.outcome,
      outcome: args.actualEvent,
    })

    return true
  },
})

// ======================= INTERNAL MUTATIONS =======================

export const markEpisodeProcessed = internalMutation({
  args: { episodeId: v.id('memoryEpisodes') },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.episodeId, { processed: true })
  },
})

export const createPattern = internalMutation({
  args: {
    memoryId: v.id('projectMemories'),
    patternData: v.object({
      patternType: v.union(
        v.literal('recurring_vulnerability'),
        v.literal('recurring_fix'),
        v.literal('developer_pattern'),
        v.literal('temporal_pattern'),
        v.literal('dependency_risk'),
        v.literal('code_path_risk'),
        v.literal('false_positive_signal'),
      ),
      name: v.string(),
      description: v.string(),
      confidence: v.number(),
      frequency: v.number(),
      attributes: v.any(),
      severity: v.union(
        v.literal('critical'),
        v.literal('high'),
        v.literal('medium'),
        v.literal('low'),
        v.literal('informational'),
      ),
    }),
  },
  handler: async (ctx, args) => {
    const memory = await ctx.db.get(args.memoryId)
    if (!memory) throw new Error('Memory not found')

    const patternId = await ctx.db.insert('memoryPatterns', {
      projectMemoryId: args.memoryId,
      tenantId: memory.tenantId,
      repositoryId: memory.repositoryId,
      patternType: args.patternData.patternType,
      name: args.patternData.name,
      description: args.patternData.description,
      confidence: args.patternData.confidence,
      frequency: args.patternData.frequency,
      firstSeenAt: Date.now(),
      lastSeenAt: Date.now(),
      attributes: args.patternData.attributes,
      severity: args.patternData.severity,
      isActive: true,
      relatedPatternIds: [],
    })

    // Update pattern count
    await ctx.db.patch(args.memoryId, {
      memoryStats: {
        ...memory.memoryStats,
        totalPatterns: memory.memoryStats.totalPatterns + 1,
      },
    })

    return patternId
  },
})

export const createPrediction = internalMutation({
  args: {
    memoryId: v.id('projectMemories'),
    predictionData: v.object({
      predictionType: v.union(
        v.literal('vulnerability_likelihood'),
        v.literal('remediation_suggestion'),
        v.literal('risk_area'),
        v.literal('false_positive_candidate'),
        v.literal('deployment_risk'),
      ),
      title: v.string(),
      description: v.string(),
      confidence: v.number(),
      basedOnPatternIds: v.array(v.id('memoryPatterns')),
      expiresAt: v.optional(v.number()),
    }),
  },
  handler: async (ctx, args) => {
    const memory = await ctx.db.get(args.memoryId)
    if (!memory) throw new Error('Memory not found')

    return await ctx.db.insert('memoryPredictions', {
      projectMemoryId: args.memoryId,
      tenantId: memory.tenantId,
      repositoryId: memory.repositoryId,
      predictionType: args.predictionData.predictionType,
      title: args.predictionData.title,
      description: args.predictionData.description,
      confidence: args.predictionData.confidence,
      basedOnPatternIds: args.predictionData.basedOnPatternIds,
      status: 'active',
      createdAt: Date.now(),
      expiresAt: args.predictionData.expiresAt,
      outcome: undefined,
    })
  },
})

// ======================= INTERNAL ACTIONS =======================

export const runLearningCycle = internalAction({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Get unprocessed episodes
    const episodes = await ctx.runQuery(internal.neuralMemory.getUnprocessedEpisodes, {
      repositoryId: args.repositoryId,
    })

    if (episodes.length === 0) return

    // Group episodes by similarity for pattern detection
    const episodeGroups = groupSimilarEpisodes(episodes)

    // Extract or strengthen patterns
    for (const group of episodeGroups) {
      if (group.length >= 3) { // Need 3+ episodes to form a pattern
        await detectAndCreatePattern(ctx, args.repositoryId, group)
      }
    }

    // Generate predictions from active patterns
    await generatePredictions(ctx, args.repositoryId)

    // Mark episodes as processed
    for (const episode of episodes) {
      await ctx.runMutation(internal.neuralMemory.markEpisodeProcessed, {
        episodeId: episode._id,
      })
    }

    // Update last learning timestamp
    const memory = await ctx.runQuery(api.neuralMemory.getProjectMemory, {
      repositoryId: args.repositoryId,
    })

    if (memory._id) {
      await ctx.runMutation(internal.neuralMemory.updateMemoryLastLearning, {
        memoryId: memory._id,
      })
    }
  },
})

// Helper function to extract features (simplified feature engineering)
function extractFeatures(episodeType: string, payload: any): string[] {
  const features: string[] = [episodeType]

  if (payload) {
    // Extract common attributes based on episode type
    if (payload.severity) features.push(`severity:${payload.severity}`)
    if (payload.cwe) features.push(`cwe:${payload.cwe}`)
    if (payload.filePath) {
      const ext = payload.filePath.split('.').pop()
      features.push(`extension:${ext}`)
      const dir = payload.filePath.split('/')[0]
      features.push(`directory:${dir}`)
    }
    if (payload.dependency) features.push(`dependency:${payload.dependency}`)
    if (payload.ruleId) features.push(`rule:${payload.ruleId}`)
  }

  return features
}

// Helper function to group similar episodes
function groupSimilarEpisodes(episodes: any[]): any[][] {
  const groups: any[][] = []

  for (const episode of episodes) {
    let addedToGroup = false

    for (const group of groups) {
      // Check if episode is similar to group
      if (areEpisodesSimilar(episode, group[0])) {
        group.push(episode)
        addedToGroup = true
        break
      }
    }

    if (!addedToGroup) {
      groups.push([episode])
    }
  }

  return groups
}

// Helper function to check episode similarity
function areEpisodesSimilar(episode1: any, episode2: any): boolean {
  if (episode1.episodeType !== episode2.episodeType) return false

  // Check overlap in embeddings
  const overlap = episode1.embedding.filter((f: string) => episode2.embedding.includes(f)).length
  const total = new Set([...episode1.embedding, ...episode2.embedding]).size

  return overlap / total > 0.5 // 50% similarity threshold
}

// Helper functions for pattern detection and prediction generation
async function detectAndCreatePattern(ctx: ActionCtx, repositoryId: Id<'repositories'>, episodes: any[]) {
  const memory = await ctx.runQuery(api.neuralMemory.getProjectMemory, { repositoryId })
  if (!memory._id) return

  // Analyze episode group to determine pattern type
  const firstEpisode = episodes[0]
  const commonFeatures = getCommonFeatures(episodes)

  let patternType: any
  let name: string
  let description: string
  let severity: any = 'medium'

  // Detect pattern type based on common features
  if (commonFeatures.includes('cwe:')) {
    patternType = 'recurring_vulnerability'
    const cwe = commonFeatures.find(f => f.startsWith('cwe:'))?.split(':')[1]
    name = `Recurring ${cwe || 'vulnerability'} pattern`
    description = `Repeated occurrences of ${cwe || 'vulnerability'} in similar contexts`
    severity = determineSeverityFromEpisodes(episodes)
  } else if (firstEpisode.episodeType === 'fix') {
    patternType = 'recurring_fix'
    name = 'Recurring fix pattern'
    description = 'Similar fix approaches used multiple times'
  } else if (firstEpisode.episodeType === 'false_positive') {
    patternType = 'false_positive_signal'
    name = 'False positive pattern'
    description = 'Repeated false positive dismissals with similar characteristics'
    severity = 'low'
  } else if (commonFeatures.some(f => f.startsWith('dependency:'))) {
    patternType = 'dependency_risk'
    const dep = commonFeatures.find(f => f.startsWith('dependency:'))?.split(':')[1]
    name = `Dependency risk: ${dep}`
    description = `Recurring issues related to ${dep} dependency`
  } else if (commonFeatures.some(f => f.startsWith('directory:'))) {
    patternType = 'code_path_risk'
    const dir = commonFeatures.find(f => f.startsWith('directory:'))?.split(':')[1]
    name = `High-risk area: ${dir}/`
    description = `Elevated finding frequency in ${dir}/ directory`
  } else {
    // Default to developer pattern
    patternType = 'developer_pattern'
    name = 'General security pattern'
    description = 'Recurring security-related events with similar characteristics'
  }

  // Calculate confidence based on frequency and consistency
  const confidence = Math.min(0.95, 0.3 + (episodes.length * 0.1))

  // Create the pattern
  await ctx.runMutation(internal.neuralMemory.createPattern, {
    memoryId: memory._id,
    patternData: {
      patternType,
      name,
      description,
      confidence,
      frequency: episodes.length,
      attributes: {
        commonFeatures,
        episodeIds: episodes.map(e => e._id),
        timeSpan: Math.max(...episodes.map(e => e.timestamp)) - Math.min(...episodes.map(e => e.timestamp)),
      },
      severity,
    },
  })
}

async function generatePredictions(ctx: ActionCtx, repositoryId: Id<'repositories'>) {
  const memory = await ctx.runQuery(api.neuralMemory.getProjectMemory, { repositoryId })
  if (!memory._id) return

  const patterns = await ctx.runQuery(api.neuralMemory.getPatterns, {
    repositoryId,
    active: true,
  })

  // Generate predictions from high-confidence patterns
  for (const pattern of patterns) {
    if (pattern.confidence > 0.7 && pattern.lastSeenAt > Date.now() - (30 * 24 * 60 * 60 * 1000)) {
      // Pattern is confident and recent

      let predictionType: any
      let title: string
      let description: string
      const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days

      switch (pattern.patternType) {
        case 'recurring_vulnerability':
          predictionType = 'vulnerability_likelihood'
          title = `High likelihood: ${pattern.name}`
          description = `Based on ${pattern.frequency} occurrences, this vulnerability type is likely to reappear in the next 30 days`
          break

        case 'recurring_fix':
          predictionType = 'remediation_suggestion'
          title = `Recommended approach: ${pattern.name}`
          description = `This fix pattern has been successful ${pattern.frequency} times before`
          break

        case 'code_path_risk':
          predictionType = 'risk_area'
          title = `High-risk area identified: ${pattern.name}`
          description = `This code area shows ${pattern.frequency}x higher finding density than average`
          break

        case 'false_positive_signal':
          predictionType = 'false_positive_candidate'
          title = `Likely false positive: ${pattern.name}`
          description = `Similar findings have been dismissed ${pattern.frequency} times as false positives`
          break

        case 'dependency_risk':
          predictionType = 'vulnerability_likelihood'
          title = `Dependency risk: ${pattern.name}`
          description = `This dependency has been associated with ${pattern.frequency} security findings`
          break

        case 'temporal_pattern':
          predictionType = 'deployment_risk'
          title = `Deployment timing risk: ${pattern.name}`
          description = `Historical data shows increased finding rate during this pattern`
          break

        default:
          continue // Skip unknown pattern types
      }

      // Check if we already have a similar prediction
      const existingPredictions = await ctx.runQuery(api.neuralMemory.getPredictions, {
        repositoryId,
        status: 'active',
      })

      const hasSimilar = existingPredictions.some(p =>
        p.predictionType === predictionType &&
        p.title.includes(pattern.name.split(':')[0])
      )

      if (!hasSimilar) {
        await ctx.runMutation(internal.neuralMemory.createPrediction, {
          memoryId: memory._id,
          predictionData: {
            predictionType,
            title,
            description,
            confidence: pattern.confidence * 0.9, // Slightly lower confidence for predictions
            basedOnPatternIds: [pattern._id],
            expiresAt,
          },
        })
      }
    }
  }
}

// Helper function to find common features across episodes
function getCommonFeatures(episodes: any[]): string[] {
  if (episodes.length === 0) return []

  const featureSets = episodes.map(e => new Set(e.embedding))
  const intersection = featureSets[0]

  for (let i = 1; i < featureSets.length; i++) {
    for (const feature of intersection) {
      if (!featureSets[i].has(feature)) {
        intersection.delete(feature)
      }
    }
  }

  return Array.from(intersection)
}

// Helper function to determine severity from episodes
function determineSeverityFromEpisodes(episodes: any[]): any {
  const severities = episodes
    .map(e => e.payload?.severity)
    .filter(s => s)

  if (severities.some(s => s === 'critical')) return 'critical'
  if (severities.some(s => s === 'high')) return 'high'
  if (severities.some(s => s === 'medium')) return 'medium'
  if (severities.some(s => s === 'low')) return 'low'
  return 'informational'
}

// Internal helper queries
export const getUnprocessedEpisodes = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('memoryEpisodes')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .filter((q) => q.eq(q.field('processed'), false))
      .collect()
  },
})

export const updateMemoryLastLearning = internalMutation({
  args: { memoryId: v.id('projectMemories') },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.memoryId, {
      lastLearningAt: Date.now(),
    })
  },
})

export const updatePattern = internalMutation({
  args: {
    patternId: v.id('memoryPatterns'),
    updates: v.object({
      confidence: v.optional(v.number()),
      frequency: v.optional(v.number()),
      lastSeenAt: v.optional(v.number()),
      isActive: v.optional(v.boolean()),
    }),
  },
  handler: async (ctx, args) => {
    const updates: any = {}
    if (args.updates.confidence !== undefined) updates.confidence = args.updates.confidence
    if (args.updates.frequency !== undefined) updates.frequency = args.updates.frequency
    if (args.updates.lastSeenAt !== undefined) updates.lastSeenAt = args.updates.lastSeenAt
    if (args.updates.isActive !== undefined) updates.isActive = args.updates.isActive

    await ctx.db.patch(args.patternId, updates)
  },
})

export const deactivatePattern = internalMutation({
  args: { patternId: v.id('memoryPatterns') },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.patternId, { isActive: false })
  },
})

export const resolvePredictionInternal = internalMutation({
  args: {
    predictionId: v.id('memoryPredictions'),
    outcome: v.union(v.literal('confirmed'), v.literal('disproved'), v.literal('expired')),
    actualEvent: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.predictionId, {
      status: args.outcome,
      outcome: args.actualEvent,
    })
  },
})

export const runFeedbackCycle = internalAction({
  args: {},
  handler: async (ctx, args) => {
    // Find expired predictions
    const now = Date.now()
    const expiredPredictions = await ctx.runQuery(internal.neuralMemory.getExpiredPredictions, { now })

    for (const prediction of expiredPredictions) {
      // Auto-resolve as expired
      await ctx.runMutation(internal.neuralMemory.resolvePredictionInternal, {
        predictionId: prediction._id,
        outcome: 'expired',
      })

      // Check if the predicted event actually occurred by looking for related episodes
      const relatedEpisodes = await ctx.runQuery(internal.neuralMemory.getEpisodesSince, {
        repositoryId: prediction.repositoryId,
        since: prediction.createdAt,
      })

      // Simple heuristic: if we find episodes that match the prediction type, consider it confirmed
      const matchingEpisodes = relatedEpisodes.filter(episode =>
        isPredictionMatched(prediction, episode)
      )

      if (matchingEpisodes.length > 0) {
        await ctx.runMutation(internal.neuralMemory.resolvePredictionInternal, {
          predictionId: prediction._id,
          outcome: 'confirmed',
          actualEvent: `Found ${matchingEpisodes.length} matching episodes`,
        })
      }
    }
  },
})

export const runCrossProjectLearning = internalAction({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    const insights = await ctx.runQuery(api.neuralMemory.getMemoryInsights, {
      tenantId: args.tenantId,
    })

    // For patterns shared across 3+ repos, create tenant-level predictions
    for (const sharedPattern of insights.sharedPatterns) {
      if (sharedPattern.repoCount >= 3) {
        // Create predictions for repos that don't have this pattern yet
        const allRepos = await ctx.runQuery(internal.neuralMemory.getTenantRepos, {
          tenantId: args.tenantId,
        })

        for (const repo of allRepos) {
          if (!sharedPattern.repositories.includes(repo._id)) {
            // This repo doesn't have this pattern yet - create a prediction
            const memory = await ctx.runQuery(api.neuralMemory.getProjectMemory, {
              repositoryId: repo._id,
            })

            if (memory._id) {
              await ctx.runMutation(internal.neuralMemory.createPrediction, {
                memoryId: memory._id,
                predictionData: {
                  predictionType: 'vulnerability_likelihood',
                  title: `Cross-repo pattern: ${sharedPattern.name}`,
                  description: `This pattern appears in ${sharedPattern.repoCount} other repos in your organization`,
                  confidence: Math.min(0.9, sharedPattern.avgConfidence + 0.1),
                  basedOnPatternIds: [],
                  expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
                },
              })
            }
          }
        }
      }
    }
  },
})

// Helper queries for internal actions
export const getExpiredPredictions = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('memoryPredictions')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', args.now))
      .filter((q) => q.eq(q.field('status'), 'active'))
      .collect()
  },
})

export const getEpisodesSince = internalQuery({
  args: {
    repositoryId: v.id('repositories'),
    since: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('memoryEpisodes')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .filter((q) => q.gt(q.field('timestamp'), args.since))
      .collect()
  },
})

export const getTenantRepos = internalQuery({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', args.tenantId))
      .collect()
  },
})

// ======================= EXPORT ACTIONS =======================

export const exportPatternsCsv = mutation({
  args: {
    repositoryId: v.id('repositories'),
    patternType: v.optional(v.union(
      v.literal('recurring_vulnerability'),
      v.literal('recurring_fix'),
      v.literal('developer_pattern'),
      v.literal('temporal_pattern'),
      v.literal('dependency_risk'),
      v.literal('code_path_risk'),
      v.literal('false_positive_signal'),
    )),
    active: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const patterns = await ctx.runQuery(api.neuralMemory.getPatterns, {
      repositoryId: args.repositoryId,
      type: args.patternType,
      active: args.active,
    })

    // Convert to CSV format
    const csvHeaders = [
      'Name',
      'Type',
      'Confidence',
      'Frequency',
      'Severity',
      'First Seen',
      'Last Seen',
      'Description',
      'Active',
      'Created By'
    ]

    const csvRows = patterns.map(pattern => [
      pattern.name,
      pattern.patternType,
      pattern.confidence.toFixed(3),
      pattern.frequency.toString(),
      pattern.severity,
      new Date(pattern.firstSeenAt).toISOString(),
      new Date(pattern.lastSeenAt).toISOString(),
      pattern.description.replace(/"/g, '""'), // Escape quotes
      pattern.isActive ? 'Yes' : 'No',
      pattern.createdBy || 'system'
    ])

    const csvContent = [
      csvHeaders.join(','),
      ...csvRows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n')

    return csvContent
  },
})

export const exportEpisodesCsv = mutation({
  args: {
    repositoryId: v.id('repositories'),
    episodeType: v.optional(v.union(
      v.literal('finding'),
      v.literal('breach'),
      v.literal('fix'),
      v.literal('gate_block'),
      v.literal('false_positive'),
      v.literal('scan_result'),
      v.literal('deployment'),
    )),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error('Repository not found')

    await verifyTenantMembership(ctx, repo.tenantId)

    const episodes = await ctx.runQuery(api.neuralMemory.getEpisodes, {
      repositoryId: args.repositoryId,
      type: args.episodeType,
      limit: args.limit || 1000,
    })

    // Convert to CSV format
    const csvHeaders = [
      'Type',
      'Timestamp',
      'Source Reference',
      'Payload Summary',
      'Processed'
    ]

    const csvRows = episodes.map(episode => [
      episode.episodeType,
      new Date(episode.timestamp).toISOString(),
      episode.sourceRef,
      JSON.stringify(episode.payload).substring(0, 200) + '...', // Truncated payload
      episode.processed ? 'Yes' : 'No'
    ])

    const csvContent = [
      csvHeaders.join(','),
      ...csvRows.map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
    ].join('\n')

    return csvContent
  },
})

// ======================= HELPER FUNCTIONS =======================

// Helper function to check if a prediction is matched by an episode
function isPredictionMatched(prediction: any, episode: any): boolean {
  switch (prediction.predictionType) {
    case 'vulnerability_likelihood':
      return episode.episodeType === 'finding'
    case 'deployment_risk':
      return episode.episodeType === 'deployment' || episode.episodeType === 'finding'
    case 'false_positive_candidate':
      return episode.episodeType === 'false_positive'
    default:
      return false
  }
}