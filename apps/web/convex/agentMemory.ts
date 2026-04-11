// WS-14 Phase 2 — Memory and Learning Loop (spec 3.13): Convex entrypoints.
//
//   refreshRepositoryMemory — internalMutation: loads all findings for a
//       repository, runs aggregateFindingMemory, inserts a new snapshot.
//
//   getRepositoryMemory — public query: latest agentMemorySnapshot for a
//       repository (or null if not yet computed).

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import {
  aggregateFindingMemory,
  type FindingMemoryInput,
} from './lib/memoryController'

// ---------------------------------------------------------------------------
// refreshRepositoryMemory
// ---------------------------------------------------------------------------

export const refreshRepositoryMemory = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    // Load up to 200 findings for this repository (bounded to stay within
    // Convex transaction limits on large codebases).
    // We use the first field of by_repository_and_status as a prefix scan
    // to retrieve all statuses in one pass.
    const findingDocs = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .take(200)

    const findings: FindingMemoryInput[] = findingDocs.map((f) => ({
      vulnClass: f.vulnClass,
      severity: f.severity,
      source: f.source,
      status: f.status,
      validationStatus: f.validationStatus,
      affectedPackages: f.affectedPackages,
      confidence: f.confidence,
      businessImpactScore: f.businessImpactScore,
    }))

    const result = aggregateFindingMemory({ findings })

    await ctx.db.insert('agentMemorySnapshots', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      recurringVulnClasses: result.recurringVulnClasses,
      falsePositiveRate: result.falsePositiveRate,
      highConfidenceClasses: result.highConfidenceClasses,
      packageRiskMap: result.packageRiskMap,
      dominantSeverity: result.dominantSeverity,
      totalFindingsAnalyzed: result.totalFindingsAnalyzed,
      resolvedCount: result.resolvedCount,
      openCount: result.openCount,
      summary: result.summary,
      computedAt: Date.now(),
    })

    return result
  },
})

// ---------------------------------------------------------------------------
// getRepositoryMemory
// ---------------------------------------------------------------------------

export const getRepositoryMemory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return null

    return await ctx.db
      .query('agentMemorySnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})
