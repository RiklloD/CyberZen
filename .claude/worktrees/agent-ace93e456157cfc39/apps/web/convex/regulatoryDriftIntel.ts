// WS-15 Phase 1 — Regulatory Drift Detection (spec 3.8): Convex entrypoints.
//
//   refreshRegulatoryDrift              — internalMutation: loads all findings
//       for the repository, runs computeRegulatoryDrift, inserts a snapshot.
//
//   refreshRegulatoryDriftForRepository — public mutation: dashboard trigger.
//
//   getLatestRegulatoryDrift            — public query: latest snapshot for a
//       repository, or null if none has been computed yet.

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  computeRegulatoryDrift,
  type FindingForDriftInput,
} from './lib/regulatoryDrift'

// ---------------------------------------------------------------------------
// refreshRegulatoryDrift (internal)
// ---------------------------------------------------------------------------

export const refreshRegulatoryDrift = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) {
      throw new Error(`Repository ${args.repositoryId} not found`)
    }

    const findingDocs = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .take(200)

    const findings: FindingForDriftInput[] = findingDocs.map((f) => ({
      vulnClass: f.vulnClass,
      severity: f.severity,
      status: f.status,
      validationStatus: f.validationStatus,
    }))

    const result = computeRegulatoryDrift({
      findings,
      repositoryName: repository.name,
    })

    // Extract per-framework scores into flat columns for efficient index lookups.
    const scoreByFramework = Object.fromEntries(
      result.frameworkScores.map((fs) => [fs.framework, fs.score]),
    )

    await ctx.db.insert('regulatoryDriftSnapshots', {
      tenantId: repository.tenantId,
      repositoryId: args.repositoryId,
      soc2Score: scoreByFramework.soc2 ?? 100,
      gdprScore: scoreByFramework.gdpr ?? 100,
      hipaaScore: scoreByFramework.hipaa ?? 100,
      pciDssScore: scoreByFramework.pci_dss ?? 100,
      nis2Score: scoreByFramework.nis2 ?? 100,
      overallDriftLevel: result.overallDriftLevel,
      openGapCount: result.openGapCount,
      criticalGapCount: result.criticalGapCount,
      affectedFrameworks: result.affectedFrameworks,
      summary: result.summary,
      computedAt: Date.now(),
    })

    // Fire-and-forget outbound webhook when new critical regulatory gaps exist.
    if (result.criticalGapCount > 0) {
      try {
        const tenant = await ctx.db.get(repository.tenantId)
        if (tenant) {
          await ctx.scheduler.runAfter(
            0,
            internal.webhooks.dispatchWebhookEvent,
            {
              tenantId: repository.tenantId,
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              eventPayload: {
                event: 'regulatory.gap_detected' as const,
                data: {
                  frameworks: result.affectedFrameworks,
                  driftLevel: result.overallDriftLevel,
                  criticalGapCount: result.criticalGapCount,
                  openGapCount: result.openGapCount,
                },
              },
            },
          )
        }
      } catch (e) {
        console.error('[webhooks] regulatory.gap_detected dispatch failed', e)
      }
    }

    return result
  },
})

// ---------------------------------------------------------------------------
// refreshRegulatoryDriftForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const refreshRegulatoryDriftForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      throw new Error(`Tenant ${args.tenantSlug} not found`)
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      throw new Error(`Repository ${args.repositoryFullName} not found`)
    }

    await ctx.scheduler.runAfter(
      0,
      internal.regulatoryDriftIntel.refreshRegulatoryDrift,
      { repositoryId: repository._id },
    )

    return { scheduled: true, repositoryId: repository._id }
  },
})

// ---------------------------------------------------------------------------
// getLatestRegulatoryDrift (public query)
// ---------------------------------------------------------------------------

export const getLatestRegulatoryDrift = query({
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
      .query('regulatoryDriftSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})
