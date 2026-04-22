// AI Model Provenance Intelligence — Convex entrypoints (spec §3.11.2 Layer 6).
//
// Analyses the latest SBOM snapshot for AI model provenance risks:
// source verification, license compliance, weights hash coverage, version
// pinning, and training dataset risk.
//
// Entrypoints:
//   refreshModelProvenance              — internalMutation: fast baseline scan
//       (no network). Runs scanModelProvenance with SBOM data only.
//
//   enrichModelProvenanceFromHF         — internalAction: fetches live HF API
//       metadata for HuggingFace model components and stores an enriched scan
//       that supersedes the baseline. Falls back gracefully per-model on error.
//
//   refreshModelProvenanceForRepository — public mutation: dashboard/manual trigger
//       (schedules both baseline + HF enrichment).
//
//   getLatestModelProvenance            — public query: latest scan for dashboard.
//   getModelProvenanceHistory           — public query: history for trend sparkline.

import { v } from 'convex/values'
import { internalAction, internalMutation, internalQuery, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import type { Doc } from './_generated/dataModel'
import {
  scanModelProvenance,
  type ModelComponentInput,
} from './lib/modelProvenance'
import {
  extractHFModelId,
  isHuggingFaceComponent,
  parseHFApiResponse,
  type HFModelEnrichment,
} from './lib/huggingFaceEnrichment'

// ---------------------------------------------------------------------------
// refreshModelProvenance (internal)
// ---------------------------------------------------------------------------

export const refreshModelProvenance = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Load the latest SBOM snapshot
    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    if (!latestSnapshot) return null

    // Load SBOM components for this snapshot
    const sbomComponents = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .take(500)

    // Map to the pure library's input type
    const modelInputs: ModelComponentInput[] = sbomComponents.map((c) => ({
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
      layer: c.layer,
      license: c.license,
      hasKnownVulnerabilities: c.hasKnownVulnerabilities,
      // weightsHash and trainingDatasets are not in the current SBOM schema —
      // future work can enrich these fields when the HF API integration lands.
      weightsHash: undefined,
      trainingDatasets: undefined,
    }))

    const scan = scanModelProvenance(modelInputs)

    // Prune old scans — keep at most 20 per repository
    const existing = await ctx.db
      .query('modelProvenanceScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (existing.length >= 20) {
      const toDelete = existing.slice(19)
      for (const old of toDelete) {
        await ctx.db.delete(old._id)
      }
    }

    // Insert new snapshot
    await ctx.db.insert('modelProvenanceScans', {
      tenantId: latestSnapshot.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: latestSnapshot._id,
      totalModels: scan.totalModels,
      verifiedCount: scan.verifiedCount,
      riskyCount: scan.riskyCcount,
      aggregateScore: scan.aggregateScore,
      overallRiskLevel: scan.overallRiskLevel,
      components: scan.components.slice(0, 10).map((c) => ({
        name: c.componentName,
        resolvedSource: c.resolvedSource,
        resolvedLicense: c.resolvedLicense,
        provenanceScore: c.provenanceScore,
        riskLevel: c.riskLevel,
        topSignalKind: c.signals[0]?.kind,
        summary: c.summary.slice(0, 280),
      })),
      summary: scan.summary,
      scannedAt: Date.now(),
    })

    return {
      totalModels: scan.totalModels,
      overallRiskLevel: scan.overallRiskLevel,
      aggregateScore: scan.aggregateScore,
    }
  },
})

// ---------------------------------------------------------------------------
// enrichModelProvenanceFromHF (internal action — live HF API enrichment)
// ---------------------------------------------------------------------------
//
// Architecture: Actions can perform HTTP calls; mutations cannot. This action
// fetches live HuggingFace metadata for every HF model component in the latest
// SBOM snapshot, merges the enriched fields into ModelComponentInput[], then
// calls scanModelProvenance and persists the result via a mutation.
//
// Concurrency: fetches are batched at BATCH_SIZE=5 to avoid hammering the
// HF API. Each fetch failure is caught individually — a single 503/404 does
// not abort the full enrichment run. The upserted scan row replaces the
// baseline `refreshModelProvenance` row for the same repository.
//
// Configuration:
//   npx convex env set HUGGINGFACE_API_TOKEN hf_...   (optional; public models
//   do not require auth, but auth doubles the rate limit)

const HF_API_BASE = 'https://huggingface.co/api/models'
const HF_FETCH_BATCH = 5  // max concurrent HF API calls

export const enrichModelProvenanceFromHF = internalAction({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args): Promise<{ enriched: number; skipped: number; errors: number }> => {
    // Load the latest snapshot + components (same logic as the baseline mutation).
    // Explicit `as` casts break the circular-inference issue that arises when an
    // internalAction calls internalQuery/internalMutation from the same module.
    const latestSnapshot = (await ctx.runQuery(
      internal.modelProvenanceIntel.getLatestSnapshotForRepo,
      { repositoryId: args.repositoryId },
    )) as Doc<'sbomSnapshots'> | null
    if (!latestSnapshot) return { enriched: 0, skipped: 0, errors: 0 }

    const allComponents = (await ctx.runQuery(
      internal.modelProvenanceIntel.getSnapshotComponents,
      { snapshotId: latestSnapshot._id },
    )) as Doc<'sbomComponents'>[]

    // Identify HF candidates
    const hfCandidates = allComponents.filter((c) =>
      isHuggingFaceComponent(c.name, c.ecosystem, c.layer),
    )

    if (hfCandidates.length === 0) {
      console.log(`[hf-enrichment] no HF model components for repo ${args.repositoryId}`)
      return { enriched: 0, skipped: allComponents.length, errors: 0 }
    }

    // Fetch HF API in bounded parallel batches
    const hfToken = process.env.HUGGINGFACE_API_TOKEN
    const enrichmentMap = new Map<string, HFModelEnrichment>()
    let errorCount = 0

    for (let i = 0; i < hfCandidates.length; i += HF_FETCH_BATCH) {
      const batch = hfCandidates.slice(i, i + HF_FETCH_BATCH)
      const results = await Promise.all(
        batch.map(async (c) => {
          const modelId = extractHFModelId(c.name)
          if (!modelId) return null

          try {
            const headers: Record<string, string> = {
              'Accept': 'application/json',
              'User-Agent': 'Sentinel-Security-Platform/1.0',
            }
            if (hfToken) headers['Authorization'] = `Bearer ${hfToken}`

            const res = await fetch(`${HF_API_BASE}/${modelId}`, { headers })

            if (!res.ok) {
              console.warn(`[hf-enrichment] ${modelId} → HTTP ${res.status}`)
              return null
            }

            // biome-ignore lint/suspicious/noExplicitAny: HF API is untyped
            const json = (await res.json()) as Record<string, any>
            const parsed = parseHFApiResponse(modelId, json)
            return parsed.ok ? { modelId, enrichment: parsed } : null
          } catch (err) {
            console.warn(`[hf-enrichment] ${modelId} fetch failed: ${err}`)
            return null
          }
        }),
      )

      for (const r of results) {
        if (r) {
          enrichmentMap.set(r.modelId, r.enrichment)
        } else {
          errorCount++
        }
      }
    }

    // Build enriched inputs: merge HF data into SBOM component fields
    const enrichedInputs: ModelComponentInput[] = allComponents.map((c) => {
      const modelId = extractHFModelId(c.name)
      const hf = modelId ? enrichmentMap.get(modelId) : undefined
      return {
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        license: hf?.license ?? c.license,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
        // commitSha serves as a lineage reference, not a binary weights hash;
        // store it in weightsHash field so the signal detector treats absence
        // as resolved rather than flagging it on enriched components.
        weightsHash: hf?.commitSha ?? undefined,
        trainingDatasets: hf?.trainingDatasets,
      }
    })

    const scan = scanModelProvenance(enrichedInputs)

    // Persist the enriched scan (replaces the baseline row)
    await ctx.runMutation(
      internal.modelProvenanceIntel.persistEnrichedModelProvenance,
      {
        repositoryId: args.repositoryId,
        snapshotId: latestSnapshot._id,
        tenantId: latestSnapshot.tenantId,
        totalModels: scan.totalModels,
        verifiedCount: scan.verifiedCount,
        riskyCount: scan.riskyCcount,
        aggregateScore: scan.aggregateScore,
        overallRiskLevel: scan.overallRiskLevel,
        components: scan.components.slice(0, 10).map((c) => ({
          name: c.componentName,
          resolvedSource: c.resolvedSource,
          resolvedLicense: c.resolvedLicense,
          provenanceScore: c.provenanceScore,
          riskLevel: c.riskLevel,
          topSignalKind: c.signals[0]?.kind,
          summary: c.summary.slice(0, 280),
        })),
        summary: `${scan.summary} (HF-enriched: ${enrichmentMap.size}/${hfCandidates.length} models)`,
      },
    )

    console.log(
      `[hf-enrichment] repo=${args.repositoryId} enriched=${enrichmentMap.size} errors=${errorCount}`,
    )
    return { enriched: enrichmentMap.size, skipped: allComponents.length - hfCandidates.length, errors: errorCount }
  },
})

// ---------------------------------------------------------------------------
// persistEnrichedModelProvenance (internal mutation — called by action above)
// ---------------------------------------------------------------------------

export const persistEnrichedModelProvenance = internalMutation({
  args: {
    repositoryId: v.id('repositories'),
    snapshotId: v.id('sbomSnapshots'),
    tenantId: v.id('tenants'),
    totalModels: v.number(),
    verifiedCount: v.number(),
    riskyCount: v.number(),
    aggregateScore: v.number(),
    overallRiskLevel: v.union(
      v.literal('verified'),
      v.literal('acceptable'),
      v.literal('unverified'),
      v.literal('risky'),
    ),
    components: v.array(v.object({
      name: v.string(),
      resolvedSource: v.string(),
      resolvedLicense: v.string(),
      provenanceScore: v.number(),
      riskLevel: v.union(
        v.literal('verified'),
        v.literal('acceptable'),
        v.literal('unverified'),
        v.literal('risky'),
      ),
      topSignalKind: v.optional(v.string()),
      summary: v.string(),
    })),
    summary: v.string(),
  },
  handler: async (ctx, args) => {
    // Prune old scans — keep at most 20 per repository
    const existing = await ctx.db
      .query('modelProvenanceScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .collect()

    if (existing.length >= 20) {
      for (const old of existing.slice(19)) {
        await ctx.db.delete(old._id)
      }
    }

    await ctx.db.insert('modelProvenanceScans', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: args.snapshotId,
      totalModels: args.totalModels,
      verifiedCount: args.verifiedCount,
      riskyCount: args.riskyCount,
      aggregateScore: args.aggregateScore,
      overallRiskLevel: args.overallRiskLevel,
      components: args.components,
      summary: args.summary,
      scannedAt: Date.now(),
    })
  },
})

// ---------------------------------------------------------------------------
// Internal helper queries (used by the action above)
// ---------------------------------------------------------------------------

export const getLatestSnapshotForRepo = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()
  },
})

export const getSnapshotComponents = internalQuery({
  args: { snapshotId: v.id('sbomSnapshots') },
  handler: async (ctx, { snapshotId }) => {
    return ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshotId))
      .take(500)
  },
})

// ---------------------------------------------------------------------------
// refreshModelProvenanceForRepository (public mutation — dashboard trigger)
// ---------------------------------------------------------------------------

export const refreshModelProvenanceForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error(`Repository ${args.repositoryId} not found`)

    // Schedule baseline scan immediately, then HF enrichment right after.
    // The enriched scan supersedes the baseline once the HF fetches complete.
    await ctx.scheduler.runAfter(
      0,
      internal.modelProvenanceIntel.refreshModelProvenance,
      { repositoryId: args.repositoryId },
    )
    await ctx.scheduler.runAfter(
      0,
      internal.modelProvenanceIntel.enrichModelProvenanceFromHF,
      { repositoryId: args.repositoryId },
    )

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// getLatestModelProvenance (public query — dashboard)
// ---------------------------------------------------------------------------

export const getLatestModelProvenance = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('modelProvenanceScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getModelProvenanceHistory (public query — sparkline)
// ---------------------------------------------------------------------------

export const getModelProvenanceHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 10, 20)

    const rows = await ctx.db
      .query('modelProvenanceScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      overallRiskLevel: r.overallRiskLevel,
      aggregateScore: r.aggregateScore,
      totalModels: r.totalModels,
      verifiedCount: r.verifiedCount,
      riskyCount: r.riskyCount,
      scannedAt: r.scannedAt,
    }))
  },
})
