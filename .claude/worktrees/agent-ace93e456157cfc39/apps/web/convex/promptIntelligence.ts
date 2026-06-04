// WS-13 — Prompt and supply-chain intelligence: Convex entrypoints.
//
// This module wires the pure detection libs into the Convex backend:
//
//   scanContent       — internalMutation: run prompt injection scan + persist result
//   recentScans       — public query: list recent injection scans for a repository
//   supplyChainAnalysis — public query: on-demand supply chain risk analysis from latest SBOM
//
// Design notes:
//   - scanContent is internal because it should only be called by agent actions /
//     workflow mutations that already have verified context, not by arbitrary callers.
//   - recentScans and supplyChainAnalysis are public queries consumed by the dashboard.
//   - supplyChainAnalysis is fully on-demand (no separate write step) because the
//     underlying SBOM component data is already normalised in sbomComponents; there
//     is no benefit to storing a pre-computed snapshot when the input is immutable.

import { v } from 'convex/values'
import { internalMutation, query } from './_generated/server'
import type { Id } from './_generated/dataModel'
import { scanForPromptInjection } from './lib/promptInjection'
import { analyzeSupplyChain } from './lib/supplyChainIntel'

// ---------------------------------------------------------------------------
// djb2 hash — deterministic dedup key for scanned content.
// Not cryptographic; used only to skip re-scanning identical inputs.
// ---------------------------------------------------------------------------

function djb2Hash(content: string): string {
  let hash = 5381
  for (let i = 0; i < content.length; i++) {
    hash = (((hash << 5) + hash) ^ content.charCodeAt(i)) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

// ---------------------------------------------------------------------------
// Shared validators (mirrors schema to keep the return type explicit)
// ---------------------------------------------------------------------------

const riskLevel = v.union(
  v.literal('clean'),
  v.literal('suspicious'),
  v.literal('likely_injection'),
  v.literal('confirmed_injection'),
)

const supplyChainRiskLevel = v.union(
  v.literal('low'),
  v.literal('medium'),
  v.literal('high'),
  v.literal('critical'),
)

// ---------------------------------------------------------------------------
// promptIntelligence.scanContent
// Internal mutation — called by agent workflow actions to scan a piece of
// untrusted text and persist the result into promptInjectionScans.
//
// Returns the scan outcome immediately so the caller can make a gate decision
// without a follow-up query.
// ---------------------------------------------------------------------------

export const scanContent = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.optional(v.id('workflowRuns')),
    /** Human-readable label for what is being scanned, e.g. "pr_body", "commit_message". */
    contentRef: v.string(),
    content: v.string(),
  },
  returns: v.object({
    scanId: v.id('promptInjectionScans'),
    score: v.number(),
    riskLevel,
    detectedPatterns: v.array(v.string()),
    categories: v.array(v.string()),
    summary: v.string(),
  }),
  handler: async (ctx, args) => {
    const result = scanForPromptInjection(args.content)
    const contentHash = djb2Hash(args.content)

    const scanId = await ctx.db.insert('promptInjectionScans', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      workflowRunId: args.workflowRunId,
      contentRef: args.contentRef,
      contentHash,
      score: result.score,
      detectedPatterns: result.detectedPatterns,
      categories: result.categories,
      riskLevel: result.riskLevel,
      scannedAt: Date.now(),
    })

    return {
      scanId,
      score: result.score,
      riskLevel: result.riskLevel,
      detectedPatterns: result.detectedPatterns,
      categories: result.categories,
      summary: result.summary,
    }
  },
})

// ---------------------------------------------------------------------------
// promptIntelligence.scanContentByRef
// Internal mutation — slug/provider-based adapter for callers (actions) that
// have tenantSlug+repositoryFullName or just repositoryFullName+provider but
// not raw Convex IDs.
//
// Resolution strategy:
//   tenantSlug provided  → by_tenant_and_full_name (precise)
//   tenantSlug absent    → by_provider_and_full_name with provider (default: 'github')
//
// Returns null when the repository cannot be resolved rather than throwing,
// so callers can fire-and-forget safely without try/catch on the null path.
// ---------------------------------------------------------------------------

export const scanContentByRef = internalMutation({
  args: {
    tenantSlug: v.optional(v.string()),
    repositoryFullName: v.string(),
    /** Repository provider — used when tenantSlug is absent. Defaults to 'github'. */
    provider: v.optional(v.union(v.literal('github'), v.literal('gitlab'))),
    workflowRunId: v.optional(v.id('workflowRuns')),
    contentRef: v.string(),
    content: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      scanId: v.id('promptInjectionScans'),
      score: v.number(),
      riskLevel,
      detectedPatterns: v.array(v.string()),
      categories: v.array(v.string()),
      summary: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const trimmed = args.content.trim()
    if (!trimmed) return null

    let tenantId: Id<'tenants'>
    let repositoryId: Id<'repositories'>

    const slug = args.tenantSlug
    if (slug) {
      const tenant = await ctx.db
        .query('tenants')
        .withIndex('by_slug', (q) => q.eq('slug', slug))
        .unique()
      if (!tenant) return null

      const repository = await ctx.db
        .query('repositories')
        .withIndex('by_tenant_and_full_name', (q) =>
          q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
        )
        .unique()
      if (!repository) return null

      tenantId = tenant._id
      repositoryId = repository._id
    } else {
      const provider = args.provider ?? 'github'
      const repository = await ctx.db
        .query('repositories')
        .withIndex('by_provider_and_full_name', (q) =>
          q.eq('provider', provider).eq('fullName', args.repositoryFullName),
        )
        .unique()
      if (!repository) return null

      tenantId = repository.tenantId
      repositoryId = repository._id
    }

    const result = scanForPromptInjection(trimmed)
    const contentHash = djb2Hash(trimmed)

    const scanId = await ctx.db.insert('promptInjectionScans', {
      tenantId,
      repositoryId,
      workflowRunId: args.workflowRunId,
      contentRef: args.contentRef,
      contentHash,
      score: result.score,
      detectedPatterns: result.detectedPatterns,
      categories: result.categories,
      riskLevel: result.riskLevel,
      scannedAt: Date.now(),
    })

    return {
      scanId,
      score: result.score,
      riskLevel: result.riskLevel,
      detectedPatterns: result.detectedPatterns,
      categories: result.categories,
      summary: result.summary,
    }
  },
})

// ---------------------------------------------------------------------------
// promptIntelligence.recentScans
// Public query — returns the most recent injection scans for a repository,
// used by the dashboard to surface the prompt injection risk panel.
// ---------------------------------------------------------------------------

export const recentScans = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
  },
  returns: v.array(
    v.object({
      _id: v.id('promptInjectionScans'),
      contentRef: v.string(),
      score: v.number(),
      riskLevel,
      detectedPatterns: v.array(v.string()),
      categories: v.array(v.string()),
      scannedAt: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) return []

    const cap = Math.min(args.limit ?? 20, 100)

    const scans = await ctx.db
      .query('promptInjectionScans')
      .withIndex('by_repository_and_scanned_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(cap)

    return scans.map((s) => ({
      _id: s._id,
      contentRef: s.contentRef,
      score: s.score,
      riskLevel: s.riskLevel,
      detectedPatterns: s.detectedPatterns,
      categories: s.categories,
      scannedAt: s.scannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// promptIntelligence.supplyChainAnalysis
// Public query — runs supply chain intelligence against the latest SBOM
// snapshot for a repository. Fully on-demand; no pre-computation needed
// because sbomComponents is immutable per snapshot.
// ---------------------------------------------------------------------------

export const supplyChainAnalysis = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      overallRiskScore: v.number(),
      riskLevel: supplyChainRiskLevel,
      flaggedComponents: v.array(
        v.object({
          name: v.string(),
          version: v.string(),
          ecosystem: v.string(),
          isDirect: v.boolean(),
          riskScore: v.number(),
          riskLevel: supplyChainRiskLevel,
          summary: v.string(),
        }),
      ),
      typosquatCandidates: v.array(v.string()),
      deepChainDepth: v.number(),
      summary: v.string(),
      snapshotId: v.union(v.null(), v.id('sbomSnapshots')),
      capturedAt: v.union(v.null(), v.number()),
    }),
  ),
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

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()

    if (!latestSnapshot) {
      return {
        overallRiskScore: 0,
        riskLevel: 'low' as const,
        flaggedComponents: [],
        typosquatCandidates: [],
        deepChainDepth: 0,
        summary:
          'No SBOM snapshot available. Run an SBOM import to enable supply chain analysis.',
        snapshotId: null,
        capturedAt: null,
      }
    }

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
      .collect()

    const analysis = analyzeSupplyChain(
      components.map((c) => ({
        name: c.name,
        version: c.version,
        ecosystem: c.ecosystem,
        layer: c.layer,
        isDirect: c.isDirect,
        trustScore: c.trustScore,
        hasKnownVulnerabilities: c.hasKnownVulnerabilities,
        dependents: c.dependents,
      })),
    )

    return {
      overallRiskScore: analysis.overallRiskScore,
      riskLevel: analysis.riskLevel,
      // Strip per-component signals (internal detail) from the public surface —
      // callers get the summary string and risk level per component.
      flaggedComponents: analysis.flaggedComponents.map((fc) => ({
        name: fc.name,
        version: fc.version,
        ecosystem: fc.ecosystem,
        isDirect: fc.isDirect,
        riskScore: fc.riskScore,
        riskLevel: fc.riskLevel,
        summary: fc.summary,
      })),
      typosquatCandidates: analysis.typosquatCandidates,
      deepChainDepth: analysis.deepChainDepth,
      summary: analysis.summary,
      snapshotId: latestSnapshot._id,
      capturedAt: latestSnapshot.capturedAt,
    }
  },
})
