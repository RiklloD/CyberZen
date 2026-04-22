// SOC 2 Automated Evidence Collection — Convex entrypoints (spec §10.1).
//
// Generates per-framework compliance evidence snapshots from the latest
// findings, gate decisions, and PR proposals for a repository.
//
// Entrypoints:
//   refreshComplianceEvidence              — internalMutation: builds evidence
//       report for all 5 frameworks and persists snapshots.
//
//   refreshComplianceEvidenceForRepository — public mutation: dashboard trigger.
//
//   getLatestComplianceEvidence            — public query: latest snapshot per
//       framework for dashboard display.
//
//   getAllFrameworkEvidence                 — public query: all frameworks in one
//       call (dashboard summary panel + API export).

import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import {
  generateComplianceEvidence,
  type ComplianceEvidenceInput,
  type EvidenceFinding,
  type EvidenceGateDecision,
} from './lib/complianceEvidence'

const ALL_FRAMEWORKS = ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'] as const
type Framework = (typeof ALL_FRAMEWORKS)[number]

// ---------------------------------------------------------------------------
// refreshComplianceEvidence (internal)
// ---------------------------------------------------------------------------

export const refreshComplianceEvidence = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const now = Date.now()

    // Load all data needed for evidence generation in parallel
    const [findingDocs, gateDecisionDocs, prProposalDocs] = await Promise.all([
      ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', args.repositoryId),
        )
        .take(300),
      ctx.db
        .query('gateDecisions')
        .withIndex('by_repository_and_stage', (q) =>
          q.eq('repositoryId', args.repositoryId),
        )
        .take(100),
      ctx.db
        .query('prProposals')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', args.repositoryId),
        )
        .take(50),
    ])

    // Build a map of finding ID → prUrl for PR audit trail evidence
    const prUrlByFindingId = new Map<string, string>()
    for (const pr of prProposalDocs) {
      if (pr.prUrl) {
        prUrlByFindingId.set(pr.findingId as string, pr.prUrl)
      }
    }

    // Shape findings into EvidenceFinding[]
    const findings: EvidenceFinding[] = findingDocs.map((f) => ({
      id: f._id as string,
      vulnClass: f.vulnClass ?? 'unknown',
      severity: f.severity,
      status: f.status,
      validationStatus: f.validationStatus,
      affectedPackages: f.affectedPackages ?? [],
      createdAt: f._creationTime,
      resolvedAt: f.resolvedAt,
      prUrl: prUrlByFindingId.get(f._id as string),
    }))

    // Shape gate decisions into EvidenceGateDecision[]
    const gateDecisions: EvidenceGateDecision[] = gateDecisionDocs.map((g) => ({
      findingId: g.findingId as string,
      decision: g.decision,
      reason: g.justification,      // schema uses 'justification'
      decidedAt: g.createdAt,       // schema uses 'createdAt' for decision timestamp
      expiresAt: g.expiresAt,
    }))

    // Get tenantId from the repository
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error(`Repository ${args.repositoryId} not found`)

    // Generate and persist a snapshot for each framework
    for (const framework of ALL_FRAMEWORKS) {
      const input: ComplianceEvidenceInput = {
        framework,
        findings,
        gateDecisions,
        repositoryName: repo.fullName,
        scanTimestamp: now,
      }

      const report = generateComplianceEvidence(input)

      await ctx.db.insert('complianceEvidenceSnapshots', {
        tenantId: repo.tenantId,
        repositoryId: args.repositoryId,
        framework,
        evidenceScore: report.evidenceScore,
        coveredControlCount: report.coveredControlCount,
        openGapControlCount: report.openGapControlCount,
        totalEvidenceItems: report.totalEvidenceItems,
        evidenceItems: report.evidenceItems.slice(0, 20), // bounded
        summary: report.summary,
        generatedAt: now,
      })
    }

    return {
      frameworkCount: ALL_FRAMEWORKS.length,
      findingCount: findings.length,
    }
  },
})

// ---------------------------------------------------------------------------
// refreshComplianceEvidenceForRepository (public mutation)
// ---------------------------------------------------------------------------

export const refreshComplianceEvidenceForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) throw new Error(`Repository ${args.repositoryId} not found`)

    await ctx.scheduler.runAfter(
      0,
      internal.complianceEvidenceIntel.refreshComplianceEvidence,
      { repositoryId: args.repositoryId },
    )

    return { scheduled: true }
  },
})

// ---------------------------------------------------------------------------
// getLatestComplianceEvidence (public query — single framework)
// ---------------------------------------------------------------------------

export const getLatestComplianceEvidence = query({
  args: {
    repositoryId: v.id('repositories'),
    framework: v.union(
      v.literal('soc2'),
      v.literal('gdpr'),
      v.literal('hipaa'),
      v.literal('pci_dss'),
      v.literal('nis2'),
    ),
  },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('complianceEvidenceSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .filter((q) => q.eq(q.field('framework'), args.framework))
      .first()
  },
})

// ---------------------------------------------------------------------------
// getFrameworkEvidenceBySlug (public query — slug+name lookup for HTTP API)
// ---------------------------------------------------------------------------

export const getFrameworkEvidenceBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .first()

    if (!tenant) return null

    const repo = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .first()

    if (!repo) return null

    const snapshots = await ctx.db
      .query('complianceEvidenceSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repo._id),
      )
      .order('desc')
      .take(50)

    const latestByFramework = new Map<string, (typeof snapshots)[0]>()
    for (const snap of snapshots) {
      if (!latestByFramework.has(snap.framework)) {
        latestByFramework.set(snap.framework, snap)
      }
    }

    return ALL_FRAMEWORKS.map((fw) => {
      const snap = latestByFramework.get(fw)
      if (!snap) {
        return {
          framework: fw,
          evidenceScore: null,
          openGapControlCount: 0,
          coveredControlCount: 0,
          summary: 'Evidence not yet generated.',
          generatedAt: null,
        }
      }
      return {
        framework: snap.framework,
        evidenceScore: snap.evidenceScore,
        openGapControlCount: snap.openGapControlCount,
        coveredControlCount: snap.coveredControlCount,
        summary: snap.summary,
        generatedAt: snap.generatedAt,
      }
    })
  },
})

// ---------------------------------------------------------------------------
// getAllFrameworkEvidence (public query — all 5 frameworks in one call)
// ---------------------------------------------------------------------------

export const getAllFrameworkEvidence = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    // Fetch the latest snapshot for each framework
    const snapshots = await ctx.db
      .query('complianceEvidenceSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(50) // enough to cover all 5 frameworks with some history

    // Deduplicate: keep only the most recent per framework
    const latestByFramework = new Map<Framework, (typeof snapshots)[0]>()
    for (const snap of snapshots) {
      if (!latestByFramework.has(snap.framework as Framework)) {
        latestByFramework.set(snap.framework as Framework, snap)
      }
    }

    return ALL_FRAMEWORKS.map((fw) => {
      const snap = latestByFramework.get(fw)
      if (!snap) {
        return {
          framework: fw,
          evidenceScore: null,
          openGapControlCount: 0,
          coveredControlCount: 0,
          summary: 'Evidence not yet generated — trigger a scan to populate.',
          generatedAt: null,
        }
      }
      return {
        framework: snap.framework,
        evidenceScore: snap.evidenceScore,
        openGapControlCount: snap.openGapControlCount,
        coveredControlCount: snap.coveredControlCount,
        summary: snap.summary,
        generatedAt: snap.generatedAt,
      }
    })
  },
})
