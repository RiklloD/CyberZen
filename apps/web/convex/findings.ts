import { ConvexError, v } from 'convex/values'
import { mutation, query } from './_generated/server'
import { internal } from './_generated/api'

// ---------------------------------------------------------------------------
// Shared validators
// ---------------------------------------------------------------------------

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

const findingStatus = v.union(
  v.literal('open'),
  v.literal('pr_opened'),
  v.literal('merged'),
  v.literal('resolved'),
  v.literal('accepted_risk'),
)

const validationStatus = v.union(
  v.literal('pending'),
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
  v.literal('dismissed'),
)

// ---------------------------------------------------------------------------
// findings.list — bounded operator findings list with optional dimension filters
//
// Index selection priority:
//   repositoryId + status  → by_repository_and_status  (most specific)
//   repositoryId only      → by_repository_and_status  (all statuses)
//   status only            → by_tenant_and_status
//   none                   → by_tenant_and_created_at  (default)
//
// Severity filtering is applied in-memory after the index scan since there is
// no compound severity index.  At MVP scale (< 10 k findings) this is safe;
// at production scale add a by_tenant_severity_created index and paginate.
// ---------------------------------------------------------------------------

const findingListRow = v.object({
  _id: v.id('findings'),
  title: v.string(),
  summary: v.string(),
  severity,
  validationStatus: v.string(),
  status: v.string(),
  confidence: v.number(),
  source: v.string(),
  vulnClass: v.string(),
  affectedPackages: v.array(v.string()),
  createdAt: v.number(),
  resolvedAt: v.optional(v.number()),
  prUrl: v.optional(v.string()),
  repositoryId: v.id('repositories'),
  repositoryName: v.string(),
  repositoryFullName: v.string(),
  disclosureRef: v.optional(v.string()),
  fixVersion: v.optional(v.string()),
})

export const list = query({
  args: {
    tenantSlug: v.string(),
    status: v.optional(findingStatus),
    severity: v.optional(severity),
    repositoryId: v.optional(v.id('repositories')),
    limit: v.optional(v.number()),
  },
  returns: v.array(findingListRow),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return []

    const cap = Math.min(args.limit ?? 50, 200)

    // Select the most specific available index, over-fetch when we will also
    // apply an in-memory severity filter to avoid returning short pages.
    const fetchCap = args.severity ? cap * 4 : cap

    let rows = await (async () => {
      if (args.repositoryId && args.status) {
        return ctx.db
          .query('findings')
          .withIndex('by_repository_and_status', (q) =>
            q.eq('repositoryId', args.repositoryId!).eq('status', args.status!),
          )
          .order('desc')
          .take(cap)
      }

      if (args.repositoryId) {
        return ctx.db
          .query('findings')
          .withIndex('by_repository_and_status', (q) =>
            q.eq('repositoryId', args.repositoryId!),
          )
          .order('desc')
          .take(fetchCap)
      }

      if (args.status) {
        return ctx.db
          .query('findings')
          .withIndex('by_tenant_and_status', (q) =>
            q.eq('tenantId', tenant._id).eq('status', args.status!),
          )
          .order('desc')
          .take(fetchCap)
      }

      return ctx.db
        .query('findings')
        .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
        .order('desc')
        .take(fetchCap)
    })()

    // In-memory severity filter (applied after the bounded index scan)
    if (args.severity) {
      rows = rows.filter((f) => f.severity === args.severity)
    }

    rows = rows.slice(0, cap)

    // Enrich: join repository and disclosure for each finding
    const repositoryCache = new Map<string, { name: string; fullName: string }>()

    const enriched = await Promise.all(
      rows.map(async (finding) => {
        let repo = repositoryCache.get(finding.repositoryId)
        if (!repo) {
          const repoDoc = await ctx.db.get(finding.repositoryId)
          repo = {
            name: repoDoc?.name ?? 'Unknown repository',
            fullName: repoDoc?.fullName ?? '',
          }
          repositoryCache.set(finding.repositoryId, repo)
        }

        const disclosure = finding.breachDisclosureId
          ? await ctx.db.get(finding.breachDisclosureId)
          : null

        return {
          _id: finding._id,
          title: finding.title,
          summary: finding.summary,
          severity: finding.severity,
          validationStatus: finding.validationStatus,
          status: finding.status,
          confidence: finding.confidence,
          source: finding.source,
          vulnClass: finding.vulnClass,
          affectedPackages: finding.affectedPackages,
          createdAt: finding.createdAt,
          resolvedAt: finding.resolvedAt,
          prUrl: finding.prUrl,
          repositoryId: finding.repositoryId,
          repositoryName: repo.name,
          repositoryFullName: repo.fullName,
          disclosureRef: disclosure?.sourceRef,
          fixVersion: disclosure?.fixVersion,
        }
      }),
    )

    return enriched
  },
})

// ---------------------------------------------------------------------------
// findings.get — single finding with full enrichment
// ---------------------------------------------------------------------------

const validationRunRow = v.object({
  _id: v.id('exploitValidationRuns'),
  status: v.string(),
  outcome: v.optional(
    v.union(
      v.literal('validated'),
      v.literal('likely_exploitable'),
      v.literal('unexploitable'),
    ),
  ),
  validationConfidence: v.number(),
  sandboxSummary: v.string(),
  evidenceSummary: v.string(),
  reproductionHint: v.string(),
  startedAt: v.number(),
  completedAt: v.optional(v.number()),
})

const gateDecisionRow = v.object({
  _id: v.id('gateDecisions'),
  stage: v.string(),
  decision: v.union(
    v.literal('approved'),
    v.literal('blocked'),
    v.literal('overridden'),
  ),
  actorType: v.string(),
  actorId: v.string(),
  justification: v.optional(v.string()),
  expiresAt: v.optional(v.number()),
  createdAt: v.number(),
})

const prProposalRow = v.object({
  _id: v.id('prProposals'),
  status: v.string(),
  fixType: v.string(),
  fixSummary: v.string(),
  proposedBranch: v.string(),
  prTitle: v.string(),
  targetPackage: v.optional(v.string()),
  targetEcosystem: v.optional(v.string()),
  currentVersion: v.optional(v.string()),
  fixVersion: v.optional(v.string()),
  prUrl: v.optional(v.string()),
  prNumber: v.optional(v.number()),
  githubError: v.optional(v.string()),
  createdAt: v.number(),
  submittedAt: v.optional(v.number()),
  mergedAt: v.optional(v.number()),
})

export const get = query({
  args: { findingId: v.id('findings') },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id('findings'),
      title: v.string(),
      summary: v.string(),
      severity,
      validationStatus,
      status: findingStatus,
      confidence: v.number(),
      source: v.string(),
      vulnClass: v.string(),
      businessImpactScore: v.number(),
      blastRadiusSummary: v.string(),
      affectedPackages: v.array(v.string()),
      affectedFiles: v.array(v.string()),
      affectedServices: v.array(v.string()),
      regulatoryImplications: v.array(v.string()),
      prUrl: v.optional(v.string()),
      createdAt: v.number(),
      resolvedAt: v.optional(v.number()),
      repository: v.object({
        _id: v.id('repositories'),
        name: v.string(),
        fullName: v.string(),
        provider: v.string(),
        defaultBranch: v.string(),
      }),
      disclosure: v.union(
        v.null(),
        v.object({
          _id: v.id('breachDisclosures'),
          sourceRef: v.string(),
          sourceName: v.string(),
          sourceTier: v.string(),
          packageName: v.string(),
          ecosystem: v.string(),
          severity,
          affectedVersions: v.array(v.string()),
          fixVersion: v.optional(v.string()),
          matchedVersions: v.array(v.string()),
          exploitAvailable: v.boolean(),
          publishedAt: v.number(),
        }),
      ),
      validationRuns: v.array(validationRunRow),
      gateDecisions: v.array(gateDecisionRow),
      prProposals: v.array(prProposalRow),
    }),
  ),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) return null

    const [repository, disclosure] = await Promise.all([
      ctx.db.get(finding.repositoryId),
      finding.breachDisclosureId ? ctx.db.get(finding.breachDisclosureId) : null,
    ])

    if (!repository) return null

    // Validation runs — direct by_finding_and_started_at index
    const validationRuns = await ctx.db
      .query('exploitValidationRuns')
      .withIndex('by_finding_and_started_at', (q) =>
        q.eq('findingId', finding._id),
      )
      .order('desc')
      .take(10)

    // PR proposals — direct by_finding index
    const prProposals = await ctx.db
      .query('prProposals')
      .withIndex('by_finding', (q) => q.eq('findingId', finding._id))
      .order('desc')
      .take(5)

    // Gate decisions — via workflow run, then filter by findingId in-memory
    const allWorkflowDecisions = await ctx.db
      .query('gateDecisions')
      .withIndex('by_workflow_run', (q) =>
        q.eq('workflowRunId', finding.workflowRunId),
      )
      .order('desc')
      .take(50)

    const gateDecisions = allWorkflowDecisions.filter(
      (d) => d.findingId === finding._id,
    )

    return {
      _id: finding._id,
      title: finding.title,
      summary: finding.summary,
      severity: finding.severity,
      validationStatus: finding.validationStatus,
      status: finding.status,
      confidence: finding.confidence,
      source: finding.source,
      vulnClass: finding.vulnClass,
      businessImpactScore: finding.businessImpactScore,
      blastRadiusSummary: finding.blastRadiusSummary,
      affectedPackages: finding.affectedPackages,
      affectedFiles: finding.affectedFiles,
      affectedServices: finding.affectedServices,
      regulatoryImplications: finding.regulatoryImplications,
      prUrl: finding.prUrl,
      createdAt: finding.createdAt,
      resolvedAt: finding.resolvedAt,
      repository: {
        _id: repository._id,
        name: repository.name,
        fullName: repository.fullName,
        provider: repository.provider,
        defaultBranch: repository.defaultBranch,
      },
      disclosure: disclosure
        ? {
            _id: disclosure._id,
            sourceRef: disclosure.sourceRef,
            sourceName: disclosure.sourceName,
            sourceTier: disclosure.sourceTier,
            packageName: disclosure.packageName,
            ecosystem: disclosure.ecosystem,
            severity: disclosure.severity,
            affectedVersions: disclosure.affectedVersions,
            fixVersion: disclosure.fixVersion,
            matchedVersions: disclosure.matchedVersions,
            exploitAvailable: disclosure.exploitAvailable,
            publishedAt: disclosure.publishedAt,
          }
        : null,
      validationRuns: validationRuns.map((r) => ({
        _id: r._id,
        status: r.status,
        outcome: r.outcome,
        validationConfidence: r.validationConfidence,
        sandboxSummary: r.sandboxSummary,
        evidenceSummary: r.evidenceSummary,
        reproductionHint: r.reproductionHint,
        startedAt: r.startedAt,
        completedAt: r.completedAt,
      })),
      gateDecisions: gateDecisions.map((d) => ({
        _id: d._id,
        stage: d.stage,
        decision: d.decision,
        actorType: d.actorType,
        actorId: d.actorId,
        justification: d.justification,
        expiresAt: d.expiresAt,
        createdAt: d.createdAt,
      })),
      prProposals: prProposals.map((p) => ({
        _id: p._id,
        status: p.status,
        fixType: p.fixType,
        fixSummary: p.fixSummary,
        proposedBranch: p.proposedBranch,
        prTitle: p.prTitle,
        targetPackage: p.targetPackage,
        targetEcosystem: p.targetEcosystem,
        currentVersion: p.currentVersion,
        fixVersion: p.fixVersion,
        prUrl: p.prUrl,
        prNumber: p.prNumber,
        githubError: p.githubError,
        createdAt: p.createdAt,
        submittedAt: p.submittedAt,
        mergedAt: p.mergedAt,
      })),
    }
  },
})

// ---------------------------------------------------------------------------
// findings.stats — aggregate counts across all findings for a tenant
//
// NOTE: uses .collect() over the full findings set for accurate counts.
// At scale, replace with denormalized counters maintained in a separate doc.
// ---------------------------------------------------------------------------

export const stats = query({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
      bySeverity: v.object({
        critical: v.number(),
        high: v.number(),
        medium: v.number(),
        low: v.number(),
        informational: v.number(),
      }),
      byStatus: v.object({
        open: v.number(),
        pr_opened: v.number(),
        merged: v.number(),
        resolved: v.number(),
        accepted_risk: v.number(),
      }),
      byValidationStatus: v.object({
        pending: v.number(),
        validated: v.number(),
        likely_exploitable: v.number(),
        unexploitable: v.number(),
        dismissed: v.number(),
      }),
      total: v.number(),
      openAndCritical: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    const findings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .collect()

    const count = (pred: (f: (typeof findings)[number]) => boolean) =>
      findings.filter(pred).length

    return {
      bySeverity: {
        critical: count((f) => f.severity === 'critical'),
        high: count((f) => f.severity === 'high'),
        medium: count((f) => f.severity === 'medium'),
        low: count((f) => f.severity === 'low'),
        informational: count((f) => f.severity === 'informational'),
      },
      byStatus: {
        open: count((f) => f.status === 'open'),
        pr_opened: count((f) => f.status === 'pr_opened'),
        merged: count((f) => f.status === 'merged'),
        resolved: count((f) => f.status === 'resolved'),
        accepted_risk: count((f) => f.status === 'accepted_risk'),
      },
      byValidationStatus: {
        pending: count((f) => f.validationStatus === 'pending'),
        validated: count((f) => f.validationStatus === 'validated'),
        likely_exploitable: count((f) => f.validationStatus === 'likely_exploitable'),
        unexploitable: count((f) => f.validationStatus === 'unexploitable'),
        dismissed: count((f) => f.validationStatus === 'dismissed'),
      },
      total: findings.length,
      openAndCritical: count(
        (f) =>
          (f.severity === 'critical' || f.severity === 'high') &&
          (f.status === 'open' || f.status === 'pr_opened'),
      ),
    }
  },
})

// ---------------------------------------------------------------------------
// findings.updateFindingStatus — operator-facing status transition (spec §7.1)
//
// Allows operators to move a finding through its lifecycle via the REST API.
// The only write constraint is that a `resolved` finding can only be re-opened
// with explicit justification; all other transitions are permitted so operators
// retain full control.
// ---------------------------------------------------------------------------

export const updateFindingStatus = mutation({
  args: {
    findingId: v.id('findings'),
    newStatus: findingStatus,
    /** Human-readable reason — required when accepting risk or resolving manually. */
    reason: v.optional(v.string()),
  },
  returns: v.object({
    findingId: v.id('findings'),
    previousStatus: findingStatus,
    newStatus: findingStatus,
  }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new ConvexError(`Finding not found: ${args.findingId}`)

    // Require a reason when accepting risk to ensure audit trail.
    if (args.newStatus === 'accepted_risk' && !args.reason) {
      throw new ConvexError('A reason is required when setting status to accepted_risk.')
    }

    const previousStatus = finding.status
    const now = Date.now()

    await ctx.db.patch(args.findingId, {
      status: args.newStatus,
      resolvedAt:
        args.newStatus === 'resolved' || args.newStatus === 'accepted_risk'
          ? now
          : undefined,
    })

    // Fire-and-forget finding.resolved webhook when an operator resolves a finding.
    if (args.newStatus === 'resolved' && previousStatus !== 'resolved') {
      try {
        const repository = await ctx.db.get(finding.repositoryId)
        const tenant = repository ? await ctx.db.get(repository.tenantId) : null
        if (tenant && repository) {
          await ctx.scheduler.runAfter(
            0,
            internal.webhooks.dispatchWebhookEvent,
            {
              tenantId: repository.tenantId,
              tenantSlug: tenant.slug,
              repositoryFullName: repository.fullName,
              eventPayload: {
                event: 'finding.resolved' as const,
                data: {
                  findingId: finding._id as string,
                  title: finding.title,
                  severity: finding.severity,
                  resolvedAt: now,
                },
              },
            },
          )
        }
      } catch (e) {
        console.error('[webhooks] finding.resolved dispatch failed', e)
      }
    }

    return {
      findingId: args.findingId,
      previousStatus,
      newStatus: args.newStatus,
    }
  },
})

// ---------------------------------------------------------------------------
// findings.getPocArtifact — return PoC artifact URL + metadata for a finding.
//
// PoC artifacts are stored as URLs pointing to secured object storage.
// The URL is present only after an exploit validation run completes with
// a validated or likely_exploitable outcome (spec §7.1).
// ---------------------------------------------------------------------------

export const getPocArtifact = query({
  args: { findingId: v.id('findings') },
  returns: v.union(
    v.null(),
    v.object({
      findingId: v.id('findings'),
      title: v.string(),
      severity,
      validationStatus,
      pocArtifactUrl: v.optional(v.string()),
      hasArtifact: v.boolean(),
    }),
  ),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) return null

    return {
      findingId: finding._id,
      title: finding.title,
      severity: finding.severity,
      validationStatus: finding.validationStatus,
      pocArtifactUrl: finding.pocArtifactUrl,
      hasArtifact: finding.pocArtifactUrl !== undefined,
    }
  },
})

// ---------------------------------------------------------------------------
// findings.getReasoningLog — return reasoning log URL + validation evidence.
//
// Reasoning logs capture the exploit validation agent's chain-of-thought,
// sandbox observation summary, and reproduction hint (spec §7.1).
// ---------------------------------------------------------------------------

export const getReasoningLog = query({
  args: { findingId: v.id('findings') },
  returns: v.union(
    v.null(),
    v.object({
      findingId: v.id('findings'),
      title: v.string(),
      severity,
      validationStatus,
      reasoningLogUrl: v.optional(v.string()),
      hasLog: v.boolean(),
      validationRuns: v.array(
        v.object({
          status: v.string(),
          outcome: v.optional(v.string()),
          validationConfidence: v.number(),
          sandboxSummary: v.string(),
          evidenceSummary: v.string(),
          reproductionHint: v.string(),
          startedAt: v.number(),
          completedAt: v.optional(v.number()),
        }),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) return null

    const validationRuns = await ctx.db
      .query('exploitValidationRuns')
      .withIndex('by_finding_and_started_at', (q) =>
        q.eq('findingId', finding._id),
      )
      .order('desc')
      .take(10)

    return {
      findingId: finding._id,
      title: finding.title,
      severity: finding.severity,
      validationStatus: finding.validationStatus,
      reasoningLogUrl: finding.reasoningLogUrl,
      hasLog: finding.reasoningLogUrl !== undefined,
      validationRuns: validationRuns.map((run) => ({
        status: run.status,
        outcome: run.outcome,
        validationConfidence: run.validationConfidence,
        sandboxSummary: run.sandboxSummary,
        evidenceSummary: run.evidenceSummary,
        reproductionHint: run.reproductionHint,
        startedAt: run.startedAt,
        completedAt: run.completedAt,
      })),
    }
  },
})
