import { v } from 'convex/values'
import { query } from './_generated/server'
import { DEFAULT_SLA_POLICY, assessSlaFinding } from './lib/slaPolicy'
import {
  computeQueueSummary,
  prioritizeRemediationQueue,
  type RemediationCandidate,
} from './lib/remediationPriority'

/**
 * Builds a prioritised remediation queue for a repository by assembling five
 * signals from existing tables:
 *   1. SLA status (computed from finding.createdAt + slaPolicy thresholds)
 *   2. Blast radius score (latest blastRadiusSnapshot.businessImpactScore)
 *   3. Exploit availability (breachDisclosure.exploitAvailable)
 *   4. Validation status (finding.validationStatus)
 *   5. Active risk acceptance status (accepted findings are excluded entirely)
 *
 * No new schema table is required — all data is assembled on the fly.
 * The queue is sorted by composite priority score descending; ties broken by
 * createdAt ascending (oldest un-remediated finding surfaces first).
 */
export const getRemediationQueueForRepository = query({
  args: {
    repositoryId: v.id('repositories'),
    /** Maximum number of findings to include in the returned queue (default 25). */
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = args.limit ?? 25
    const now = Date.now()

    // ── Load the repository name (needed for candidate metadata) ──────────────
    const repository = await ctx.db.get(args.repositoryId)
    if (!repository) return { queue: [], summary: computeQueueSummary([]) }

    // ── Collect all active findings (open + pr_opened + merged) ──────────────
    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'open'),
      )
      .take(200)

    const prFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'pr_opened'),
      )
      .take(100)

    const mergedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', args.repositoryId).eq('status', 'merged'),
      )
      .take(50)

    const allActiveFindings = [...openFindings, ...prFindings, ...mergedFindings]

    if (allActiveFindings.length === 0) {
      return { queue: [], summary: computeQueueSummary([]) }
    }

    // ── Build a Set of finding IDs that have an active risk acceptance ────────
    const acceptances = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .collect()

    const acceptedFindingIds = new Set(
      acceptances
        .filter((a) => a.status === 'active')
        .map((a) => a.findingId as string),
    )

    // ── Build a Map from findingId → latest blast radius score ────────────────
    // Query the repository's blast radius snapshots ordered newest-first so
    // the first entry we see per findingId is the most recent.
    const blastSnapshots = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .take(300)

    const blastRadiusMap = new Map<string, number>()
    for (const snap of blastSnapshots) {
      const key = snap.findingId as string
      if (!blastRadiusMap.has(key)) {
        blastRadiusMap.set(key, snap.businessImpactScore)
      }
    }

    // ── Assemble candidates ───────────────────────────────────────────────────
    const candidates: RemediationCandidate[] = []

    for (const finding of allActiveFindings) {
      const fid = finding._id as string

      // Skip findings that have an active risk acceptance
      if (acceptedFindingIds.has(fid)) continue

      // Compute SLA status purely from finding metadata + policy (no DB read)
      const slaAssessment = assessSlaFinding({
        findingId: fid,
        severity: finding.severity,
        status: finding.status,
        openedAt: finding.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      })

      // Check exploit availability from linked breach disclosure
      let exploitAvailable = false
      if (finding.breachDisclosureId) {
        const disclosure = await ctx.db.get(finding.breachDisclosureId)
        exploitAvailable = disclosure?.exploitAvailable ?? false
      }

      candidates.push({
        findingId: fid,
        title: finding.title,
        severity: finding.severity as RemediationCandidate['severity'],
        slaStatus: slaAssessment.slaStatus as RemediationCandidate['slaStatus'],
        blastRadiusScore: blastRadiusMap.get(fid) ?? -1,
        exploitAvailable,
        validationStatus:
          finding.validationStatus as RemediationCandidate['validationStatus'],
        createdAt: finding.createdAt,
        repositoryName: repository.name,
        affectedPackages: finding.affectedPackages,
      })
    }

    const fullQueue = prioritizeRemediationQueue(candidates)
    const queue = fullQueue.slice(0, limit)
    const summary = computeQueueSummary(fullQueue) // summary counts all, not just sliced

    return { queue, summary }
  },
})

/**
 * Slug-based variant for the HTTP endpoint.
 */
export const getRemediationQueueBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    limit: v.optional(v.number()),
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

    const limit = args.limit ?? 25
    const now = Date.now()

    const openFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'open'),
      )
      .take(200)

    const prFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'pr_opened'),
      )
      .take(100)

    const mergedFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) =>
        q.eq('repositoryId', repository._id).eq('status', 'merged'),
      )
      .take(50)

    const allActiveFindings = [...openFindings, ...prFindings, ...mergedFindings]

    if (allActiveFindings.length === 0) {
      return { queue: [], summary: computeQueueSummary([]) }
    }

    const acceptances = await ctx.db
      .query('riskAcceptances')
      .withIndex('by_repository_and_created_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .collect()

    const acceptedFindingIds = new Set(
      acceptances
        .filter((a) => a.status === 'active')
        .map((a) => a.findingId as string),
    )

    const blastSnapshots = await ctx.db
      .query('blastRadiusSnapshots')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(300)

    const blastRadiusMap = new Map<string, number>()
    for (const snap of blastSnapshots) {
      const key = snap.findingId as string
      if (!blastRadiusMap.has(key)) {
        blastRadiusMap.set(key, snap.businessImpactScore)
      }
    }

    const candidates: RemediationCandidate[] = []

    for (const finding of allActiveFindings) {
      const fid = finding._id as string
      if (acceptedFindingIds.has(fid)) continue

      const slaAssessment = assessSlaFinding({
        findingId: fid,
        severity: finding.severity,
        status: finding.status,
        openedAt: finding.createdAt,
        policy: DEFAULT_SLA_POLICY,
        nowMs: now,
      })

      let exploitAvailable = false
      if (finding.breachDisclosureId) {
        const disclosure = await ctx.db.get(finding.breachDisclosureId)
        exploitAvailable = disclosure?.exploitAvailable ?? false
      }

      candidates.push({
        findingId: fid,
        title: finding.title,
        severity: finding.severity as RemediationCandidate['severity'],
        slaStatus: slaAssessment.slaStatus as RemediationCandidate['slaStatus'],
        blastRadiusScore: blastRadiusMap.get(fid) ?? -1,
        exploitAvailable,
        validationStatus:
          finding.validationStatus as RemediationCandidate['validationStatus'],
        createdAt: finding.createdAt,
        repositoryName: repository.name,
        affectedPackages: finding.affectedPackages,
      })
    }

    const fullQueue = prioritizeRemediationQueue(candidates)

    return {
      tenantSlug: tenant.slug,
      repositoryFullName: repository.fullName,
      queue: fullQueue.slice(0, limit),
      summary: computeQueueSummary(fullQueue),
    }
  },
})
