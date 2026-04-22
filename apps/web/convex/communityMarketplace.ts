/**
 * Community Rule/Fingerprint Contribution Marketplace
 *
 * Spec §10 Phase 4: "Public rule/fingerprint contribution marketplace"
 *
 * Operators submit custom vulnerability fingerprint patterns and detection rule
 * templates. The community votes and reports on them. Approved contributions
 * flow into the platform's detection library, creating a network-effect moat.
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import {
  REPORT_REVIEW_THRESHOLD,
  deriveStatus,
  rankContributions,
  summarizeMarketplaceStats,
  validateContribution,
  type CommunityContribution,
} from './lib/communityFingerprint'

// ---------------------------------------------------------------------------
// submitContribution — public mutation
// ---------------------------------------------------------------------------

/**
 * Submit a new community contribution for community review.
 *
 * Validates the input using the pure library rules, then inserts the row with
 * `pending` status.  Returns the new contribution ID.
 */
export const submitContribution = mutation({
  args: {
    contributorTenantId: v.id('tenants'),
    type: v.union(v.literal('fingerprint'), v.literal('detection_rule')),
    title: v.string(),
    description: v.string(),
    vulnClass: v.string(),
    severity: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('informational'),
    ),
    patternText: v.string(),
  },
  handler: async (ctx, args) => {
    const validation = validateContribution({
      title: args.title,
      description: args.description,
      patternText: args.patternText,
      vulnClass: args.vulnClass,
    })
    if (!validation.valid) {
      throw new Error(`Invalid contribution: ${validation.errors.join('; ')}`)
    }

    const id = await ctx.db.insert('communityContributions', {
      contributorTenantId: args.contributorTenantId,
      type: args.type,
      title: args.title,
      description: args.description,
      vulnClass: args.vulnClass,
      severity: args.severity,
      patternText: args.patternText,
      status: 'pending',
      upvoteCount: 0,
      downvoteCount: 0,
      reportCount: 0,
      createdAt: Date.now(),
    })
    return { id }
  },
})

// ---------------------------------------------------------------------------
// voteOnContribution — public mutation
// ---------------------------------------------------------------------------

/**
 * Cast or change a vote on a community contribution.
 *
 * Idempotent: if the voter has already voted the same way, this is a no-op.
 * If they switch vote direction (upvote → downvote or vice versa), the existing
 * vote row is patched and the counts on the contribution are updated atomically.
 *
 * Contributors cannot vote on their own submissions.
 */
export const voteOnContribution = mutation({
  args: {
    contributionId: v.id('communityContributions'),
    voterTenantId: v.id('tenants'),
    voteType: v.union(v.literal('upvote'), v.literal('downvote')),
  },
  handler: async (ctx, { contributionId, voterTenantId, voteType }) => {
    const contribution = await ctx.db.get(contributionId)
    if (!contribution) throw new Error('Contribution not found.')
    if (contribution.status === 'rejected') {
      throw new Error('Cannot vote on a rejected contribution.')
    }
    if (contribution.contributorTenantId === voterTenantId) {
      throw new Error('Cannot vote on your own contribution.')
    }

    // Check for existing vote from this tenant on this contribution.
    const existing = await ctx.db
      .query('contributionVotes')
      .withIndex('by_voter_and_contribution', (q) =>
        q.eq('voterTenantId', voterTenantId).eq('contributionId', contributionId),
      )
      .unique()

    if (existing) {
      if (existing.voteType === voteType) return { changed: false } // idempotent

      // Switch vote direction — patch vote row and adjust counts.
      await ctx.db.patch(existing._id, { voteType })
      if (voteType === 'upvote') {
        await ctx.db.patch(contributionId, {
          upvoteCount: contribution.upvoteCount + 1,
          downvoteCount: Math.max(0, contribution.downvoteCount - 1),
        })
      } else {
        await ctx.db.patch(contributionId, {
          downvoteCount: contribution.downvoteCount + 1,
          upvoteCount: Math.max(0, contribution.upvoteCount - 1),
        })
      }
      return { changed: true }
    }

    // First vote from this tenant.
    await ctx.db.insert('contributionVotes', {
      contributionId,
      voterTenantId,
      voteType,
      createdAt: Date.now(),
    })
    if (voteType === 'upvote') {
      await ctx.db.patch(contributionId, {
        upvoteCount: contribution.upvoteCount + 1,
      })
    } else {
      await ctx.db.patch(contributionId, {
        downvoteCount: contribution.downvoteCount + 1,
      })
    }
    return { changed: true }
  },
})

// ---------------------------------------------------------------------------
// reportContribution — public mutation
// ---------------------------------------------------------------------------

/**
 * File an accuracy/abuse report against a community contribution.
 *
 * When `reportCount` reaches `REPORT_REVIEW_THRESHOLD`, the contribution is
 * automatically transitioned to `under_review` for operator attention.
 *
 * Uses the voter dedup index so each tenant can only report once per contribution.
 */
export const reportContribution = mutation({
  args: {
    contributionId: v.id('communityContributions'),
    reporterTenantId: v.id('tenants'),
  },
  handler: async (ctx, { contributionId, reporterTenantId }) => {
    const contribution = await ctx.db.get(contributionId)
    if (!contribution) throw new Error('Contribution not found.')
    if (
      contribution.status === 'approved' ||
      contribution.status === 'rejected'
    ) {
      throw new Error('Cannot report an already-resolved contribution.')
    }

    // One report per tenant per contribution — re-use vote dedup index.
    const existing = await ctx.db
      .query('contributionVotes')
      .withIndex('by_voter_and_contribution', (q) =>
        q
          .eq('voterTenantId', reporterTenantId)
          .eq('contributionId', contributionId),
      )
      .unique()
    if (existing) return { changed: false } // already reported or voted

    await ctx.db.insert('contributionVotes', {
      contributionId,
      voterTenantId: reporterTenantId,
      voteType: 'downvote', // reports are stored as downvotes in the dedup table
      createdAt: Date.now(),
    })

    const newReportCount = contribution.reportCount + 1
    const newStatus = deriveStatus({
      ...contribution,
      reportCount: newReportCount,
    })
    await ctx.db.patch(contributionId, {
      reportCount: newReportCount,
      status: newStatus,
    })
    return { changed: true, movedToReview: newReportCount >= REPORT_REVIEW_THRESHOLD }
  },
})

// ---------------------------------------------------------------------------
// approveContribution — internal mutation (operator use via Convex dashboard)
// ---------------------------------------------------------------------------

export const approveContribution = internalMutation({
  args: {
    contributionId: v.id('communityContributions'),
    reviewNote: v.optional(v.string()),
  },
  handler: async (ctx, { contributionId, reviewNote }) => {
    const contribution = await ctx.db.get(contributionId)
    if (!contribution) throw new Error('Contribution not found.')
    await ctx.db.patch(contributionId, {
      status: 'approved',
      approvedAt: Date.now(),
      reviewNote: reviewNote ?? undefined,
    })
  },
})

// ---------------------------------------------------------------------------
// rejectContribution — internal mutation (operator use)
// ---------------------------------------------------------------------------

export const rejectContribution = internalMutation({
  args: {
    contributionId: v.id('communityContributions'),
    reviewNote: v.optional(v.string()),
  },
  handler: async (ctx, { contributionId, reviewNote }) => {
    const contribution = await ctx.db.get(contributionId)
    if (!contribution) throw new Error('Contribution not found.')
    await ctx.db.patch(contributionId, {
      status: 'rejected',
      reviewNote: reviewNote ?? undefined,
    })
  },
})

// ---------------------------------------------------------------------------
// listContributions — public query
// ---------------------------------------------------------------------------

/**
 * List community contributions, optionally filtered by type and/or status.
 *
 * Returns up to `limit` contributions sorted by net score descending (via the
 * pure `rankContributions` helper).
 */
export const listContributions = query({
  args: {
    type: v.optional(
      v.union(v.literal('fingerprint'), v.literal('detection_rule')),
    ),
    status: v.optional(
      v.union(
        v.literal('pending'),
        v.literal('under_review'),
        v.literal('approved'),
        v.literal('rejected'),
      ),
    ),
    vulnClass: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { type, status, vulnClass, limit }) => {
    const cap = Math.min(limit ?? 50, 200)

    // Fetch up to 500 rows so the pure sort has enough material to rank.
    let rows: CommunityContribution[]

    if (type !== undefined && status !== undefined) {
      rows = (await ctx.db
        .query('communityContributions')
        .withIndex('by_type_and_status', (q) =>
          q.eq('type', type).eq('status', status),
        )
        .take(500)) as CommunityContribution[]
    } else if (status !== undefined) {
      rows = (await ctx.db
        .query('communityContributions')
        .withIndex('by_status_and_created_at', (q) => q.eq('status', status))
        .take(500)) as CommunityContribution[]
    } else {
      rows = (await ctx.db
        .query('communityContributions')
        .order('desc')
        .take(500)) as CommunityContribution[]
    }

    let filtered = type !== undefined ? rows.filter((r) => r.type === type) : rows
    if (vulnClass !== undefined) {
      filtered = filtered.filter((r) => r.vulnClass === vulnClass)
    }

    return rankContributions(filtered).slice(0, cap)
  },
})

// ---------------------------------------------------------------------------
// getContributionDetail — public query
// ---------------------------------------------------------------------------

export const getContributionDetail = query({
  args: { contributionId: v.id('communityContributions') },
  handler: async (ctx, { contributionId }) => {
    const contribution = await ctx.db.get(contributionId)
    if (!contribution) return null

    const voteCount = (
      await ctx.db
        .query('contributionVotes')
        .withIndex('by_contribution', (q) => q.eq('contributionId', contributionId))
        .take(1000)
    ).length

    return { ...contribution, totalVoteRows: voteCount }
  },
})

// ---------------------------------------------------------------------------
// getMarketplaceStats — public query
// ---------------------------------------------------------------------------

/**
 * Return aggregate marketplace statistics — used by the dashboard panel and
 * the `/api/marketplace/stats` HTTP endpoint.
 */
export const getMarketplaceStats = query({
  args: {},
  handler: async (ctx) => {
    const all = (await ctx.db
      .query('communityContributions')
      .order('desc')
      .take(2000)) as CommunityContribution[]
    return summarizeMarketplaceStats(all)
  },
})

// ---------------------------------------------------------------------------
// getTopContributors — public query
// ---------------------------------------------------------------------------

/**
 * Return the top-N tenants ranked by the number of approved contributions.
 */
export const getTopContributors = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const cap = Math.min(limit ?? 10, 50)

    const approved = await ctx.db
      .query('communityContributions')
      .withIndex('by_status_and_created_at', (q) => q.eq('status', 'approved'))
      .take(2000)

    // Tally counts per tenant.
    const counts: Record<string, number> = {}
    for (const c of approved) {
      const key = c.contributorTenantId as string
      counts[key] = (counts[key] ?? 0) + 1
    }

    // Sort descending and resolve tenant slugs.
    const sorted = Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, cap)

    const result = await Promise.all(
      sorted.map(async ([tenantId, approvedCount]) => {
        const tenant = await ctx.db.get(tenantId as any)
        return {
          tenantId,
          tenantSlug: (tenant as any)?.slug ?? tenantId,
          approvedCount,
        }
      }),
    )

    return result
  },
})

// ---------------------------------------------------------------------------
// getApprovedByVulnClass — public query (for detection library integration)
// ---------------------------------------------------------------------------

/**
 * Return all approved contributions for a specific vulnerability class.
 * Used when seeding the detection library from community patterns.
 */
export const getApprovedByVulnClass = query({
  args: { vulnClass: v.string() },
  handler: async (ctx, { vulnClass }) => {
    return ctx.db
      .query('communityContributions')
      .withIndex('by_type_and_status', (q) =>
        q.eq('type', 'fingerprint').eq('status', 'approved'),
      )
      .filter((q) => q.eq(q.field('vulnClass'), vulnClass))
      .take(100)
  },
})
