/**
 * WS-53 — GitHub Branch Protection Analyzer: Convex entrypoints.
 *
 * Evaluates a repository's default-branch protection configuration against 8
 * security rules and persists the result.  The internalAction fetches real
 * data from the GitHub API when GITHUB_TOKEN is available; it falls back to a
 * permissive simulated config that surfaces the absence of protection data as
 * a medium-risk finding.
 *
 * Entrypoints:
 *   recordBranchProtectionScan       — internalMutation: persist a result
 *   checkAndStoreBranchProtection     — internalAction: fetch GitHub API + persist
 *   triggerBranchProtectionCheck      — public mutation: on-demand by slug+fullName
 *   getLatestBranchProtectionScan     — public query: most recent result for a repo
 *   getBranchProtectionScanHistory    — public query: last 30 lean summaries
 *   getBranchProtectionSummaryByTenant — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalAction, internalMutation, mutation, query } from './_generated/server'
import {
  type BranchProtectionInput,
  computeBranchProtection,
} from './lib/branchProtection'

const MAX_ROWS_PER_REPO = 30

// ---------------------------------------------------------------------------
// recordBranchProtectionScan — internalMutation
// ---------------------------------------------------------------------------

export const recordBranchProtectionScan = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    defaultBranch: v.string(),
    config: v.object({
      enabled: v.boolean(),
      requiredReviewerCount: v.number(),
      allowForcePushes: v.boolean(),
      hasRequiredStatusChecks: v.boolean(),
      dismissStaleReviews: v.boolean(),
      hasCodeowners: v.boolean(),
      adminsBypass: v.boolean(),
      allowDeletions: v.boolean(),
      requireSignedCommits: v.boolean(),
      requireLinearHistory: v.boolean(),
    }),
    dataSource: v.union(v.literal('github_api'), v.literal('simulated')),
  },
  handler: async (ctx, { tenantId, repositoryId, defaultBranch, config, dataSource }) => {
    const input: BranchProtectionInput = config
    const result = computeBranchProtection(input)
    const now = Date.now()

    await ctx.db.insert('branchProtectionResults', {
      tenantId,
      repositoryId,
      defaultBranch,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      mediumCount: result.mediumCount,
      lowCount: result.lowCount,
      findings: result.findings,
      summary: result.summary,
      dataSource,
      scannedAt: now,
    })

    // Prune old rows
    const all = await ctx.db
      .query('branchProtectionResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .collect()
    if (all.length > MAX_ROWS_PER_REPO) {
      for (const old of all.slice(MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(old._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// checkAndStoreBranchProtection — internalAction
// ---------------------------------------------------------------------------

export const checkAndStoreBranchProtection = internalAction({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    repositoryFullName: v.string(),
    defaultBranch: v.string(),
  },
  handler: async (ctx, { tenantId, repositoryId, repositoryFullName, defaultBranch }) => {
    const token = process.env.GITHUB_TOKEN
    let config: BranchProtectionInput
    let dataSource: 'github_api' | 'simulated'

    if (token) {
      try {
        // Fetch branch protection from GitHub REST API v3
        const [owner, repo] = repositoryFullName.split('/')
        const url = `https://api.github.com/repos/${owner}/${repo}/branches/${defaultBranch}/protection`
        const res = await fetch(url, {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        })

        if (res.status === 404) {
          // Branch exists but no protection is configured
          config = buildConfig({ enabled: false })
          dataSource = 'github_api'
        } else if (!res.ok) {
          throw new Error(`GitHub API returned ${res.status}`)
        } else {
          const data = (await res.json()) as GitHubBranchProtectionResponse
          config = parseGitHubResponse(data, defaultBranch)
          dataSource = 'github_api'
        }

        // Check for CODEOWNERS file
        const coUrl = `https://api.github.com/repos/${repositoryFullName}/contents/.github/CODEOWNERS`
        const coRes = await fetch(coUrl, {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        })
        if (coRes.ok) {
          config = { ...config, hasCodeowners: true }
        }
      } catch {
        // Fallback to simulated when GitHub API is unreachable
        config = buildSimulatedConfig()
        dataSource = 'simulated'
      }
    } else {
      config = buildSimulatedConfig()
      dataSource = 'simulated'
    }

    await ctx.runMutation(internal.branchProtectionIntel.recordBranchProtectionScan, {
      tenantId,
      repositoryId,
      defaultBranch,
      config,
      dataSource,
    })
  },
})

// ---------------------------------------------------------------------------
// GitHub API response parser
// ---------------------------------------------------------------------------

interface GitHubBranchProtectionResponse {
  required_pull_request_reviews?: {
    required_approving_review_count?: number
    dismiss_stale_reviews?: boolean
    require_code_owner_reviews?: boolean
  }
  allow_force_pushes?: { enabled: boolean }
  allow_deletions?: { enabled: boolean }
  required_status_checks?: { contexts: string[]; checks?: unknown[] }
  restrictions?: unknown
  enforce_admins?: { enabled: boolean }
  required_linear_history?: { enabled: boolean }
  required_signatures?: { enabled: boolean }
}

function parseGitHubResponse(
  data: GitHubBranchProtectionResponse,
  _branch: string,
): BranchProtectionInput {
  const reviews = data.required_pull_request_reviews
  const statusChecks = data.required_status_checks
  const hasChecks =
    statusChecks !== undefined &&
    ((statusChecks.contexts?.length ?? 0) > 0 || (statusChecks.checks as unknown[])?.length > 0)

  return {
    enabled: true,
    requiredReviewerCount: reviews?.required_approving_review_count ?? 0,
    allowForcePushes: data.allow_force_pushes?.enabled ?? false,
    hasRequiredStatusChecks: hasChecks,
    dismissStaleReviews: reviews?.dismiss_stale_reviews ?? false,
    hasCodeowners: reviews?.require_code_owner_reviews ?? false,
    adminsBypass: data.enforce_admins?.enabled === false, // enforce_admins.enabled=true means NO bypass
    allowDeletions: data.allow_deletions?.enabled ?? false,
    requireSignedCommits: data.required_signatures?.enabled ?? false,
    requireLinearHistory: data.required_linear_history?.enabled ?? false,
  }
}

/** Build a BranchProtectionInput with overrides. */
function buildConfig(overrides: Partial<BranchProtectionInput>): BranchProtectionInput {
  return {
    enabled: true,
    requiredReviewerCount: 0,
    allowForcePushes: false,
    hasRequiredStatusChecks: false,
    dismissStaleReviews: false,
    hasCodeowners: false,
    adminsBypass: true,
    allowDeletions: false,
    requireSignedCommits: false,
    requireLinearHistory: false,
    ...overrides,
  }
}

/**
 * Conservative simulation used when GITHUB_TOKEN is absent.
 * Represents a typical "protection present but partially configured" state
 * so the scanner produces medium-severity findings rather than a false
 * critical alarm.
 */
function buildSimulatedConfig(): BranchProtectionInput {
  return buildConfig({
    enabled: true,
    requiredReviewerCount: 0, // common gap
    hasRequiredStatusChecks: false, // common gap
    hasCodeowners: false, // common gap
    adminsBypass: true, // common default
  })
}

// ---------------------------------------------------------------------------
// triggerBranchProtectionCheck — public mutation
// ---------------------------------------------------------------------------

export const triggerBranchProtectionCheck = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repository) return

    const defaultBranch = (repository as { defaultBranch?: string }).defaultBranch ?? 'main'

    await ctx.scheduler.runAfter(
      0,
      internal.branchProtectionIntel.checkAndStoreBranchProtection,
      {
        tenantId: tenant._id,
        repositoryId: repository._id,
        repositoryFullName,
        defaultBranch,
      },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestBranchProtectionScan — public query
// ---------------------------------------------------------------------------

export const getLatestBranchProtectionScan = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('branchProtectionResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestBranchProtectionBySlug — public query (slug-based)
// ---------------------------------------------------------------------------

export const getLatestBranchProtectionBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return null

    return ctx.db
      .query('branchProtectionResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getBranchProtectionScanHistory — public query (lean)
// ---------------------------------------------------------------------------

export const getBranchProtectionScanHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('branchProtectionResults')
      .withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(limit)

    return rows.map((r) => ({
      _id: r._id,
      riskScore: r.riskScore,
      riskLevel: r.riskLevel,
      totalFindings: r.totalFindings,
      dataSource: r.dataSource,
      scannedAt: r.scannedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getBranchProtectionSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getBranchProtectionSummaryByTenant = query({
  args: {
    tenantId: v.id('tenants'),
  },
  handler: async (ctx, { tenantId }) => {
    const allSnapshots = await ctx.db
      .query('branchProtectionResults')
      .withIndex('by_tenant_and_scanned_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(500)

    // Deduplicate to one per repository
    const seenRepos = new Set<string>()
    const latest: typeof allSnapshots = []
    for (const snap of allSnapshots) {
      if (!seenRepos.has(snap.repositoryId)) {
        seenRepos.add(snap.repositoryId)
        latest.push(snap)
      }
    }

    const criticalCount = latest.filter((s) => s.riskLevel === 'critical').length
    const highCount = latest.filter((s) => s.riskLevel === 'high').length
    const mediumCount = latest.filter((s) => s.riskLevel === 'medium').length
    const lowCount = latest.filter((s) => s.riskLevel === 'low').length
    const cleanCount = latest.filter((s) => s.riskLevel === 'none').length
    const totalFindings = latest.reduce((a, s) => a + s.totalFindings, 0)
    const avgRiskScore =
      latest.length > 0
        ? Math.round(latest.reduce((a, s) => a + s.riskScore, 0) / latest.length)
        : 0

    const worstRepo =
      latest.length > 0 ? latest.reduce((a, b) => (a.riskScore > b.riskScore ? a : b)) : null

    return {
      repositoriesScanned: latest.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      cleanCount,
      totalFindings,
      avgRiskScore,
      worstRepositoryId: worstRepo?.repositoryId ?? null,
      worstRiskScore: worstRepo?.riskScore ?? null,
    }
  },
})
