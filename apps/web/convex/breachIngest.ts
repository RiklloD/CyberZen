"use node";

import { ConvexError, v } from 'convex/values'
import type { FunctionReturnType } from 'convex/server'
import type { Id } from './_generated/dataModel'
import { api, internal } from './_generated/api'
import { action, internalAction, type ActionCtx } from './_generated/server'
import {
  coerceGithubSecurityAdvisoryInput,
  coerceOsvAdvisoryInput,
  type GithubSecurityAdvisoryApiResponse,
  type OsvApiVulnerabilityResponse,
} from './lib/breachFeeds'
import {
  buildGithubAdvisoryBatches,
  buildOsvPackageQueries,
  collectOsvVulnerabilityIds,
  parseGithubNextCursor,
  type TrackedAdvisoryPackage,
} from './lib/advisorySync'

const liveIngestResult = v.object({
  eventId: v.id('ingestionEvents'),
  workflowRunId: v.id('workflowRuns'),
  disclosureId: v.id('breachDisclosures'),
  deduped: v.boolean(),
  advisoryId: v.string(),
  sourceUrl: v.string(),
})

type LiveIngestResult = {
  eventId: Id<'ingestionEvents'>
  workflowRunId: Id<'workflowRuns'>
  disclosureId: Id<'breachDisclosures'>
  deduped: boolean
  advisoryId: string
  sourceUrl: string
}

type GithubIngestMutationResult = FunctionReturnType<
  typeof api.events.ingestGithubSecurityAdvisory
>
type OsvIngestMutationResult = FunctionReturnType<
  typeof api.events.ingestOsvAdvisory
>
type RepositorySyncTarget = FunctionReturnType<
  typeof api.advisorySync.getRepositoryAdvisorySyncTarget
>

const syncProviderSummary = v.object({
  queried: v.number(),
  fetched: v.number(),
  imported: v.number(),
  deduped: v.number(),
})

const repositorySyncSummary = v.object({
  tenantSlug: v.string(),
  repositoryFullName: v.string(),
  repositoryName: v.string(),
  packageCount: v.number(),
  status: v.union(
    v.literal('completed'),
    v.literal('skipped'),
    v.literal('failed'),
  ),
  reason: v.optional(v.string()),
  github: syncProviderSummary,
  osv: syncProviderSummary,
  startedAt: v.number(),
  completedAt: v.number(),
})

const syncRecentAdvisoriesResult = v.object({
  repositoryCount: v.number(),
  completedRepositoryCount: v.number(),
  skippedRepositoryCount: v.number(),
  failedRepositoryCount: v.number(),
  github: syncProviderSummary,
  osv: syncProviderSummary,
  repositories: v.array(repositorySyncSummary),
})

type SyncProviderSummary = {
  queried: number
  fetched: number
  imported: number
  deduped: number
}

type RepositorySyncSummary = {
  tenantSlug: string
  repositoryFullName: string
  repositoryName: string
  packageCount: number
  status: 'completed' | 'skipped' | 'failed'
  reason?: string
  github: SyncProviderSummary
  osv: SyncProviderSummary
  startedAt: number
  completedAt: number
}

type SyncRecentAdvisoriesResult = {
  repositoryCount: number
  completedRepositoryCount: number
  skippedRepositoryCount: number
  failedRepositoryCount: number
  github: SyncProviderSummary
  osv: SyncProviderSummary
  repositories: RepositorySyncSummary[]
}

type OsvQueryBatchResponse = {
  results?: Array<
    | {
        vulns?: Array<{
          id?: string | null
        }> | null
      }
    | null
  > | null
}

function githubHeaders() {
  const token =
    process.env.GITHUB_SECURITY_ADVISORY_TOKEN ??
    process.env.GITHUB_TOKEN ??
    process.env.GH_TOKEN

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'CyberZen-Sentinel',
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  return headers
}

function createEmptyProviderSummary(): SyncProviderSummary {
  return {
    queried: 0,
    fetched: 0,
    imported: 0,
    deduped: 0,
  }
}

function mergeProviderSummary(
  left: SyncProviderSummary,
  right: SyncProviderSummary,
): SyncProviderSummary {
  return {
    queried: left.queried + right.queried,
    fetched: left.fetched + right.fetched,
    imported: left.imported + right.imported,
    deduped: left.deduped + right.deduped,
  }
}

async function parseErrorBody(response: Response) {
  try {
    const body = await response.text()
    return body.slice(0, 400)
  } catch {
    return 'No response body was available.'
  }
}

async function fetchGithubSecurityAdvisoryById(ghsaId: string) {
  const response = await fetch(
    `https://api.github.com/advisories/${encodeURIComponent(ghsaId)}`,
    {
      headers: githubHeaders(),
    },
  )

  if (!response.ok) {
    throw new ConvexError(
      `GitHub Security Advisory fetch failed for ${ghsaId} (${response.status}): ${await parseErrorBody(response)}`,
    )
  }

  const advisory = (await response.json()) as GithubSecurityAdvisoryApiResponse
  if (typeof advisory.ghsa_id !== 'string') {
    throw new ConvexError(
      `GitHub Security Advisory response for ${ghsaId} did not include a valid ghsa_id.`,
    )
  }

  return advisory
}

async function fetchGithubSecurityAdvisoriesByBatch(args: {
  ecosystem: string
  affects: string[]
  modifiedSince: string
  limit: number
}) {
  const advisories: GithubSecurityAdvisoryApiResponse[] = []
  let cursor: string | undefined

  while (advisories.length < args.limit) {
    const params = new URLSearchParams({
      ecosystem: args.ecosystem,
      direction: 'desc',
      modified: `>=${args.modifiedSince}`,
      per_page: String(Math.min(100, args.limit - advisories.length)),
      sort: 'updated',
      type: 'reviewed',
    })

    for (const affects of args.affects) {
      params.append('affects[]', affects)
    }

    if (cursor) {
      params.set('after', cursor)
    }

    const response = await fetch(`https://api.github.com/advisories?${params.toString()}`, {
      headers: githubHeaders(),
    })

    if (!response.ok) {
      throw new ConvexError(
        `GitHub advisory list fetch failed (${response.status}): ${await parseErrorBody(response)}`,
      )
    }

    const page = (await response.json()) as GithubSecurityAdvisoryApiResponse[]
    advisories.push(...page)

    cursor = parseGithubNextCursor(response.headers.get('link'))
    if (!cursor || page.length === 0) {
      break
    }
  }

  return advisories.slice(0, args.limit)
}

async function fetchOsvAdvisoryById(osvId: string) {
  const response = await fetch(
    `https://api.osv.dev/v1/vulns/${encodeURIComponent(osvId)}`,
  )

  if (!response.ok) {
    throw new ConvexError(
      `OSV fetch failed for ${osvId} (${response.status}): ${await parseErrorBody(response)}`,
    )
  }

  const advisory = (await response.json()) as OsvApiVulnerabilityResponse
  if (typeof advisory.id !== 'string') {
    throw new ConvexError(`OSV response for ${osvId} did not include a valid id.`)
  }

  return advisory
}

async function queryOsvAdvisoriesByPackages(
  queries: Array<{
    package: {
      name: string
      ecosystem: string
    }
    version: string
  }>,
) {
  const response = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'CyberZen-Sentinel',
    },
    body: JSON.stringify({
      queries,
    }),
  })

  if (!response.ok) {
    throw new ConvexError(
      `OSV batch query failed (${response.status}): ${await parseErrorBody(response)}`,
    )
  }

  const payload = (await response.json()) as OsvQueryBatchResponse
  return collectOsvVulnerabilityIds(payload.results ?? [])
}

async function getRepositorySyncTarget(
  ctx: ActionCtx,
  tenantSlug: string,
  repositoryFullName: string,
) {
  const target: RepositorySyncTarget = await ctx.runQuery(
    api.advisorySync.getRepositoryAdvisorySyncTarget,
    {
      tenantSlug,
      repositoryFullName,
    },
  )

  if (!target) {
    throw new ConvexError(
      `Repository sync target not found for ${tenantSlug}/${repositoryFullName}.`,
    )
  }

  return target
}

async function ingestGithubAdvisoriesForRepository(
  ctx: ActionCtx,
  target: NonNullable<RepositorySyncTarget>,
  packages: TrackedAdvisoryPackage[],
  modifiedSince: string,
  limit: number,
) {
  const batches = buildGithubAdvisoryBatches(packages)
  const ingestedResults: LiveIngestResult[] = []
  let queried = 0

  for (const batch of batches) {
    if (ingestedResults.length >= limit) {
      break
    }

    queried += 1
    const advisories = await fetchGithubSecurityAdvisoriesByBatch({
      ecosystem: batch.ecosystem,
      affects: batch.affects,
      modifiedSince,
      limit: limit - ingestedResults.length,
    })

    for (const advisory of advisories) {
      const result: GithubIngestMutationResult = await ctx.runMutation(
        api.events.ingestGithubSecurityAdvisory,
        {
          tenantSlug: target.tenantSlug,
          repositoryFullName: target.repositoryFullName,
          advisory: coerceGithubSecurityAdvisoryInput(advisory),
        },
      )

      ingestedResults.push({
        ...result,
        advisoryId: advisory.ghsa_id,
        sourceUrl: `https://github.com/advisories/${encodeURIComponent(advisory.ghsa_id)}`,
      })
    }
  }

  return {
    queried,
    fetched: ingestedResults.length,
    imported: ingestedResults.filter((result) => !result.deduped).length,
    deduped: ingestedResults.filter((result) => result.deduped).length,
  }
}

async function ingestOsvAdvisoriesForRepository(
  ctx: ActionCtx,
  target: NonNullable<RepositorySyncTarget>,
  packages: TrackedAdvisoryPackage[],
  limit: number,
) {
  const queryBatches = buildOsvPackageQueries(packages)
  const advisoryIds = new Set<string>()
  let queried = 0

  for (const queryBatch of queryBatches) {
    if (advisoryIds.size >= limit) {
      break
    }

    queried += 1
    const ids = await queryOsvAdvisoriesByPackages(queryBatch)

    for (const advisoryId of ids) {
      advisoryIds.add(advisoryId)

      if (advisoryIds.size >= limit) {
        break
      }
    }
  }

  const ingestedResults: LiveIngestResult[] = []

  for (const advisoryId of advisoryIds) {
    const advisory = await fetchOsvAdvisoryById(advisoryId)
    const result: OsvIngestMutationResult = await ctx.runMutation(
      api.events.ingestOsvAdvisory,
      {
        tenantSlug: target.tenantSlug,
        repositoryFullName: target.repositoryFullName,
        advisory: coerceOsvAdvisoryInput(advisory),
      },
    )

    ingestedResults.push({
      ...result,
      advisoryId: advisory.id,
      sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
    })
  }

  return {
    queried,
    fetched: ingestedResults.length,
    imported: ingestedResults.filter((result) => !result.deduped).length,
    deduped: ingestedResults.filter((result) => result.deduped).length,
  }
}

async function syncRepositoryAdvisories(
  ctx: ActionCtx,
  args: {
    tenantSlug: string
    repositoryFullName: string
    lookbackHours: number
    githubLimit: number
    osvLimit: number
    triggerType: 'manual' | 'scheduled'
  },
): Promise<RepositorySyncSummary> {
  const startedAt = Date.now()
  const target = await getRepositorySyncTarget(
    ctx,
    args.tenantSlug,
    args.repositoryFullName,
  )

  if (target.packageCount === 0) {
    return {
      tenantSlug: target.tenantSlug,
      repositoryFullName: target.repositoryFullName,
      repositoryName: target.repositoryName,
      packageCount: 0,
      status: 'skipped',
      reason: 'Skipped advisory sync because the repository has no imported SBOM snapshot yet.',
      github: createEmptyProviderSummary(),
      osv: createEmptyProviderSummary(),
      startedAt,
      completedAt: Date.now(),
    }
  }

  const lookbackHours = Math.max(args.lookbackHours, 1)
  const modifiedSince = new Date(Date.now() - lookbackHours * 60 * 60 * 1000)
    .toISOString()
  const packages = target.packages

  const github = await ingestGithubAdvisoriesForRepository(
    ctx,
    target,
    packages,
    modifiedSince,
    Math.max(args.githubLimit, 1),
  )
  const osv = await ingestOsvAdvisoriesForRepository(
    ctx,
    target,
    packages,
    Math.max(args.osvLimit, 1),
  )

  return {
    tenantSlug: target.tenantSlug,
    repositoryFullName: target.repositoryFullName,
    repositoryName: target.repositoryName,
    packageCount: target.packageCount,
    status: 'completed',
    github,
    osv,
    startedAt,
    completedAt: Date.now(),
  }
}

async function syncRepositoriesAdvisories(
  ctx: ActionCtx,
  args: {
    tenantSlug?: string
    repositoryFullName?: string
    maxRepositories: number
    lookbackHours: number
    githubLimit: number
    osvLimit: number
    triggerType: 'manual' | 'scheduled'
  },
): Promise<SyncRecentAdvisoriesResult> {
  const targets =
    args.tenantSlug && args.repositoryFullName
      ? [
          {
            tenantSlug: args.tenantSlug,
            repositoryFullName: args.repositoryFullName,
          },
        ]
      : await ctx.runQuery(internal.advisorySync.listRepositoryAdvisorySyncTargets, {
          limit: args.maxRepositories,
        })

  const repositories: RepositorySyncSummary[] = []

  for (const target of targets) {
    let summary: RepositorySyncSummary

    try {
      summary = await syncRepositoryAdvisories(ctx, {
        tenantSlug: target.tenantSlug,
        repositoryFullName: target.repositoryFullName,
        lookbackHours: args.lookbackHours,
        githubLimit: args.githubLimit,
        osvLimit: args.osvLimit,
        triggerType: args.triggerType,
      })
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unknown advisory sync failure.'
      const repositoryName =
        target.repositoryFullName.split('/').at(-1) ?? target.repositoryFullName

      summary = {
        tenantSlug: target.tenantSlug,
        repositoryFullName: target.repositoryFullName,
        repositoryName,
        packageCount: 0,
        status: 'failed',
        reason: message,
        github: createEmptyProviderSummary(),
        osv: createEmptyProviderSummary(),
        startedAt: Date.now(),
        completedAt: Date.now(),
      }
    }

    if (
      summary.status === 'completed' ||
      summary.status === 'skipped' ||
      summary.status === 'failed'
    ) {
      await ctx.runMutation(internal.advisoryAggregator.recordSyncRun, {
        tenantSlug: summary.tenantSlug,
        repositoryFullName: summary.repositoryFullName,
        triggerType: args.triggerType,
        status: summary.status,
        packageCount: summary.packageCount,
        lookbackHours: args.lookbackHours,
        github: summary.github,
        osv: summary.osv,
        reason: summary.reason,
        startedAt: summary.startedAt,
        completedAt: summary.completedAt,
      })
    }

    repositories.push(summary)
  }

  return {
    repositoryCount: repositories.length,
    completedRepositoryCount: repositories.filter(
      (repository) => repository.status === 'completed',
    ).length,
    skippedRepositoryCount: repositories.filter(
      (repository) => repository.status === 'skipped',
    ).length,
    failedRepositoryCount: repositories.filter(
      (repository) => repository.status === 'failed',
    ).length,
    github: repositories.reduce(
      (summary, repository) => mergeProviderSummary(summary, repository.github),
      createEmptyProviderSummary(),
    ),
    osv: repositories.reduce(
      (summary, repository) => mergeProviderSummary(summary, repository.osv),
      createEmptyProviderSummary(),
    ),
    repositories,
  }
}

export const importGithubSecurityAdvisoryById = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    ghsaId: v.string(),
  },
  returns: liveIngestResult,
  handler: async (ctx, args): Promise<LiveIngestResult> => {
    const advisory = await fetchGithubSecurityAdvisoryById(args.ghsaId)
    const result: GithubIngestMutationResult = await ctx.runMutation(
      api.events.ingestGithubSecurityAdvisory,
      {
        tenantSlug: args.tenantSlug,
        repositoryFullName: args.repositoryFullName,
        advisory: coerceGithubSecurityAdvisoryInput(advisory),
      },
    )

    return {
      ...result,
      advisoryId: advisory.ghsa_id,
      sourceUrl: `https://github.com/advisories/${encodeURIComponent(advisory.ghsa_id)}`,
    }
  },
})

export const importOsvAdvisoryById = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    osvId: v.string(),
  },
  returns: liveIngestResult,
  handler: async (ctx, args): Promise<LiveIngestResult> => {
    const advisory = await fetchOsvAdvisoryById(args.osvId)
    const result: OsvIngestMutationResult = await ctx.runMutation(
      api.events.ingestOsvAdvisory,
      {
        tenantSlug: args.tenantSlug,
        repositoryFullName: args.repositoryFullName,
        advisory: coerceOsvAdvisoryInput(advisory),
      },
    )

    return {
      ...result,
      advisoryId: advisory.id,
      sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
    }
  },
})

export const syncRecentAdvisories = action({
  args: {
    tenantSlug: v.optional(v.string()),
    repositoryFullName: v.optional(v.string()),
    maxRepositories: v.optional(v.number()),
    lookbackHours: v.optional(v.number()),
    githubLimit: v.optional(v.number()),
    osvLimit: v.optional(v.number()),
  },
  returns: syncRecentAdvisoriesResult,
  handler: async (ctx, args): Promise<SyncRecentAdvisoriesResult> => {
    if (Boolean(args.tenantSlug) !== Boolean(args.repositoryFullName)) {
      throw new ConvexError(
        'tenantSlug and repositoryFullName must be provided together when targeting a single repository.',
      )
    }

    return syncRepositoriesAdvisories(ctx, {
      tenantSlug: args.tenantSlug ?? undefined,
      repositoryFullName: args.repositoryFullName ?? undefined,
      maxRepositories: Math.min(Math.max(args.maxRepositories ?? 20, 1), 50),
      lookbackHours: Math.max(args.lookbackHours ?? 72, 1),
      githubLimit: Math.min(Math.max(args.githubLimit ?? 100, 1), 250),
      osvLimit: Math.min(Math.max(args.osvLimit ?? 100, 1), 250),
      triggerType: 'manual',
    })
  },
})

export const syncRecentAdvisoriesOnSchedule = internalAction({
  args: {
    maxRepositories: v.optional(v.number()),
    lookbackHours: v.optional(v.number()),
    githubLimit: v.optional(v.number()),
    osvLimit: v.optional(v.number()),
  },
  returns: syncRecentAdvisoriesResult,
  handler: async (ctx, args): Promise<SyncRecentAdvisoriesResult> => {
    return syncRepositoriesAdvisories(ctx, {
      maxRepositories: Math.min(Math.max(args.maxRepositories ?? 20, 1), 50),
      lookbackHours: Math.max(args.lookbackHours ?? 72, 1),
      githubLimit: Math.min(Math.max(args.githubLimit ?? 100, 1), 250),
      osvLimit: Math.min(Math.max(args.osvLimit ?? 100, 1), 250),
      triggerType: 'scheduled',
    })
  },
})
