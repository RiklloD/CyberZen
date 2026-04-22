"use node";

import { ConvexError, v } from 'convex/values'
import type { FunctionReturnType } from 'convex/server'
import type { Id } from './_generated/dataModel'
import { api, internal } from './_generated/api'
import { action, internalAction, type ActionCtx } from './_generated/server'
import {
  coerceGithubSecurityAdvisoryInput,
  coerceOsvAdvisoryInput,
  normalizeNvdCve,
  normalizeNpmAdvisory,
  normalizePypiSafetyEntry,
  normalizeRustSecAdvisory,
  normalizeGoVulnEntry,
  type GithubSecurityAdvisoryApiResponse,
  type OsvApiVulnerabilityResponse,
  type NvdCveItem,
  type NpmAdvisory,
  type PypiSafetyEntry,
  type RustSecAdvisory,
  type GoVulnEntry,
} from './lib/breachFeeds'
import {
  buildGithubAdvisoryBatches,
  buildOsvPackageQueries,
  collectOsvVulnerabilityIds,
  parseGithubNextCursor,
  type TrackedAdvisoryPackage,
} from './lib/advisorySync'
import { resolveGitHubConfig, githubHeaders as buildGithubApiHeaders } from './lib/githubClient'

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
  // Delegates to shared client — respects GHES_BASE_URL / GHES_API_URL env vars
  return buildGithubApiHeaders(resolveGitHubConfig())
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
  const ghCfg = resolveGitHubConfig()
  const response = await fetch(
    `${ghCfg.baseUrl}/advisories/${encodeURIComponent(ghsaId)}`,
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

    const response = await fetch(`${resolveGitHubConfig().baseUrl}/advisories?${params.toString()}`, {
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

      // Fire-and-forget prompt injection scan on advisory text.
      // Only runs for new advisories — deduped records were already scanned on
      // first ingestion. Failures are logged and swallowed so a scan error
      // never aborts a sync batch.
      if (!result.deduped) {
        const advisoryContent = [advisory.summary, advisory.description]
          .filter(Boolean)
          .join('\n\n')
        if (advisoryContent) {
          try {
            await ctx.runMutation(internal.promptIntelligence.scanContentByRef, {
              tenantSlug: target.tenantSlug,
              repositoryFullName: target.repositoryFullName,
              workflowRunId: result.workflowRunId,
              contentRef: `ghsa:${advisory.ghsa_id}`,
              content: advisoryContent,
            })
          } catch (err) {
            console.warn(
              `[sentinel] prompt injection scan failed for GHSA ${advisory.ghsa_id}:`,
              err,
            )
          }
        }
      }

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

    // Fire-and-forget prompt injection scan on advisory text.
    // Same gating and error-swallowing as the GHSA path above.
    if (!result.deduped) {
      const advisoryContent = [advisory.summary, advisory.details]
        .filter(Boolean)
        .join('\n\n')
      if (advisoryContent) {
        try {
          await ctx.runMutation(internal.promptIntelligence.scanContentByRef, {
            tenantSlug: target.tenantSlug,
            repositoryFullName: target.repositoryFullName,
            workflowRunId: result.workflowRunId,
            contentRef: `osv:${advisory.id}`,
            content: advisoryContent,
          })
        } catch (err) {
          console.warn(
            `[sentinel] prompt injection scan failed for OSV ${advisory.id}:`,
            err,
          )
        }
      }
    }

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

// ── Shared helper: NormalizedDisclosure → ingestBreachDisclosure args ────────

import type { NormalizedDisclosure } from './lib/breachFeeds'

function disclosureToIngestArgs(
  tenantSlug: string,
  repositoryFullName: string,
  d: NormalizedDisclosure,
) {
  return {
    tenantSlug,
    repositoryFullName,
    packageName: d.packageName,
    sourceName: d.sourceName,
    sourceRef: d.sourceRef,
    summary: d.summary,
    ecosystem: d.ecosystem,
    sourceType: d.sourceType as
      | 'manual'
      | 'github_security_advisory'
      | 'osv'
      | 'nvd'
      | 'npm_advisory'
      | 'pypi_safety'
      | 'rustsec'
      | 'go_vuln',
    sourceTier: d.sourceTier as 'tier_1' | 'tier_2' | 'tier_3',
    affectedVersions: d.affectedVersions,
    fixVersion: d.fixVersion,
    exploitAvailable: d.exploitAvailable,
    aliases: d.aliases,
    publishedAt: d.publishedAt,
    severity: d.severity,
  }
}

// ── NVD sync ──────────────────────────────────────────────────────────────────
//
// Fetches recent CVEs from the NVD REST API 2.0.
// Set NVD_API_KEY in Convex env for higher rate limits (50 req/30s vs 5 req/30s).
// Docs: https://nvd.nist.gov/developers/vulnerabilities

export const syncNvdAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    lookbackHours: v.optional(v.number()),
    maxResults: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const lookback = args.lookbackHours ?? 72
    const maxResults = Math.min(args.maxResults ?? 100, 500)
    const apiKey = process.env.NVD_API_KEY

    const since = new Date(Date.now() - lookback * 3600 * 1000).toISOString().slice(0, 19)
    const params = new URLSearchParams({
      pubStartDate: since + '.000',
      resultsPerPage: String(maxResults),
    })

    const headers: Record<string, string> = {
      Accept: 'application/json',
    }
    if (apiKey) headers['apiKey'] = apiKey

    const resp = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`,
      { headers },
    )
    if (!resp.ok) {
      throw new ConvexError(`NVD API error: ${resp.status}`)
    }

    const data = await resp.json() as {
      vulnerabilities?: Array<{ cve: NvdCveItem }>
    }

    const cves = data.vulnerabilities ?? []
    let imported = 0
    let skipped = 0

    for (const { cve } of cves) {
      // For NVD entries, we try to associate with the repo's known packages
      // by ingesting via the canonical disclosure path
      const disclosure = normalizeNvdCve({
        cve,
        packageName: 'unknown', // NVD doesn't provide package; matched later by SBOM
        ecosystem: 'unknown',
      })

      try {
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToIngestArgs(args.tenantSlug, args.repositoryFullName, disclosure))
        imported++
      } catch {
        skipped++
      }
    }

    return { total: cves.length, imported, skipped }
  },
})

// ── npm Advisory sync ─────────────────────────────────────────────────────────
//
// Queries the npm audit endpoint for a list of package names.
// Body: { name: Record<string, string[]> } where values are version arrays.

export const syncNpmAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Package names to query (from the repo's latest SBOM) */
    packages: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.packages.length === 0) return { total: 0, imported: 0, skipped: 0 }

    // Build npm audit v1 bulk query
    const auditPayload: Record<string, { [version: string]: Record<string, unknown> }> = {}
    for (const pkg of args.packages) {
      auditPayload[pkg] = { '*': {} }
    }

    const resp = await fetch('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(auditPayload),
    })

    if (!resp.ok) {
      throw new ConvexError(`npm advisory API error: ${resp.status}`)
    }

    const data = await resp.json() as Record<string, NpmAdvisory[]>
    let imported = 0
    let skipped = 0

    for (const advisories of Object.values(data)) {
      for (const advisory of advisories) {
        const disclosure = normalizeNpmAdvisory(advisory)
        if (!disclosure) { skipped++; continue }

        try {
          await ctx.runMutation(api.events.ingestBreachDisclosure,
            disclosureToIngestArgs(args.tenantSlug, args.repositoryFullName, disclosure))
          imported++
        } catch {
          skipped++
        }
      }
    }

    return { total: imported + skipped, imported, skipped }
  },
})

// ── PyPI Safety DB sync ───────────────────────────────────────────────────────
//
// Safety DB is a public GitHub-hosted JSON list of known vulnerable PyPI packages.
// Repo: https://github.com/pyupio/safety-db (CC0 license, no auth required)

export const syncPypiSafetyAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Python packages to look up (from SBOM) */
    packages: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.packages.length === 0) return { total: 0, imported: 0, skipped: 0 }

    const resp = await fetch(
      'https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json',
    )
    if (!resp.ok) {
      throw new ConvexError(`PyPI Safety DB fetch error: ${resp.status}`)
    }

    const db = await resp.json() as Record<string, PypiSafetyEntry[]>
    const normalizedPackages = new Set(args.packages.map((p) => p.toLowerCase()))

    let imported = 0
    let skipped = 0

    for (const [pkgName, entries] of Object.entries(db)) {
      if (!normalizedPackages.has(pkgName.toLowerCase())) continue

      for (const entry of entries) {
        const disclosure = normalizePypiSafetyEntry(entry)
        if (!disclosure) { skipped++; continue }

        try {
          await ctx.runMutation(api.events.ingestBreachDisclosure,
            disclosureToIngestArgs(args.tenantSlug, args.repositoryFullName, disclosure))
          imported++
        } catch {
          skipped++
        }
      }
    }

    return { total: imported + skipped, imported, skipped }
  },
})

// ── RustSec sync ──────────────────────────────────────────────────────────────
//
// RustSec advisory DB is publicly hosted at https://rustsec.org/advisories/
// Machine-readable format: https://github.com/rustsec/advisory-db (TOML files)
// We use the JSON export maintained at the osv.dev mirror for RustSec.

export const syncRustSecAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Cargo package names from the repo's SBOM */
    packages: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.packages.length === 0) return { total: 0, imported: 0, skipped: 0 }

    let imported = 0
    let skipped = 0

    for (const pkg of args.packages.slice(0, 20)) {
      const resp = await fetch(
        `https://osv.dev/v1/query`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: { name: pkg, ecosystem: 'crates.io' } }),
        },
      )
      if (!resp.ok) { skipped++; continue }

      const data = await resp.json() as { vulns?: GoVulnEntry[] }
      for (const vuln of data.vulns ?? []) {
        const advisory: RustSecAdvisory = {
          id: vuln.id,
          package: pkg,
          date: vuln.published?.slice(0, 10) ?? undefined,
          title: vuln.summary ?? undefined,
          description: vuln.details ?? undefined,
          aliases: vuln.aliases ?? [],
        }

        const disclosure = normalizeRustSecAdvisory(advisory)
        if (!disclosure) { skipped++; continue }

        try {
          await ctx.runMutation(api.events.ingestBreachDisclosure,
            disclosureToIngestArgs(args.tenantSlug, args.repositoryFullName, disclosure))
          imported++
        } catch {
          skipped++
        }
      }
    }

    return { total: imported + skipped, imported, skipped }
  },
})

// ── Go Vulnerability DB sync ──────────────────────────────────────────────────
//
// Official Go Vulnerability Database: https://vuln.go.dev
// API: GET https://vuln.go.dev/v1/query (POST with module path)

export const syncGoVulnAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Go module paths from the repo's SBOM (e.g. "golang.org/x/net") */
    modules: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.modules.length === 0) return { total: 0, imported: 0, skipped: 0 }

    let imported = 0
    let skipped = 0

    for (const mod of args.modules.slice(0, 20)) {
      const resp = await fetch('https://vuln.go.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ module: mod }),
      })
      if (!resp.ok) { skipped++; continue }

      const data = await resp.json() as { vulns?: GoVulnEntry[] }

      for (const entry of data.vulns ?? []) {
        // Extract affected versions for this module from the entry
        const affected = entry.affected?.find(
          (a) => a.package?.name?.toLowerCase() === mod.toLowerCase(),
        )
        const affectedVersions = affected?.versions ?? []
        const fixVersion = affected?.ranges
          ?.flatMap((r) => r.events ?? [])
          .find((e) => e.fixed)?.fixed ?? undefined

        const disclosure = normalizeGoVulnEntry(entry, mod, affectedVersions, fixVersion)

        try {
          await ctx.runMutation(api.events.ingestBreachDisclosure,
            disclosureToIngestArgs(args.tenantSlug, args.repositoryFullName, disclosure))
          imported++
        } catch {
          skipped++
        }
      }
    }

    return { total: imported + skipped, imported, skipped }
  },
})
