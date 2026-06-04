import { ConvexError, v } from 'convex/values'
import {
  action,
  internalMutation,
  internalQuery,
  mutation,
} from './_generated/server'
import { internal } from './_generated/api'
import type { Id } from './_generated/dataModel'
import {
  applyVersionBumpToManifest,
  buildPrProposalContent,
  ECOSYSTEM_MANIFEST_PATHS,
} from './lib/prGeneration'

// ---------------------------------------------------------------------------
// Shared validators (avoid repeating literal unions)
// ---------------------------------------------------------------------------

const prStatus = v.union(
  v.literal('draft'),
  v.literal('open'),
  v.literal('merged'),
  v.literal('closed'),
  v.literal('failed'),
)

const fixType = v.union(
  v.literal('version_bump'),
  v.literal('patch'),
  v.literal('config_change'),
  v.literal('manual'),
)

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

// ---------------------------------------------------------------------------
// GitHub API helpers — V8 fetch (no "use node" needed, no Node.js modules)
// ---------------------------------------------------------------------------

function githubPrHeaders(): Record<string, string> {
  const token =
    process.env.GITHUB_PR_TOKEN ??
    process.env.GITHUB_TOKEN ??
    process.env.GH_TOKEN

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'CyberZen-Sentinel',
    'X-GitHub-Api-Version': '2022-11-28',
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  return headers
}

async function safeReadBody(response: Response): Promise<string> {
  try {
    return (await response.text()).slice(0, 400)
  } catch {
    return 'No response body was available.'
  }
}

// ---------------------------------------------------------------------------
// Base64 helpers — chunk-safe, no stack overflow on large manifest files
// ---------------------------------------------------------------------------

/** Encode a UTF-8 string to base64, chunking to avoid call-stack limits. */
function encodeBase64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  const chunkSize = 8192
  let binary = ''
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }
  return btoa(binary)
}

/** Decode a base64 string (with embedded newlines) back to UTF-8 text. */
function decodeBase64(encoded: string): string {
  const binaryStr = atob(encoded.replace(/\n/g, ''))
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i)
  }
  return new TextDecoder().decode(bytes)
}

// ---------------------------------------------------------------------------
// GitHub Contents API: fetch and update individual repository files
// ---------------------------------------------------------------------------

type GithubFileContent = { content: string; blobSha: string }

/**
 * Fetch a file's decoded text content and blob SHA from the GitHub Contents API.
 * Returns null for 404 (file not found). Throws on other error statuses.
 */
async function fetchGithubFile(
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<GithubFileContent | null> {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`,
    { headers: githubPrHeaders() },
  )

  if (response.status === 404) return null

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(`GitHub get-contents failed for ${path} (${response.status}): ${body}`)
  }

  const data = (await response.json()) as {
    type?: string
    content?: string
    sha?: string
    encoding?: string
  }

  // Skip directories and submodule entries
  if (data.type !== 'file' || !data.content || !data.sha) return null

  return { content: decodeBase64(data.content), blobSha: data.sha }
}

/**
 * Commit an updated file to a branch via the GitHub Contents API.
 * `blobSha` must be the existing file's blob SHA as returned by fetchGithubFile.
 */
async function commitGithubFile(params: {
  owner: string
  repo: string
  path: string
  content: string
  blobSha: string
  message: string
  branch: string
}): Promise<void> {
  const response = await fetch(
    `https://api.github.com/repos/${params.owner}/${params.repo}/contents/${params.path}`,
    {
      method: 'PUT',
      headers: { ...githubPrHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: params.message,
        content: encodeBase64(params.content),
        sha: params.blobSha,
        branch: params.branch,
      }),
    },
  )

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(
      `GitHub update-file failed for ${params.path} (${response.status}): ${body}`,
    )
  }
}

async function getBaseBranchSha(
  owner: string,
  repo: string,
  branch: string,
): Promise<string> {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(branch)}`,
    { headers: githubPrHeaders() },
  )

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(`GitHub get-ref failed (${response.status}): ${body}`)
  }

  const data = (await response.json()) as { object?: { sha?: string } }
  const sha = data?.object?.sha

  if (!sha) {
    throw new Error('GitHub get-ref returned no SHA')
  }

  return sha
}

async function createBranch(
  owner: string,
  repo: string,
  headBranch: string,
  baseSha: string,
): Promise<void> {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/refs`,
    {
      method: 'POST',
      headers: { ...githubPrHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref: `refs/heads/${headBranch}`, sha: baseSha }),
    },
  )

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(`GitHub create-branch failed (${response.status}): ${body}`)
  }
}

// Creates a single-file commit on headBranch so that the branch is at least
// one commit ahead of base and GitHub allows a PR to be opened.
async function createTrackingFile(
  owner: string,
  repo: string,
  headBranch: string,
  fixSummary: string,
): Promise<void> {
  const content = [
    '# Sentinel Fix Proposal',
    '',
    fixSummary,
    '',
    'See the pull request description for the full context and required changes.',
    '',
    '_Generated by Sentinel — autonomous security platform._',
  ].join('\n')

  // btoa over a UTF-8 byte string (the standard way in V8 / browsers)
  const encoded = btoa(
    String.fromCodePoint(...new TextEncoder().encode(content)),
  )

  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/.sentinel/fix-proposal.md`,
    {
      method: 'PUT',
      headers: { ...githubPrHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `chore: sentinel fix proposal — ${fixSummary}`,
        content: encoded,
        branch: headBranch,
      }),
    },
  )

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(`GitHub create-file failed (${response.status}): ${body}`)
  }
}

type GithubPrResult = { prUrl: string; prNumber: number }

async function openGithubPullRequest(params: {
  owner: string
  repo: string
  baseBranch: string
  headBranch: string
  title: string
  body: string
  fixSummary: string
  // Manifest editing — all optional; if all three are present we attempt a real file edit
  ecosystem?: string
  packageName?: string
  fixVersion?: string
}): Promise<GithubPrResult> {
  const baseSha = await getBaseBranchSha(params.owner, params.repo, params.baseBranch)
  await createBranch(params.owner, params.repo, params.headBranch, baseSha)

  // --- Real manifest editing (best-effort; falls back to tracking placeholder) -----------
  let manifestPatched = false

  if (params.ecosystem && params.packageName && params.fixVersion) {
    const candidates = ECOSYSTEM_MANIFEST_PATHS[params.ecosystem.toLowerCase()] ?? []

    try {
      for (const manifestPath of candidates) {
        const file = await fetchGithubFile(
          params.owner,
          params.repo,
          manifestPath,
          params.baseBranch,
        )
        if (!file) continue

        const patched = applyVersionBumpToManifest(
          manifestPath,
          file.content,
          params.packageName,
          params.fixVersion,
        )
        if (!patched) continue

        await commitGithubFile({
          owner: params.owner,
          repo: params.repo,
          path: manifestPath,
          content: patched,
          blobSha: file.blobSha,
          message: `fix(deps): bump ${params.packageName} to ${params.fixVersion} (security)`,
          branch: params.headBranch,
        })

        manifestPatched = true
        break // stop at the first successfully patched manifest
      }
    } catch (err) {
      // Log but do not fail — a real diff is a best-effort enhancement.
      // The PR will still be opened with the tracking placeholder below.
      console.warn(
        `[sentinel] Manifest patching failed for ${params.ecosystem}/${params.packageName}:`,
        err instanceof Error ? err.message : String(err),
      )
    }
  }

  // Fallback: tracking placeholder ensures the branch is at least one commit ahead of base.
  if (!manifestPatched) {
    await createTrackingFile(params.owner, params.repo, params.headBranch, params.fixSummary)
  }
  // --------------------------------------------------------------------------------------

  const response = await fetch(
    `https://api.github.com/repos/${params.owner}/${params.repo}/pulls`,
    {
      method: 'POST',
      headers: { ...githubPrHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: params.title,
        body: params.body,
        head: params.headBranch,
        base: params.baseBranch,
        draft: true,
      }),
    },
  )

  if (!response.ok) {
    const body = await safeReadBody(response)
    throw new Error(`GitHub create-PR failed (${response.status}): ${body}`)
  }

  const pr = (await response.json()) as { html_url?: string; number?: number }

  if (!pr.html_url || !pr.number) {
    throw new Error('GitHub create-PR returned no URL or number')
  }

  return { prUrl: pr.html_url, prNumber: pr.number }
}

// ---------------------------------------------------------------------------
// Internal query: gather context needed to build a PR proposal
// ---------------------------------------------------------------------------

const proposalContextValidator = v.object({
  tenantSlug: v.string(),
  finding: v.object({
    _id: v.id('findings'),
    title: v.string(),
    summary: v.string(),
    severity,
    affectedPackages: v.array(v.string()),
    workflowRunId: v.id('workflowRuns'),
  }),
  repository: v.object({
    _id: v.id('repositories'),
    tenantId: v.id('tenants'),
    name: v.string(),
    fullName: v.string(),
    defaultBranch: v.string(),
  }),
  disclosure: v.union(
    v.null(),
    v.object({
      packageName: v.string(),
      ecosystem: v.string(),
      sourceRef: v.string(),
      fixVersion: v.optional(v.string()),
      matchedVersions: v.array(v.string()),
    }),
  ),
})

export const getProposalContext = internalQuery({
  args: {
    findingId: v.id('findings'),
  },
  returns: v.union(proposalContextValidator, v.null()),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId)
    if (!finding) return null

    const repository = await ctx.db.get(finding.repositoryId)
    if (!repository) return null

    const tenant = await ctx.db.get(repository.tenantId)
    if (!tenant) return null

    const disclosure = finding.breachDisclosureId
      ? await ctx.db.get(finding.breachDisclosureId)
      : null

    return {
      tenantSlug: tenant.slug,
      finding: {
        _id: finding._id,
        title: finding.title,
        summary: finding.summary,
        severity: finding.severity,
        affectedPackages: finding.affectedPackages,
        workflowRunId: finding.workflowRunId,
      },
      repository: {
        _id: repository._id,
        tenantId: repository.tenantId,
        name: repository.name,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
      },
      disclosure: disclosure
        ? {
            packageName: disclosure.packageName,
            ecosystem: disclosure.ecosystem,
            sourceRef: disclosure.sourceRef,
            fixVersion: disclosure.fixVersion,
            matchedVersions: disclosure.matchedVersions,
          }
        : null,
    }
  },
})

// ---------------------------------------------------------------------------
// Internal mutations: granular state transitions
// ---------------------------------------------------------------------------

export const createPrProposal = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    findingId: v.id('findings'),
    proposedBranch: v.string(),
    prTitle: v.string(),
    prBody: v.string(),
    fixType,
    fixSummary: v.string(),
    targetPackage: v.optional(v.string()),
    targetEcosystem: v.optional(v.string()),
    currentVersion: v.optional(v.string()),
    fixVersion: v.optional(v.string()),
  },
  returns: v.id('prProposals'),
  handler: async (ctx, args) => {
    // Advance the finding to 'pr_opened' so downstream queries can filter it.
    await ctx.db.patch('findings', args.findingId, { status: 'pr_opened' })

    return await ctx.db.insert('prProposals', {
      ...args,
      status: 'draft',
      createdAt: Date.now(),
    })
  },
})

export const recordPrOpened = internalMutation({
  args: {
    proposalId: v.id('prProposals'),
    findingId: v.id('findings'),
    prUrl: v.string(),
    prNumber: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.patch('prProposals', args.proposalId, {
      status: 'open',
      prUrl: args.prUrl,
      prNumber: args.prNumber,
      submittedAt: Date.now(),
    })
    // Mirror the PR URL onto the finding so the dashboard can surface it directly.
    await ctx.db.patch('findings', args.findingId, { prUrl: args.prUrl })
    return null
  },
})

export const recordPrFailed = internalMutation({
  args: {
    proposalId: v.id('prProposals'),
    githubError: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.patch('prProposals', args.proposalId, {
      status: 'failed',
      githubError: args.githubError,
    })
    return null
  },
})

// ---------------------------------------------------------------------------
// Public mutations: operator-driven lifecycle changes
// ---------------------------------------------------------------------------

export const markPrMerged = mutation({
  args: {
    proposalId: v.id('prProposals'),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const proposal = await ctx.db.get(args.proposalId)
    if (!proposal) throw new ConvexError('PR proposal not found')

    if (proposal.status !== 'open') {
      throw new ConvexError(
        `Cannot mark a '${proposal.status}' proposal as merged. Only 'open' proposals can be merged.`,
      )
    }

    const now = Date.now()
    await ctx.db.patch('prProposals', args.proposalId, {
      status: 'merged',
      mergedAt: now,
    })
    await ctx.db.patch('findings', proposal.findingId, {
      status: 'merged',
      resolvedAt: now,
    })
    return null
  },
})

export const markPrClosed = mutation({
  args: {
    proposalId: v.id('prProposals'),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const proposal = await ctx.db.get(args.proposalId)
    if (!proposal) throw new ConvexError('PR proposal not found')

    await ctx.db.patch('prProposals', args.proposalId, { status: 'closed' })
    return null
  },
})

// ---------------------------------------------------------------------------
// Public action: generate a PR proposal and optionally open it on GitHub
// ---------------------------------------------------------------------------

export const proposeFix = action({
  args: {
    findingId: v.id('findings'),
    workflowRunId: v.id('workflowRuns'),
    actorId: v.optional(v.string()),
  },
  returns: v.object({
    proposalId: v.id('prProposals'),
    status: prStatus,
    prUrl: v.optional(v.string()),
    message: v.string(),
  }),
  handler: async (
    ctx,
    args,
  ): Promise<{
    proposalId: Id<'prProposals'>
    status: 'draft' | 'open' | 'failed'
    prUrl?: string
    message: string
  }> => {
    const context = await ctx.runQuery(internal.prGeneration.getProposalContext, {
      findingId: args.findingId,
    })

    if (!context) {
      throw new ConvexError('Finding or repository not found for PR proposal.')
    }

    const { tenantSlug, finding, repository, disclosure } = context

    // Prefer the disclosure's primary package; fall back to the first affected package.
    const primaryPackage = disclosure?.packageName ?? finding.affectedPackages[0]
    const currentVersion = disclosure?.matchedVersions[0]

    const content = buildPrProposalContent({
      repositoryName: repository.name,
      findingTitle: finding.title,
      findingSummary: finding.summary,
      findingSeverity: finding.severity,
      affectedPackages: finding.affectedPackages,
      disclosureRef: disclosure?.sourceRef,
      packageName: primaryPackage,
      packageEcosystem: disclosure?.ecosystem,
      currentVersion,
      fixVersion: disclosure?.fixVersion,
    })

    // Create the draft proposal record and advance the finding status atomically.
    const proposalId = await ctx.runMutation(
      internal.prGeneration.createPrProposal,
      {
        tenantId: repository.tenantId,
        repositoryId: repository._id,
        workflowRunId: args.workflowRunId,
        findingId: args.findingId,
        proposedBranch: content.proposedBranch,
        prTitle: content.prTitle,
        prBody: content.prBody,
        fixType: content.fixType,
        fixSummary: content.fixSummary,
        targetPackage: content.targetPackage,
        targetEcosystem: content.targetEcosystem,
        currentVersion: content.currentVersion,
        fixVersion: content.fixVersion,
      },
    )

    // If no GitHub token is configured, return the draft so the operator can
    // review and open the PR manually.
    const githubToken =
      process.env.GITHUB_PR_TOKEN ??
      process.env.GITHUB_TOKEN ??
      process.env.GH_TOKEN

    if (!githubToken) {
      return {
        proposalId,
        status: 'draft',
        message:
          'PR proposal drafted. Set GITHUB_TOKEN in the Convex deployment to open the PR on GitHub automatically.',
      }
    }

    // Split owner/repo from the repository's full name.
    const slashIndex = repository.fullName.indexOf('/')
    const owner = slashIndex > 0 ? repository.fullName.slice(0, slashIndex) : ''
    const repo = slashIndex > 0 ? repository.fullName.slice(slashIndex + 1) : ''

    if (!owner || !repo) {
      await ctx.runMutation(internal.prGeneration.recordPrFailed, {
        proposalId,
        githubError: `Repository fullName "${repository.fullName}" is not in owner/repo format.`,
      })
      return {
        proposalId,
        status: 'failed',
        message: 'PR proposal drafted but GitHub PR creation failed: invalid repository name.',
      }
    }

    try {
      const { prUrl, prNumber } = await openGithubPullRequest({
        owner,
        repo,
        baseBranch: repository.defaultBranch,
        headBranch: content.proposedBranch,
        title: content.prTitle,
        body: content.prBody,
        fixSummary: content.fixSummary,
        ecosystem: content.targetEcosystem,
        packageName: content.targetPackage,
        fixVersion: content.fixVersion,
      })

      await ctx.runMutation(internal.prGeneration.recordPrOpened, {
        proposalId,
        findingId: args.findingId,
        prUrl,
        prNumber,
      })

      // Fire-and-forget outbound webhook for finding.pr_opened events.
      try {
        await ctx.scheduler.runAfter(
          0,
          internal.webhooks.dispatchWebhookEvent,
          {
            tenantId: repository.tenantId,
            tenantSlug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'finding.pr_opened' as const,
              data: {
                findingId: args.findingId as string,
                title: finding.title,
                severity: finding.severity,
                prUrl,
                prTitle: content.prTitle,
                proposedBranch: content.proposedBranch,
              },
            },
          },
        )
      } catch (e) {
        console.error('[webhooks] finding.pr_opened dispatch failed', e)
      }

      return {
        proposalId,
        status: 'open',
        prUrl,
        message: `PR #${prNumber} opened: ${prUrl}`,
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)

      await ctx.runMutation(internal.prGeneration.recordPrFailed, {
        proposalId,
        githubError: errorMessage,
      })

      return {
        proposalId,
        status: 'failed',
        message: `PR proposal drafted but GitHub PR creation failed: ${errorMessage}`,
      }
    }
  },
})
