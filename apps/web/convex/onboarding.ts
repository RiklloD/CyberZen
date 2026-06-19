import { v } from 'convex/values'
import { api } from './_generated/api'
import type { Id } from './_generated/dataModel'
import { mutation } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

const deploymentMode = v.union(
  v.literal('cloud_saas'),
  v.literal('vpc_injection'),
  v.literal('on_prem'),
)

const repositoryInput = v.object({
  fullName: v.string(),
  provider: v.union(v.literal('github'), v.literal('gitlab')),
  defaultBranch: v.string(),
  primaryLanguage: v.string(),
  visibility: v.union(v.literal('private'), v.literal('public')),
  importSnapshot: v.optional(
    v.object({
      rootPath: v.optional(v.string()),
      sourceFiles: v.array(v.string()),
      components: v.array(
        v.object({
          name: v.string(),
          version: v.string(),
          ecosystem: v.string(),
          layer: v.string(),
          isDirect: v.boolean(),
          sourceFile: v.string(),
          dependents: v.array(v.string()),
          license: v.optional(v.string()),
        }),
      ),
    }),
  ),
})

const onboardingRepositoryResult = v.object({
  _id: v.id('repositories'),
  fullName: v.string(),
  provider: v.string(),
  created: v.boolean(),
  scanQueued: v.boolean(),
  workflowRunId: v.optional(v.id('workflowRuns')),
  snapshotId: v.optional(v.id('sbomSnapshots')),
  componentCount: v.optional(v.number()),
})

function formatRepositoryName(fullName: string) {
  return fullName.split('/').at(-1) ?? fullName
}

function baselineFilesForLanguage(language: string) {
  const normalized = language.trim().toLowerCase()

  if (
    normalized.includes('typescript') ||
    normalized.includes('javascript') ||
    normalized.includes('node') ||
    normalized.includes('react')
  ) {
    return [
      'package.json',
      'package-lock.json',
      'pnpm-lock.yaml',
      'tsconfig.json',
      'Dockerfile',
      '.github/workflows/ci.yml',
    ]
  }

  if (normalized.includes('python')) {
    return [
      'pyproject.toml',
      'requirements.txt',
      'poetry.lock',
      'Dockerfile',
      '.github/workflows/ci.yml',
    ]
  }

  if (normalized.includes('go')) {
    return ['go.mod', 'go.sum', 'Dockerfile', '.github/workflows/ci.yml']
  }

  if (normalized.includes('terraform') || normalized.includes('iac')) {
    return ['main.tf', 'variables.tf', 'providers.tf', 'Dockerfile', '.github/workflows/ci.yml']
  }

  return ['README.md', 'Dockerfile', '.github/workflows/ci.yml']
}

export const provisionWorkspace = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    companyName: v.string(),
    deploymentMode,
    currentPhase: v.optional(
      v.union(
        v.literal('phase_0'),
        v.literal('phase_1'),
        v.literal('phase_2'),
        v.literal('phase_3'),
        v.literal('phase_4'),
      ),
    ),
    repositories: v.array(repositoryInput),
  },
  returns: v.object({
    tenantId: v.id('tenants'),
    tenantSlug: v.string(),
    tenantName: v.string(),
    createdTenant: v.boolean(),
    repositories: v.array(onboardingRepositoryResult),
  }),
  handler: async (ctx, args) => {
    const { userId: currentUserId } = await requireSessionAuth(ctx, args.authToken)

    const tenantName = args.companyName.trim() || args.tenantSlug
    const existingTenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    let tenantId: Id<'tenants'>
    let createdTenant = false

    if (existingTenant) {
      tenantId = existingTenant._id
      await ctx.db.patch(existingTenant._id, {
        name: tenantName,
        deploymentMode: args.deploymentMode,
        ...(args.currentPhase ? { currentPhase: args.currentPhase } : {}),
      })

      const existingMembership = await ctx.db
        .query('tenantMembers')
        .withIndex('by_tenant_and_user', (q) =>
          q.eq('tenantId', tenantId).eq('userId', currentUserId),
        )
        .unique()

      const anyMembership = await ctx.db
        .query('tenantMembers')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
        .take(1)

      if (existingMembership) {
        await ctx.db.patch(existingMembership._id, {
          selectedAt: Date.now(),
        })
      } else if (anyMembership.length === 0) {
        await ctx.db.insert('tenantMembers', {
          tenantId,
          userId: currentUserId,
          role: 'owner',
          selectedAt: Date.now(),
          joinedAt: Date.now(),
        })
      } else {
        throw new Error(
          'Workspace already exists. Switch to it or join with an invite link.',
        )
      }
    } else {
      tenantId = await ctx.db.insert('tenants', {
        slug: args.tenantSlug,
        name: tenantName,
        status: 'active',
        deploymentMode: args.deploymentMode,
        currentPhase: args.currentPhase ?? 'phase_1',
        createdAt: Date.now(),
      })
      createdTenant = true

      await ctx.db.insert('tenantMembers', {
        tenantId,
        userId: currentUserId,
        role: 'owner',
        selectedAt: Date.now(),
        joinedAt: Date.now(),
      })
    }

    const results: Array<{
      _id: Id<'repositories'>
      fullName: string
      provider: 'github' | 'gitlab'
      created: boolean
      scanQueued: boolean
      workflowRunId?: Id<'workflowRuns'>
      snapshotId?: Id<'sbomSnapshots'>
      componentCount?: number
    }> = []

    for (const repoSpec of args.repositories) {
      const fullName = repoSpec.fullName.trim()
      if (!fullName) {
        continue
      }

      const name = formatRepositoryName(fullName)
      const existingRepository = await ctx.db
        .query('repositories')
        .withIndex('by_tenant_and_full_name', (q) =>
          q.eq('tenantId', tenantId).eq('fullName', fullName),
        )
        .unique()

      let repositoryId: Id<'repositories'>
      let created = false

      if (existingRepository) {
        repositoryId = existingRepository._id
        await ctx.db.patch(existingRepository._id, {
          provider: repoSpec.provider,
          name,
          defaultBranch: repoSpec.defaultBranch,
          visibility: repoSpec.visibility,
          primaryLanguage: repoSpec.primaryLanguage,
        })
      } else {
        repositoryId = await ctx.db.insert('repositories', {
          tenantId,
          provider: repoSpec.provider,
          name,
          fullName,
          defaultBranch: repoSpec.defaultBranch,
          visibility: repoSpec.visibility,
          primaryLanguage: repoSpec.primaryLanguage,
        })
        created = true
      }

      const kickoffCommitSha = `onboarding-${Date.now().toString(36)}-${fullName.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`

      if (repoSpec.importSnapshot) {
        const snapshotResult = await ctx.runMutation(api.sbom.ingestRepositoryInventory, {
          tenantSlug: args.tenantSlug,
          repositoryFullName: fullName,
          branch: repoSpec.defaultBranch,
          commitSha: kickoffCommitSha,
          sourceFiles: repoSpec.importSnapshot.sourceFiles,
          components: repoSpec.importSnapshot.components,
        })

        results.push({
          _id: repositoryId,
          fullName,
          provider: repoSpec.provider,
          created,
          scanQueued: true,
          snapshotId: snapshotResult.snapshotId,
          componentCount: snapshotResult.componentCount,
        })
        continue
      }

      const kickoffChangedFiles = baselineFilesForLanguage(repoSpec.primaryLanguage)

      const kickoffResult = await ctx.runMutation(api.events.ingestGithubPush, {
        tenantSlug: args.tenantSlug,
        repositoryFullName: fullName,
        branch: repoSpec.defaultBranch,
        commitSha: kickoffCommitSha,
        changedFiles: kickoffChangedFiles,
        commitMessages: [
          `Initial onboarding scan for ${fullName}`,
          `Baseline scan generated from ${repoSpec.primaryLanguage} repository metadata`,
        ],
      })

      results.push({
        _id: repositoryId,
        fullName,
        provider: repoSpec.provider,
        created,
        scanQueued: true,
        workflowRunId: kickoffResult.workflowRunId,
        snapshotId: undefined,
        componentCount: undefined,
      })
    }

    return {
      tenantId,
      tenantSlug: args.tenantSlug,
      tenantName,
      createdTenant,
      repositories: results,
    }
  },
})
