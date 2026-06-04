import { v } from 'convex/values'
import { internalQuery, query } from './_generated/server'

const packageValidator = v.object({
  packageName: v.string(),
  ecosystem: v.string(),
  version: v.string(),
})

const repositoryTargetValidator = v.object({
  tenantSlug: v.string(),
  repositoryFullName: v.string(),
  repositoryName: v.string(),
  defaultBranch: v.string(),
  packageCount: v.number(),
  packages: v.array(packageValidator),
})

export const getRepositoryAdvisorySyncTarget = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  returns: v.union(repositoryTargetValidator, v.null()),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', args.repositoryFullName),
      )
      .unique()

    if (!repository) {
      return null
    }

    const latestSnapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()

    if (!latestSnapshot) {
      return {
        tenantSlug: tenant.slug,
        repositoryFullName: repository.fullName,
        repositoryName: repository.name,
        defaultBranch: repository.defaultBranch,
        packageCount: 0,
        packages: [],
      }
    }

    const packages = (
      await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
        .collect()
    ).map((component) => ({
      packageName: component.name,
      ecosystem: component.ecosystem,
      version: component.version,
    }))

    return {
      tenantSlug: tenant.slug,
      repositoryFullName: repository.fullName,
      repositoryName: repository.name,
      defaultBranch: repository.defaultBranch,
      packageCount: packages.length,
      packages,
    }
  },
})

export const listRepositoryAdvisorySyncTargets = internalQuery({
  args: {
    limit: v.optional(v.number()),
  },
  returns: v.array(
    v.object({
      tenantSlug: v.string(),
      repositoryFullName: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const limit = Math.min(Math.max(args.limit ?? 20, 1), 50)
    const repositories = await ctx.db.query('repositories').take(limit)
    const targets: Array<{
      tenantSlug: string
      repositoryFullName: string
    }> = []

    for (const repository of repositories) {
      const tenant = await ctx.db.get(repository.tenantId)

      if (!tenant) {
        continue
      }

      targets.push({
        tenantSlug: tenant.slug,
        repositoryFullName: repository.fullName,
      })
    }

    return targets
  },
})
