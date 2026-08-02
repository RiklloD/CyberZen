import { internalQuery } from './_generated/server'
import { v } from 'convex/values'

/** Internal data access used only by explicit, tenant-bound CLI HTTP routes. */
export const getRepositoryForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), fullName: v.string() },
  returns: v.any(),
  handler: async (ctx, { tenantId, fullName }) => {
    return await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenantId).eq('fullName', fullName),
      )
      .unique()
  },
})

export const getRepositoryDetailsForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), fullName: v.string() },
  returns: v.any(),
  handler: async (ctx, { tenantId, fullName }) => {
    const repository = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenantId).eq('fullName', fullName),
      )
      .unique()
    if (!repository) return null
    return {
      repositoryId: repository._id,
      fullName: repository.fullName,
      provider: repository.provider,
      name: repository.name,
      defaultBranch: repository.defaultBranch,
      visibility: repository.visibility,
      primaryLanguage: repository.primaryLanguage,
      latestCommitSha: repository.latestCommitSha ?? null,
      lastScannedAt: repository.lastScannedAt ?? null,
      disconnectedAt: repository.disconnectedAt ?? null,
    }
  },
})

export const listRepositoriesForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    const repositories = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .collect()
    return repositories.map((repository) => ({
      repositoryId: repository._id,
      fullName: repository.fullName,
      provider: repository.provider,
      defaultBranch: repository.defaultBranch,
      visibility: repository.visibility,
      primaryLanguage: repository.primaryLanguage,
      latestCommitSha: repository.latestCommitSha ?? null,
      lastScannedAt: repository.lastScannedAt ?? null,
      disconnectedAt: repository.disconnectedAt ?? null,
    }))
  },
})

export const listWorkflowRunsForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), limit: v.number() },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId, limit }) => {
    const runs = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(Math.min(Math.max(limit, 1), 100))
    return await Promise.all(
      runs.map(async (run) => {
        const repository = await ctx.db.get(run.repositoryId)
        return {
          workflowRunId: run._id,
          repository: repository?.fullName ?? null,
          workflowType: run.workflowType,
          status: run.status,
          priority: run.priority,
          currentStage: run.currentStage ?? null,
          summary: run.summary,
          totalTaskCount: run.totalTaskCount,
          completedTaskCount: run.completedTaskCount,
          startedAt: run.startedAt,
          completedAt: run.completedAt ?? null,
        }
      }),
    )
  },
})

export const getWorkflowRunDetailsForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), workflowRunId: v.id('workflowRuns') },
  returns: v.any(),
  handler: async (ctx, { tenantId, workflowRunId }) => {
    const run = await ctx.db.get(workflowRunId)
    if (!run || run.tenantId !== tenantId) return null
    const repository = await ctx.db.get(run.repositoryId)
    const tasks = await ctx.db
      .query('workflowTasks')
      .withIndex('by_workflow_run_and_order', (q) => q.eq('workflowRunId', workflowRunId))
      .order('asc')
      .collect()
    const logs = await ctx.db
      .query('scanLogs')
      .withIndex('by_workflow_run_and_created_at', (q) => q.eq('workflowRunId', workflowRunId))
      .order('asc')
      .take(500)
    return {
      workflowRunId: run._id,
      repository: repository?.fullName ?? null,
      workflowType: run.workflowType,
      status: run.status,
      priority: run.priority,
      currentStage: run.currentStage ?? null,
      summary: run.summary,
      totalTaskCount: run.totalTaskCount,
      completedTaskCount: run.completedTaskCount,
      startedAt: run.startedAt,
      completedAt: run.completedAt ?? null,
      tasks,
      logs,
    }
  },
})

export const getRepositoryMemorySummary = internalQuery({
  args: { repositoryId: v.id('repositories') },
  returns: v.object({
    version: v.number(),
    lastLearningAt: v.union(v.number(), v.null()),
    totalEpisodes: v.number(),
    totalPatterns: v.number(),
    predictionAccuracy: v.number(),
    coverageScore: v.number(),
  }),
  handler: async (ctx, { repositoryId }) => {
    const memory = await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', repositoryId))
      .unique()
    if (!memory) {
      return {
        version: 0,
        lastLearningAt: null,
        totalEpisodes: 0,
        totalPatterns: 0,
        predictionAccuracy: 0,
        coverageScore: 0,
      }
    }
    return {
      version: memory.version,
      lastLearningAt: memory.lastLearningAt ?? null,
      totalEpisodes: memory.memoryStats.totalEpisodes,
      totalPatterns: memory.memoryStats.totalPatterns,
      predictionAccuracy: memory.memoryStats.predictionAccuracy,
      coverageScore: memory.memoryStats.coverageScore,
    }
  },
})

export const getBillingSummaryForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.object({
    subscription: v.any(),
    plan: v.any(),
    invoices: v.array(v.any()),
    usage: v.array(v.any()),
  }),
  handler: async (ctx, { tenantId }) => {
    const subscription = await ctx.db
      .query('subscriptions')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .first()
    const plan = subscription
      ? await ctx.db
          .query('billingPlans')
          .withIndex('by_slug', (q) => q.eq('slug', subscription.planSlug))
          .unique()
      : null
    const invoices = await ctx.db
      .query('invoices')
      .withIndex('by_tenant_and_period', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(24)
    const now = Date.now()
    const records = await ctx.db
      .query('usageRecords')
      .withIndex('by_tenant_and_period', (q) => q.eq('tenantId', tenantId))
      .collect()
    const latest = new Map<string, (typeof records)[number]>()
    for (const record of records) {
      if (record.periodEnd >= now) {
        const previous = latest.get(record.metric)
        if (!previous || record.recordedAt > previous.recordedAt) latest.set(record.metric, record)
      }
    }
    return {
      subscription: subscription
        ? {
            planSlug: subscription.planSlug,
            status: subscription.status,
            currentPeriodStart: subscription.currentPeriodStart,
            currentPeriodEnd: subscription.currentPeriodEnd,
            cancelAtPeriodEnd: subscription.cancelAtPeriodEnd,
          }
        : null,
      plan,
      invoices,
      usage: Array.from(latest.values()).map((record) => ({
        metric: record.metric,
        value: record.value,
        periodStart: record.periodStart,
        periodEnd: record.periodEnd,
      })),
    }
  },
})

export const getIntegrationHealthForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    return await ctx.db
      .query('integrationHealth')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .take(50)
  },
})

export const getJobOperationsSummary = internalQuery({
  args: {},
  returns: v.object({ health: v.array(v.any()), paused: v.any() }),
  handler: async (ctx) => {
    const runs = await ctx.db.query('cronJobRuns').order('desc').take(500)
    const byJob = new Map<string, { jobName: string; lastRun: number | null; lastStatus: string | null; lastDuration: number | null; lastError: string | null; successCount: number; failureCount: number; consecutiveFailures: number }>()
    for (const run of runs) {
      const current = byJob.get(run.jobName) ?? {
        jobName: run.jobName,
        lastRun: null,
        lastStatus: null,
        lastDuration: null,
        lastError: null,
        successCount: 0,
        failureCount: 0,
        consecutiveFailures: 0,
      }
      if (run.status === 'success') current.successCount += 1
      if (run.status === 'failed') current.failureCount += 1
      if (current.lastRun === null || run.startedAt > current.lastRun) {
        current.lastRun = run.startedAt
        current.lastStatus = run.status
        current.lastDuration = run.duration ?? null
        current.lastError = run.error ?? null
      }
      byJob.set(run.jobName, current)
    }
    const pausedRows = await ctx.db.query('cronSettings').collect()
    return {
      health: [...byJob.values()].sort((a, b) => (b.lastRun ?? 0) - (a.lastRun ?? 0)),
      paused: Object.fromEntries(pausedRows.filter((row) => row.paused).map((row) => [row.jobName, true])),
    }
  },
})

export const getTenantSlugForCli = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, { tenantId }) => (await ctx.db.get(tenantId))?.slug ?? null,
})

export const getTenantForCli = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.any(),
  handler: async (ctx, { tenantId }) => await ctx.db.get(tenantId),
})

export const listApiKeySummariesForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    const keys = await ctx.db
      .query('apiKeys')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .collect()
    return keys.map((key) => ({
      keyId: key._id,
      name: key.name,
      prefix: key.prefix,
      scopes: key.scopes,
      lastUsedAt: key.lastUsedAt ?? null,
      expiresAt: key.expiresAt ?? null,
      revokedAt: key.revokedAt ?? null,
      createdAt: key.createdAt,
    }))
  },
})

export const getTenantMemberSummaries = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    const members = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .collect()
    return await Promise.all(
      members.map(async (member) => {
        const user = await ctx.db.get(member.userId)
        return {
          userId: member.userId,
          role: member.role,
          email: user?.email ?? null,
          name: user?.name ?? null,
        }
      }),
    )
  },
})

export const getTenantInvites = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    return await ctx.db
      .query('tenantInvites')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(100)
  },
})
