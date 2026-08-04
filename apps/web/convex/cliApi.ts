import { internalMutation, internalQuery } from './_generated/server'
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

export const getFindingDetailsForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), findingId: v.id('findings') },
  returns: v.any(),
  handler: async (ctx, { tenantId, findingId }) => {
    const finding = await ctx.db.get(findingId)
    if (!finding || finding.tenantId !== tenantId) return null
    const repository = await ctx.db.get(finding.repositoryId)
    const workflow = await ctx.db.get(finding.workflowRunId)
    return {
      ...finding,
      repository: repository?.fullName ?? null,
      workflowStatus: workflow?.status ?? null,
    }
  },
})

export const updateFindingStatusForTenant = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    findingId: v.id('findings'),
    newStatus: v.string(),
    reason: v.optional(v.string()),
  },
  returns: v.any(),
  handler: async (ctx, { tenantId, findingId, newStatus, reason }) => {
    const finding = await ctx.db.get(findingId)
    if (!finding || finding.tenantId !== tenantId) return null
    const allowed = ['open', 'pr_opened', 'merged', 'resolved', 'accepted_risk', 'false_positive', 'ignored', 'snoozed']
    if (!allowed.includes(newStatus)) throw new Error(`Invalid finding status: ${newStatus}`)
    await ctx.db.patch(findingId, {
      status: newStatus as typeof finding.status,
      resolvedAt: newStatus === 'resolved' ? Date.now() : finding.resolvedAt,
    })
    return { findingId, status: newStatus, reason: reason ?? null }
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

// ─── Settings: 2FA (resolved through the API key's owner) ───────────────────

export const getApiKeyOwner = internalQuery({
  args: { keyId: v.id('apiKeys') },
  returns: v.union(v.id('users'), v.null()),
  handler: async (ctx, { keyId }) => {
    const key = await ctx.db.get(keyId)
    return key?.createdById ?? null
  },
})

export const getTwoFactorStatusForUser = internalQuery({
  args: { userId: v.id('users') },
  returns: v.any(),
  handler: async (ctx, { userId }) => {
    const enrollment = await ctx.db
      .query('twoFactorEnrollments')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()
    if (!enrollment) return { enrolled: false, verified: false, enforced: false }
    return {
      enrolled: true,
      verified: enrollment.verified,
      enforced: enrollment.enforced,
      enrolledAt: enrollment.enrolledAt,
      lastUsedAt: enrollment.lastUsedAt ?? null,
    }
  },
})

function generateBase32Secret(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bytes = new Uint8Array(20)
  for (let i = 0; i < 20; i++) bytes[i] = Math.floor(Math.random() * 256)
  let secret = ''
  for (let i = 0; i < 20; i++) secret += chars[bytes[i] % 32]
  return secret
}

function generateBackupCodes(): string[] {
  const codes: string[] = []
  for (let i = 0; i < 10; i++) {
    const bytes = new Uint8Array(4)
    for (let j = 0; j < 4; j++) bytes[j] = Math.floor(Math.random() * 256)
    codes.push(Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''))
  }
  return codes
}

export const startTwoFactorEnrollmentForUser = internalMutation({
  args: { userId: v.id('users'), tenantId: v.id('tenants') },
  returns: v.any(),
  handler: async (ctx, { userId, tenantId }) => {
    const existing = await ctx.db
      .query('twoFactorEnrollments')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()
    if (existing?.verified) throw new Error('2FA already enrolled. Disable first to re-enroll.')
    const secret = generateBase32Secret()
    const backupCodes = generateBackupCodes()
    const now = Date.now()
    const otpauthUri = `otpauth://totp/CyberZen:${userId}?secret=${secret}&issuer=CyberZen&algorithm=SHA1&digits=6&period=30`
    if (existing) {
      await ctx.db.patch(existing._id, {
        secretEncrypted: secret,
        verified: false,
        backupCodesEncrypted: JSON.stringify(backupCodes),
        enrolledAt: now,
      })
    } else {
      await ctx.db.insert('twoFactorEnrollments', {
        userId,
        tenantId,
        secretEncrypted: secret,
        verified: false,
        enforced: false,
        backupCodesEncrypted: JSON.stringify(backupCodes),
        enrolledAt: now,
      })
    }
    return { secret, otpauthUri, backupCodes }
  },
})

export const verifyTwoFactorEnrollmentForUser = internalMutation({
  args: { userId: v.id('users'), code: v.string() },
  returns: v.any(),
  handler: async (ctx, { userId, code }) => {
    const enrollment = await ctx.db
      .query('twoFactorEnrollments')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()
    if (!enrollment) throw new Error('No enrollment in progress')
    if (enrollment.verified) throw new Error('Already verified')
    if (code.length !== 6 || !/^\d{6}$/.test(code)) throw new Error('Invalid TOTP code format. Enter a 6-digit code.')
    await ctx.db.patch(enrollment._id, { verified: true, lastUsedAt: Date.now() })
    await ctx.db.insert('auditLog', {
      tenantId: enrollment.tenantId,
      actorUserId: userId,
      action: 'two_factor.enrolled',
      resourceType: 'twoFactorEnrollments',
      resourceId: enrollment._id,
      at: Date.now(),
    })
    return { success: true }
  },
})

export const disableTwoFactorForUser = internalMutation({
  args: { userId: v.id('users'), code: v.string() },
  returns: v.any(),
  handler: async (ctx, { userId, code }) => {
    const enrollment = await ctx.db
      .query('twoFactorEnrollments')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique()
    if (!enrollment) throw new Error('2FA not enrolled')
    if (code.length !== 6 || !/^\d{6}$/.test(code)) throw new Error('Invalid code. Enter your current TOTP code to disable.')
    await ctx.db.delete(enrollment._id)
    await ctx.db.insert('auditLog', {
      tenantId: enrollment.tenantId,
      actorUserId: userId,
      action: 'two_factor.disabled',
      resourceType: 'twoFactorEnrollments',
      at: Date.now(),
    })
    return { success: true }
  },
})

// ─── Settings: IP allowlist, retention, SSO ────────────────────────────────

export const getIpAllowlistForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.string()),
  handler: async (ctx, { tenantId }) => {
    const tenant = await ctx.db.get(tenantId)
    return tenant?.ipAllowlist ?? []
  },
})

function isValidCidr(cidr: string): boolean {
  const parts = cidr.split('/')
  if (parts.length !== 2) return false
  const [ip, prefixStr] = parts
  const prefix = parseInt(prefixStr ?? '', 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const ipParts = (ip ?? '').split('.')
  if (ipParts.length !== 4) return false
  return ipParts.every((p) => {
    const n = parseInt(p, 10)
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p
  })
}

export const updateIpAllowlistForTenant = internalMutation({
  args: { tenantId: v.id('tenants'), cidrs: v.array(v.string()) },
  returns: v.null(),
  handler: async (ctx, { tenantId, cidrs }) => {
    if (cidrs.length > 100) throw new Error('Maximum of 100 CIDR rules allowed')
    for (const cidr of cidrs) {
      if (!isValidCidr(cidr)) throw new Error(`Invalid CIDR notation: ${cidr}`)
    }
    await ctx.db.patch(tenantId, { ipAllowlist: cidrs })
    return null
  },
})

export const getRetentionPoliciesForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.any(),
  handler: async (ctx, { tenantId }) => {
    const config = await ctx.db
      .query('tenantRetentionConfig')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .unique()
    return {
      findingsDays: config?.findingsDays ?? 365,
      auditLogsDays: config?.auditLogsDays ?? 730,
      apiUsageRecordsDays: config?.apiUsageRecordsDays ?? 90,
      webhookDeliveriesDays: config?.webhookDeliveriesDays ?? 30,
      updatedAt: config?.updatedAt ?? null,
    }
  },
})

export const updateRetentionPoliciesForTenant = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    findingsDays: v.number(),
    auditLogsDays: v.number(),
    apiUsageRecordsDays: v.number(),
    webhookDeliveriesDays: v.number(),
  },
  returns: v.any(),
  handler: async (ctx, args) => {
    const mins = { findingsDays: 90, auditLogsDays: 365, apiUsageRecordsDays: 30, webhookDeliveriesDays: 7 }
    if (args.findingsDays < mins.findingsDays) throw new Error(`findingsDays must be at least ${mins.findingsDays} days`)
    if (args.auditLogsDays < mins.auditLogsDays) throw new Error(`auditLogsDays must be at least ${mins.auditLogsDays} days`)
    if (args.apiUsageRecordsDays < mins.apiUsageRecordsDays) throw new Error(`apiUsageRecordsDays must be at least ${mins.apiUsageRecordsDays} days`)
    if (args.webhookDeliveriesDays < mins.webhookDeliveriesDays) throw new Error(`webhookDeliveriesDays must be at least ${mins.webhookDeliveriesDays} days`)
    const now = Date.now()
    const existing = await ctx.db
      .query('tenantRetentionConfig')
      .withIndex('by_tenant', (q) => q.eq('tenantId', args.tenantId))
      .unique()
    const values = {
      findingsDays: args.findingsDays,
      auditLogsDays: args.auditLogsDays,
      apiUsageRecordsDays: args.apiUsageRecordsDays,
      webhookDeliveriesDays: args.webhookDeliveriesDays,
    }
    if (existing) {
      await ctx.db.patch(existing._id, { ...values, updatedAt: now })
    } else {
      await ctx.db.insert('tenantRetentionConfig', { tenantId: args.tenantId, ...values, updatedAt: now })
    }
    return { ...values, updatedAt: now }
  },
})

export const listSsoConfigsForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId }) => {
    return await ctx.db
      .query('ssoConfigs')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .collect()
  },
})

// ─── Admin: audit log, feature flags ───────────────────────────────────────

export const listAuditLogForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), limit: v.number(), actionFilter: v.optional(v.string()) },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId, limit, actionFilter }) => {
    const max = Math.min(Math.max(limit, 1), 500)
    if (actionFilter) {
      return await ctx.db
        .query('auditLog')
        .withIndex('by_tenant_and_action', (q) => q.eq('tenantId', tenantId).eq('action', actionFilter))
        .order('desc')
        .take(max)
    }
    return await ctx.db
      .query('auditLog')
      .withIndex('by_tenant_and_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(max)
  },
})

export const listFeatureFlagsForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.array(v.string()),
  handler: async (ctx, { tenantId }) => {
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) return []
    const subscription = await ctx.db
      .query('subscriptions')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenantId))
      .first()
    const planSlug = subscription?.planSlug ?? 'free'
    const plan = await ctx.db
      .query('plans')
      .withIndex('by_slug', (q) => q.eq('slug', planSlug))
      .unique()
    return plan?.featureFlags ?? []
  },
})

// ─── Breach intelligence: advisory disclosures ──────────────────────────────

export const listBreachDisclosuresForTenant = internalQuery({
  args: { tenantId: v.id('tenants'), limit: v.number() },
  returns: v.array(v.any()),
  handler: async (ctx, { tenantId, limit }) => {
    const max = Math.min(Math.max(limit, 1), 100)
    return await ctx.db
      .query('breachDisclosures')
      .withIndex('by_tenant_and_published_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(max)
  },
})
