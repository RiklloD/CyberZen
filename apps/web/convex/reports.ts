import { ConvexError, v } from 'convex/values'
import { action, internalMutation, internalQuery, mutation, query } from './_generated/server'
import type { MutationCtx, QueryCtx } from './_generated/server'
import { api, internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth'
import type { Id } from './_generated/dataModel'
import type { TenantExecutiveReport } from './lib/executiveReport'

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

// Inernal query wrapper so actions can verify session auth via ctx.runQuery
export const verifyAuth = internalQuery({
  args: { authToken: v.string() },
  returns: v.null(),
  handler: async (ctx, { authToken }): Promise<null> => {
    await requireSessionAuth(ctx, authToken)
    return null
  },
})

async function requireAdminMembership(
  ctx: QueryCtx | MutationCtx,
  authToken: string,
  tenantSlug: string,
) {
  const { userId } = await requireSessionAuth(ctx, authToken)
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()
  if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`)

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()
  if (!membership) throw new ConvexError('Not a member of this workspace')

  return { tenant, userId, membership }
}

// ---------------------------------------------------------------------------
// generateExecutiveReport — action: assembles and stores a report snapshot
// ---------------------------------------------------------------------------

export const generateExecutiveReport = action({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    period: v.optional(v.string()),
    type: v.optional(
      v.union(v.literal('monthly'), v.literal('quarterly'), v.literal('adhoc')),
    ),
  },
  returns: v.id('executiveReports'),
  handler: async (ctx, { authToken, tenantSlug, period, type }) => {
    await ctx.runQuery(internal.reports.verifyAuth, { authToken })

    const tenant = await ctx.runQuery(internal.reports.lookupTenantBySlug, { tenantSlug })
    if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`)

    const now = new Date()
    const resolvedType = type ?? 'adhoc'
    const resolvedPeriod = period ?? buildPeriodLabel(now, resolvedType)

    // Insert a placeholder row with 'generating' status
    const reportId: Id<'executiveReports'> = await ctx.runMutation(
      internal.reports.insertPlaceholder,
      {
        tenantId: tenant._id,
        period: resolvedPeriod,
        type: resolvedType,
      },
    )

    try {
      // Gather data from existing intelligence tables
      const reportData = await ctx.runQuery(
        api.executiveReportIntel.getExecutiveReport,
        { tenantSlug },
      )

      const securityTimeline = await ctx.runQuery(
        internal.reports.getSecurityTimeline,
        { tenantId: tenant._id },
      )

      const scoreTrend = buildScoreTrend(reportData, securityTimeline)
      const topRisks = buildTopRisks(reportData)
      const remediationMetrics = buildRemediationMetrics(reportData)
      const complianceStatus = buildComplianceStatus(reportData)
      const talkingPoints = buildTalkingPoints(reportData)

      await ctx.runMutation(internal.reports.finalizeReport, {
        reportId,
        scoreTrend: JSON.stringify(scoreTrend),
        topRisks: JSON.stringify(topRisks),
        remediationMetrics: JSON.stringify(remediationMetrics),
        complianceStatus: JSON.stringify(complianceStatus),
        talkingPoints: JSON.stringify(talkingPoints),
      })
    } catch (err) {
      await ctx.runMutation(internal.reports.markReportFailed, {
        reportId,
        errorMessage: err instanceof Error ? err.message : 'Unknown error',
      })
      throw err
    }

    return reportId
  },
})

// ---------------------------------------------------------------------------
// Period label builder
// ---------------------------------------------------------------------------

function buildPeriodLabel(
  date: Date,
  type: 'monthly' | 'quarterly' | 'adhoc',
): string {
  const year = date.getFullYear()
  if (type === 'quarterly') {
    const q = Math.ceil((date.getMonth() + 1) / 3)
    return `${year}-Q${q}`
  }
  if (type === 'monthly') {
    const month = String(date.getMonth() + 1).padStart(2, '0')
    return `${year}-${month}`
  }
  return `${year}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

// ---------------------------------------------------------------------------
// Data assembly helpers
// ---------------------------------------------------------------------------

type ExecutiveReportData = TenantExecutiveReport | null

function buildScoreTrend(
  data: ExecutiveReportData,
  _timeline: Array<{ label: string; score: number }>,
) {
  if (!data) return []
  const avg = data.domainAverages
  return [
    { label: 'Health', score: Math.round(avg.healthAvg ?? 0) },
    { label: 'Drift Posture', score: Math.round(avg.driftPostureAvg ?? 0) },
    { label: 'Supply Chain', score: Math.round(avg.supplyChainAvg ?? 0) },
    { label: 'Compliance', score: Math.round(avg.complianceAvg ?? 0) },
  ]
}

function buildTopRisks(data: ExecutiveReportData) {
  if (!data) return []
  return data.worstRepos.slice(0, 5).map((repo) => ({
    repositoryName: repo.repositoryFullName,
    score: repo.compositeScore,
    grade: repo.grade,
    businessImpact: `Security health grade ${repo.grade} — immediate attention recommended`,
    recommendation: 'Review open critical findings and prioritise remediation',
  }))
}

function buildRemediationMetrics(data: ExecutiveReportData) {
  if (!data) return { openCritical: 0, mttr: 'N/A', gateBlockRate: '0%' }
  const critical = data.worstRepos.filter((r) => r.riskLevel === 'critical').length
  return {
    openCritical: critical,
    mttr: 'N/A',
    gateBlockRate: '0%',
    velocityTrend: critical === 0 ? 'excellent' : critical < 3 ? 'good' : 'needs_attention',
  }
}

function buildComplianceStatus(data: ExecutiveReportData) {
  if (!data) return []
  return data.frameworkCompliance.map((f) => ({
    framework: f.framework,
    status: f.complianceRate >= 80 ? 'compliant' : f.complianceRate >= 50 ? 'at_risk' : 'non_compliant',
    score: f.complianceRate,
  }))
}

function buildTalkingPoints(data: ExecutiveReportData) {
  if (!data) return []

  const points: Array<{ section: string; point: string }> = []
  const critical = data.worstRepos.filter((r) => r.riskLevel === 'critical').length

  if (critical > 0) {
    points.push({
      section: 'Risk',
      point: `We have ${critical} critical security finding${critical > 1 ? 's' : ''} requiring immediate attention.`,
    })
  } else {
    points.push({
      section: 'Risk',
      point: 'No critical security findings are currently open — our defences are holding.',
    })
  }

  points.push({
    section: 'Operations',
    point: 'Mean time to remediation is being tracked — check the findings dashboard for the latest metrics.',
  })

  if (data.riskLevel === 'critical' || data.riskLevel === 'high') {
    points.push({
      section: 'Controls',
      point: `Current risk level is ${data.riskLevel} — CI/CD gate enforcement is active and blocking vulnerable deployments.`,
    })
  }

  const avgScore = Math.round(
    ((data.domainAverages.healthAvg ?? 0) +
      (data.domainAverages.driftPostureAvg ?? 0) +
      (data.domainAverages.supplyChainAvg ?? 0) +
      (data.domainAverages.complianceAvg ?? 0)) /
      4,
  )
  points.push({
    section: 'Posture',
    point: `Overall security posture score is ${avgScore}/100 across health, drift, supply chain, and compliance.`,
  })

  return points
}

// ---------------------------------------------------------------------------
// Internal mutations / queries
// ---------------------------------------------------------------------------

export const lookupTenantBySlug = internalQuery({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    return await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
  },
})

export const getSecurityTimeline = internalQuery({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    // Get the last 6 repository health scores per tenant as a proxy for trend
    const scores = await ctx.db
      .query('repositoryHealthScoreResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(6)

    return scores.map((s, i) => ({
      label: `Week -${i}`,
      score: s.overallScore,
    }))
  },
})

export const insertPlaceholder = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    period: v.string(),
    type: v.union(v.literal('monthly'), v.literal('quarterly'), v.literal('adhoc')),
  },
  returns: v.id('executiveReports'),
  handler: async (ctx, { tenantId, period, type }) => {
    return await ctx.db.insert('executiveReports', {
      tenantId,
      period,
      type,
      status: 'generating',
      generatedAt: Date.now(),
    })
  },
})

export const finalizeReport = internalMutation({
  args: {
    reportId: v.id('executiveReports'),
    scoreTrend: v.string(),
    topRisks: v.string(),
    remediationMetrics: v.string(),
    complianceStatus: v.string(),
    talkingPoints: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { reportId, ...rest }) => {
    await ctx.db.patch(reportId, { ...rest, status: 'ready' })
    return null
  },
})

export const markReportFailed = internalMutation({
  args: {
    reportId: v.id('executiveReports'),
    errorMessage: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { reportId, errorMessage }) => {
    await ctx.db.patch(reportId, { status: 'failed', errorMessage })
    return null
  },
})

// ---------------------------------------------------------------------------
// listReports — public query: list generated reports for a tenant
// ---------------------------------------------------------------------------

export const listReports = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await requireAdminMembership(ctx, authToken, tenantSlug)

    return await ctx.db
      .query('executiveReports')
      .withIndex('by_tenant_and_generated_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(20)
  },
})

// ---------------------------------------------------------------------------
// getReport — public query: get a single report by ID
// ---------------------------------------------------------------------------

export const getReport = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    reportId: v.id('executiveReports'),
  },
  handler: async (ctx, { authToken, tenantSlug, reportId }) => {
    const { tenant } = await requireAdminMembership(ctx, authToken, tenantSlug)

    const report = await ctx.db.get(reportId)
    if (!report || report.tenantId !== tenant._id) return null

    return report
  },
})

// ---------------------------------------------------------------------------
// scheduleReportDelivery — mutation: configure auto-delivery
// ---------------------------------------------------------------------------

export const scheduleReportDelivery = mutation({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
    frequency: v.union(v.literal('monthly'), v.literal('quarterly')),
    recipients: v.array(v.string()),
    isActive: v.boolean(),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, frequency, recipients, isActive }) => {
    const { tenant, membership } = await requireAdminMembership(
      ctx,
      authToken,
      tenantSlug,
    )
    if (membership.role !== 'owner' && membership.role !== 'admin') {
      throw new ConvexError('Only owners and admins can configure report delivery')
    }

    const existing = await ctx.db
      .query('reportDeliveryConfigs')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .first()

    if (existing) {
      await ctx.db.patch(existing._id, { frequency, recipients, isActive, updatedAt: Date.now() })
    } else {
      await ctx.db.insert('reportDeliveryConfigs', {
        tenantId: tenant._id,
        frequency,
        recipients,
        isActive,
        updatedAt: Date.now(),
      })
    }
    return null
  },
})

// ---------------------------------------------------------------------------
// getDeliveryConfig — public query
// ---------------------------------------------------------------------------

export const getDeliveryConfig = query({
  args: {
    authToken: v.string(),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { tenant } = await requireAdminMembership(ctx, authToken, tenantSlug)

    return await ctx.db
      .query('reportDeliveryConfigs')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .first()
  },
})
