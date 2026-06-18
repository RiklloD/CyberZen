// ═══════════════════════════════════════════════════════════════════════════
// AGENT ORCHESTRATOR — Task routing, lifecycle management, scheduling
// ═══════════════════════════════════════════════════════════════════════════
//
// Public mutations for triggering agent tasks from the UI or workflow engine.
// Internal actions for executing agent tasks via the scheduler.
//

import { v } from 'convex/values'
import { mutation, query, internalAction, internalMutation } from './_generated/server'
import { internal, api } from './_generated/api'
import type { Id } from './_generated/dataModel'

// ─── Auth Helper ─────────────────────────────────────────────────────────────

async function resolveTenantAndRepo(
  ctx: Parameters<Parameters<typeof mutation>[0]['handler']>[0],
  tenantSlug: string,
  repositoryFullName?: string,
) {
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()
  if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

  let repository = null
  if (repositoryFullName) {
    repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.eq(q.field('tenantId'), tenant._id) &&
        q.eq(q.field('fullName'), repositoryFullName),
      )
      .first()
  }

  return { tenant, repository }
}

// ─── Public: Trigger a remediation agent for a finding ──────────────────────

export const triggerRemediation = mutation({
  args: {
    tenantSlug: v.string(),
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await resolveTenantAndRepo(ctx, args.tenantSlug)

    const finding = await ctx.db.get(args.findingId)
    if (!finding) throw new Error('Finding not found')

    const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      findingId: args.findingId,
      agentType: 'remediation',
      trigger: 'manual_request',
      priority: finding.severity === 'critical' || finding.severity === 'high' ? 'critical' : 'high',
      inputSummary: `Analyze finding: ${finding.title} (${finding.severity})`,
    })

    // Schedule the agent action
    await ctx.scheduler.runAfter(0, internal.agents.remediationAgent.analyze, {
      taskId,
      findingId: args.findingId,
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
    })

    return { taskId }
  },
})

// ─── Public: Trigger exploit validation ──────────────────────────────────────

export const triggerExploitValidation = mutation({
  args: {
    tenantSlug: v.string(),
    findingId: v.id('findings'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await resolveTenantAndRepo(ctx, args.tenantSlug)

    const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      findingId: args.findingId,
      agentType: 'exploit_validation',
      trigger: 'manual_request',
      priority: 'high',
      inputSummary: `Validate exploit for finding ${args.findingId}`,
    })

    await ctx.scheduler.runAfter(0, internal.agents.exploitValidationAgent.validate, {
      taskId,
      findingId: args.findingId,
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
    })

    return { taskId }
  },
})

// ─── Public: Trigger Red Team round ──────────────────────────────────────────

export const triggerRedTeamRound = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await resolveTenantAndRepo(ctx, args.tenantSlug)

    // Get current round number
    const lastAttack = await ctx.db
      .query('redTeamAttacks')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .order('desc')
      .first()
    const roundNumber = (lastAttack?.roundNumber ?? 0) + 1

    const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      agentType: 'red_team',
      trigger: 'manual_request',
      priority: 'medium',
      inputSummary: `Red Team round ${roundNumber} for repo ${args.repositoryId}`,
    })

    await ctx.scheduler.runAfter(0, internal.agents.redTeamAgent.runRound, {
      taskId,
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      roundNumber,
    })

    return { taskId, roundNumber }
  },
})

// ─── Public: Trigger Prompt Injection scan ───────────────────────────────────

export const triggerPromptInjectionScan = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await resolveTenantAndRepo(ctx, args.tenantSlug)

    const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      agentType: 'prompt_injection',
      trigger: 'manual_request',
      priority: 'medium',
      inputSummary: `Prompt injection scan for repo ${args.repositoryId}`,
    })

    await ctx.scheduler.runAfter(0, internal.agents.promptInjectionAgent.scan, {
      taskId,
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
    })

    return { taskId }
  },
})

// ─── Public: Trigger surface reduction scan ──────────────────────────────────

export const triggerSurfaceReductionScan = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenant } = await resolveTenantAndRepo(ctx, args.tenantSlug)

    const taskId = await ctx.runMutation(internal.agentData.createAgentTask, {
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
      agentType: 'surface_reduction',
      trigger: 'manual_request',
      priority: 'low',
      inputSummary: `Surface reduction scan for repo ${args.repositoryId}`,
    })

    await ctx.scheduler.runAfter(0, internal.agents.surfaceReductionAgent.scan, {
      taskId,
      tenantId: tenant._id,
      repositoryId: args.repositoryId,
    })

    return { taskId }
  },
})

// ─── Queries: Agent Activity ─────────────────────────────────────────────────

export const getAgentTasksForTenant = query({
  args: {
    tenantSlug: v.string(),
    status: v.optional(v.string()),
    agentType: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    let q = ctx.db
      .query('agentTasks')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id),
      )

    // We can't filter on status in the index query since we need all statuses
    // and filter client-side. Use by_tenant index for general listing.
    const allTasks = await ctx.db
      .query('agentTasks')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(args.limit ?? 50)

    return allTasks
      .filter((t) => !args.status || t.status === args.status)
      .filter((t) => !args.agentType || t.agentType === args.agentType)
  },
})

export const getAgentTask = query({
  args: { taskId: v.id('agentTasks') },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.taskId)
  },
})

export const getReasoningLog = query({
  args: { agentTaskId: v.id('agentTasks') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('agentReasoningLogs')
      .withIndex('by_agent_task', (q) => q.eq('agentTaskId', args.agentTaskId))
      .unique()
  },
})

export const getRemediationProposalsForFinding = query({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('remediationProposals')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .order('desc')
      .collect()
  },
})

export const getRemediationProposalsForTenant = query({
  args: { tenantSlug: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    return await ctx.db
      .query('remediationProposals')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(args.limit ?? 20)
  },
})

export const getExploitValidationResults = query({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('exploitValidationResults')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .order('desc')
      .collect()
  },
})

export const getRedTeamAttacksForTenant = query({
  args: { tenantSlug: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    return await ctx.db
      .query('redTeamAttacks')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(args.limit ?? 30)
  },
})

export const getBlueTeamRulesForTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    return await ctx.db
      .query('blueTeamDetectionRules')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(50)
  },
})

export const getPromptInjectionFindingsForTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return []

    return await ctx.db
      .query('promptInjectionFindings')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(50)
  },
})

export const getLLMUsageForTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return { totalCostUsd: 0, totalTokens: 0, records: [] }

    const records = await ctx.db
      .query('llmUsageRecords')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    const totalCostUsd = records.reduce((sum, r) => sum + r.estimatedCostUsd, 0)
    const totalTokens = records.reduce((sum, r) => sum + r.promptTokens + r.completionTokens, 0)

    return { totalCostUsd, totalTokens, records }
  },
})
