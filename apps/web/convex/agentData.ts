// ═══════════════════════════════════════════════════════════════════════════
// AGENT DATA HELPERS — Shared internal queries & mutations for all agents
// ═══════════════════════════════════════════════════════════════════════════
//
// Agents (Convex actions) cannot use ctx.db directly. They must call queries
// and mutations via ctx.runQuery / ctx.runMutation. This file provides the
// shared data access layer that every agent uses.
//

import { v } from 'convex/values'
import { internalQuery, internalMutation } from './_generated/server'
import type { Id } from './_generated/dataModel'

// ─── Task Lifecycle ──────────────────────────────────────────────────────────

export const createAgentTask = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    agentType: v.string(),
    trigger: v.string(),
    priority: v.string(),
    inputSummary: v.string(),
    workflowRunId: v.optional(v.id('workflowRuns')),
    findingId: v.optional(v.id('findings')),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('agentTasks', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      workflowRunId: args.workflowRunId,
      findingId: args.findingId,
      agentType: args.agentType,
      trigger: args.trigger,
      status: 'queued',
      priority: args.priority as 'critical' | 'high' | 'medium' | 'low',
      inputSummary: args.inputSummary,
      retryCount: 0,
      maxRetries: 3,
    })
  },
})

export const startAgentTask = internalMutation({
  args: { taskId: v.id('agentTasks') },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.taskId, {
      status: 'running',
      startedAt: Date.now(),
    })
  },
})

export const completeAgentTask = internalMutation({
  args: {
    taskId: v.id('agentTasks'),
    outputSummary: v.string(),
    llmProvider: v.optional(v.string()),
    llmModel: v.optional(v.string()),
    tokenUsage: v.optional(
      v.object({
        prompt: v.number(),
        completion: v.number(),
        total: v.number(),
        costUsd: v.number(),
      }),
    ),
    reasoningLogId: v.optional(v.id('agentReasoningLogs')),
    error: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.taskId, {
      status: args.error ? 'failed' : 'completed',
      outputSummary: args.outputSummary,
      llmProvider: args.llmProvider,
      llmModel: args.llmModel,
      tokenUsage: args.tokenUsage,
      reasoningLogId: args.reasoningLogId,
      completedAt: Date.now(),
      error: args.error,
    })
  },
})

// ─── Reasoning Logs ──────────────────────────────────────────────────────────

export const writeReasoningLog = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    agentTaskId: v.id('agentTasks'),
    agentType: v.string(),
    messages: v.array(
      v.object({
        role: v.string(),
        content: v.string(),
        timestamp: v.number(),
      }),
    ),
    toolCalls: v.array(
      v.object({
        name: v.string(),
        arguments: v.string(),
        result: v.string(),
        timestamp: v.number(),
      }),
    ),
    output: v.any(),
    llmProvider: v.string(),
    llmModel: v.string(),
    totalTokens: v.number(),
    totalCostUsd: v.number(),
    latencyMs: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('agentReasoningLogs', {
      tenantId: args.tenantId,
      agentTaskId: args.agentTaskId,
      agentType: args.agentType,
      messages: args.messages as never,
      toolCalls: args.toolCalls as never,
      output: args.output,
      llmProvider: args.llmProvider,
      llmModel: args.llmModel,
      totalTokens: args.totalTokens,
      totalCostUsd: args.totalCostUsd,
      latencyMs: args.latencyMs,
      createdAt: Date.now(),
    })
  },
})

// ─── LLM Usage Tracking ──────────────────────────────────────────────────────

export const recordLLMUsage = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    agentType: v.string(),
    provider: v.string(),
    model: v.string(),
    promptTokens: v.number(),
    completionTokens: v.number(),
    estimatedCostUsd: v.number(),
    taskId: v.string(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('llmUsageRecords', {
      tenantId: args.tenantId,
      agentType: args.agentType,
      provider: args.provider,
      model: args.model,
      promptTokens: args.promptTokens,
      completionTokens: args.completionTokens,
      estimatedCostUsd: args.estimatedCostUsd,
      taskId: args.taskId,
      timestamp: Date.now(),
    })
  },
})

// ─── Finding Data ────────────────────────────────────────────────────────────

export const getFinding = internalQuery({
  args: { findingId: v.id('findings') },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.findingId)
  },
})

export const getRepository = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.repositoryId)
  },
})

export const getSBOMForRepository = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', args.repositoryId),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .take(200)

    return { snapshot, components }
  },
})

export const getTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.tenantId)
  },
})

// ─── Memory Data ─────────────────────────────────────────────────────────────

export const getProjectMemory = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('projectMemories')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .unique()
  },
})

export const getActivePatterns = internalQuery({
  args: {
    repositoryId: v.id('repositories'),
    patternType: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    let q = ctx.db
      .query('memoryPatterns')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))

    const patterns = await q.collect()
    return patterns
      .filter((p) => p.isActive)
      .filter((p) => !args.patternType || p.patternType === args.patternType)
      .slice(0, 20) // cap context size
  },
})

// ─── Write Results ───────────────────────────────────────────────────────────

export const createRemediationProposal = internalMutation({
  args: {
    findingId: v.id('findings'),
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    agentTaskId: v.id('agentTasks'),
    vulnerabilityExplanation: v.string(),
    exploitPath: v.string(),
    businessImpact: v.string(),
    fixDescription: v.string(),
    fixDiff: v.string(),
    fixRationale: v.string(),
    postFixTest: v.string(),
    requiresArchitecturalChange: v.boolean(),
    confidence: v.number(),
  },
  handler: async (ctx, args) => {
    const now = Date.now()
    return await ctx.db.insert('remediationProposals', {
      findingId: args.findingId,
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      agentTaskId: args.agentTaskId,
      status: 'proposed',
      vulnerabilityExplanation: args.vulnerabilityExplanation,
      exploitPath: args.exploitPath,
      businessImpact: args.businessImpact,
      fixDescription: args.fixDescription,
      fixDiff: args.fixDiff,
      fixRationale: args.fixRationale,
      postFixTest: args.postFixTest,
      requiresArchitecturalChange: args.requiresArchitecturalChange,
      confidence: args.confidence,
      createdAt: now,
      updatedAt: now,
    })
  },
})

export const createExploitValidationResult = internalMutation({
  args: {
    findingId: v.id('findings'),
    tenantId: v.id('tenants'),
    agentTaskId: v.id('agentTasks'),
    outcome: v.string(),
    pocCode: v.string(),
    pocExpectedOutput: v.string(),
    pocType: v.string(),
    executionLog: v.string(),
    confidence: v.number(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('exploitValidationResults', {
      findingId: args.findingId,
      tenantId: args.tenantId,
      agentTaskId: args.agentTaskId,
      outcome: args.outcome as 'exploited' | 'partial' | 'not_exploitable',
      pocCode: args.pocCode,
      pocExpectedOutput: args.pocExpectedOutput,
      pocType: args.pocType as 'curl' | 'python' | 'javascript',
      executionLog: args.executionLog,
      confidence: args.confidence,
      createdAt: Date.now(),
    })
  },
})

export const createRedTeamAttack = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    roundNumber: v.number(),
    strategy: v.string(),
    attackVector: v.string(),
    targetEndpoint: v.optional(v.string()),
    payload: v.string(),
    outcome: v.string(),
    evidence: v.optional(v.string()),
    agentTaskId: v.id('agentTasks'),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('redTeamAttacks', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      roundNumber: args.roundNumber,
      strategy: args.strategy,
      attackVector: args.attackVector,
      targetEndpoint: args.targetEndpoint,
      payload: args.payload,
      outcome: args.outcome as 'success' | 'partial' | 'failure',
      evidence: args.evidence,
      agentTaskId: args.agentTaskId,
      createdAt: Date.now(),
    })
  },
})

export const createBlueTeamRule = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    ruleType: v.string(),
    ruleName: v.string(),
    ruleContent: v.string(),
    basedOnAttackId: v.optional(v.id('redTeamAttacks')),
    effectiveness: v.optional(v.number()),
    falsePositiveRisk: v.number(),
    agentTaskId: v.id('agentTasks'),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('blueTeamDetectionRules', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      ruleType: args.ruleType as 'waf' | 'siem' | 'log_query' | 'rate_limit',
      ruleName: args.ruleName,
      ruleContent: args.ruleContent,
      basedOnAttackId: args.basedOnAttackId,
      effectiveness: args.effectiveness,
      falsePositiveRisk: args.falsePositiveRisk,
      agentTaskId: args.agentTaskId,
      createdAt: Date.now(),
    })
  },
})

export const createPromptInjectionFinding = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    agentTaskId: v.id('agentTasks'),
    llmCallChain: v.string(),
    inputSource: v.string(),
    vulnerabilityType: v.string(),
    payload: v.string(),
    outcome: v.string(),
    mitigationCode: v.string(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('promptInjectionFindings', {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      agentTaskId: args.agentTaskId,
      llmCallChain: args.llmCallChain,
      inputSource: args.inputSource,
      vulnerabilityType: args.vulnerabilityType,
      payload: args.payload,
      outcome: args.outcome as 'critical' | 'high' | 'medium' | 'low',
      mitigationCode: args.mitigationCode,
      createdAt: Date.now(),
    })
  },
})

// ─── Tenant Helpers ──────────────────────────────────────────────────────────

export const getAllActiveRepositories = internalQuery({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query('repositories').collect()
  },
})

export const getPendingAgentTasks = internalQuery({
  args: {
    agentType: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const tasks = await ctx.db
      .query('agentTasks')
      .withIndex('by_status', (q) => q.eq('status', 'queued'))
      .collect()

    return args.agentType
      ? tasks.filter((t) => t.agentType === args.agentType)
      : tasks
  },
})
