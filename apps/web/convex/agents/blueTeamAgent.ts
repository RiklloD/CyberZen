// ═══════════════════════════════════════════════════════════════════════════
// BLUE TEAM AGENT — Generate detection rules from Red Team findings
// ═══════════════════════════════════════════════════════════════════════════
//
// After each Red Team round where attacks succeeded, the Blue Agent generates:
// 1. WAF rules (ModSecurity syntax)
// 2. SIEM alert queries (Splunk SPL, Elastic KQL)
// 3. Log analysis patterns
// 4. Rate limiting recommendations
//
// The rules are tested against the attack signatures and rated by effectiveness.
//

import { v } from 'convex/values'
import { internalAction, internalQuery } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

// ─── Query: Get successful attacks for Blue Agent to defend against ─────────

export const getSuccessfulAttacks = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    const allAttacks = await ctx.db
      .query('redTeamAttacks')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .collect()

    return allAttacks.filter((a) => a.outcome === 'success' || a.outcome === 'partial')
  },
})

const SYSTEM_PROMPT = `You are Sentinel's Blue Team Agent — a detection engineering expert.
Given successful attacks from the Red Team, generate detection rules that would catch these attacks in production.

Generate rules in multiple formats so they can be deployed across different security tools.

OUTPUT FORMAT (strict JSON):
{
  "rules": [
    {
      "rule_type": "waf" | "siem" | "log_query" | "rate_limit",
      "rule_name": "Descriptive name",
      "rule_content": "The actual rule in standard syntax (ModSecurity for WAF, Splunk SPL for SIEM, etc.)",
      "effectiveness": 0.0-1.0,
      "false_positive_risk": 0.0-1.0,
      "based_on_attack": "Which attack vector this defends against"
    }
  ],
  "coverage_summary": "What percentage of the Red Team's attack vectors are now covered",
  "gaps": ["Attack vectors that could not be covered with rules"]
}`

export const generateRules = internalAction({
  args: {
    taskId: v.id('agentTasks'),
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    await ctx.runMutation(internal.agentData.startAgentTask, { taskId: args.taskId })
    const messages: { role: string; content: string; timestamp: number }[] = []

    try {
      const repo = await ctx.runQuery(internal.agentData.getRepository, { repositoryId: args.repositoryId })
      if (!repo) throw new Error('Repository not found')

      const successfulAttacks = await ctx.runQuery(internal.agents.blueTeamAgent.getSuccessfulAttacks, {
        repositoryId: args.repositoryId,
      })

      if (successfulAttacks.length === 0) {
        await ctx.runMutation(internal.agentData.completeAgentTask, {
          taskId: args.taskId,
          outputSummary: 'No successful attacks to generate rules for.',
        })
        return { rulesGenerated: 0 }
      }

      // Build context
      const context = [
        '## Codebase',
        `- **Repository:** ${repo.fullName}`,
        `- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`,
        '',
        `## Successful Attacks to Defend Against (${successfulAttacks.length} attacks)`,
        successfulAttacks.map((a: Record<string, unknown>, i: number) =>
          `${i + 1}. **${a.attackVector}** ${a.targetEndpoint ? `on ${a.targetEndpoint}` : ''}: ${a.payload?.slice(0, 200) ?? 'N/A'}`
        ).join('\n'),
        '',
        '## Task',
        'Generate detection rules that would catch these attacks in production.',
      ].join('\n')

      messages.push({ role: 'user', content: context, timestamp: Date.now() })

      const config = selectProvider('deep_reasoning')
      const response = await callLLM({
        provider: config.provider,
        model: config.model,
        systemPrompt: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: context }],
        temperature: 0.1,
        maxTokens: 4096,
        responseFormat: 'json',
      })

      messages.push({ role: 'assistant', content: response.content, timestamp: Date.now() })

      let parsed: {
        rules: Array<{
          rule_type: string
          rule_name: string
          rule_content: string
          effectiveness: number
          false_positive_risk: number
          based_on_attack: string
        }>
        coverage_summary: string
        gaps: string[]
      }
      try {
        parsed = JSON.parse(response.content)
      } catch {
        const jsonMatch = response.content.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('LLM did not return valid JSON')
        parsed = JSON.parse(jsonMatch[0])
      }

      // Store rules
      for (const rule of parsed.rules ?? []) {
        await ctx.runMutation(internal.agentData.createBlueTeamRule, {
          tenantId: args.tenantId,
          repositoryId: args.repositoryId,
          ruleType: rule.rule_type ?? 'waf',
          ruleName: rule.rule_name ?? 'Unnamed rule',
          ruleContent: rule.rule_content ?? '',
          effectiveness: rule.effectiveness ?? 0.5,
          falsePositiveRisk: rule.false_positive_risk ?? 0.3,
          agentTaskId: args.taskId,
        })
      }

      const logId = await ctx.runMutation(internal.agentData.writeReasoningLog, {
        tenantId: args.tenantId,
        agentTaskId: args.taskId,
        agentType: 'blue_team',
        messages,
        toolCalls: [],
        output: parsed,
        llmProvider: response.provider,
        llmModel: response.model,
        totalTokens: response.usage.totalTokens,
        totalCostUsd: response.usage.estimatedCostUsd,
        latencyMs: response.latencyMs,
      })

      await ctx.runMutation(internal.agentData.recordLLMUsage, {
        tenantId: args.tenantId,
        agentType: 'blue_team',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Generated ${parsed.rules?.length ?? 0} detection rules. Coverage: ${parsed.coverage_summary?.slice(0, 100) ?? 'N/A'}`,
        llmProvider: response.provider,
        llmModel: response.model,
        tokenUsage: {
          prompt: response.usage.promptTokens,
          completion: response.usage.completionTokens,
          total: response.usage.totalTokens,
          costUsd: response.usage.estimatedCostUsd,
        },
        reasoningLogId: logId,
      })

      return { rulesGenerated: parsed.rules?.length ?? 0 }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Failed: ${error}`,
        error,
      })
      throw err
    }
  },
})
