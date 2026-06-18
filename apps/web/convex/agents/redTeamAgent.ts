// ═══════════════════════════════════════════════════════════════════════════
// RED TEAM AGENT — Adversarial attack generation and probing
// ═══════════════════════════════════════════════════════════════════════════
//
// The Red Agent selects attack strategies based on historical knowledge of the
// codebase, generates adversarial payloads, and records outcomes.
// Over multiple rounds, it learns which attack types work against this specific app.
//

import { v } from 'convex/values'
import { internalAction, internalQuery, internalMutation } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

// ─── Query: Get previous attacks for this repo (memory) ─────────────────────

export const getPreviousAttacks = internalQuery({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('redTeamAttacks')
      .withIndex('by_repository', (q) => q.eq('repositoryId', args.repositoryId))
      .order('desc')
      .take(20)
  },
})

const SYSTEM_PROMPT = `You are Sentinel's Red Team Agent — an expert adversary simulating real attacks.
Given information about a codebase and your previous attack history, plan and execute new attacks.

Strategy selection:
- Analyze what worked before and what didn't
- Try attack vectors that haven't been attempted yet
- Escalate from partial successes in previous rounds
- Consider the tech stack and known framework vulnerabilities

OUTPUT FORMAT (strict JSON):
{
  "strategy": "Name of the attack strategy",
  "attacks": [
    {
      "attack_vector": "Type of attack (SQL injection, XSS, SSRF, auth bypass, etc.)",
      "target_endpoint": "Which endpoint or component",
      "payload": "The actual attack payload/request",
      "expected_outcome": "success | partial | failure",
      "evidence": "Why this would succeed or fail against this codebase",
      "new_vulnerability": true/false
    }
  ],
  "confidence_map": "Brief summary of which areas of the app are most vulnerable",
  "round_summary": "Executive summary of this adversarial round"
}`

export const runRound = internalAction({
  args: {
    taskId: v.id('agentTasks'),
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    roundNumber: v.number(),
  },
  handler: async (ctx, args) => {
    await ctx.runMutation(internal.agentData.startAgentTask, { taskId: args.taskId })
    const messages: { role: string; content: string; timestamp: number }[] = []

    try {
      const repo = await ctx.runQuery(internal.agentData.getRepository, { repositoryId: args.repositoryId })
      if (!repo) throw new Error('Repository not found')

      const sbomData = await ctx.runQuery(internal.agentData.getSBOMForRepository, { repositoryId: args.repositoryId })
      const previousAttacks = await ctx.runQuery(internal.agents.redTeamAgent.getPreviousAttacks, {
        repositoryId: args.repositoryId,
      })

      // Build context
      const context = [
        '## Target Codebase',
        `- **Repository:** ${repo.fullName}`,
        `- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`,
        '',
        '## SBOM Context',
        sbomData?.components?.length
          ? sbomData.components.slice(0, 20).map((c: Record<string, unknown>) => `  - ${c.name}@${c.version}`).join('\n')
          : '  No SBOM data available.',
        '',
        `## Previous Attack History (${previousAttacks.length} attacks logged)`,
        previousAttacks.length > 0
          ? previousAttacks.map((a: Record<string, unknown>) =>
              `  - Round ${a.roundNumber}: ${a.attackVector} → ${a.outcome}${a.evidence ? ` (${a.evidence})` : ''}`
            ).join('\n')
          : '  No previous attacks — this is the first round.',
        '',
        `## Your Task (Round ${args.roundNumber})`,
        'Based on the codebase analysis and your attack history, generate the next set of attacks.',
        'Focus on vectors most likely to succeed against this tech stack.',
      ].join('\n')

      messages.push({ role: 'user', content: context, timestamp: Date.now() })

      const config = selectProvider('exploit_generation')
      const response = await callLLM({
        provider: config.provider,
        model: config.model,
        systemPrompt: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: context }],
        temperature: 0.2,
        maxTokens: 4096,
        responseFormat: 'json',
      })

      messages.push({ role: 'assistant', content: response.content, timestamp: Date.now() })

      let parsed: {
        strategy: string
        attacks: Array<{
          attack_vector: string
          target_endpoint?: string
          payload: string
          expected_outcome: string
          evidence?: string
          new_vulnerability: boolean
        }>
        confidence_map: string
        round_summary: string
      }
      try {
        parsed = JSON.parse(response.content)
      } catch {
        const jsonMatch = response.content.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('LLM did not return valid JSON')
        parsed = JSON.parse(jsonMatch[0])
      }

      // Store each attack
      let successCount = 0
      for (const attack of parsed.attacks ?? []) {
        await ctx.runMutation(internal.agentData.createRedTeamAttack, {
          tenantId: args.tenantId,
          repositoryId: args.repositoryId,
          roundNumber: args.roundNumber,
          strategy: parsed.strategy ?? 'unknown',
          attackVector: attack.attack_vector ?? 'unknown',
          targetEndpoint: attack.target_endpoint,
          payload: attack.payload ?? '',
          outcome: attack.expected_outcome ?? 'failure',
          evidence: attack.evidence,
          agentTaskId: args.taskId,
        })
        if (attack.expected_outcome === 'success') successCount++
      }

      const logId = await ctx.runMutation(internal.agentData.writeReasoningLog, {
        tenantId: args.tenantId,
        agentTaskId: args.taskId,
        agentType: 'red_team',
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
        agentType: 'red_team',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Round ${args.roundNumber}: ${parsed.attacks?.length ?? 0} attacks (${successCount} expected success). Strategy: ${parsed.strategy}`,
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

      return { attacksGenerated: parsed.attacks?.length ?? 0, strategy: parsed.strategy }
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
