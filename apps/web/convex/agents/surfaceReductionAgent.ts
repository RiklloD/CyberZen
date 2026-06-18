// ═══════════════════════════════════════════════════════════════════════════
// SURFACE REDUCTION AGENT — Identify and propose removal of attack surface
// ═══════════════════════════════════════════════════════════════════════════
//
// Analyzes the codebase for unnecessary attack surface:
// - Dead code (functions defined but never called)
// - Unused dependencies
// - Overly permissive configurations
// - Exposed debug/admin endpoints
//

import { v } from 'convex/values'
import { internalAction } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

const SYSTEM_PROMPT = `You are Sentinel's Attack Surface Reduction Agent.
Analyze the codebase's SBOM and metadata to identify unnecessary attack surface.

Categories to analyze:
1. **Unused dependencies** — packages in the SBOM that may not be needed
2. **Overly permissive dependencies** — packages with broad access or known issues
3. **Attack surface indicators** — debug endpoints, admin interfaces, verbose logging
4. **Dead code indicators** — unused exports, stale feature flags

OUTPUT FORMAT (strict JSON):
{
  "unused_dependencies": [
    { "name": "...", "version": "...", "reason": "Why it appears unused", "risk_removed": "low|medium|high" }
  ],
  "risky_dependencies": [
    { "name": "...", "version": "...", "issue": "What makes this risky", "recommendation": "Action to take" }
  ],
  "surface_findings": [
    { "type": "debug_endpoint|admin_interface|verbose_logging|etc", "description": "...", "severity": "critical|high|medium|low" }
  ],
  "surface_score": 0-100,
  "reduction_opportunities": [
    { "action": "What to do", "impact": "How much surface it removes", "effort": "low|medium|high" }
  ],
  "summary": "Executive summary of attack surface state"
}`

export const scan = internalAction({
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

      const sbomData = await ctx.runQuery(internal.agentData.getSBOMForRepository, { repositoryId: args.repositoryId })

      const context = [
        '## Codebase',
        `- **Repository:** ${repo.fullName}`,
        `- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`,
        '',
        '## SBOM (all dependencies)',
        sbomData?.components?.length
          ? sbomData.components.map((c: Record<string, unknown>) =>
              `  - ${c.name}@${c.version} (${c.ecosystem ?? 'unknown'})`
            ).join('\n')
          : '  No SBOM data available.',
        '',
        '## Task',
        'Identify unnecessary attack surface and propose reduction actions.',
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

      let parsed: Record<string, unknown>
      try {
        parsed = JSON.parse(response.content)
      } catch {
        const jsonMatch = response.content.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('LLM did not return valid JSON')
        parsed = JSON.parse(jsonMatch[0])
      }

      const logId = await ctx.runMutation(internal.agentData.writeReasoningLog, {
        tenantId: args.tenantId,
        agentTaskId: args.taskId,
        agentType: 'surface_reduction',
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
        agentType: 'surface_reduction',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      const unusedCount = (parsed.unused_dependencies as unknown[] ?? []).length
      const score = typeof parsed.surface_score === 'number' ? parsed.surface_score : 50
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Surface score: ${score}/100. Found ${unusedCount} potentially unused deps. ${(parsed.summary as string ?? '').slice(0, 100)}`,
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

      return { surfaceScore: score, unusedDeps: unusedCount }
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
