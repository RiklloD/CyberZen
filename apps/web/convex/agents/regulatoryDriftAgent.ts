// ═══════════════════════════════════════════════════════════════════════════
// REGULATORY DRIFT AGENT — Map regulatory changes to code-level implications
// ═══════════════════════════════════════════════════════════════════════════
//
// Analyzes the codebase against known regulatory frameworks and identifies
// compliance gaps, mapping them to specific code changes needed.
//

import { v } from 'convex/values'
import { internalAction } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

const SYSTEM_PROMPT = `You are Sentinel's Regulatory Drift Agent — a compliance and legal-tech expert.
Analyze the codebase for compliance with major regulatory frameworks and identify gaps.

Frameworks to evaluate:
- GDPR (EU data protection)
- SOC 2 (security controls)
- PCI-DSS (payment card data)
- HIPAA (health data)
- NIS2 (EU network security)

OUTPUT FORMAT (strict JSON):
{
  "applicable_frameworks": ["GDPR", "SOC2", "etc"],
  "gaps": [
    {
      "framework": "GDPR",
      "requirement": "Article 32: Security of processing",
      "gap_description": "What's missing",
      "affected_area": "Which part of the codebase",
      "severity": "critical|high|medium|low",
      "fix_description": "What needs to change",
      "fix_files": ["suggested files to modify"]
    }
  ],
  "compliant_areas": [
    { "framework": "SOC2", "area": "Access control", "evidence": "Why this appears compliant" }
  ],
  "overall_compliance_score": 0-100,
  "summary": "Executive summary"
}`

export const analyze = internalAction({
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
      const tenant = await ctx.runQuery(internal.agentData.getTenant, { tenantId: args.tenantId })

      const context = [
        '## Codebase',
        `- **Repository:** ${repo.fullName}`,
        `- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`,
        `- **Tenant:** ${tenant?.name ?? 'unknown'} (mode: ${tenant?.deploymentMode ?? 'unknown'})`,
        '',
        '## Dependencies',
        sbomData?.components?.length
          ? sbomData.components.slice(0, 30).map((c: Record<string, unknown>) => `  - ${c.name}@${c.version}`).join('\n')
          : '  No SBOM data available.',
        '',
        '## Task',
        'Analyze this codebase for regulatory compliance gaps. Consider what data the dependencies suggest the application handles.',
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
        agentType: 'regulatory_drift',
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
        agentType: 'regulatory_drift',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      const gapCount = (parsed.gaps as unknown[] ?? []).length
      const score = typeof parsed.overall_compliance_score === 'number' ? parsed.overall_compliance_score : 70
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Compliance score: ${score}/100. Found ${gapCount} gaps. ${(parsed.summary as string ?? '').slice(0, 100)}`,
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

      return { complianceScore: score, gapsFound: gapCount }
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
