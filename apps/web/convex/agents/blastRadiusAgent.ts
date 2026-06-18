// ═══════════════════════════════════════════════════════════════════════════
// BLAST RADIUS AGENT — LLM reasoning over architecture to trace attack paths
// ═══════════════════════════════════════════════════════════════════════════
//
// Given a finding, this agent reasons about:
// 1. What services and data are reachable from the vulnerable component
// 2. What's the full attack chain (network → privilege → data → lateral)
// 3. Business impact quantification (data exposure, regulatory, revenue)
//

import { v } from 'convex/values'
import { internalAction } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

const SYSTEM_PROMPT = `You are Sentinel's Blast Radius Reasoning Agent — a threat modeling expert.
Given a vulnerability finding and the system architecture, reason about the full attack path and business impact.

Think step by step:
1. If this vulnerability is exploited, what can the attacker access directly?
2. From that position, what services/data can they reach through the architecture?
3. Can they escalate privileges? If so, what does that unlock?
4. What sensitive data, critical services, or regulatory-scoped systems are in the blast radius?
5. Quantify the business impact (data exposure count, regulatory fines, revenue impact).

OUTPUT FORMAT (strict JSON):
{
  "attack_chain": [
    { "step": 1, "action": "...", "result": "..." },
    { "step": 2, "action": "...", "result": "..." }
  ],
  "reachable_services": ["service1", "service2"],
  "data_exposure": {
    "types": ["PII", "credentials", "financial"],
    "estimated_records": "N/A or approximate",
    "sensitivity": "high|medium|low"
  },
  "regulatory_implications": ["GDPR Article X", "PCI-DSS Requirement Y"],
  "business_impact_narrative": "Plain-English summary for executives",
  "blast_radius_score": 0-100,
  "confidence": 0.0-1.0
}`

export const analyze = internalAction({
  args: {
    taskId: v.id('agentTasks'),
    findingId: v.id('findings'),
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    await ctx.runMutation(internal.agentData.startAgentTask, { taskId: args.taskId })
    const messages: { role: string; content: string; timestamp: number }[] = []

    try {
      const finding = await ctx.runQuery(internal.agentData.getFinding, { findingId: args.findingId })
      if (!finding) throw new Error('Finding not found')

      const repo = await ctx.runQuery(internal.agentData.getRepository, { repositoryId: args.repositoryId })
      const sbomData = await ctx.runQuery(internal.agentData.getSBOMForRepository, { repositoryId: args.repositoryId })

      // Build context
      const context = [
        '## Vulnerability',
        `- **Title:** ${finding.title}`,
        `- **Severity:** ${finding.severity}`,
        `- **Class:** ${finding.vulnClass ?? finding.class ?? 'unknown'}`,
        `- **Description:** ${finding.description ?? finding.detail ?? 'N/A'}`,
        finding.affectedFiles ? `- **Affected Files:** ${JSON.stringify(finding.affectedFiles)}` : '',
        '',
        '## Architecture Context',
        `- **Repository:** ${repo?.fullName ?? 'unknown'}`,
        `- **Language:** ${repo?.primaryLanguage ?? repo?.language ?? 'unknown'}`,
      ].filter(Boolean).join('\n')

      if (sbomData?.components?.length) {
        const compNames = sbomData.components.slice(0, 30).map((c: Record<string, unknown>) => `${c.name}@${c.version}`)
        context.concat('\n## SBOM Components (dependency graph)\n' + compNames.join(', '))
      }

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
        agentType: 'blast_radius',
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
        agentType: 'blast_radius',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      const score = typeof parsed.blast_radius_score === 'number' ? parsed.blast_radius_score : 50
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Blast radius score: ${score}/100. ${(parsed.business_impact_narrative as string ?? '').slice(0, 100)}`,
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

      return { blastRadiusScore: score, analysis: parsed }
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
