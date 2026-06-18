// ═══════════════════════════════════════════════════════════════════════════
// REMEDIATION AGENT — LLM-powered fix analysis and generation
// ═══════════════════════════════════════════════════════════════════════════
//
// Given a security finding, this agent:
// 1. Analyzes the vulnerable code context
// 2. Uses an LLM to reason about the vulnerability
// 3. Generates a fix with full reasoning chain
// 4. Stores the remediation proposal for PR generation
//

import { v } from 'convex/values'
import { internalAction } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'
import type { LLMMessage } from '../lib/llmClient'

const SYSTEM_PROMPT = `You are Sentinel, an autonomous security engineer.
Your task is to analyze a security finding and generate a minimal, focused fix.

RULES:
1. Generate ONLY the code change needed — no unrelated refactoring
2. The fix must not break existing tests
3. The fix must not introduce new vulnerabilities
4. Explain your reasoning so a junior developer can understand
5. If the fix requires architectural changes beyond a simple patch, say so
6. Include a suggested regression test

OUTPUT FORMAT (strict JSON):
{
  "vulnerability_explanation": "What the vulnerability is and why it matters",
  "exploit_path": "Step-by-step how an attacker would exploit this",
  "business_impact": "What's at stake if this is exploited",
  "fix_description": "What the fix does in plain language",
  "fix_diff": "The actual code change as a unified diff",
  "fix_rationale": "Why this fix is correct and complete",
  "post_fix_test": "A test case that would catch regression",
  "requires_architectural_change": false,
  "confidence": 0.95
}`

export const analyze = internalAction({
  args: {
    taskId: v.id('agentTasks'),
    findingId: v.id('findings'),
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    // Mark task as running
    await ctx.runMutation(internal.agentData.startAgentTask, { taskId: args.taskId })

    const messages: { role: string; content: string; timestamp: number }[] = []
    let error: string | undefined

    try {
      // 1. Load finding context
      const finding = await ctx.runQuery(internal.agentData.getFinding, {
        findingId: args.findingId,
      })
      if (!finding) throw new Error('Finding not found')

      const repository = await ctx.runQuery(internal.agentData.getRepository, {
        repositoryId: args.repositoryId,
      })
      if (!repository) throw new Error('Repository not found')

      const sbomData = await ctx.runQuery(internal.agentData.getSBOMForRepository, {
        repositoryId: args.repositoryId,
      })

      // 2. Load customer memory (patterns, fix history)
      const memory = await ctx.runQuery(internal.agentData.getProjectMemory, {
        repositoryId: args.repositoryId,
      })
      const fixPatterns = await ctx.runQuery(internal.agentData.getActivePatterns, {
        repositoryId: args.repositoryId,
        patternType: 'recurring_fix',
      })

      // 3. Build context for the LLM
      const contextBlock = buildFindingContext(finding, repository, sbomData, memory, fixPatterns)
      messages.push({
        role: 'user',
        content: contextBlock,
        timestamp: Date.now(),
      })

      // 4. Select provider and call LLM
      const config = selectProvider('code_generation')
      const response = await callLLM({
        provider: config.provider,
        model: config.model,
        systemPrompt: SYSTEM_PROMPT,
        messages: messages.map((m) => ({ role: m.role as 'user' | 'assistant' | 'system', content: m.content })),
        temperature: config.temperature,
        maxTokens: config.maxTokens,
        responseFormat: 'json',
      })

      messages.push({
        role: 'assistant',
        content: response.content,
        timestamp: Date.now(),
      })

      // 5. Parse LLM response
      let parsed: {
        vulnerability_explanation: string
        exploit_path: string
        business_impact: string
        fix_description: string
        fix_diff: string
        fix_rationale: string
        post_fix_test: string
        requires_architectural_change: boolean
        confidence: number
      }

      try {
        parsed = JSON.parse(response.content)
      } catch {
        // Try to extract JSON from the response
        const jsonMatch = response.content.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('LLM did not return valid JSON')
        parsed = JSON.parse(jsonMatch[0])
      }

      // 6. Store remediation proposal
      const proposalId = await ctx.runMutation(internal.agentData.createRemediationProposal, {
        findingId: args.findingId,
        tenantId: args.tenantId,
        repositoryId: args.repositoryId,
        agentTaskId: args.taskId,
        vulnerabilityExplanation: parsed.vulnerability_explanation ?? 'Unable to generate explanation.',
        exploitPath: parsed.exploit_path ?? 'Unable to determine exploit path.',
        businessImpact: parsed.business_impact ?? 'Impact analysis pending.',
        fixDescription: parsed.fix_description ?? 'No fix description available.',
        fixDiff: parsed.fix_diff ?? '',
        fixRationale: parsed.fix_rationale ?? 'No rationale provided.',
        postFixTest: parsed.post_fix_test ?? '',
        requiresArchitecturalChange: parsed.requires_architectural_change ?? false,
        confidence: parsed.confidence ?? 0.5,
      })

      // 7. Write reasoning log
      const logId = await ctx.runMutation(internal.agentData.writeReasoningLog, {
        tenantId: args.tenantId,
        agentTaskId: args.taskId,
        agentType: 'remediation',
        messages,
        toolCalls: [],
        output: parsed,
        llmProvider: response.provider,
        llmModel: response.model,
        totalTokens: response.usage.totalTokens,
        totalCostUsd: response.usage.estimatedCostUsd,
        latencyMs: response.latencyMs,
      })

      // 8. Record usage
      await ctx.runMutation(internal.agentData.recordLLMUsage, {
        tenantId: args.tenantId,
        agentType: 'remediation',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      // 9. Complete task
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Generated fix proposal (confidence: ${Math.round((parsed.confidence ?? 0.5) * 100)}%). ${parsed.requires_architectural_change ? 'Requires architectural changes.' : 'Minimal fix available.'}`,
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

      return { proposalId, confidence: parsed.confidence ?? 0.5 }
    } catch (err) {
      error = err instanceof Error ? err.message : String(err)
      messages.push({ role: 'assistant', content: `[ERROR] ${error}`, timestamp: Date.now() })

      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Failed: ${error}`,
        error,
      })

      throw err
    }
  },
})

// ─── Context Builder ─────────────────────────────────────────────────────────

function buildFindingContext(
  finding: Record<string, unknown>,
  repo: Record<string, unknown>,
  sbomData: { snapshot: Record<string, unknown>; components: Record<string, unknown>[] } | null,
  memory: Record<string, unknown> | null,
  fixPatterns: Record<string, unknown>[],
): string {
  const parts: string[] = []

  parts.push('## Security Finding')
  parts.push(`- **Title:** ${finding.title ?? 'Unknown'}`)
  parts.push(`- **Severity:** ${finding.severity ?? 'unknown'}`)
  parts.push(`- **Class:** ${finding.vulnClass ?? finding.class ?? 'unknown'}`)
  parts.push(`- **Source:** ${finding.source ?? finding.detectionSource ?? 'unknown'}`)
  parts.push(`- **Description:** ${finding.description ?? finding.detail ?? 'No description provided.'}`)
  if (finding.affectedFiles) parts.push(`- **Affected Files:** ${JSON.stringify(finding.affectedFiles)}`)
  if (finding.affectedPackages) parts.push(`- **Affected Packages:** ${JSON.stringify(finding.affectedPackages)}`)

  parts.push('\n## Repository Context')
  parts.push(`- **Name:** ${repo.fullName ?? 'unknown'}`)
  parts.push(`- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`)
  parts.push(`- **Default Branch:** ${repo.defaultBranch ?? 'main'}`)

  if (sbomData?.components?.length) {
    parts.push('\n## SBOM Context (top components)')
    const topComps = sbomData.components.slice(0, 15)
    for (const c of topComps) {
      parts.push(`  - ${c.name ?? 'unknown'}@${c.version ?? 'unknown'} (${c.ecosystem ?? 'unknown'})`)
    }
  }

  if (fixPatterns.length > 0) {
    parts.push('\n## Historical Fix Patterns (from memory)')
    for (const p of fixPatterns.slice(0, 5)) {
      parts.push(`  - **${p.name ?? 'Pattern'}:** ${p.description ?? ''} (confidence: ${p.confidence ?? 'N/A'})`)
    }
  }

  if (memory?.memoryStats) {
    const stats = memory.memoryStats as Record<string, number>
    parts.push('\n## Memory Stats')
    parts.push(`  - Total episodes: ${stats.totalEpisodes ?? 0}`)
    parts.push(`  - Total patterns: ${stats.totalPatterns ?? 0}`)
    parts.push(`  - Prediction accuracy: ${((stats.predictionAccuracy ?? 0) * 100).toFixed(0)}%`)
  }

  parts.push('\n## Task')
  parts.push('Analyze this vulnerability and generate a fix. Respond as strict JSON per the system instructions.')

  return parts.join('\n')
}
