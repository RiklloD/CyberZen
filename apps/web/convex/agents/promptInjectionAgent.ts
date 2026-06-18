// ═══════════════════════════════════════════════════════════════════════════
// PROMPT INJECTION AGENT — Detect and test LLM-related attack surfaces
// ═══════════════════════════════════════════════════════════════════════════
//
// Scans the codebase for LLM API calls, maps data flow, and generates
// adversarial payloads to test prompt injection resistance.
//

import { v } from 'convex/values'
import { internalAction } from '../_generated/server'
import { internal } from '../_generated/api'
import type { Id } from '../_generated/dataModel'
import { callLLM, selectProvider } from '../lib/llmClient'

const SYSTEM_PROMPT = `You are Sentinel's Prompt Injection Testing Agent.
Analyze the codebase's LLM integration points and generate adversarial test payloads.

1. Identify LLM call chains (OpenAI, Anthropic, LangChain, LlamaIndex, Vercel AI SDK imports)
2. Map data flow: user input → prompt construction → LLM → output handling
3. For each chain, generate payloads testing: role override, context exfiltration, tool hijacking, RAG poisoning
4. Classify severity and generate mitigation code

OUTPUT FORMAT (strict JSON):
{
  "llm_call_chains_found": [
    {
      "description": "What this chain does",
      "input_source": "Where user input enters",
      "output_handling": "What happens with the LLM output",
      "risk_level": "critical|high|medium|low"
    }
  ],
  "test_payloads": [
    {
      "chain_ref": 0,
      "vulnerability_type": "role_override | context_exfil | tool_hijack | rag_poisoning | multi_turn_erosion",
      "payload": "The adversarial payload",
      "expected_severity": "critical|high|medium|low",
      "mitigation_code": "Code to fix this vulnerability"
    }
  ],
  "summary": "Executive summary of LLM attack surface"
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

      // Check if this repo even has LLM dependencies
      const llmPackages = (sbomData?.components ?? []).filter((c: Record<string, unknown>) => {
        const name = (c.name as string ?? '').toLowerCase()
        return name.includes('openai') || name.includes('anthropic') ||
               name.includes('langchain') || name.includes('llamaindex') ||
               name.includes('ai-sdk') || name.includes('ai') && name.includes('vercel') ||
               name.includes('cohere') || name.includes('ollama') ||
               name.includes('huggingface') || name.includes('transformers')
      })

      const context = [
        '## Codebase Analysis',
        `- **Repository:** ${repo.fullName}`,
        `- **Language:** ${repo.primaryLanguage ?? repo.language ?? 'unknown'}`,
        '',
        '## LLM Dependencies Detected',
        llmPackages.length > 0
          ? llmPackages.map((c: Record<string, unknown>) => `  - ${c.name}@${c.version}`).join('\n')
          : '  No LLM-specific packages detected in SBOM. Analyze based on common patterns.',
        '',
        '## Task',
        'Analyze the LLM attack surface and generate prompt injection test payloads.',
        'If no LLM integration is present, report minimal risk and explain why.',
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
        llm_call_chains_found: Array<{
          description: string
          input_source: string
          output_handling: string
          risk_level: string
        }>
        test_payloads: Array<{
          chain_ref: number
          vulnerability_type: string
          payload: string
          expected_severity: string
          mitigation_code: string
        }>
        summary: string
      }
      try {
        parsed = JSON.parse(response.content)
      } catch {
        const jsonMatch = response.content.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('LLM did not return valid JSON')
        parsed = JSON.parse(jsonMatch[0])
      }

      // Store findings
      for (const payload of parsed.test_payloads ?? []) {
        const chain = parsed.llm_call_chains_found?.[payload.chain_ref] ?? parsed.llm_call_chains_found?.[0]
        await ctx.runMutation(internal.agentData.createPromptInjectionFinding, {
          tenantId: args.tenantId,
          repositoryId: args.repositoryId,
          agentTaskId: args.taskId,
          llmCallChain: chain?.description ?? 'Unknown chain',
          inputSource: chain?.input_source ?? 'Unknown input',
          vulnerabilityType: payload.vulnerability_type ?? 'unknown',
          payload: payload.payload ?? '',
          outcome: payload.expected_severity ?? 'low',
          mitigationCode: payload.mitigation_code ?? '',
        })
      }

      const logId = await ctx.runMutation(internal.agentData.writeReasoningLog, {
        tenantId: args.tenantId,
        agentTaskId: args.taskId,
        agentType: 'prompt_injection',
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
        agentType: 'prompt_injection',
        provider: response.provider,
        model: response.model,
        promptTokens: response.usage.promptTokens,
        completionTokens: response.usage.completionTokens,
        estimatedCostUsd: response.usage.estimatedCostUsd,
        taskId: args.taskId,
      })

      const chainCount = parsed.llm_call_chains_found?.length ?? 0
      await ctx.runMutation(internal.agentData.completeAgentTask, {
        taskId: args.taskId,
        outputSummary: `Found ${chainCount} LLM call chains, generated ${parsed.test_payloads?.length ?? 0} test payloads. ${(parsed.summary ?? '').slice(0, 100)}`,
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

      return { chainsFound: chainCount, payloadsGenerated: parsed.test_payloads?.length ?? 0 }
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
