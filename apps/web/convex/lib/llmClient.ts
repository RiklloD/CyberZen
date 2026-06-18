// ═══════════════════════════════════════════════════════════════════════════
// LLM CLIENT — Unified provider interface for OpenAI, Anthropic, Ollama, custom
// ═══════════════════════════════════════════════════════════════════════════
//
// This is a **pure library** with no Convex imports — it can be imported by any
// Convex action. All HTTP calls happen via the global `fetch` available in the
// Convex action runtime.
//
// Providers are selected at call time via the LLMRequest.provider field.
// API keys are read from environment variables.
//

// ─── Types ───────────────────────────────────────────────────────────────────

export type LLMProvider = 'openai' | 'anthropic' | 'ollama' | 'custom'

export type LLMMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  toolCallId?: string
}

export type LLMTool = {
  type: 'function'
  function: {
    name: string
    description: string
    parameters: Record<string, unknown> // JSON Schema
  }
}

export type LLMRequest = {
  provider: LLMProvider
  model: string
  messages: LLMMessage[]
  systemPrompt?: string
  temperature?: number // default 0.1 for security tasks
  maxTokens?: number // default 4096
  responseFormat?: 'text' | 'json'
  stopSequences?: string[]
}

export type LLMResponse = {
  content: string
  usage: {
    promptTokens: number
    completionTokens: number
    totalTokens: number
    estimatedCostUsd: number
  }
  model: string
  provider: LLMProvider
  latencyMs: number
  requestId: string
}

export type LLMConfig = {
  provider: LLMProvider
  model: string
  temperature: number
  maxTokens: number
}

// ─── Pricing (per 1K tokens, USD) ────────────────────────────────────────────

const PRICING: Record<string, { input: number; output: number }> = {
  'gpt-4o': { input: 0.0025, output: 0.01 },
  'gpt-4o-mini': { input: 0.00015, output: 0.0006 },
  'o3': { input: 0.015, output: 0.06 },
  'o3-mini': { input: 0.0011, output: 0.0044 },
  'claude-sonnet-4-6': { input: 0.003, output: 0.015 },
  'claude-sonnet-4-20250514': { input: 0.003, output: 0.015 },
  'claude-haiku-3.5': { input: 0.0008, output: 0.004 },
  'codellama': { input: 0, output: 0 }, // local
  'deepseek-coder': { input: 0, output: 0 }, // local
}

function estimateCost(model: string, promptTokens: number, completionTokens: number): number {
  const pricing = PRICING[model] ?? { input: 0.001, output: 0.002 }
  return (
    (promptTokens / 1000) * pricing.input +
    (completionTokens / 1000) * pricing.output
  )
}

// ─── API Key Resolution ──────────────────────────────────────────────────────

function getApiKey(provider: LLMProvider): string | null {
  switch (provider) {
    case 'openai':
      return process.env.OPENAI_API_KEY ?? null
    case 'anthropic':
      return process.env.ANTHROPIC_API_KEY ?? null
    case 'ollama':
      return 'ollama' // no key needed
    case 'custom':
      return process.env.CUSTOM_LLM_API_KEY ?? null
    default:
      return null
  }
}

function getBaseUrl(provider: LLMProvider): string {
  switch (provider) {
    case 'openai':
      return process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1'
    case 'anthropic':
      return 'https://api.anthropic.com/v1'
    case 'ollama':
      return process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434/v1'
    case 'custom':
      return process.env.CUSTOM_LLM_BASE_URL ?? 'http://localhost:8080/v1'
    default:
      return 'https://api.openai.com/v1'
  }
}

// ─── Provider Implementations ────────────────────────────────────────────────

/**
 * Call OpenAI-compatible API (also works for Ollama, vLLM, LM Studio, etc.)
 */
async function callOpenAICompatible(
  req: LLMRequest,
  baseUrl: string,
  apiKey: string,
): Promise<{ content: string; promptTokens: number; completionTokens: number }> {
  const body: Record<string, unknown> = {
    model: req.model,
    messages: req.systemPrompt
      ? [{ role: 'system', content: req.systemPrompt }, ...req.messages]
      : req.messages,
    temperature: req.temperature ?? 0.1,
    max_tokens: req.maxTokens ?? 4096,
  }

  if (req.responseFormat === 'json') {
    body.response_format = { type: 'json_object' }
  }

  if (req.stopSequences && req.stopSequences.length > 0) {
    body.stop = req.stopSequences
  }

  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const errorBody = await response.text().catch(() => 'No response body')
    throw new Error(
      `LLM API error (${response.status}) from ${req.provider}: ${errorBody.slice(0, 500)}`,
    )
  }

  const data = await response.json()
  const content = data.choices?.[0]?.message?.content ?? ''
  const promptTokens = data.usage?.prompt_tokens ?? 0
  const completionTokens = data.usage?.completion_tokens ?? 0

  return { content, promptTokens, completionTokens }
}

/**
 * Call Anthropic Messages API (different format from OpenAI)
 */
async function callAnthropic(
  req: LLMRequest,
  baseUrl: string,
  apiKey: string,
): Promise<{ content: string; promptTokens: number; completionTokens: number }> {
  // Anthropic separates system from messages
  const systemContent = req.systemPrompt ?? ''
  const messages = req.messages.map((m) => ({
    role: m.role === 'tool' ? 'user' : m.role,
    content: m.content,
  }))

  const body: Record<string, unknown> = {
    model: req.model,
    max_tokens: req.maxTokens ?? 4096,
    temperature: req.temperature ?? 0.1,
    messages,
  }

  if (systemContent) {
    body.system = systemContent
  }

  if (req.stopSequences && req.stopSequences.length > 0) {
    body.stop_sequences = req.stopSequences
  }

  const response = await fetch(`${baseUrl}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const errorBody = await response.text().catch(() => 'No response body')
    throw new Error(
      `Anthropic API error (${response.status}): ${errorBody.slice(0, 500)}`,
    )
  }

  const data = await response.json()
  const content = data.content?.map((c: { text?: string }) => c.text ?? '').join('') ?? ''
  const promptTokens = data.usage?.input_tokens ?? 0
  const completionTokens = data.usage?.output_tokens ?? 0

  return { content, promptTokens, completionTokens }
}

// ─── Retry Logic ─────────────────────────────────────────────────────────────

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504])

export async function callWithRetry<T>(
  fn: () => Promise<T>,
  opts: { maxRetries?: number; baseDelayMs?: number } = {},
): Promise<T> {
  const maxRetries = opts.maxRetries ?? 3
  const baseDelayMs = opts.baseDelayMs ?? 1000
  let lastError: Error | null = null

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (err) {
      lastError = err as Error
      const errorMsg = (err as Error).message

      // Don't retry on auth or bad-request errors
      if (
        errorMsg.includes('(401)') ||
        errorMsg.includes('(403)') ||
        errorMsg.includes('(400)')
      ) {
        throw err
      }

      // Check if retryable
      const isRetryable =
        RETRYABLE_STATUS.has(extractStatusCode(errorMsg)) ||
        errorMsg.includes('timeout') ||
        errorMsg.includes('fetch failed') ||
        errorMsg.includes('ECONNRESET')

      if (!isRetryable || attempt === maxRetries) {
        throw err
      }

      // Exponential backoff with jitter
      const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 500
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }

  throw lastError ?? new Error('Retry loop exhausted')
}

function extractStatusCode(msg: string): number {
  const match = msg.match(/\((\d{3})\)/)
  return match ? parseInt(match[1], 10) : 0
}

// ─── Main Entry Point ────────────────────────────────────────────────────────

/**
 * Call an LLM provider. This is the single entry point all agents use.
 * Handles: provider selection, auth, retry, cost estimation.
 */
export async function callLLM(req: LLMRequest): Promise<LLMResponse> {
  const apiKey = getApiKey(req.provider)
  if (!apiKey) {
    throw new Error(
      `No API key configured for provider "${req.provider}". ` +
        `Set the corresponding environment variable.`,
    )
  }

  const baseUrl = getBaseUrl(req.provider)
  const startTime = Date.now()
  const requestId = `${req.provider}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

  const { content, promptTokens, completionTokens } = await callWithRetry(async () => {
    if (req.provider === 'anthropic') {
      return callAnthropic(req, baseUrl, apiKey)
    }
    // OpenAI, Ollama, custom all use the same OpenAI-compatible format
    return callOpenAICompatible(req, baseUrl, apiKey)
  })

  const latencyMs = Date.now() - startTime
  const estimatedCostUsd = estimateCost(req.model, promptTokens, completionTokens)

  return {
    content,
    usage: {
      promptTokens,
      completionTokens,
      totalTokens: promptTokens + completionTokens,
      estimatedCostUsd,
    },
    model: req.model,
    provider: req.provider,
    latencyMs,
    requestId,
  }
}

// ─── Provider Selection Strategy ─────────────────────────────────────────────

export type AgentTaskType =
  | 'code_generation'
  | 'deep_reasoning'
  | 'classification'
  | 'bulk_processing'
  | 'exploit_generation'
  | 'summary'

export function selectProvider(taskType: AgentTaskType): LLMConfig {
  const hasAnthropic = !!process.env.ANTHROPIC_API_KEY
  const hasOpenAI = !!process.env.OPENAI_API_KEY
  const hasOllama = !!process.env.OLLAMA_BASE_URL

  // Tier 1: Deep reasoning — prefer Anthropic Claude for long-context analysis
  if (taskType === 'deep_reasoning' && hasAnthropic) {
    return { provider: 'anthropic', model: 'claude-sonnet-4-6', temperature: 0.1, maxTokens: 8192 }
  }

  // Tier 2: Code generation — OpenAI GPT-4o for best code output
  if (taskType === 'code_generation' && hasOpenAI) {
    return { provider: 'openai', model: 'gpt-4o', temperature: 0.0, maxTokens: 4096 }
  }

  // Tier 3: Exploit generation — needs strong reasoning + code
  if (taskType === 'exploit_generation' && hasAnthropic) {
    return { provider: 'anthropic', model: 'claude-sonnet-4-6', temperature: 0.0, maxTokens: 4096 }
  }

  // Tier 4: Classification / extraction — cheap model
  if (taskType === 'classification' || taskType === 'summary' || taskType === 'bulk_processing') {
    if (hasOpenAI) {
      return { provider: 'openai', model: 'gpt-4o-mini', temperature: 0.0, maxTokens: 2048 }
    }
  }

  // Fallback chain: OpenAI → Anthropic → Ollama → error
  if (hasOpenAI) {
    return { provider: 'openai', model: 'gpt-4o-mini', temperature: 0.1, maxTokens: 4096 }
  }
  if (hasAnthropic) {
    return { provider: 'anthropic', model: 'claude-haiku-3.5', temperature: 0.1, maxTokens: 4096 }
  }
  if (hasOllama) {
    return { provider: 'ollama', model: 'deepseek-coder', temperature: 0.1, maxTokens: 4096 }
  }

  throw new Error(
    'No LLM provider configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_BASE_URL.',
  )
}
