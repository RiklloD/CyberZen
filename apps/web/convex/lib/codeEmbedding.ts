/**
 * Code Embedding Utilities
 *
 * Wraps OpenAI text-embedding-3-small for semantic code analysis.
 * Also provides cosine similarity search across a pattern library.
 *
 * Uses "use node" in callers — this lib is pure math, safe in any runtime.
 * The fetch call to OpenAI must happen in an action (node runtime).
 */

// ── Vector math ───────────────────────────────────────────────────────────────

/**
 * Cosine similarity between two unit vectors.
 * Returns -1 to 1; higher = more similar.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0
  let dot = 0
  let magA = 0
  let magB = 0
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i]
    magA += a[i] * a[i]
    magB += b[i] * b[i]
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB)
  return denom === 0 ? 0 : dot / denom
}

/**
 * Normalize a vector to unit length (L2 norm = 1).
 * Pre-normalizing makes cosine similarity equivalent to dot product.
 */
export function normalize(v: number[]): number[] {
  const mag = Math.sqrt(v.reduce((sum, x) => sum + x * x, 0))
  if (mag === 0) return v
  return v.map((x) => x / mag)
}

// ── OpenAI embedding call ─────────────────────────────────────────────────────

const EMBEDDING_MODEL = 'text-embedding-3-small'
const EMBEDDING_DIMS = 1536

export type EmbeddingResult = {
  vector: number[]
  tokenCount: number
  model: string
}

/**
 * Embed a text string using OpenAI text-embedding-3-small.
 * Must be called from a Convex action (node runtime).
 * Returns a L2-normalized vector.
 */
export async function embedText(text: string, apiKey: string): Promise<EmbeddingResult> {
  // Truncate to avoid token limit (8191 tokens for text-embedding-3-small)
  const truncated = text.slice(0, 24_000) // ~6k tokens

  const resp = await fetch('https://api.openai.com/v1/embeddings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      input: truncated,
      model: EMBEDDING_MODEL,
      dimensions: EMBEDDING_DIMS,
    }),
  })

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    throw new Error(`OpenAI embeddings API error ${resp.status}: ${body.slice(0, 200)}`)
  }

  const data = await resp.json() as {
    data: Array<{ embedding: number[] }>
    usage: { total_tokens: number }
    model: string
  }

  const raw = data.data[0]?.embedding
  if (!raw || raw.length === 0) throw new Error('Empty embedding returned from OpenAI')

  return {
    vector: normalize(raw),
    tokenCount: data.usage?.total_tokens ?? 0,
    model: data.model ?? EMBEDDING_MODEL,
  }
}

/**
 * Batch-embed multiple texts in a single API call (up to 100 inputs per request).
 * Returns normalized vectors in the same order as the input.
 */
export async function embedBatch(
  texts: string[],
  apiKey: string,
): Promise<EmbeddingResult[]> {
  if (texts.length === 0) return []

  const truncated = texts.map((t) => t.slice(0, 24_000))

  const resp = await fetch('https://api.openai.com/v1/embeddings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      input: truncated,
      model: EMBEDDING_MODEL,
      dimensions: EMBEDDING_DIMS,
    }),
  })

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    throw new Error(`OpenAI embeddings API error ${resp.status}: ${body.slice(0, 200)}`)
  }

  const data = await resp.json() as {
    data: Array<{ embedding: number[]; index: number }>
    usage: { total_tokens: number }
    model: string
  }

  // OpenAI may return results out of order — sort by index
  const sorted = [...data.data].sort((a, b) => a.index - b.index)

  return sorted.map((item) => ({
    vector: normalize(item.embedding),
    tokenCount: Math.round((data.usage?.total_tokens ?? 0) / texts.length),
    model: data.model ?? EMBEDDING_MODEL,
  }))
}

// ── Pattern search ────────────────────────────────────────────────────────────

export type PatternMatch = {
  patternId: string
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  description: string
  similarity: number
  confidence: number
}

export type StoredPattern = {
  patternId: string
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  description: string
  vector: number[]
}

/**
 * Find the top-k most similar vulnerability patterns for a code embedding.
 * Runs in O(n·d) where n=pattern count, d=dimensions.
 * With 500 patterns × 1536 dims this takes ~3ms in V8.
 */
export function searchPatterns(
  queryVector: number[],
  patterns: StoredPattern[],
  opts: {
    topK?: number
    minSimilarity?: number
  } = {},
): PatternMatch[] {
  const topK = opts.topK ?? 5
  const minSim = opts.minSimilarity ?? 0.70

  const scored = patterns
    .map((p) => ({
      ...p,
      similarity: cosineSimilarity(queryVector, p.vector),
    }))
    .filter((p) => p.similarity >= minSim)
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, topK)

  return scored.map((p) => ({
    patternId: p.patternId,
    vulnClass: p.vulnClass,
    severity: p.severity,
    description: p.description,
    similarity: Math.round(p.similarity * 1000) / 1000,
    // Confidence = similarity rescaled to 0.5–1.0 range
    confidence: Math.round(((p.similarity - 0.70) / 0.30) * 0.5 * 100 + 50) / 100,
  }))
}

// ── Code context extraction ───────────────────────────────────────────────────

/**
 * Extract a text representation of a code change for embedding.
 * Takes changed file paths + optional code snippets and produces a
 * normalized description suitable for embedding.
 */
export function buildCodeContext(args: {
  changedFiles: string[]
  repositoryName: string
  packageDependencies: string[]
  commitMessage?: string
}): string {
  const lines: string[] = []

  lines.push(`Repository: ${args.repositoryName}`)

  if (args.commitMessage) {
    lines.push(`Commit: ${args.commitMessage.slice(0, 200)}`)
  }

  if (args.changedFiles.length > 0) {
    lines.push('Changed files:')
    for (const f of args.changedFiles.slice(0, 50)) {
      lines.push(`  ${f}`)
    }
  }

  if (args.packageDependencies.length > 0) {
    lines.push('Dependencies:')
    lines.push(args.packageDependencies.slice(0, 30).join(', '))
  }

  return lines.join('\n')
}
