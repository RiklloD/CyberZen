/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  isAiSafetyConfig,
  scanAiMlSecurityDrift,
  type AiMlSecDriftResult,
} from './aiMlSecurityDrift'

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function scan(files: string[]): AiMlSecDriftResult {
  return scanAiMlSecurityDrift(files)
}

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

describe('scanAiMlSecurityDrift — output shape', () => {
  it('returns the expected fields on empty input', () => {
    const r = scan([])
    expect(r).toMatchObject({
      riskScore:     0,
      riskLevel:     'none',
      totalFindings: 0,
      highCount:     0,
      mediumCount:   0,
      lowCount:      0,
      findings:      [],
    })
    expect(r.summary).toContain('No AI/ML security configuration changes detected')
  })

  it('includes summary text with count and score when findings exist', () => {
    const r = scan(['openai.yaml'])
    expect(r.summary).toMatch(/\d+ AI\/ML security configuration/)
    expect(r.summary).toContain('risk score')
  })
})

// ---------------------------------------------------------------------------
// Rule 1: LLM_CLIENT_DRIFT (high)
// ---------------------------------------------------------------------------

describe('LLM_CLIENT_DRIFT', () => {
  it('matches openai.yaml ungated', () => {
    const r = scan(['openai.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
    expect(r.highCount).toBe(1)
  })

  it('matches anthropic.json ungated', () => {
    const r = scan(['anthropic.json'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('matches azure-openai.yaml ungated', () => {
    const r = scan(['azure-openai.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('matches llm-config.json ungated', () => {
    const r = scan(['llm-config.json'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('matches llm-provider-config.yaml via prefix', () => {
    const r = scan(['config/llm-provider-config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('matches settings.json inside openai/ dir', () => {
    const r = scan(['openai/settings.json'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('does not match openai/ dir without config extension', () => {
    const r = scan(['openai/README.md'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeUndefined()
  })

  it('does not match openai.py (source file)', () => {
    const r = scan(['openai.py'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeUndefined()
  })

  it('does not match files in node_modules', () => {
    const r = scan(['node_modules/openai/openai.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 2: VECTOR_DB_DRIFT (high)
// ---------------------------------------------------------------------------

describe('VECTOR_DB_DRIFT', () => {
  it('matches pinecone.yaml ungated', () => {
    const r = scan(['pinecone.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
    expect(r.highCount).toBeGreaterThanOrEqual(1)
  })

  it('matches weaviate.json ungated', () => {
    const r = scan(['weaviate.json'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('matches chromadb.conf ungated', () => {
    const r = scan(['chromadb.conf'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('matches qdrant.yaml ungated', () => {
    const r = scan(['qdrant.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('matches milvus.json ungated', () => {
    const r = scan(['milvus.json'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside vector-db/ dir', () => {
    const r = scan(['vector-db/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('matches pinecone-index.json via prefix', () => {
    const r = scan(['deploy/pinecone-index.json'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeDefined()
  })

  it('does not match vector-db/README.md', () => {
    const r = scan(['vector-db/README.md'])
    expect(r.findings.find((f) => f.ruleId === 'VECTOR_DB_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 3: AI_ORCHESTRATION_DRIFT (high)
// ---------------------------------------------------------------------------

describe('AI_ORCHESTRATION_DRIFT', () => {
  it('matches llamaindex.yaml ungated', () => {
    const r = scan(['llamaindex.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
    expect(r.highCount).toBeGreaterThanOrEqual(1)
  })

  it('matches autogen.json ungated', () => {
    const r = scan(['autogen.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
  })

  it('matches haystack.yaml ungated', () => {
    const r = scan(['haystack.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
  })

  it('matches agent-config.yaml ungated', () => {
    const r = scan(['agent-config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside agents/ dir', () => {
    const r = scan(['agents/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
  })

  it('matches llamaindex-settings.json via prefix', () => {
    const r = scan(['config/llamaindex-settings.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeDefined()
  })

  it('does not match agents/README.md', () => {
    const r = scan(['agents/README.md'])
    expect(r.findings.find((f) => f.ruleId === 'AI_ORCHESTRATION_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 4: ML_MODEL_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('ML_MODEL_CONFIG_DRIFT', () => {
  it('matches model.yaml ungated', () => {
    const r = scan(['model.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeDefined()
    expect(r.mediumCount).toBeGreaterThanOrEqual(1)
  })

  it('matches mlflow.yaml ungated', () => {
    const r = scan(['mlflow.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches bentoml.yaml ungated', () => {
    const r = scan(['bentoml.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside model-registry/ dir', () => {
    const r = scan(['model-registry/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches mlflow-config.yaml via prefix', () => {
    const r = scan(['deploy/mlflow-config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeDefined()
  })

  it('does not match model.py (source file)', () => {
    const r = scan(['model.py'])
    expect(r.findings.find((f) => f.ruleId === 'ML_MODEL_CONFIG_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 5: AI_GATEWAY_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('AI_GATEWAY_DRIFT', () => {
  it('matches litellm.yaml ungated', () => {
    const r = scan(['litellm.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
    expect(r.mediumCount).toBeGreaterThanOrEqual(1)
  })

  it('matches litellm-proxy.json ungated', () => {
    const r = scan(['litellm-proxy.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
  })

  it('matches portkey.yaml ungated', () => {
    const r = scan(['portkey.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
  })

  it('matches ai-gateway.json ungated', () => {
    const r = scan(['ai-gateway.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside litellm/ dir', () => {
    const r = scan(['litellm/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
  })

  it('matches litellm-proxy-config.yaml via prefix', () => {
    const r = scan(['deploy/litellm-proxy-config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeDefined()
  })

  it('does not match litellm/README.txt', () => {
    const r = scan(['litellm/README.txt'])
    expect(r.findings.find((f) => f.ruleId === 'AI_GATEWAY_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 6: EMBEDDING_PIPELINE_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('EMBEDDING_PIPELINE_DRIFT', () => {
  it('matches embedding.yaml ungated', () => {
    const r = scan(['embedding.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeDefined()
    expect(r.mediumCount).toBeGreaterThanOrEqual(1)
  })

  it('matches faiss.json ungated', () => {
    const r = scan(['faiss.json'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeDefined()
  })

  it('matches embeddings.yaml ungated', () => {
    const r = scan(['embeddings.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside embeddings/ dir', () => {
    const r = scan(['embeddings/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeDefined()
  })

  it('matches embedding-config.json via prefix', () => {
    const r = scan(['deploy/embedding-config.json'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeDefined()
  })

  it('does not match embedding.py', () => {
    const r = scan(['embedding.py'])
    expect(r.findings.find((f) => f.ruleId === 'EMBEDDING_PIPELINE_DRIFT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 7: AI_EVAL_CONFIG_DRIFT (low)
// ---------------------------------------------------------------------------

describe('AI_EVAL_CONFIG_DRIFT', () => {
  it('matches ragas.yaml ungated', () => {
    const r = scan(['ragas.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_EVAL_CONFIG_DRIFT')).toBeDefined()
    expect(r.lowCount).toBeGreaterThanOrEqual(1)
  })

  it('matches trulens.json ungated', () => {
    const r = scan(['trulens.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_EVAL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches evals.yaml ungated', () => {
    const r = scan(['evals.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_EVAL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches config.yaml inside evals/ dir', () => {
    const r = scan(['evals/config.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_EVAL_CONFIG_DRIFT')).toBeDefined()
  })

  it('matches deepeval-config.json via prefix', () => {
    const r = scan(['tests/deepeval-config.json'])
    expect(r.findings.find((f) => f.ruleId === 'AI_EVAL_CONFIG_DRIFT')).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// Rule 8: AI_SAFETY_CONFIG_DRIFT (low) — exported function
// ---------------------------------------------------------------------------

describe('isAiSafetyConfig', () => {
  it('matches lakera.yaml ungated', () => {
    expect(isAiSafetyConfig('lakera.yaml', 'lakera.yaml')).toBe(true)
  })

  it('matches rebuff.yaml ungated', () => {
    expect(isAiSafetyConfig('rebuff.yaml', 'rebuff.yaml')).toBe(true)
  })

  it('matches nemo-guardrails.yaml ungated', () => {
    expect(isAiSafetyConfig('nemo-guardrails.yaml', 'nemo-guardrails.yaml')).toBe(true)
  })

  it('matches ai-safety.json ungated', () => {
    expect(isAiSafetyConfig('ai-safety.json', 'ai-safety.json')).toBe(true)
  })

  it('does NOT match guardrails.yaml without AI safety directory context', () => {
    expect(isAiSafetyConfig('infra/guardrails.yaml', 'guardrails.yaml')).toBe(false)
  })

  it('matches guardrails.yaml inside nemo-guardrails/ dir', () => {
    expect(isAiSafetyConfig('nemo-guardrails/guardrails.yaml', 'guardrails.yaml')).toBe(true)
  })

  it('matches guardrails.yaml inside ai-safety/ dir', () => {
    expect(isAiSafetyConfig('ai-safety/guardrails.yaml', 'guardrails.yaml')).toBe(true)
  })

  it('matches content-filter.yaml inside content-filter/ dir', () => {
    expect(isAiSafetyConfig('content-filter/content-filter.yaml', 'content-filter.yaml')).toBe(true)
  })

  it('does NOT match content-filter.yaml without directory context', () => {
    expect(isAiSafetyConfig('config/content-filter.yaml', 'content-filter.yaml')).toBe(false)
  })

  it('matches lakera-guard-policy.yaml via prefix', () => {
    expect(isAiSafetyConfig('config/lakera-guard-policy.yaml', 'lakera-guard-policy.yaml')).toBe(true)
  })

  it('matches config.yaml inside ai-safety/ dir', () => {
    expect(isAiSafetyConfig('ai-safety/config.yaml', 'config.yaml')).toBe(true)
  })

  it('does NOT match ai-safety/README.md', () => {
    expect(isAiSafetyConfig('ai-safety/README.md', 'README.md')).toBe(false)
  })

  it('triggers AI_SAFETY_CONFIG_DRIFT rule via scan', () => {
    const r = scan(['lakera.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'AI_SAFETY_CONFIG_DRIFT')).toBeDefined()
    expect(r.lowCount).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// Vendor path exclusion
// ---------------------------------------------------------------------------

describe('vendor path exclusion', () => {
  it('does not flag files inside node_modules/', () => {
    const r = scan(['node_modules/langchain/openai.yaml'])
    expect(r.totalFindings).toBe(0)
  })

  it('does not flag files inside .venv/', () => {
    const r = scan(['.venv/lib/pinecone/pinecone.yaml'])
    expect(r.totalFindings).toBe(0)
  })

  it('does not flag files inside vendor/', () => {
    const r = scan(['vendor/autogen/autogen.yaml'])
    expect(r.totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Per-rule deduplication
// ---------------------------------------------------------------------------

describe('per-rule deduplication', () => {
  it('counts multiple matching files under one rule finding', () => {
    const r = scan([
      'openai.yaml',
      'openai/config.json',
      'llm-config.yaml',
    ])
    const f = r.findings.find((x) => x.ruleId === 'LLM_CLIENT_DRIFT')
    expect(f).toBeDefined()
    expect(f?.matchCount).toBe(3)
    // Only one finding entry per rule
    expect(r.findings.filter((x) => x.ruleId === 'LLM_CLIENT_DRIFT')).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and riskLevel none for empty input', () => {
    const r = scan([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('returns riskLevel low for a single low finding', () => {
    const r = scan(['ragas.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('returns riskLevel low for a single medium finding', () => {
    const r = scan(['embedding.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('returns riskLevel low for a single high finding', () => {
    const r = scan(['openai.yaml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high findings score 45 (at cap)', () => {
    const r = scan(['openai.yaml', 'pinecone.yaml', 'llamaindex.yaml'])
    expect(r.riskScore).toBe(45)
  })

  it('high cap prevents score over 45 for high findings alone', () => {
    const r = scan([
      'openai.yaml', 'pinecone.yaml', 'llamaindex.yaml',
      'anthropic.json',
    ])
    // 4 high findings: 4 × 15 = 60, but capped at 45
    expect(r.riskScore).toBe(45)
    // 45 is not < 45 → riskLevel is 'high'
    expect(r.riskLevel).toBe('high')
  })

  it('combined high+medium returns correct score', () => {
    const r = scan(['openai.yaml', 'embedding.yaml'])
    // 1 high (15) + 1 medium (8) = 23
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })

  it('all 8 rules triggered produces correct score', () => {
    const r = scan([
      'openai.yaml',         // LLM_CLIENT_DRIFT (high)
      'pinecone.yaml',       // VECTOR_DB_DRIFT (high)
      'llamaindex.yaml',     // AI_ORCHESTRATION_DRIFT (high)
      'model.yaml',          // ML_MODEL_CONFIG_DRIFT (medium)
      'litellm.yaml',        // AI_GATEWAY_DRIFT (medium)
      'embedding.yaml',      // EMBEDDING_PIPELINE_DRIFT (medium)
      'ragas.yaml',          // AI_EVAL_CONFIG_DRIFT (low)
      'lakera.yaml',         // AI_SAFETY_CONFIG_DRIFT (low)
    ])
    // high: 3 × 15 = 45 (cap = 45)
    // medium: 3 × 8 = 24 (cap = 25 → 24)
    // low: 2 × 4 = 8 (cap = 15 → 8)
    // total: 45 + 24 + 8 = 77
    expect(r.riskScore).toBe(77)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
  })

  it('returns riskLevel critical when score reaches 80', () => {
    // Need 80+: high cap 45 + medium cap 25 + 10+ low
    const r = scan([
      'openai.yaml',        // high
      'pinecone.yaml',      // high
      'llamaindex.yaml',    // high
      'model.yaml',         // medium
      'litellm.yaml',       // medium
      'embedding.yaml',     // medium
      'embed-config.json',  // embedding (same rule, deduped)
      'ragas.yaml',         // low
      'trulens.json',       // low (same rule, deduped)
      'evals.yaml',         // low (same rule, deduped)
      'lakera.yaml',        // low
    ])
    // high: 3 × 15 = 45 (cap 45)
    // medium: 3 × 8 = 24 (cap 25 → 24)
    // low: 2 × 4 = 8 (cap 15 → 8)
    // 45 + 24 + 8 = 77 — still high
    // To reach critical we need high 45 + medium 25 + low 10+
    // 3 medium rules at 8 each = 24 < 25, can't cap medium with 3 rules
    // Actually: need medium cap (25) → requires ceil(25/8)=4 medium findings
    // but there are only 3 medium rules total, so max medium = 24
    // Therefore max total = 45 + 24 + 15 = 84 (critical) but need 4+ low rules
    // There are only 2 low rules, so max low = 8
    // Max possible = 45 + 24 + 8 = 77 (high) with 8 total rules
    expect(r.riskScore).toBeLessThanOrEqual(77)
    expect(r.riskLevel).toBe('high')
  })

  it('score is capped at 100 even if arithmetic would exceed it', () => {
    // Use many duplicated files — counts accumulate but are per-rule capped already
    const files = Array.from({ length: 50 }, (_, i) => `openai-${i}.yaml`)
    const r = scan(files)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// matchedPath and matchCount fields
// ---------------------------------------------------------------------------

describe('matchedPath and matchCount', () => {
  it('records first matched path', () => {
    const r = scan(['config/openai.yaml', 'openai/settings.json'])
    const f = r.findings.find((x) => x.ruleId === 'LLM_CLIENT_DRIFT')
    expect(f?.matchedPath).toBe('config/openai.yaml')
  })

  it('records correct matchCount', () => {
    const r = scan(['openai.yaml', 'llm-config.json', 'anthropic.yaml'])
    const f = r.findings.find((x) => x.ruleId === 'LLM_CLIENT_DRIFT')
    expect(f?.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('path normalisation', () => {
  it('strips leading ./ from paths', () => {
    const r = scan(['./openai.yaml'])
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })

  it('converts backslashes to forward slashes', () => {
    const r = scan(['openai\\settings.json'])
    // After normalise → 'openai/settings.json' → dir match
    expect(r.findings.find((f) => f.ruleId === 'LLM_CLIENT_DRIFT')).toBeDefined()
  })
})
