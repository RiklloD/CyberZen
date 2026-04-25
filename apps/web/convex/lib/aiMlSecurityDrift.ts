// WS-101 — AI/ML Dependency Security Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to AI/ML dependency security configuration: LLM provider client configuration
// (OpenAI/Anthropic/Azure OpenAI/Cohere/Mistral API key and endpoint config),
// vector database configuration (Pinecone/Weaviate/Chroma/Qdrant/Milvus), AI
// orchestration framework configuration (LlamaIndex/LangGraph/AutoGen/Haystack/
// DSPy), ML model training and registry configuration (model.yaml, training
// hyperparameters, model-registry configs), AI gateway and proxy configuration
// (LiteLLM proxy/Portkey/OpenRouter gateway config), embedding pipeline
// configuration (sentence-transformers/FAISS index params/embedding service
// configs), AI evaluation framework configuration (Ragas/TruLens/PromptFlow/
// DeepEval), and AI safety and guardrail configuration (NeMo Guardrails/Rebuff/
// Lakera Guard/content filter policies).
//
// Distinct from:
//   WS-69  (developer security tooling: SAST / SCA / secret scanning)
//   WS-89  (OS hardening: sshd_config / sudoers / sysctl / PAM)
//   WS-95  (endpoint security: CrowdStrike / SentinelOne / MDE / exclusion lists)
//   WS-100 (business impact scoring: synthesises signals from other detectors)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  '.npm/', '.yarn/', '__pycache__/', '.venv/', 'venv/', 'target/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: LLM_CLIENT_DRIFT (high)
// ---------------------------------------------------------------------------
// Direct LLM provider client configuration.  These files hold API keys,
// endpoint URLs, model selections, and rate-limit overrides.  Unauthorised
// changes can redirect inference traffic, expose keys, or swap the model
// served to production.

const LLM_CLIENT_UNGATED = new Set([
  'openai.yaml', 'openai.yml', 'openai.json', 'openai.conf',
  'anthropic.yaml', 'anthropic.yml', 'anthropic.json', 'anthropic.conf',
  'azure-openai.yaml', 'azure-openai.json', 'azure-openai.conf',
  'cohere.yaml', 'cohere.json', 'cohere.conf',
  'mistral.yaml', 'mistral.json', 'mistral.conf',
  'gemini.yaml', 'gemini.json', 'gemini.conf',
  'llm-config.yaml', 'llm-config.yml', 'llm-config.json', 'llm.conf',
  'llm-provider.yaml', 'llm-provider.json',
])

const LLM_CLIENT_DIRS = [
  'openai/', 'anthropic/', 'azure-openai/', 'cohere/', 'mistral/',
  'llm/', 'llm-config/', 'llm-providers/', 'ai-providers/', 'providers/llm/',
]

function isLlmClientConfig(path: string, base: string): boolean {
  if (LLM_CLIENT_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('openai-') ||
    base.startsWith('anthropic-') ||
    base.startsWith('azure-openai-') ||
    base.startsWith('cohere-') ||
    base.startsWith('mistral-') ||
    base.startsWith('gemini-') ||
    base.startsWith('llm-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml|env)$/.test(base)
  }

  return LLM_CLIENT_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml|env)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: VECTOR_DB_DRIFT (high)
// ---------------------------------------------------------------------------
// Vector database connection and index configuration.  Vector DBs store
// embedding representations of sensitive data — misconfigs can expose
// collections to unauthenticated reads, change index parameters silently,
// or redirect queries to an untrusted cluster.

const VECTOR_DB_UNGATED = new Set([
  'pinecone.yaml', 'pinecone.yml', 'pinecone.json', 'pinecone.conf',
  'weaviate.yaml', 'weaviate.yml', 'weaviate.json', 'weaviate.conf',
  'chroma.yaml', 'chroma.yml', 'chroma.json', 'chromadb.conf',
  'qdrant.yaml', 'qdrant.yml', 'qdrant.json', 'qdrant.conf',
  'milvus.yaml', 'milvus.yml', 'milvus.json', 'milvus.conf',
  'pgvector.yaml', 'pgvector.json',
  'vector-db.yaml', 'vector-db.json', 'vectordb.conf',
])

const VECTOR_DB_DIRS = [
  'pinecone/', 'weaviate/', 'chromadb/', 'chroma/', 'qdrant/', 'milvus/',
  'vector-db/', 'vectordb/', 'vector-store/', 'embeddings-store/',
]

function isVectorDbConfig(path: string, base: string): boolean {
  if (VECTOR_DB_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('pinecone-') ||
    base.startsWith('weaviate-') ||
    base.startsWith('chroma-') ||
    base.startsWith('qdrant-') ||
    base.startsWith('milvus-') ||
    base.startsWith('vector-db-') ||
    base.startsWith('vectordb-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return VECTOR_DB_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: AI_ORCHESTRATION_DRIFT (high)
// ---------------------------------------------------------------------------
// AI orchestration framework configuration.  LlamaIndex, LangGraph, AutoGen,
// Haystack, and DSPy are the primary AI agent and pipeline orchestrators —
// their config files control model routing, memory backends, tool calling
// permissions, and multi-agent trust boundaries.  Changes can silently enable
// dangerous tool permissions or redirect agent memory to untrusted stores.

const AI_ORCH_UNGATED = new Set([
  'llamaindex.yaml', 'llamaindex.yml', 'llamaindex.json',
  'llama-index.yaml', 'llama-index.json', 'llama_index.yaml',
  'autogen.yaml', 'autogen.yml', 'autogen.json', 'autogen.conf',
  'haystack.yaml', 'haystack.yml', 'haystack.json',
  'dspy.yaml', 'dspy.yml', 'dspy.json',
  'langgraph.yaml', 'langgraph.json',
  'crewai.yaml', 'crewai.json',
  'ai-pipeline.yaml', 'ai-pipeline.json',
  'agent-config.yaml', 'agent-config.json',
])

const AI_ORCH_DIRS = [
  'llamaindex/', 'llama-index/', 'autogen/', 'haystack/', 'dspy/',
  'langgraph/', 'crewai/', 'ai-pipeline/', 'agent/', 'agents/',
  'orchestration/', 'ai-orchestration/', 'rag-pipeline/',
]

function isAiOrchestrationConfig(path: string, base: string): boolean {
  if (AI_ORCH_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('llamaindex-') ||
    base.startsWith('llama-index-') ||
    base.startsWith('autogen-') ||
    base.startsWith('haystack-') ||
    base.startsWith('dspy-') ||
    base.startsWith('langgraph-') ||
    base.startsWith('crewai-') ||
    base.startsWith('agent-config')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return AI_ORCH_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: ML_MODEL_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------
// ML model training and registry configuration.  Training hyperparameter files
// (model.yaml), model registry configs (mlflow, BentoML, Seldon), and
// experiment tracking configs.  Drift here can alter which model version is
// served to production or quietly degrade model quality.

const ML_MODEL_UNGATED = new Set([
  'model.yaml', 'model.yml', 'model.json', 'model.conf',
  'model-config.yaml', 'model-config.json',
  'mlflow.yaml', 'mlflow.yml', 'mlflow.json',
  'bentoml.yaml', 'bentoml.json',
  'seldon.yaml', 'seldon.json',
  'triton.yaml', 'triton.json',
  'serving.yaml', 'serving.json',
  'torchserve.yaml', 'torchserve.json',
  'mlserver.yaml', 'mlserver.json',
])

const ML_MODEL_DIRS = [
  'mlflow/', 'bentoml/', 'seldon/', 'triton/', 'torchserve/',
  'model-registry/', 'model-serving/', 'models/', 'ml-models/',
  'training/', 'experiments/',
]

function isMlModelConfig(path: string, base: string): boolean {
  if (ML_MODEL_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('mlflow-') ||
    base.startsWith('bentoml-') ||
    base.startsWith('seldon-') ||
    base.startsWith('triton-') ||
    base.startsWith('torchserve-') ||
    base.startsWith('model-config') ||
    base.startsWith('model-serving')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return ML_MODEL_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: AI_GATEWAY_DRIFT (medium)
// ---------------------------------------------------------------------------
// AI gateway and proxy configuration.  LiteLLM proxy, Portkey, and OpenRouter
// gateway configs control which downstream LLM provider handles each request,
// apply rate limits, and optionally log prompt/response pairs.  Misconfigs can
// bypass content filtering, expose logging destinations, or degrade fallback
// behaviour.

const AI_GATEWAY_UNGATED = new Set([
  'litellm.yaml', 'litellm.yml', 'litellm.json', 'litellm.conf',
  'litellm-proxy.yaml', 'litellm-proxy.json',
  'portkey.yaml', 'portkey.json', 'portkey.conf',
  'openrouter.yaml', 'openrouter.json',
  'ai-gateway.yaml', 'ai-gateway.json', 'ai-gateway.conf',
  'llm-gateway.yaml', 'llm-gateway.json',
  'kong-ai.yaml', 'kong-ai.json',
])

const AI_GATEWAY_DIRS = [
  'litellm/', 'portkey/', 'openrouter/', 'ai-gateway/', 'llm-gateway/',
  'gateway/', 'llm-proxy/', 'ai-proxy/',
]

function isAiGatewayConfig(path: string, base: string): boolean {
  if (AI_GATEWAY_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('litellm-') ||
    base.startsWith('portkey-') ||
    base.startsWith('openrouter-') ||
    base.startsWith('ai-gateway-') ||
    base.startsWith('llm-gateway-') ||
    base.startsWith('llm-proxy-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return AI_GATEWAY_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: EMBEDDING_PIPELINE_DRIFT (medium)
// ---------------------------------------------------------------------------
// Embedding pipeline configuration.  sentence-transformers model selection,
// FAISS index parameters, and embedding-service configs control how text is
// encoded before being written to the vector store.  Changing the embedding
// model or normalisation parameters silently breaks semantic search for all
// existing embeddings.

const EMBEDDING_UNGATED = new Set([
  'embedding.yaml', 'embedding.yml', 'embedding.json', 'embedding.conf',
  'embeddings.yaml', 'embeddings.json',
  'embedding-config.yaml', 'embedding-config.json',
  'faiss.yaml', 'faiss.json',
  'sentence-transformers.yaml', 'sentence-transformers.json',
  'embed-config.yaml', 'embed-config.json',
])

const EMBEDDING_DIRS = [
  'embeddings/', 'embedding/', 'faiss/', 'sentence-transformers/',
  'embed/', 'embedding-service/', 'embedding-pipeline/',
]

function isEmbeddingPipelineConfig(path: string, base: string): boolean {
  if (EMBEDDING_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('embedding-') ||
    base.startsWith('embeddings-') ||
    base.startsWith('faiss-') ||
    base.startsWith('embed-config')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return EMBEDDING_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: AI_EVAL_CONFIG_DRIFT (low)
// ---------------------------------------------------------------------------
// AI evaluation framework configuration.  Ragas, TruLens, PromptFlow, and
// DeepEval configs define evaluation metrics, benchmark datasets, and
// pass/fail thresholds.  Drift here can lower quality gates or disable
// automated regression detection before production deployments.

const AI_EVAL_UNGATED = new Set([
  'ragas.yaml', 'ragas.yml', 'ragas.json',
  'trulens.yaml', 'trulens.json',
  'promptflow.yaml', 'promptflow.yml', 'promptflow.json',
  'deepeval.yaml', 'deepeval.json',
  'evals.yaml', 'evals.yml', 'evals.json',
  'eval-config.yaml', 'eval-config.json',
  'lm-eval.yaml', 'lm-eval.json',
  'ai-eval.yaml', 'ai-eval.json',
])

const AI_EVAL_DIRS = [
  'ragas/', 'trulens/', 'promptflow/', 'deepeval/',
  'evals/', 'evaluations/', 'ai-evals/', 'llm-evals/',
  'benchmarks/', 'eval-pipeline/',
]

function isAiEvalConfig(path: string, base: string): boolean {
  if (AI_EVAL_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('ragas-') ||
    base.startsWith('trulens-') ||
    base.startsWith('promptflow-') ||
    base.startsWith('deepeval-') ||
    base.startsWith('eval-config') ||
    base.startsWith('ai-eval-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return AI_EVAL_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: AI_SAFETY_CONFIG_DRIFT (low) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures an AI safety, guardrail, or content
// moderation system: NeMo Guardrails rail definitions, Rebuff prompt injection
// defence config, Lakera Guard policy files, and generic content-filter policy
// files deployed alongside LLM applications.
//
// Trade-offs to consider:
//   - guardrails.yaml is common in non-AI projects (HashiCorp, Atlantis) —
//     require AI safety directory context
//   - nemo-guardrails/ and rebuff/ dirs are unambiguous
//   - content-filter.yaml is too generic — require ai-safety dir context
//   - lakera.yaml / lakera-guard.yaml are specific enough to match ungated

const AI_SAFETY_UNGATED = new Set([
  'lakera.yaml', 'lakera.yml', 'lakera.json', 'lakera.conf',
  'lakera-guard.yaml', 'lakera-guard.json',
  'rebuff.yaml', 'rebuff.json', 'rebuff.conf',
  'nemo-guardrails.yaml', 'nemo-guardrails.json',
  'ai-safety.yaml', 'ai-safety.json',
  'ai-moderation.yaml', 'ai-moderation.json',
  'llm-safety.yaml', 'llm-safety.json',
])

const AI_SAFETY_DIRS = [
  'nemo-guardrails/', 'guardrails/', 'rebuff/', 'lakera/',
  'ai-safety/', 'llm-safety/', 'content-filter/', 'moderation/',
  'safety/', 'ai-guardrails/',
]

export function isAiSafetyConfig(path: string, base: string): boolean {
  if (AI_SAFETY_UNGATED.has(base)) return true

  const low = path.toLowerCase()

  // guardrails.yaml is generic — only match in AI safety directory context
  if (
    (base === 'guardrails.yaml' ||
     base === 'guardrails.yml' ||
     base === 'guardrails.json' ||
     base === 'content-filter.yaml' ||
     base === 'content-filter.json' ||
     base === 'content-policy.yaml' ||
     base === 'content-policy.json') &&
    AI_SAFETY_DIRS.some((d) => low.includes(d))
  ) {
    return true
  }

  if (
    base.startsWith('lakera-') ||
    base.startsWith('rebuff-') ||
    base.startsWith('nemo-guardrails-') ||
    base.startsWith('ai-safety-') ||
    base.startsWith('llm-safety-') ||
    base.startsWith('ai-moderation-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
  }

  return AI_SAFETY_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type AiMlSecRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: AiMlSecRule[] = [
  {
    id: 'LLM_CLIENT_DRIFT',
    severity: 'high',
    description: 'LLM provider client configuration modified (OpenAI / Anthropic / Azure OpenAI / Cohere / Mistral).',
    recommendation: 'Verify the provider endpoint, model selection, and API key references have not been changed to redirect traffic or expose credentials; rotate any keys referenced in modified config files.',
    match: isLlmClientConfig,
  },
  {
    id: 'VECTOR_DB_DRIFT',
    severity: 'high',
    description: 'Vector database connection or index configuration modified (Pinecone / Weaviate / Chroma / Qdrant / Milvus).',
    recommendation: 'Audit index name, authentication settings, and namespace/collection changes; verify the cluster endpoint has not been redirected to an untrusted host and that collection access controls are intact.',
    match: isVectorDbConfig,
  },
  {
    id: 'AI_ORCHESTRATION_DRIFT',
    severity: 'high',
    description: 'AI orchestration framework configuration modified (LlamaIndex / LangGraph / AutoGen / Haystack / DSPy / CrewAI).',
    recommendation: 'Review agent tool permissions, memory backend endpoints, and model routing rules for unauthorised changes; ensure multi-agent trust boundaries and tool calling policies remain restrictive.',
    match: isAiOrchestrationConfig,
  },
  {
    id: 'ML_MODEL_CONFIG_DRIFT',
    severity: 'medium',
    description: 'ML model training or registry configuration modified (MLflow / BentoML / Seldon / Triton / TorchServe).',
    recommendation: 'Check model registry references and serving endpoint configuration for unexpected version bumps or model substitutions that could silently degrade production quality or introduce backdoored weights.',
    match: isMlModelConfig,
  },
  {
    id: 'AI_GATEWAY_DRIFT',
    severity: 'medium',
    description: 'AI gateway or LLM proxy configuration modified (LiteLLM / Portkey / OpenRouter).',
    recommendation: 'Verify provider routing rules, fallback chains, and logging destinations have not been altered to bypass content filtering, change the serving model, or redirect prompt logs to an unauthorised endpoint.',
    match: isAiGatewayConfig,
  },
  {
    id: 'EMBEDDING_PIPELINE_DRIFT',
    severity: 'medium',
    description: 'Embedding pipeline or FAISS index configuration modified (sentence-transformers / FAISS / embedding service).',
    recommendation: 'Review embedding model selection and normalisation parameters — changing the embedding model invalidates all existing vector store entries and may break semantic search silently; verify changes are intentional.',
    match: isEmbeddingPipelineConfig,
  },
  {
    id: 'AI_EVAL_CONFIG_DRIFT',
    severity: 'low',
    description: 'AI evaluation framework configuration modified (Ragas / TruLens / PromptFlow / DeepEval).',
    recommendation: 'Check that evaluation metrics thresholds and benchmark dataset references have not been lowered to make failing models appear compliant; restore any disabled regression checks.',
    match: isAiEvalConfig,
  },
  {
    id: 'AI_SAFETY_CONFIG_DRIFT',
    severity: 'low',
    description: 'AI safety, guardrail, or content moderation configuration modified (NeMo Guardrails / Rebuff / Lakera).',
    recommendation: 'Audit rail definitions, prompt injection defence rules, and content filter policies for weakened or disabled checks; ensure safety guardrails are not bypassed by the modified configuration.',
    match: (p, b) => isAiSafetyConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring model (identical to all WS-60+ detectors)
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP:     Record<Severity, number> = { high: 45, medium: 25, low: 15 }

type AiMlRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

function computeRiskLevel(score: number): AiMlRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type AiMlSecFinding = {
  ruleId:         string
  severity:       Severity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type AiMlSecDriftResult = {
  riskScore:     number
  riskLevel:     AiMlRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      AiMlSecFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanAiMlSecurityDrift(
  changedFiles: string[],
): AiMlSecDriftResult {
  const findings: AiMlSecFinding[] = []

  for (const rule of RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const path = normalise(raw)
      if (isVendorPath(path)) continue
      const base = path.split('/').pop() ?? ''
      if (rule.match(path, base)) {
        matchCount++
        if (matchCount === 1) firstPath = path
      }
    }

    if (matchCount > 0) {
      findings.push({
        ruleId:         rule.id,
        severity:       rule.severity,
        matchedPath:    firstPath,
        matchCount,
        description:    rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  const grouped = { high: 0, medium: 0, low: 0 }
  for (const f of findings) grouped[f.severity]++

  let score = 0
  for (const sev of ['high', 'medium', 'low'] as Severity[]) {
    score += Math.min(grouped[sev] * SEVERITY_PENALTY[sev], SEVERITY_CAP[sev])
  }
  score = Math.min(score, 100)

  const riskLevel     = computeRiskLevel(score)
  const totalFindings = findings.length

  const summary =
    totalFindings === 0
      ? 'No AI/ML security configuration changes detected.'
      : `${totalFindings} AI/ML security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

  return {
    riskScore:   score,
    riskLevel,
    totalFindings,
    highCount:   grouped.high,
    mediumCount: grouped.medium,
    lowCount:    grouped.low,
    findings,
    summary,
  }
}
