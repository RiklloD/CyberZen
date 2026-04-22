// AI/ML Model Supply Chain Intelligence — pure, no Convex dependencies.
//
// Analyses SBOM components for AI/ML model supply chain risks that standard
// dependency analysis misses.  The threat model is different from traditional
// software supply chain:
//
//  1. Model weight files can contain arbitrary serialised Python objects
//     (.pkl / pickle / .pt) — a known Remote Code Execution vector when
//     loaded with torch.load() without `weights_only=True`.
//
//  2. ML model registries (Hugging Face, ONNX Zoo) are largely unmoderated —
//     any account can publish a model with a name similar to a popular one
//     (model typosquatting).
//
//  3. ML framework versions age quickly and carry known CVEs that are
//     routinely underreported in traditional advisory feeds.
//
//  4. Packages that pull remote model weights at runtime introduce an
//     implicit network dependency that bypasses SBOM inventory entirely.
//
// The scanner returns a `ModelSupplyChainScan` with per-component signals
// and a repository-level aggregate risk level.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MlComponentInput = {
  name: string
  version: string
  ecosystem: string
  isDirect: boolean
  layer: string
  hasKnownVulnerabilities: boolean
  trustScore: number
}

export type ModelRiskSignalKind =
  | 'pickle_serialization_risk'    // Framework loads .pkl or .pt by default
  | 'unpinned_ml_framework'        // ML package without a pinned (==) version
  | 'outdated_ml_framework'        // Version matches a known-vulnerable range
  | 'model_typosquat_risk'         // Name ≤2 edits from a well-known ML package
  | 'remote_weight_download'       // Package fetches model weights from the internet
  | 'unsafe_model_loader'          // Deprecated / unsafe API detected in framework

export type ModelRiskSignal = {
  kind: ModelRiskSignalKind
  weight: number
  description: string
}

export type MlComponentResult = {
  name: string
  version: string
  ecosystem: string
  isDirect: boolean
  isMlPackage: boolean
  riskScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  signals: ModelRiskSignal[]
  summary: string
}

export type ModelSupplyChainScan = {
  /** 0–100 aggregate risk score for the repository's ML supply chain. */
  overallRiskScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  /** How many unique ML/AI frameworks were detected. */
  mlFrameworkCount: number
  /** Names of detected ML/AI frameworks. */
  mlFrameworks: string[]
  /** Components with at least one risk signal, sorted by riskScore desc. */
  flaggedComponents: MlComponentResult[]
  /** True when any framework in the SBOM can load pickle-format model files. */
  hasPickleRisk: boolean
  /** True when any ML package lacks a pinned version constraint. */
  hasUnpinnedFramework: boolean
  /** Number of ML components with known CVEs. */
  vulnerableFrameworkCount: number
  summary: string
}

// ---------------------------------------------------------------------------
// ML package catalogue
//
// These are the packages we classify as "AI/ML supply chain" and apply the
// heightened risk signals to.  Grouped by their primary risk characteristic.
// ---------------------------------------------------------------------------

// Frameworks that use pickle serialisation by default for model files.
const PICKLE_LOADER_PACKAGES = new Set([
  'torch', 'pytorch', 'torchvision', 'torchaudio',
  'tensorflow', 'tf', 'tensorflow-cpu', 'tensorflow-gpu',
  'keras', 'tf-keras',
  'paddle', 'paddlepaddle', 'paddlepaddle-gpu',
  'mxnet', 'mxnet-cu110',
  'caffe2',
  'dill', 'cloudpickle', 'joblib',
  'pickle5',
])

// Frameworks that download model weights from external registries at runtime.
const REMOTE_WEIGHT_PACKAGES = new Set([
  'transformers', 'huggingface_hub', 'huggingface-hub',
  'diffusers',
  'sentence-transformers', 'sentence_transformers',
  'timm',
  'open_clip_torch',
  'clip',
  'lavis',
  'detectron2',
  'segment_anything',
  'whisper', 'openai-whisper',
  'spacy', 'en_core_web_sm', 'en_core_web_lg',
  'gensim',
  'fastai',
])

// All known ML framework packages (union of the above + orchestration libs).
const ALL_ML_PACKAGES = new Set([
  ...PICKLE_LOADER_PACKAGES,
  ...REMOTE_WEIGHT_PACKAGES,
  'scikit-learn', 'sklearn', 'xgboost', 'lightgbm', 'catboost',
  'onnx', 'onnxruntime', 'onnxruntime-gpu',
  'jax', 'jaxlib', 'flax', 'optax',
  'langchain', 'langchain-core', 'langchain-community',
  'openai', 'anthropic', 'cohere', 'mistralai',
  'llama_cpp_python', 'llama-cpp-python',
  'ctransformers',
  'autogen', 'pyautogen',
  'crewai',
  'llamaindex', 'llama-index', 'llama_index',
  'peft', 'trl', 'accelerate', 'bitsandbytes',
  'einops', 'torchmetrics',
  'pytorch-lightning', 'lightning',
  'mlflow', 'wandb', 'comet_ml',
])

// Well-known ML package names — used for typosquat detection.
const WELL_KNOWN_ML = [
  'torch', 'tensorflow', 'transformers', 'scikit-learn', 'keras',
  'diffusers', 'sentence-transformers', 'huggingface-hub', 'onnxruntime',
  'jax', 'flax', 'langchain', 'openai', 'anthropic', 'llama-index',
  'xgboost', 'lightgbm', 'fastai', 'timm', 'wandb', 'mlflow',
]

// ---------------------------------------------------------------------------
// Known vulnerable version ranges (simplified — advisory-derived)
// Format: [packageName, minBadVersion, maxBadVersion (exclusive)]
// These are illustrative; a production system would query the CVE feed.
// ---------------------------------------------------------------------------

type VulnRange = { min: string; max: string; cve: string; summary: string }

const KNOWN_VULNERABLE: Record<string, VulnRange[]> = {
  torch: [
    { min: '0.0.0', max: '2.0.0', cve: 'CVE-2022-45907', summary: 'RCE via malicious .pt file loaded without weights_only=True' },
  ],
  tensorflow: [
    { min: '0.0.0', max: '2.12.0', cve: 'CVE-2023-25668', summary: 'Heap buffer overflow in tf.raw_ops.ImageProjectiveTransformV3' },
  ],
  transformers: [
    { min: '0.0.0', max: '4.36.0', cve: 'CVE-2024-3568', summary: 'Arbitrary code execution via model deserialization in pipeline()' },
  ],
}

// ---------------------------------------------------------------------------
// Levenshtein distance (bounded, for typosquat detection)
// ---------------------------------------------------------------------------

function levenshteinBounded(a: string, b: string, bound: number): number {
  if (Math.abs(a.length - b.length) > bound) return bound + 1
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  const curr = new Array<number>(b.length + 1)
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i
    for (let j = 1; j <= b.length; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1])
    }
    for (let k = 0; k <= b.length; k++) prev[k] = curr[k]
  }
  return prev[b.length]
}

function normalisePkgName(name: string): string {
  // Collapse hyphens, underscores, and dots; lowercase
  return name.toLowerCase().replace(/[-_.]/g, '')
}

// ---------------------------------------------------------------------------
// Version comparison (simplified semver — major.minor.patch)
// Returns -1 (a<b), 0 (equal), 1 (a>b)
// ---------------------------------------------------------------------------

function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const parse = (v: string) =>
    v
      .replace(/[^0-9.]/g, '')
      .split('.')
      .map(Number)
      .slice(0, 3)
      .map((n) => (Number.isNaN(n) ? 0 : n))

  const [aArr, bArr] = [parse(a), parse(b)]
  const len = Math.max(aArr.length, bArr.length)

  for (let i = 0; i < len; i++) {
    const av = aArr[i] ?? 0
    const bv = bArr[i] ?? 0
    if (av < bv) return -1
    if (av > bv) return 1
  }
  return 0
}

function isVersionVulnerable(version: string, ranges: VulnRange[]): VulnRange | null {
  for (const range of ranges) {
    const gtMin = compareVersions(version, range.min) >= 0
    const ltMax = compareVersions(version, range.max) < 0
    if (gtMin && ltMax) return range
  }
  return null
}

// ---------------------------------------------------------------------------
// Per-component analysis
// ---------------------------------------------------------------------------

function riskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 70) return 'critical'
  if (score >= 45) return 'high'
  if (score >= 20) return 'medium'
  return 'low'
}

function analyseComponent(c: MlComponentInput): MlComponentResult {
  const normName = normalisePkgName(c.name)
  const isMl = ALL_ML_PACKAGES.has(c.name) ||
    [...ALL_ML_PACKAGES].some((p) => normalisePkgName(p) === normName)

  const signals: ModelRiskSignal[] = []

  // --- Pickle serialisation risk ----------------------------------------
  const isPickleLoader = PICKLE_LOADER_PACKAGES.has(c.name) ||
    [...PICKLE_LOADER_PACKAGES].some((p) => normalisePkgName(p) === normName)

  if (isMl && isPickleLoader) {
    signals.push({
      kind: 'pickle_serialization_risk',
      weight: 45,
      description:
        `"${c.name}" can load pickle-format model files (.pkl / .pt) by default. ` +
        `Malicious model files distributed through untrusted channels can exploit ` +
        `this to execute arbitrary code during deserialization. ` +
        `Enforce weights_only=True (PyTorch ≥2.0) or use safe serialisation formats.`,
    })
  }

  // --- Remote weight download risk ----------------------------------------
  const isRemoteLoader = REMOTE_WEIGHT_PACKAGES.has(c.name) ||
    [...REMOTE_WEIGHT_PACKAGES].some((p) => normalisePkgName(p) === normName)

  if (isMl && isRemoteLoader) {
    signals.push({
      kind: 'remote_weight_download',
      weight: 30,
      description:
        `"${c.name}" downloads model weights from external registries at runtime. ` +
        `This creates an implicit network dependency not captured in the SBOM, and ` +
        `exposes the application to model-level supply chain tampering if the registry ` +
        `is compromised or the model name is reused by a malicious actor.`,
    })
  }

  // --- Unpinned ML framework -----------------------------------------------
  const isPinned = c.version.includes('==') || /^\d+\.\d+\.\d+/.test(c.version)
  const looksUnpinned = !isPinned && (c.version === '*' || c.version === '' || c.version.startsWith('^') || c.version.startsWith('~') || c.version.startsWith('>='))

  if (isMl && looksUnpinned) {
    signals.push({
      kind: 'unpinned_ml_framework',
      weight: 20,
      description:
        `"${c.name}" is not pinned to an exact version ("${c.version || '*'}"). ` +
        `ML frameworks ship frequent releases that may introduce breaking API changes ` +
        `or load different default model formats, making reproducibility and security ` +
        `auditing unreliable.`,
    })
  }

  // --- Known vulnerable version ----------------------------------------
  const vulnRanges = KNOWN_VULNERABLE[c.name.toLowerCase()]
  if (vulnRanges) {
    const hit = isVersionVulnerable(c.version, vulnRanges)
    if (hit) {
      signals.push({
        kind: 'outdated_ml_framework',
        weight: 55,
        description:
          `"${c.name}@${c.version}" falls within a known-vulnerable range ` +
          `(${hit.cve}): ${hit.summary}. Upgrade to ≥${hit.max} immediately.`,
      })
    }
  }

  // --- Model typosquat risk -----------------------------------------------
  if (!isMl) {
    // Only flag non-ML packages that are suspiciously close to well-known ML ones
    for (const known of WELL_KNOWN_ML) {
      const dist = levenshteinBounded(normName, normalisePkgName(known), 2)
      if (dist > 0 && dist <= 2) {
        signals.push({
          kind: 'model_typosquat_risk',
          weight: 50,
          description:
            `"${c.name}" is typographically close to the well-known ML package ` +
            `"${known}" (edit distance ${dist}). This may be a typosquat designed ` +
            `to inject malicious code or model weights into the pipeline.`,
        })
        break
      }
    }
  }

  const rawScore = signals.reduce((a, s) => a + s.weight, 0)
  const riskScore = Math.min(rawScore, 100)
  const level = riskLevel(riskScore)
  const topSignal = [...signals].sort((a, b) => b.weight - a.weight)[0]

  return {
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    isDirect: c.isDirect,
    isMlPackage: isMl,
    riskScore,
    riskLevel: level,
    signals,
    summary: topSignal?.description ?? `No ML model supply chain signals detected for "${c.name}".`,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function scanModelSupplyChain(components: MlComponentInput[]): ModelSupplyChainScan {
  if (components.length === 0) {
    return {
      overallRiskScore: 0,
      riskLevel: 'low',
      mlFrameworkCount: 0,
      mlFrameworks: [],
      flaggedComponents: [],
      hasPickleRisk: false,
      hasUnpinnedFramework: false,
      vulnerableFrameworkCount: 0,
      summary: 'No components to analyse.',
    }
  }

  const results = components.map(analyseComponent)
  const flagged = results
    .filter((r) => r.signals.length > 0)
    .sort((a, b) => b.riskScore - a.riskScore)

  const mlComponents = results.filter((r) => r.isMlPackage)
  const mlFrameworks = [...new Set(mlComponents.map((r) => r.name))]
  const mlFrameworkCount = mlFrameworks.length

  const hasPickleRisk = flagged.some((r) =>
    r.signals.some((s) => s.kind === 'pickle_serialization_risk'),
  )
  const hasUnpinnedFramework = flagged.some((r) =>
    r.signals.some((s) => s.kind === 'unpinned_ml_framework'),
  )
  const vulnerableFrameworkCount = flagged.filter((r) =>
    r.signals.some((s) => s.kind === 'outdated_ml_framework'),
  ).length

  // Overall score: weighted average of flagged component scores by flagged ratio
  const flaggedRatio = flagged.length / Math.max(components.length, 1)
  const avgFlaggedScore =
    flagged.length > 0
      ? Math.round(flagged.reduce((a, c) => a + c.riskScore, 0) / flagged.length)
      : 0
  const overallRiskScore = Math.min(Math.round(avgFlaggedScore * flaggedRatio * 1.5), 100)
  const level = riskLevel(overallRiskScore)

  const critCount = flagged.filter((c) => c.riskLevel === 'critical').length
  const highCount = flagged.filter((c) => c.riskLevel === 'high').length

  const summary =
    flagged.length === 0
      ? mlFrameworkCount === 0
        ? `No AI/ML frameworks detected in this repository's SBOM.`
        : `${mlFrameworkCount} ML framework(s) detected; no model supply chain risk signals found.`
      : [
          `ML supply chain risk: ${flagged.length} package(s) flagged out of ${mlFrameworkCount} ML frameworks.`,
          critCount > 0 ? ` ${critCount} critical.` : '',
          highCount > 0 ? ` ${highCount} high.` : '',
          hasPickleRisk ? ' Pickle serialisation risk present — unsafe model loading possible.' : '',
        ].join('')

  return {
    overallRiskScore,
    riskLevel: level,
    mlFrameworkCount,
    mlFrameworks,
    flaggedComponents: flagged,
    hasPickleRisk,
    hasUnpinnedFramework,
    vulnerableFrameworkCount,
    summary,
  }
}

/** Returns true when a package name is an ML/AI component we track. */
export function isMlPackage(name: string): boolean {
  if (ALL_ML_PACKAGES.has(name)) return true
  const norm = normalisePkgName(name)
  return [...ALL_ML_PACKAGES].some((p) => normalisePkgName(p) === norm)
}
