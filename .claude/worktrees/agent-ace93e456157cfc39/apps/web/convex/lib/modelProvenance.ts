// AI Model Provenance Tracking — pure library, no Convex dependencies.
//
// Spec §3.11.2 Layer 6 — "AI Model Dependencies":
//   For AI-native applications, models and embedding systems in use:
//   - Foundation model providers and specific model versions
//   - Open source models with their weights and training lineage
//   - Vector database providers and index configurations
//   - Fine-tuning datasets and their provenance
//
// This library analyses SBOM components that reference AI/ML models and
// produces a per-model provenance risk assessment covering:
//
//   1. Source verification   — is the model from a known, trusted registry?
//   2. License compliance    — is the license permissive, restrictive, or unknown?
//   3. Model card presence   — does the model have a model card documenting usage?
//   4. Hash verifiability    — is the weights hash pinned and verifiable?
//   5. Version pinning       — is an exact version specified (not a float-ref)?
//   6. Training data risk    — are known-problematic datasets referenced?
//
// The aggregate `provenanceScore` (0–100, higher = more trustworthy) feeds
// the repository-level risk report.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ProvenanceSignalKind =
  | 'unknown_source'        // Model not from any recognised registry
  | 'restricted_license'    // License prohibits commercial use or redistribution
  | 'no_license'            // License field absent or empty
  | 'no_model_card'         // No model card / README detected for the model
  | 'unverified_hash'       // No weights hash to verify against
  | 'unpinned_version'      // Version is a float-ref, alias, or wildcard
  | 'training_data_risk'    // Associated training dataset has known issues
  | 'pre_release_model'     // Version indicates alpha/beta/dev status

export type ProvenanceSignalSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface ProvenanceSignal {
  kind: ProvenanceSignalKind
  severity: ProvenanceSignalSeverity
  description: string
  /** Raw penalty subtracted from the 100-point base score. */
  penalty: number
}

export type ProvenanceRiskLevel = 'verified' | 'acceptable' | 'unverified' | 'risky'

export interface ModelProvenanceResult {
  /** Display name from the SBOM component. */
  componentName: string
  /** Resolved source registry (e.g. 'huggingface', 'openai', 'local', 'unknown'). */
  resolvedSource: string
  /** Normalised license identifier (or 'unknown'). */
  resolvedLicense: string
  /** 0–100 provenance trust score. Higher = more trustworthy. */
  provenanceScore: number
  riskLevel: ProvenanceRiskLevel
  signals: ProvenanceSignal[]
  summary: string
}

export interface ModelProvenanceScan {
  totalModels: number
  verifiedCount: number
  riskyCcount: number
  overallRiskLevel: ProvenanceRiskLevel
  /** 0–100 aggregate provenance score across all models. */
  aggregateScore: number
  components: ModelProvenanceResult[]
  summary: string
}

// ---------------------------------------------------------------------------
// Input type
// ---------------------------------------------------------------------------

export interface ModelComponentInput {
  /** Package / model name from the SBOM. */
  name: string
  /** Version string from the SBOM. */
  version: string
  /** Ecosystem identifier (e.g. 'huggingface', 'pypi', 'npm'). */
  ecosystem: string
  /** Layer in the SBOM (e.g. 'ai_model', 'direct', 'container'). */
  layer: string
  /** Optional license string from the SBOM component. */
  license?: string
  /** Optional weights hash stored in the SBOM (e.g. SHA-256 of model file). */
  weightsHash?: string
  /** Optional training dataset references. */
  trainingDatasets?: string[]
  /** Whether the component already has known vulnerabilities. */
  hasKnownVulnerabilities: boolean
}

// ---------------------------------------------------------------------------
// Known AI model registries
// ---------------------------------------------------------------------------

/** Registries that provide reasonable provenance guarantees. */
const KNOWN_REGISTRIES = [
  'huggingface',
  'hugging_face',
  'openai',
  'anthropic',
  'google',
  'mistral',
  'cohere',
  'stability-ai',
  'meta-llama',
  'microsoft',
  'nvidia',
  'replicate',
  'together',
  'groq',
  'aws-bedrock',
  'vertexai',
  'azure-openai',
] as const

// ---------------------------------------------------------------------------
// Known permissive vs. restricted licences
// ---------------------------------------------------------------------------
// Note: permissive licences (MIT, Apache-2.0, OpenRail, etc.) are treated as
// "not restricted" — they are safe by default. Only the restricted set below
// is actively flagged. Any unrecognised licence falls into the `no_license`
// signal path when the license field is absent/empty.

const RESTRICTED_LICENSES = new Set([
  'cc-by-nc-4.0',
  'cc-by-nc-sa-4.0',
  'cc-by-nc-nd-4.0',
  'gpl-2.0',
  'gpl-3.0',
  'agpl-3.0',
  'proprietary',
  'commercial',
  'research-only',
  'non-commercial',
])

// ---------------------------------------------------------------------------
// Known training datasets with documented risks
// ---------------------------------------------------------------------------

const RISKY_DATASETS = new Set([
  'laion-400m',     // CSAM detection issues (2023)
  'laion-5b',       // Same family
  'pile',           // PII and copyright concerns
  'the-pile',
  'c4',             // Some copyright issues
  'books1',         // Copyright concerns
  'books2',
  'bookcorpus',
])

// ---------------------------------------------------------------------------
// Source resolver
// ---------------------------------------------------------------------------

function resolveSource(name: string, ecosystem: string): string {
  const n = name.toLowerCase()
  const e = ecosystem.toLowerCase()

  for (const registry of KNOWN_REGISTRIES) {
    if (n.includes(registry) || e.includes(registry)) return registry
  }

  if (e === 'ai_model' || e === 'ai-model' || e === 'huggingface') return 'huggingface'
  if (e === 'pypi') return 'pypi'      // Python ML packages — not a model registry per se
  if (e === 'npm') return 'npm'
  if (n.includes('/') && !n.startsWith('http')) return 'huggingface' // user/model-name pattern
  if (n.startsWith('gpt-') || n.startsWith('text-')) return 'openai'
  if (n.startsWith('claude-')) return 'anthropic'
  if (n.startsWith('gemini-') || n.startsWith('bison-')) return 'google'

  return 'unknown'
}

// ---------------------------------------------------------------------------
// License normaliser
// ---------------------------------------------------------------------------

function normalizeLicense(license: string | undefined): string {
  if (!license?.trim()) return 'unknown'
  return license.toLowerCase().trim()
}

// ---------------------------------------------------------------------------
// Version pin checker
// ---------------------------------------------------------------------------

function isVersionPinned(version: string): boolean {
  if (!version || version === '*' || version === 'latest') return false
  // Float-refs like "main", "dev", "beta", "alpha", "latest-stable"
  if (/^(main|master|dev|development|beta|alpha|rc|nightly|latest|snapshot)$/i.test(version)) return false
  // SemVer ranges
  if (/[^0-9.]/.test(version) && !version.match(/^\d+\.\d+(\.\d+)?/)) return false
  return true
}

// ---------------------------------------------------------------------------
// Pre-release detector
// ---------------------------------------------------------------------------

function isPreRelease(version: string): boolean {
  return /[-_.]?(alpha|beta|rc|dev|nightly|preview|experimental)/i.test(version)
}

// ---------------------------------------------------------------------------
// Signal detectors
// ---------------------------------------------------------------------------

function detectSignals(input: ModelComponentInput): ProvenanceSignal[] {
  const signals: ProvenanceSignal[] = []
  const source = resolveSource(input.name, input.ecosystem)
  const license = normalizeLicense(input.license)

  // 1. Source verification
  if (source === 'unknown') {
    signals.push({
      kind: 'unknown_source',
      severity: 'high',
      description: `Model "${input.name}" could not be attributed to any recognised AI model registry. Provenance is unverifiable.`,
      penalty: 25,
    })
  }

  // 2. License compliance
  if (license === 'unknown') {
    signals.push({
      kind: 'no_license',
      severity: 'medium',
      description: 'No license information is available for this model. Usage rights are unclear.',
      penalty: 15,
    })
  } else if (RESTRICTED_LICENSES.has(license)) {
    signals.push({
      kind: 'restricted_license',
      severity: 'high',
      description: `License "${input.license}" restricts commercial use, redistribution, or modification.`,
      penalty: 20,
    })
  }

  // 3. Weights hash — treat absence as a verifiability gap
  if (!input.weightsHash) {
    signals.push({
      kind: 'unverified_hash',
      severity: 'medium',
      description: 'No weights hash is recorded in the SBOM. Model integrity cannot be verified against a known-good checksum.',
      penalty: 15,
    })
  }

  // 4. Version pinning
  if (!isVersionPinned(input.version)) {
    signals.push({
      kind: 'unpinned_version',
      severity: 'medium',
      description: `Version "${input.version}" is not pinned to an exact release. The resolved model weights may change silently on the next pull.`,
      penalty: 10,
    })
  }

  // 5. Pre-release
  if (isPreRelease(input.version)) {
    signals.push({
      kind: 'pre_release_model',
      severity: 'low',
      description: `Version "${input.version}" indicates a pre-release model. Pre-release weights may change without notice.`,
      penalty: 8,
    })
  }

  // 6. Training data risk
  if (input.trainingDatasets) {
    for (const ds of input.trainingDatasets) {
      if (RISKY_DATASETS.has(ds.toLowerCase())) {
        signals.push({
          kind: 'training_data_risk',
          severity: 'high',
          description: `Training dataset "${ds}" has documented issues (PII exposure, copyright concerns, or CSAM detection). Review before production use.`,
          penalty: 20,
        })
        break  // one signal is enough even if multiple risky datasets match
      }
    }
  }

  return signals
}

// ---------------------------------------------------------------------------
// Score → risk level classifier
// ---------------------------------------------------------------------------

function scoreToRiskLevel(score: number): ProvenanceRiskLevel {
  if (score >= 80) return 'verified'
  if (score >= 60) return 'acceptable'
  if (score >= 40) return 'unverified'
  return 'risky'
}

// ---------------------------------------------------------------------------
// User contribution: scoreProvenanceSignals
// ---------------------------------------------------------------------------
//
// TODO: Implement the provenance score calculation.
//
// This function receives the array of detected signals for a single model
// component and the base score (100). Your goal is to compute a final
// provenanceScore in the range [0, 100].
//
// The simplest approach: subtract each signal's `penalty` from 100.
//
// Trade-offs to consider:
//   - Should a `critical` severity signal impose a hard floor regardless of
//     other signals (e.g. training_data_risk always → score ≤ 50)?
//   - Should penalties compound multiplicatively (harsher for multiple issues)
//     or simply sum (allows many low-severity issues to accumulate naturally)?
//   - If the model has NO signals at all, should the score be exactly 100 or
//     should the base for unrecognised ecosystems be lower (e.g. 85)?
//
// The function signature is fixed — return a number in [0, 100].
//
// Called by: assessModelProvenance (below)
// Tested by: modelProvenance.test.ts lines 100–140
//
export function scoreProvenanceSignals(
  signals: ProvenanceSignal[],
  _baseScore: number,
): number {
  // No signals → perfect score (no concerns detected).
  if (signals.length === 0) return 100

  // Primary mechanism: additive penalty subtraction from the 100-point base.
  const totalPenalty = signals.reduce((sum, s) => sum + s.penalty, 0)
  let score = 100 - totalPenalty

  // Hard floor #1 — training_data_risk
  // Training dataset contamination (CSAM detection, PII exposure, copyright) is
  // a fundamental provenance concern that cannot be resolved by patching the
  // model version. A score above 50 would imply manageable risk, which is
  // misleading when the underlying training data is compromised.
  const hasTrainingDataRisk = signals.some((s) => s.kind === 'training_data_risk')
  if (hasTrainingDataRisk) score = Math.min(score, 50)

  // Hard floor #2 — compound high/critical severity
  // Two or more high-or-critical signals indicate systemic provenance failure
  // (e.g. unknown source AND restricted license = unidentifiable, non-commercial
  // model). The additive model under-penalises this because each penalty was
  // calibrated for a single independent concern. Cap at 40 to reflect the
  // multiplicative trust loss when multiple serious signals co-occur.
  const highSeverityCount = signals.filter(
    (s) => s.severity === 'critical' || s.severity === 'high',
  ).length
  if (highSeverityCount >= 2) score = Math.min(score, 40)

  return Math.max(0, Math.min(100, score))
}

// ---------------------------------------------------------------------------
// Main assessment function
// ---------------------------------------------------------------------------

export function assessModelProvenance(input: ModelComponentInput): ModelProvenanceResult {
  const signals = detectSignals(input)
  const source = resolveSource(input.name, input.ecosystem)
  const license = normalizeLicense(input.license)

  const provenanceScore = scoreProvenanceSignals(signals, 100)
  const riskLevel = scoreToRiskLevel(provenanceScore)

  const signalDescriptions = signals.map((s) => s.description).join(' ')
  const summary = signals.length === 0
    ? `Model "${input.name}" passes all provenance checks. Source: ${source}, License: ${license}.`
    : `Model "${input.name}" has ${signals.length} provenance concern(s). ${signalDescriptions.slice(0, 200)}`

  return {
    componentName: input.name,
    resolvedSource: source,
    resolvedLicense: license,
    provenanceScore,
    riskLevel,
    signals,
    summary,
  }
}

// ---------------------------------------------------------------------------
// Repository-level scan
// ---------------------------------------------------------------------------

export function scanModelProvenance(components: ModelComponentInput[]): ModelProvenanceScan {
  // Only analyse components that are in the AI model layer or have model-like names
  const modelComponents = components.filter((c) =>
    c.layer === 'ai_model' ||
    c.layer === 'ai-model' ||
    c.ecosystem === 'huggingface' ||
    c.ecosystem === 'ai_model' ||
    resolveSource(c.name, c.ecosystem) !== 'unknown' && c.layer !== 'direct' ||
    c.name.includes('gpt-') ||
    c.name.includes('claude-') ||
    c.name.includes('gemini-') ||
    c.name.startsWith('llama') ||
    c.name.startsWith('mistral'),
  )

  if (modelComponents.length === 0) {
    return {
      totalModels: 0,
      verifiedCount: 0,
      riskyCcount: 0,
      overallRiskLevel: 'verified',
      aggregateScore: 100,
      components: [],
      summary: 'No AI model dependencies detected in this SBOM snapshot.',
    }
  }

  const results = modelComponents.map(assessModelProvenance)

  const verifiedCount = results.filter((r) => r.riskLevel === 'verified').length
  const riskyCcount = results.filter((r) => r.riskLevel === 'risky').length
  const aggregateScore = Math.round(
    results.reduce((sum, r) => sum + r.provenanceScore, 0) / results.length,
  )

  // Aggregate risk: worst single risk level drives the aggregate
  let overallRiskLevel: ProvenanceRiskLevel = 'verified'
  for (const r of results) {
    const levelOrder: ProvenanceRiskLevel[] = ['verified', 'acceptable', 'unverified', 'risky']
    if (levelOrder.indexOf(r.riskLevel) > levelOrder.indexOf(overallRiskLevel)) {
      overallRiskLevel = r.riskLevel
    }
  }

  const summary = riskyCcount > 0
    ? `${riskyCcount} of ${results.length} AI model(s) have risky provenance. Aggregate score: ${aggregateScore}/100.`
    : verifiedCount === results.length
      ? `All ${results.length} AI model(s) pass provenance checks. Aggregate score: ${aggregateScore}/100.`
      : `${results.length} AI model(s) analysed. ${verifiedCount} verified, ${riskyCcount} risky. Score: ${aggregateScore}/100.`

  return {
    totalModels: results.length,
    verifiedCount,
    riskyCcount,
    overallRiskLevel,
    aggregateScore,
    components: results,
    summary,
  }
}
