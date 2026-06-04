/**
 * HuggingFace API enrichment — pure parser library (no network, no Convex).
 *
 * Spec §3.11.2 Layer 6 — "AI Model Dependencies":
 *   Enriches AI model SBOM components with live metadata from the HuggingFace
 *   Hub: commit SHA (lineage), license, model card presence, training datasets,
 *   and gating status.
 *
 * Design notes:
 *   - This file is a pure parser. The HTTP fetch happens in the action layer
 *     (modelProvenanceIntel.ts). Inputs here are already-fetched JSON objects.
 *   - `commitSha` is the git commit hash of the model repo — it is a lineage
 *     reference, NOT a weights integrity hash. The two must not be conflated:
 *     a commit SHA tells you which revision was recorded; a weights hash would
 *     verify the binary after download. The SBOM `weightsHash` field remains
 *     for explicit binary hashes supplied by the operator.
 *   - HF API endpoint: GET https://huggingface.co/api/models/{org}/{model}
 *     Auth: optional `Authorization: Bearer <HUGGINGFACE_API_TOKEN>` header.
 *     Public models do not require auth; auth raises the rate limit.
 */

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export interface HFModelEnrichment {
  /** Canonical HuggingFace model ID, e.g. "meta-llama/Llama-2-7b". */
  modelId: string
  /**
   * Git commit SHA of the model repo at the time of the API call.
   * Acts as a provenance lineage reference, NOT a binary weights hash.
   * Use for "did the model revision change unexpectedly?" checks.
   */
  commitSha: string | null
  /** SPDX-style license identifier extracted from cardData or tags. */
  license: string | null
  /** True when README.md exists in the model repo siblings. */
  modelCardPresent: boolean
  /**
   * Training dataset references extracted from cardData.datasets and
   * `dataset:` prefixed tags. Empty array when none are declared.
   */
  trainingDatasets: string[]
  /**
   * True when the model requires HuggingFace account acceptance of a gating
   * agreement. Affects deployability in airgapped / restricted environments.
   */
  isGated: boolean
  /** Pipeline tag, e.g. "text-generation", "feature-extraction". */
  pipelineTag: string | null
  /** ISO 8601 last-modified timestamp from the HF API. */
  lastModified: string | null
}

/** Returned when the API response cannot be parsed or indicates an error. */
export interface HFEnrichmentFailure {
  modelId: string
  error: string
}

export type HFEnrichmentResult =
  | ({ ok: true } & HFModelEnrichment)
  | ({ ok: false } & HFEnrichmentFailure)

// ---------------------------------------------------------------------------
// HuggingFace component identification
// ---------------------------------------------------------------------------

/**
 * Returns true when an SBOM component should be enriched via the HF API.
 *
 * Priority rules (applied in order):
 *   1. Ecosystem explicitly names HuggingFace → definitive match.
 *   2. Ecosystem is a generic AI model layer + name is org/model format →
 *      strong signal (avoids enriching Python/npm packages that happen to
 *      have a slash in their scope path).
 *
 * Excluded by design:
 *   - npm scoped packages start with '@' (e.g. '@openai/api') — the '@'
 *     prefix is a reliable exclusion signal.
 *   - Go module paths include a hostname segment (e.g. 'github.com/foo/bar')
 *     which is caught by the multi-segment path guard.
 */
export function isHuggingFaceComponent(
  name: string,
  ecosystem: string,
  layer: string,
): boolean {
  // A blank name can never be resolved to an HF model ID — reject early
  // regardless of ecosystem so we don't enqueue a useless API call.
  if (!name) return false

  const eco = ecosystem.toLowerCase()
  const lyr = layer.toLowerCase()

  // Rule 1: ecosystem explicitly says HuggingFace AND name is a valid org/model
  // HF model IDs are always "org/model" (two segments) — reject longer paths.
  if ((eco === 'huggingface' || eco === 'hugging_face') && isOrgModelPattern(name)) return true

  // Rule 2: AI model layer + org/model pattern
  //   Accepts:  "meta-llama/Llama-2-7b"       (single slash, no @, no hostname)
  //   Rejects:  "@openai/api"                  (@ prefix)
  //   Rejects:  "github.com/owner/repo"        (3+ segments)
  if ((lyr === 'ai_model' || lyr === 'ai-model') && isOrgModelPattern(name)) {
    return true
  }

  return false
}

/**
 * Extract the HuggingFace model ID from a component name.
 *
 * Returns the name verbatim when it already matches the org/model pattern,
 * or null when the name cannot be reliably mapped to an HF model ID.
 */
export function extractHFModelId(name: string): string | null {
  if (!name) return null
  if (isOrgModelPattern(name)) return name
  return null
}

/** True for "org/model" — exactly one slash, no '@', no hostname dots in path. */
function isOrgModelPattern(name: string): boolean {
  if (name.startsWith('@')) return false
  const parts = name.split('/')
  if (parts.length !== 2) return false
  const [org, model] = parts
  if (!org || !model) return false
  // Reject hostname-style orgs (github.com, cdn.example.com)
  if (org.includes('.')) return false
  return true
}

// ---------------------------------------------------------------------------
// HF API response parser
// ---------------------------------------------------------------------------

/**
 * Parse the JSON body of a HuggingFace /api/models/{id} response.
 *
 * Tolerant to missing / extra fields — returns null for any field the API
 * omits rather than throwing. The caller decides how to handle partial data.
 */
export function parseHFApiResponse(
  modelId: string,
  // biome-ignore lint/suspicious/noExplicitAny: HF API response is untyped
  json: Record<string, any>,
): HFEnrichmentResult {
  try {
    const commitSha: string | null =
      typeof json.sha === 'string' ? json.sha : null

    // License — prefer cardData.license, fall back to tags "license:<id>"
    const cardLicense: string | undefined = json.cardData?.license
    const tagLicense = extractTagValue(json.tags, 'license')
    const license: string | null = cardLicense ?? tagLicense ?? null

    // Model card — README.md in siblings list
    const siblings: { rfilename?: string }[] = Array.isArray(json.siblings)
      ? json.siblings
      : []
    const modelCardPresent = siblings.some(
      (s) => s.rfilename?.toLowerCase() === 'readme.md',
    )

    // Training datasets — cardData.datasets union with "dataset:<id>" tags
    const cardDatasets: string[] = Array.isArray(json.cardData?.datasets)
      ? (json.cardData.datasets as string[]).filter((d) => typeof d === 'string')
      : []
    const tagDatasets: string[] = extractAllTagValues(json.tags, 'dataset')
    const trainingDatasets = dedupeStrings([...cardDatasets, ...tagDatasets])

    // Gated — boolean or "auto"/"manual" string both mean gated
    const isGated: boolean =
      json.gated === true ||
      json.gated === 'auto' ||
      json.gated === 'manual'

    const pipelineTag: string | null =
      typeof json.pipeline_tag === 'string' ? json.pipeline_tag : null

    const lastModified: string | null =
      typeof json.lastModified === 'string' ? json.lastModified : null

    return {
      ok: true,
      modelId,
      commitSha,
      license,
      modelCardPresent,
      trainingDatasets,
      isGated,
      pipelineTag,
      lastModified,
    }
  } catch (err) {
    return {
      ok: false,
      modelId,
      error: err instanceof Error ? err.message : 'parse_error',
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the value from the first tag matching "prefix:<value>".
 * Returns null when no matching tag exists.
 */
function extractTagValue(
  tags: unknown,
  prefix: string,
): string | null {
  if (!Array.isArray(tags)) return null
  for (const tag of tags) {
    if (typeof tag === 'string' && tag.startsWith(`${prefix}:`)) {
      return tag.slice(prefix.length + 1)
    }
  }
  return null
}

/** Extract all values from tags matching "prefix:<value>". */
function extractAllTagValues(tags: unknown, prefix: string): string[] {
  if (!Array.isArray(tags)) return []
  const results: string[] = []
  for (const tag of tags) {
    if (typeof tag === 'string' && tag.startsWith(`${prefix}:`)) {
      results.push(tag.slice(prefix.length + 1))
    }
  }
  return results
}

/** Deduplicate an array of strings, case-insensitively. */
function dedupeStrings(arr: string[]): string[] {
  const seen = new Set<string>()
  return arr.filter((s) => {
    const key = s.toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
