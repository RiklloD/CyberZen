// WS-14 Phase 1 — Blast Radius Causality Graph: pure computation library.
//
// No DB access. All intelligence lives here; Convex mutations are persistence
// wrappers only. This design keeps the library fully unit-testable without
// spinning up a Convex environment.
//
// Formula (from spec, Section 3.5):
//   businessImpactScore =
//     (severity_weight × 40)
//     + (directExposureCount × 20, capped at 30)
//     + (exploitAvailable ? 20 : 0)
//     + (transitiveExposureCount > 5 ? 10 : 0)
//
// Severity weights: critical=1.0, high=0.75, medium=0.5, low=0.25, informational=0

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type SbomComponentInput = {
  name: string
  normalizedName: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  hasKnownVulnerabilities: boolean
  dependents: string[]
}

export type FindingInput = {
  affectedPackages: string[]
  affectedFiles: string[]
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  source: string
  exploitAvailable?: boolean
}

export type BlastRadiusInput = {
  finding: FindingInput
  components: SbomComponentInput[]
  repositoryName: string
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type RiskTier = 'critical' | 'high' | 'medium' | 'low'

export type BlastRadiusResult = {
  /** Services that depend on the affected package (derived from components[].dependents). */
  reachableServices: string[]
  /** Unique dependency layers present in the blast path (e.g. 'direct', 'transitive', 'container'). */
  exposedDataLayers: string[]
  /** How many direct-dependency components are in the blast path. */
  directExposureCount: number
  /** How many transitive components are in the blast path. */
  transitiveExposureCount: number
  /** Max dependency-chain depth from the finding to a service root. */
  attackPathDepth: number
  /** 0–100 weighted business impact score. */
  businessImpactScore: number
  /** 1–2 sentence human-readable impact statement. */
  summary: string
  /** Bucketed risk tier derived from businessImpactScore. */
  riskTier: RiskTier
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
  informational: 0,
}

function severityWeight(severity: string): number {
  return SEVERITY_WEIGHT[severity] ?? 0.25
}

function uniqueStrings(arr: string[]): string[] {
  return [...new Set(arr.filter(Boolean))]
}

/** Convert a numeric score into a bucketed risk tier. */
function scoreToRiskTier(score: number): RiskTier {
  if (score >= 75) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

/**
 * Estimate the attack path depth for a single component.
 * - Direct dependencies: depth 1 (attacker targets the vulnerable pkg directly)
 * - Container-layer deps: depth 3 (rooted deep in an image layer)
 * - All other transitive deps: depth 2 (one hop from the vulnerable pkg to the repo)
 */
function componentDepth(component: SbomComponentInput): number {
  if (component.layer === 'container') return 3
  if (!component.isDirect) return 2
  return 1
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildSummary(args: {
  repositoryName: string
  directExposureCount: number
  transitiveExposureCount: number
  reachableServiceCount: number
  riskTier: RiskTier
  severity: string
}): string {
  const {
    repositoryName,
    directExposureCount,
    transitiveExposureCount,
    reachableServiceCount,
    riskTier,
    severity,
  } = args

  if (directExposureCount + transitiveExposureCount === 0) {
    return `No matched components found in ${repositoryName}; blast radius is contained.`
  }

  const exposureParts: string[] = []
  if (directExposureCount > 0) {
    exposureParts.push(
      `${directExposureCount} direct dependency path${directExposureCount === 1 ? '' : 's'}`,
    )
  }
  if (transitiveExposureCount > 0) {
    exposureParts.push(
      `${transitiveExposureCount} transitive path${transitiveExposureCount === 1 ? '' : 's'}`,
    )
  }

  const exposurePhrase = exposureParts.join(' and ')
  const servicePhrase =
    reachableServiceCount > 1
      ? ` with blast radius reaching ${reachableServiceCount} dependent services`
      : ''

  const capitalSeverity = severity.charAt(0).toUpperCase() + severity.slice(1)
  return `${capitalSeverity} exposure in ${repositoryName} through ${exposurePhrase}${servicePhrase}. Risk tier: ${riskTier}.`
}

// ---------------------------------------------------------------------------
// Core computation
// ---------------------------------------------------------------------------

/**
 * Compute the blast radius for a given finding + SBOM component set.
 * Pure function — no async, no DB calls, O(n) where n = components.length.
 */
export function computeBlastRadius(input: BlastRadiusInput): BlastRadiusResult {
  const { finding, components, repositoryName } = input

  // Build a lowercase set for fast package name matching.
  const affectedSet = new Set(
    finding.affectedPackages.map((p) => p.toLowerCase().trim()),
  )

  // Find SBOM components that match the vulnerable packages.
  const affectedComponents = components.filter(
    (c) =>
      affectedSet.has(c.name.toLowerCase().trim()) ||
      affectedSet.has(c.normalizedName.toLowerCase().trim()),
  )

  const directComponents = affectedComponents.filter((c) => c.isDirect)
  const transitiveComponents = affectedComponents.filter((c) => !c.isDirect)

  const directExposureCount = directComponents.length
  const transitiveExposureCount = transitiveComponents.length

  // Union of all service names that depend on the affected packages.
  const serviceNames = affectedComponents.flatMap((c) => c.dependents)
  // Include the repository itself when there are direct hits.
  if (directExposureCount > 0) {
    serviceNames.push(repositoryName)
  }
  const reachableServices = uniqueStrings(serviceNames)

  // Unique dependency layers present in the blast path.
  const exposedDataLayers = uniqueStrings(affectedComponents.map((c) => c.layer))

  // Max chain depth across all affected components.
  const attackPathDepth = affectedComponents.reduce(
    (max, c) => Math.max(max, componentDepth(c)),
    0,
  )

  // Business impact score (0–100) per spec formula.
  const sw = severityWeight(finding.severity)
  const directScore = Math.min(directExposureCount * 20, 30)
  const exploitScore = finding.exploitAvailable ? 20 : 0
  const transitiveBonus = transitiveExposureCount > 5 ? 10 : 0
  const businessImpactScore = Math.min(
    Math.round(sw * 40 + directScore + exploitScore + transitiveBonus),
    100,
  )

  const riskTier = scoreToRiskTier(businessImpactScore)

  const summary = buildSummary({
    repositoryName,
    directExposureCount,
    transitiveExposureCount,
    reachableServiceCount: reachableServices.length,
    riskTier,
    severity: finding.severity,
  })

  return {
    reachableServices,
    exposedDataLayers,
    directExposureCount,
    transitiveExposureCount,
    attackPathDepth,
    businessImpactScore,
    summary,
    riskTier,
  }
}
