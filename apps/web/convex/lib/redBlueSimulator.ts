// WS-14 Phase 2 — Adversarial Red-Blue Agent Loop (spec 3.3): local-first
// simulation library.
//
// No DB access. Takes a RepositoryMemoryRecord + blast radius context and
// produces an AdversarialRoundResult that is persisted by the Convex mutation.
//
// This is a deterministic simulation (no randomness) so test results are
// reproducible and the scheduler can re-run rounds without side-effects.

import type { RepositoryMemoryRecord } from './memoryController'

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

export type BlastRadiusSnapshotInput = {
  reachableServices: string[]
  exposedDataLayers: string[]
  directExposureCount: number
  attackPathDepth: number
  riskTier: string
} | null

export type AdversarialRoundInput = {
  repositoryMemory: RepositoryMemoryRecord
  blastRadiusSnapshot: BlastRadiusSnapshotInput
  openFindingCount: number
  roundNumber: number
  repositoryName: string
}

export type RoundOutcome = 'red_wins' | 'blue_wins' | 'draw'

export type AdversarialRoundResult = {
  /** What attack strategy the Red Agent selected this round. */
  redStrategySummary: string
  /** 0–100 estimate of attack surface covered this round. */
  attackSurfaceCoverage: number
  /** Number of simulated new findings the Red Agent would generate. */
  simulatedFindingsGenerated: number
  /** 0–100 Blue Agent detection capability for this round. */
  blueDetectionScore: number
  /** 1–3 short exploit chain descriptions derived from packageRiskMap + services. */
  exploitChains: string[]
  /** Round winner based on coverage vs detection thresholds. */
  roundOutcome: RoundOutcome
  /** 0–10 Red Agent confidence gain from this round. */
  confidenceGain: number
  /** 1–2 sentence narrative. */
  summary: string
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function capitalizeFirst(s: string): string {
  if (!s) return s
  return s.charAt(0).toUpperCase() + s.slice(1)
}

function riskTierBonus(riskTier: string): number {
  if (riskTier === 'critical') return 3
  if (riskTier === 'high') return 2
  return 1
}

/**
 * Choose an attack strategy based on the memory record and blast radius.
 * Grounded in the most recurring vuln class and reachable services.
 */
function buildRedStrategy(
  memory: RepositoryMemoryRecord,
  blast: BlastRadiusSnapshotInput,
): string {
  const topClass = memory.recurringVulnClasses[0]
  const classHint = topClass
    ? `targeting ${topClass.vulnClass.replaceAll('_', ' ')} (${topClass.count} historical hit${topClass.count === 1 ? '' : 's'})`
    : 'broad-spectrum recon sweep with no prior signal'

  const serviceHint =
    blast && blast.reachableServices.length > 0
      ? ` via ${blast.reachableServices.slice(0, 2).join(' and ')}`
      : ''

  return `${capitalizeFirst(classHint)}${serviceHint}.`
}

/**
 * Generate up to 3 exploit chain descriptions from the highest-risk packages
 * and reachable services.
 */
function buildExploitChains(
  memory: RepositoryMemoryRecord,
  blast: BlastRadiusSnapshotInput,
): string[] {
  const chains: string[] = []

  // Top packages by risk score as starting points
  const topPackages = Object.entries(memory.packageRiskMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)

  for (const [pkg, score] of topPackages) {
    const service = blast?.reachableServices[chains.length] ?? 'downstream service'
    chains.push(`${pkg} (score ${score}) → ${service}`)
  }

  // Fallback: depth-based chain when no package risk data
  if (chains.length === 0 && blast && blast.attackPathDepth > 0) {
    chains.push(
      `Depth-${blast.attackPathDepth} transitive chain traversal targeting ${blast.exposedDataLayers[0] ?? 'runtime'} layer`,
    )
  }

  if (chains.length === 0) {
    chains.push('No high-confidence exploit chains identified this round')
  }

  return chains.slice(0, 3)
}

// ---------------------------------------------------------------------------
// Core simulation
// ---------------------------------------------------------------------------

/**
 * Simulate one adversarial round.
 *
 * All formulas are specified in the WS-14 Phase 2 prompt and kept here
 * so the library is self-documenting.
 */
export function simulateAdversarialRound(
  input: AdversarialRoundInput,
): AdversarialRoundResult {
  const {
    repositoryMemory,
    blastRadiusSnapshot,
    openFindingCount,
    roundNumber,
    repositoryName,
  } = input

  const blast = blastRadiusSnapshot

  // ── Attack surface coverage (0–100) ──────────────────────────────────────
  // Formula: min(100, (direct×15) + (services×5) + (depth×10) + (findings×2))
  const directScore = (blast?.directExposureCount ?? 0) * 15
  const serviceScore = (blast?.reachableServices.length ?? 0) * 5
  const depthScore = (blast?.attackPathDepth ?? 0) * 10
  const findingScore = openFindingCount * 2
  const attackSurfaceCoverage = Math.min(
    100,
    directScore + serviceScore + depthScore + findingScore,
  )

  // ── Simulated findings generated ─────────────────────────────────────────
  // Formula: max(1, floor(openFindingCount × 0.3 + riskBonus))
  const riskBonus = riskTierBonus(blast?.riskTier ?? 'low')
  const simulatedFindingsGenerated = Math.max(
    1,
    Math.floor(openFindingCount * 0.3 + riskBonus),
  )

  // ── Blue detection score (0–100) ─────────────────────────────────────────
  // Formula: min(100, round((1 - falsePositiveRate) × 50 + roundNumber × 2))
  const blueDetectionScore = Math.min(
    100,
    Math.round(
      (1 - repositoryMemory.falsePositiveRate) * 50 + roundNumber * 2,
    ),
  )

  // ── Round outcome ─────────────────────────────────────────────────────────
  // red_wins  : detection < 40 AND coverage > 60
  // blue_wins : detection > 70
  // draw      : everything else
  let roundOutcome: RoundOutcome
  if (blueDetectionScore < 40 && attackSurfaceCoverage > 60) {
    roundOutcome = 'red_wins'
  } else if (blueDetectionScore > 70) {
    roundOutcome = 'blue_wins'
  } else {
    roundOutcome = 'draw'
  }

  // ── Red Agent confidence gain (0–10) ─────────────────────────────────────
  const winBonus =
    roundOutcome === 'red_wins' ? 3 : roundOutcome === 'draw' ? 1 : 0
  const confidenceGain = Math.min(
    10,
    Math.round((attackSurfaceCoverage / 100) * 5 + winBonus),
  )

  // ── Narrative content ─────────────────────────────────────────────────────
  const redStrategySummary = buildRedStrategy(repositoryMemory, blast)
  const exploitChains = buildExploitChains(repositoryMemory, blast)

  const outcomePhrase =
    roundOutcome === 'red_wins'
      ? 'Red Agent breached the surface'
      : roundOutcome === 'blue_wins'
        ? 'Blue Agent held the perimeter'
        : 'inconclusive engagement'

  const summary = `Round ${roundNumber} for ${repositoryName}: ${outcomePhrase}. Coverage ${attackSurfaceCoverage}%, detection ${blueDetectionScore}%, ${simulatedFindingsGenerated} simulated finding${simulatedFindingsGenerated === 1 ? '' : 's'} generated.`

  return {
    redStrategySummary,
    attackSurfaceCoverage,
    simulatedFindingsGenerated,
    blueDetectionScore,
    exploitChains,
    roundOutcome,
    confidenceGain,
    summary,
  }
}
