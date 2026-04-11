// WS-14 Phase 4 — Red Agent Finding Escalation (spec 3.1.2): pure escalation
// library.
//
// No DB access. When the Red Agent wins an adversarial round its exploit chains
// are high-signal candidates for real security findings. This library converts
// an AdversarialRoundResult into a structured list of FindingCandidates that
// the Convex mutation can persist to the findings table.
//
// Exploit chain format produced by redBlueSimulator.ts:
//   • "{pkg} (score {N}) → {service}"  — package-based chain
//   • "Depth-{N} transitive chain traversal targeting {layer} layer" — depth-based
//   • "No high-confidence exploit chains identified this round"        — skip
//
// Each meaningful chain becomes one FindingCandidate. Fallback/empty chains
// are silently dropped; if no candidates survive filtering the caller should
// skip persistence.

import type { AdversarialRoundResult } from './redBlueSimulator'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FindingSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export type FindingCandidate = {
  /** Structured vulnerability class label. */
  vulnClass: string
  /** Short human-readable title for the finding. */
  title: string
  /** Longer narrative combining chain text and round context. */
  summary: string
  /** 0–1 confidence derived from Red Agent confidenceGain (0–10). */
  confidence: number
  severity: FindingSeverity
  /** Business impact 0–100, severity-derived (no direct-exposure bonus for synthetic findings). */
  businessImpactScore: number
  /** Package names extracted from the exploit chain. */
  affectedPackages: string[]
  /** Service names extracted from the exploit chain. */
  affectedServices: string[]
  /** One-sentence blast radius hint. */
  blastRadiusSummary: string
}

export type EscalationResult = {
  candidates: FindingCandidate[]
  /** Prose summary for the ingestion event. */
  escalationSummary: string
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const NO_CHAINS_SENTINEL =
  'No high-confidence exploit chains identified this round'

// Pattern: "{pkg} (score {N}) → {service}"
const PACKAGE_CHAIN_RE = /^(.+?)\s+\(score\s+(\d+)\)\s+→\s+(.+)$/

// Pattern: "Depth-{N} transitive chain traversal targeting {layer} layer"
const DEPTH_CHAIN_RE =
  /^Depth-(\d+) transitive chain traversal targeting (.+) layer$/

// ---------------------------------------------------------------------------
// Severity / impact helpers
// ---------------------------------------------------------------------------

function severityFromScore(score: number): FindingSeverity {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

// Intentionally lower than confirmed-finding scores: synthetic findings lack
// direct-exposure and exploit-availability confirmation, so a separate table
// keeps that distinction explicit rather than calling businessImpactScoreForSeverity
// with zero bonuses (which would create a cross-lib dependency for a pure module).
const BUSINESS_IMPACT: Record<FindingSeverity, number> = {
  critical: 88,
  high: 72,
  medium: 52,
  low: 36,
  informational: 15,
}

// ---------------------------------------------------------------------------
// Chain parsers
// ---------------------------------------------------------------------------

type ParsedChain =
  | { kind: 'package'; pkg: string; score: number; service: string }
  | { kind: 'depth'; depth: number; layer: string }
  | { kind: 'skip' }

function parseChain(chain: string): ParsedChain {
  if (chain === NO_CHAINS_SENTINEL) return { kind: 'skip' }

  const packageMatch = PACKAGE_CHAIN_RE.exec(chain)
  if (packageMatch) {
    return {
      kind: 'package',
      pkg: packageMatch[1].trim(),
      score: parseInt(packageMatch[2], 10),
      service: packageMatch[3].trim(),
    }
  }

  const depthMatch = DEPTH_CHAIN_RE.exec(chain)
  if (depthMatch) {
    return {
      kind: 'depth',
      depth: parseInt(depthMatch[1], 10),
      layer: depthMatch[2].trim(),
    }
  }

  // Unrecognised format — treat as skip rather than crashing.
  return { kind: 'skip' }
}

// ---------------------------------------------------------------------------
// Candidate builders
// ---------------------------------------------------------------------------

function buildPackageCandidate(
  parsed: Extract<ParsedChain, { kind: 'package' }>,
  roundNumber: number,
  repositoryName: string,
  confidence: number,
): FindingCandidate {
  const severity = severityFromScore(parsed.score)
  return {
    vulnClass: 'vulnerable_dependency',
    title: `Red Agent exploit: ${parsed.pkg} → ${parsed.service}`,
    summary: `Red Agent (round ${roundNumber}) identified a ${severity} exploit path in ${repositoryName}: ${parsed.pkg} (risk score ${parsed.score}) reaches ${parsed.service}. Escalated from a red_wins adversarial round for immediate triage.`,
    confidence,
    severity,
    businessImpactScore: BUSINESS_IMPACT[severity],
    affectedPackages: [parsed.pkg],
    affectedServices: [parsed.service],
    blastRadiusSummary: `${parsed.pkg} (score ${parsed.score}) can be leveraged to reach ${parsed.service}.`,
  }
}

function buildDepthCandidate(
  parsed: Extract<ParsedChain, { kind: 'depth' }>,
  roundNumber: number,
  repositoryName: string,
  coverage: number,
  confidence: number,
): FindingCandidate {
  const severity = severityFromScore(coverage)
  return {
    vulnClass: 'supply_chain_traversal',
    title: `Red Agent exploit: depth-${parsed.depth} traversal → ${parsed.layer} layer`,
    summary: `Red Agent (round ${roundNumber}) identified a depth-${parsed.depth} transitive chain traversal in ${repositoryName} reaching the ${parsed.layer} layer. Attack surface coverage was ${coverage}%. Escalated from a red_wins adversarial round for immediate triage.`,
    confidence,
    severity,
    businessImpactScore: BUSINESS_IMPACT[severity],
    affectedPackages: [],
    affectedServices: [parsed.layer],
    blastRadiusSummary: `Transitive dependency chain of depth ${parsed.depth} reaches the ${parsed.layer} layer.`,
  }
}

// ---------------------------------------------------------------------------
// Core export
// ---------------------------------------------------------------------------

/**
 * Convert a red_wins AdversarialRoundResult into escalation candidates.
 *
 * Returns an empty candidates list if no meaningful exploit chains exist.
 * The caller is responsible for skipping persistence in that case.
 */
export function escalateRedAgentRound(input: {
  round: AdversarialRoundResult
  roundNumber: number
  repositoryName: string
}): EscalationResult {
  const { round, roundNumber, repositoryName } = input

  // confidence: map 0–10 gain to 0–1 float, minimum 0.3 for red_wins
  const confidence = Math.max(0.3, Math.min(1, round.confidenceGain / 10))

  const candidates: FindingCandidate[] = []

  for (const chain of round.exploitChains) {
    const parsed = parseChain(chain)

    if (parsed.kind === 'package') {
      candidates.push(
        buildPackageCandidate(parsed, roundNumber, repositoryName, confidence),
      )
    } else if (parsed.kind === 'depth') {
      candidates.push(
        buildDepthCandidate(
          parsed,
          roundNumber,
          repositoryName,
          round.attackSurfaceCoverage,
          confidence,
        ),
      )
    }
    // skip: nothing to add
  }

  const escalationSummary =
    candidates.length === 0
      ? `Red Agent won round ${roundNumber} for ${repositoryName} but produced no parseable exploit chains.`
      : `Red Agent won round ${roundNumber} for ${repositoryName}; ${candidates.length} exploit chain${candidates.length === 1 ? '' : 's'} escalated as candidate finding${candidates.length === 1 ? '' : 's'}.`

  return { candidates, escalationSummary }
}
