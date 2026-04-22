/**
 * WS-44 — Supply Chain Posture Score: pure computation library.
 *
 * Aggregates the outputs of five supply-chain scanners (EOL Detection,
 * Abandonment Detection, CVE Version Scanner, Malicious Package Detection,
 * Dependency Confusion Attack Detector) plus SBOM attestation status into a
 * single 0–100 posture score and A–F grade.
 *
 * Design: The posture scorer is intentionally decoupled from the five
 * sub-scanner libraries. It accepts pre-shaped summary inputs so it can be
 * tested in isolation without importing the full sub-scanner databases.
 * The Intel module (`supplyChainPostureIntel.ts`) is responsible for calling
 * each sub-scanner, extracting the summary fields, and feeding them here.
 *
 * Penalty model (applied additively, each category capped):
 *
 *   CVE (cap –50):         –15 × critical + –8 × high + –4 × medium
 *   Malicious (cap –50):   –25 × critical + –12 × high
 *   Confusion (cap –40):   –20 × critical + –10 × high
 *   Abandonment (cap –35): –20 × critical + –10 × high
 *   EOL (cap –25):         –8 × eolCount  + –4 × nearEolCount
 *   Attestation:           –20 if tampered / –5 if unverified|none / 0 if valid
 *
 * Grade thresholds:
 *   A ≥ 90 | B ≥ 75 | C ≥ 55 | D ≥ 35 | F < 35
 *
 * Risk level:
 *   critical — any critical-severity finding, or score < 40
 *   high     — any high-severity finding, or score < 60
 *   medium   — score < 75
 *   low      — score < 90
 *   clean    — score ≥ 90
 */

// ---------------------------------------------------------------------------
// Penalty constants (exported so tests and the Intel module can reference them)
// ---------------------------------------------------------------------------

export const CVE_CRITICAL_PENALTY = 15
export const CVE_HIGH_PENALTY = 8
export const CVE_MEDIUM_PENALTY = 4
export const CVE_CAP = 50

export const MALICIOUS_CRITICAL_PENALTY = 25
export const MALICIOUS_HIGH_PENALTY = 12
export const MALICIOUS_CAP = 50

export const CONFUSION_CRITICAL_PENALTY = 20
export const CONFUSION_HIGH_PENALTY = 10
export const CONFUSION_CAP = 40

export const ABANDONMENT_CRITICAL_PENALTY = 20
export const ABANDONMENT_HIGH_PENALTY = 10
export const ABANDONMENT_CAP = 35

export const EOL_EOL_PENALTY = 8
export const EOL_NEAR_EOL_PENALTY = 4
export const EOL_CAP = 25

export const ATTESTATION_TAMPERED_PENALTY = 20
export const ATTESTATION_UNVERIFIED_PENALTY = 5

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationStatus = 'valid' | 'tampered' | 'unverified' | 'none'

export type BreakdownCategory =
  | 'cve'
  | 'malicious'
  | 'confusion'
  | 'abandonment'
  | 'eol'
  | 'attestation'

export type PostureBreakdownEntry = {
  category: BreakdownCategory
  label: string
  penalty: number
  detail: string
}

export type PostureGrade = 'A' | 'B' | 'C' | 'D' | 'F'

export type PostureRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean'

/** Summary inputs from each sub-scanner (counts only — no finding arrays). */
export type SupplyChainPostureInput = {
  componentCount: number
  /** From computeCveReport */
  cve: {
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
    overallRisk: string
  }
  /** From computeMaliciousReport */
  malicious: {
    criticalCount: number
    highCount: number
    overallRisk: string
  }
  /** From computeConfusionReport */
  confusion: {
    criticalCount: number
    highCount: number
    overallRisk: string
  }
  /** From computeAbandonmentReport */
  abandonment: {
    criticalCount: number
    highCount: number
    overallRisk: string
  }
  /** From computeEolReport */
  eol: {
    eolCount: number
    nearEolCount: number
    overallStatus: string
  }
  attestationStatus: AttestationStatus
}

export type SupplyChainPostureResult = {
  /** 0–100 composite score. Higher = healthier. */
  score: number
  /** Letter grade derived from score thresholds. */
  grade: PostureGrade
  /** Severity classification for dashboard colouring. */
  riskLevel: PostureRiskLevel
  /** Per-category penalty breakdown (only categories with non-zero penalty). */
  breakdown: PostureBreakdownEntry[]
  /** Human-readable one-line summary. */
  summary: string
  /** Pass-through per-scanner risk strings for secondary display. */
  cveRisk: string
  maliciousRisk: string
  confusionRisk: string
  abandonmentRisk: string
  eolRisk: string
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/** Convert a numeric score (0–100) to its letter grade. */
export function scoreToGrade(score: number): PostureGrade {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 55) return 'C'
  if (score >= 35) return 'D'
  return 'F'
}

/**
 * Derive the risk level from the score and the presence of critical/high
 * findings. Critical findings always escalate to 'critical' regardless of
 * the numeric score.
 */
export function scoreToRiskLevel(
  score: number,
  hasCritical: boolean,
  hasHigh: boolean,
): PostureRiskLevel {
  if (hasCritical || score < 40) return 'critical'
  if (hasHigh || score < 60) return 'high'
  if (score < 75) return 'medium'
  if (score < 90) return 'low'
  return 'clean'
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

export function computeSupplyChainPosture(
  input: SupplyChainPostureInput,
): SupplyChainPostureResult {
  const breakdown: PostureBreakdownEntry[] = []
  let totalPenalty = 0

  // ── CVE penalty ─────────────────────────────────────────────────────────
  {
    const raw =
      input.cve.criticalCount * CVE_CRITICAL_PENALTY +
      input.cve.highCount * CVE_HIGH_PENALTY +
      input.cve.mediumCount * CVE_MEDIUM_PENALTY
    const penalty = Math.min(raw, CVE_CAP)
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'cve',
        label: 'Known CVEs',
        penalty,
        detail: buildDetail([
          [input.cve.criticalCount, 'critical'],
          [input.cve.highCount, 'high'],
          [input.cve.mediumCount, 'medium'],
        ]),
      })
    }
  }

  // ── Malicious package penalty ────────────────────────────────────────────
  {
    const raw =
      input.malicious.criticalCount * MALICIOUS_CRITICAL_PENALTY +
      input.malicious.highCount * MALICIOUS_HIGH_PENALTY
    const penalty = Math.min(raw, MALICIOUS_CAP)
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'malicious',
        label: 'Malicious packages',
        penalty,
        detail: buildDetail([
          [input.malicious.criticalCount, 'confirmed malicious'],
          [input.malicious.highCount, 'suspected typosquat'],
        ]),
      })
    }
  }

  // ── Dependency confusion penalty ─────────────────────────────────────────
  {
    const raw =
      input.confusion.criticalCount * CONFUSION_CRITICAL_PENALTY +
      input.confusion.highCount * CONFUSION_HIGH_PENALTY
    const penalty = Math.min(raw, CONFUSION_CAP)
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'confusion',
        label: 'Dependency confusion',
        penalty,
        detail: buildDetail([
          [input.confusion.criticalCount, 'critical signal'],
          [input.confusion.highCount, 'high signal'],
        ]),
      })
    }
  }

  // ── Abandonment penalty ──────────────────────────────────────────────────
  {
    const raw =
      input.abandonment.criticalCount * ABANDONMENT_CRITICAL_PENALTY +
      input.abandonment.highCount * ABANDONMENT_HIGH_PENALTY
    const penalty = Math.min(raw, ABANDONMENT_CAP)
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'abandonment',
        label: 'Abandoned packages',
        penalty,
        detail: buildDetail([
          [input.abandonment.criticalCount, 'supply-chain-compromised'],
          [input.abandonment.highCount, 'archived/unmaintained'],
        ]),
      })
    }
  }

  // ── EOL penalty ──────────────────────────────────────────────────────────
  {
    const raw =
      input.eol.eolCount * EOL_EOL_PENALTY +
      input.eol.nearEolCount * EOL_NEAR_EOL_PENALTY
    const penalty = Math.min(raw, EOL_CAP)
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'eol',
        label: 'End-of-life components',
        penalty,
        detail: buildDetail([
          [input.eol.eolCount, 'EOL'],
          [input.eol.nearEolCount, 'near-EOL'],
        ]),
      })
    }
  }

  // ── Attestation penalty ──────────────────────────────────────────────────
  {
    const penalty =
      input.attestationStatus === 'tampered'
        ? ATTESTATION_TAMPERED_PENALTY
        : input.attestationStatus === 'unverified' || input.attestationStatus === 'none'
          ? ATTESTATION_UNVERIFIED_PENALTY
          : 0
    if (penalty > 0) {
      totalPenalty += penalty
      breakdown.push({
        category: 'attestation',
        label: 'SBOM attestation',
        penalty,
        detail:
          input.attestationStatus === 'tampered'
            ? 'SBOM content hash mismatch — possible tampering detected'
            : 'SBOM attestation not yet verified',
      })
    }
  }

  // ── Aggregate ────────────────────────────────────────────────────────────
  const score = Math.max(0, 100 - totalPenalty)
  const grade = scoreToGrade(score)

  const hasCritical =
    input.cve.criticalCount > 0 ||
    input.malicious.criticalCount > 0 ||
    input.confusion.criticalCount > 0 ||
    input.abandonment.criticalCount > 0

  const hasHigh =
    input.cve.highCount > 0 ||
    input.malicious.highCount > 0 ||
    input.confusion.highCount > 0 ||
    input.abandonment.highCount > 0

  const riskLevel = scoreToRiskLevel(score, hasCritical, hasHigh)

  return {
    score,
    grade,
    riskLevel,
    breakdown,
    summary: buildSummary(score, grade, input),
    cveRisk: input.cve.overallRisk,
    maliciousRisk: input.malicious.overallRisk,
    confusionRisk: input.confusion.overallRisk,
    abandonmentRisk: input.abandonment.overallRisk,
    eolRisk: input.eol.overallStatus,
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/** Produce "3 criticals, 1 high" style detail strings. */
function buildDetail(pairs: [number, string][]): string {
  return pairs
    .filter(([count]) => count > 0)
    .map(([count, label]) => `${count} ${label}${count > 1 ? 's' : ''}`)
    .join(', ')
}

function buildSummary(
  score: number,
  grade: PostureGrade,
  input: SupplyChainPostureInput,
): string {
  if (score >= 90) {
    return `Supply chain posture: ${score}/100 (grade ${grade}). No significant risks detected across ${input.componentCount} component${input.componentCount !== 1 ? 's' : ''}.`
  }

  const highlights: string[] = []
  if (input.cve.criticalCount > 0)
    highlights.push(
      `${input.cve.criticalCount} critical CVE${input.cve.criticalCount > 1 ? 's' : ''}`,
    )
  if (input.malicious.criticalCount > 0)
    highlights.push(
      `${input.malicious.criticalCount} confirmed malicious package${input.malicious.criticalCount > 1 ? 's' : ''}`,
    )
  if (input.confusion.criticalCount > 0)
    highlights.push(
      `${input.confusion.criticalCount} confusion attack signal${input.confusion.criticalCount > 1 ? 's' : ''}`,
    )
  if (input.abandonment.criticalCount > 0)
    highlights.push(
      `${input.abandonment.criticalCount} compromised package${input.abandonment.criticalCount > 1 ? 's' : ''}`,
    )
  if (input.eol.eolCount > 0)
    highlights.push(`${input.eol.eolCount} EOL component${input.eol.eolCount > 1 ? 's' : ''}`)
  if (input.attestationStatus === 'tampered') highlights.push('SBOM tampering detected')

  const detail = highlights.length > 0 ? ` Issues: ${highlights.join(', ')}.` : ''
  return `Supply chain posture: ${score}/100 (grade ${grade}).${detail}`
}
