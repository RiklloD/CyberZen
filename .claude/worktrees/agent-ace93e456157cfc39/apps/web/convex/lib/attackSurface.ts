// WS-14 Phase 3 — Attack Surface Reduction Agent (spec 3.7): pure computation
// library.
//
// No DB access. All intelligence lives here; Convex mutations are persistence
// wrappers only. This design keeps the library fully unit-testable without
// spinning up a Convex environment.
//
// Attack Surface Score (0–100, HIGHER = more surface has been reduced):
//
//   score =
//     (remediationScore × 50)         // severity-weighted fraction resolved/mitigated
//     + mitigationBonus               // active PRs as fraction of open findings (0–10)
//     + validationBonus               // validated-and-resolved / total-validated  (0–15)
//     + memoryHealthBonus             // FP rate health + no recurring criticals    (0–10)
//     + sbomBonus                     // SBOM snapshot present                     (0–5)
//     + noValidatedCriticalBonus      // zero open validated/likely criticals       (0–10)
//
// Maximum possible score = 50 + 10 + 15 + 10 + 5 + 10 = 100.
//
// Severity step weights (remediation only): critical=4, high=3, medium=2, low=1, informational=0.
// A "pr_opened" finding counts as 0.5× weight (partially mitigated, not yet resolved).

import type { RepositoryMemoryRecord } from './memoryController'

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type FindingForSurfaceInput = {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  /** 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' */
  status: string
  /** 'pending' | 'validated' | 'likely_exploitable' | 'unexploitable' | 'dismissed' */
  validationStatus: string
}

export type AttackSurfaceInput = {
  findings: FindingForSurfaceInput[]
  /** Latest RepositoryMemoryRecord from Phase 2 (may be null if not yet computed). */
  repositoryMemory: RepositoryMemoryRecord | null
  /** Whether the repository has an active SBOM snapshot. */
  hasActiveSbom: boolean
  /** Previous snapshot score (0–100) used to compute trend. Pass null for first snapshot. */
  previousScore: number | null
  repositoryName: string
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type AttackSurfaceTrend = 'improving' | 'stable' | 'degrading'

export type AttackSurfaceResult = {
  /** 0–100 composite reduction score. Higher = more attack surface has been reduced. */
  score: number
  /** 0–1 severity-weighted fraction of findings that are resolved/mitigated. */
  remediationRate: number
  /** Count of open findings with severity = 'critical'. */
  openCriticalCount: number
  /** Count of open findings with severity = 'high'. */
  openHighCount: number
  /** Count of findings in 'pr_opened' status (active mitigation in progress). */
  activeMitigationCount: number
  /** Total findings analyzed. */
  totalFindings: number
  /** Count of findings in 'resolved', 'merged', or 'accepted_risk' status. */
  resolvedFindings: number
  /** Direction relative to previousScore. */
  trend: AttackSurfaceTrend
  /** 1–2 sentence human-readable summary. */
  summary: string
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Weights for remediation scoring (higher = more critical to resolve). */
const REMEDIATION_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
}

function remediationWeight(severity: string): number {
  return REMEDIATION_WEIGHT[severity] ?? 1
}

const RESOLVED_STATUSES = new Set(['resolved', 'merged', 'accepted_risk'])
const OPEN_STATUSES = new Set(['open', 'pr_opened'])
const VALIDATED_STATUSES = new Set(['validated', 'likely_exploitable'])
// 'pr_opened' gets half-credit in remediationScore; kept as a const so it
// stays in sync if the status string is ever renamed.
const PR_OPENED_STATUS = 'pr_opened'

// ---------------------------------------------------------------------------
// Sub-score helpers
// ---------------------------------------------------------------------------

// 'resolved' / 'merged' / 'accepted_risk' → full weight
// PR_OPENED_STATUS                         → half weight (in-progress)
// 'open'                                   → zero weight
function computeRemediationScore(findings: FindingForSurfaceInput[]): number {
  if (findings.length === 0) return 0

  let totalWeight = 0
  let creditedWeight = 0

  for (const f of findings) {
    const w = remediationWeight(f.severity)
    totalWeight += w
    if (RESOLVED_STATUSES.has(f.status)) {
      creditedWeight += w
    } else if (f.status === PR_OPENED_STATUS) {
      creditedWeight += w * 0.5
    }
  }

  if (totalWeight === 0) return 0
  return creditedWeight / totalWeight
}

// If no open findings exist the attack surface is already contained — full bonus.
function computeMitigationBonus(findings: FindingForSurfaceInput[]): number {
  const openFindings = findings.filter((f) => OPEN_STATUSES.has(f.status))
  if (openFindings.length === 0) return 10
  const activeCount = openFindings.filter(
    (f) => f.status === PR_OPENED_STATUS,
  ).length
  return (activeCount / openFindings.length) * 10
}

// 7-point neutral baseline when no validated findings exist yet (unconfirmed ≠ unexposed).
function computeValidationBonus(findings: FindingForSurfaceInput[]): number {
  const validatedFindings = findings.filter((f) =>
    VALIDATED_STATUSES.has(f.validationStatus),
  )
  if (validatedFindings.length === 0) return 7
  const resolvedValidated = validatedFindings.filter((f) =>
    RESOLVED_STATUSES.has(f.status),
  ).length
  return (resolvedValidated / validatedFindings.length) * 15
}

/**
 * Bonus derived from the Phase 2 memory record (0–10).
 *
 * Two sub-components:
 *   • FP health (0–5): low false-positive rate means the agent's detections are
 *     trustworthy, so remediation actions are meaningful.
 *   • No-recurring-critical (0–5): if any vuln class with avg severity = critical
 *     is appearing more than once, the surface is still actively expanding.
 */
function computeMemoryHealthBonus(
  memory: RepositoryMemoryRecord | null,
): number {
  if (!memory) return 0

  const fpBonus = (1 - Math.min(1, memory.falsePositiveRate)) * 5
  const hasRecurringCritical = memory.recurringVulnClasses.some(
    (c) => c.avgSeverityWeight >= 1.0 && c.count > 1,
  )
  const classBonus = hasRecurringCritical ? 0 : 5

  return fpBonus + classBonus
}

// Loses 5 pts per open validated/likely-exploitable critical, floored at 0.
function computeNoValidatedCriticalBonus(
  findings: FindingForSurfaceInput[],
): number {
  const openValidatedCriticals = findings.filter(
    (f) =>
      f.severity === 'critical' &&
      f.status === 'open' &&
      VALIDATED_STATUSES.has(f.validationStatus),
  ).length
  return Math.max(0, 10 - openValidatedCriticals * 5)
}

// ---------------------------------------------------------------------------
// Trend
// ---------------------------------------------------------------------------

function computeTrend(
  currentScore: number,
  previousScore: number | null,
): AttackSurfaceTrend {
  if (previousScore === null) return 'stable'
  const delta = currentScore - previousScore
  if (delta > 2) return 'improving'
  if (delta < -2) return 'degrading'
  return 'stable'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildSummary(args: {
  repositoryName: string
  score: number
  openCriticalCount: number
  openHighCount: number
  activeMitigationCount: number
  resolvedFindings: number
  totalFindings: number
  trend: AttackSurfaceTrend
}): string {
  const {
    repositoryName,
    score,
    openCriticalCount,
    openHighCount,
    activeMitigationCount,
    resolvedFindings,
    totalFindings,
    trend,
  } = args

  if (totalFindings === 0) {
    return `No findings tracked for ${repositoryName} yet; attack surface score is not yet meaningful.`
  }

  const trendPhrase =
    trend === 'improving'
      ? 'trending upward'
      : trend === 'degrading'
        ? 'trending downward'
        : 'stable'

  const criticalNote =
    openCriticalCount > 0
      ? ` ${openCriticalCount} open critical${openHighCount > 0 ? ` and ${openHighCount} high` : ''} finding${openCriticalCount + openHighCount === 1 ? '' : 's'} remain.`
      : openHighCount > 0
        ? ` ${openHighCount} open high finding${openHighCount === 1 ? '' : 's'} remain.`
        : ''

  const mitigationNote =
    activeMitigationCount > 0
      ? ` ${activeMitigationCount} finding${activeMitigationCount === 1 ? '' : 's'} under active PR mitigation.`
      : ''

  return `${repositoryName} attack surface score ${score}/100 (${trendPhrase}); ${resolvedFindings}/${totalFindings} findings resolved.${criticalNote}${mitigationNote}`
}

// ---------------------------------------------------------------------------
// Core computation
// ---------------------------------------------------------------------------

export function computeAttackSurface(
  input: AttackSurfaceInput,
): AttackSurfaceResult {
  const {
    findings,
    repositoryMemory,
    hasActiveSbom,
    previousScore,
    repositoryName,
  } = input

  // ── Sub-scores ─────────────────────────────────────────────────────────────
  const remediationScore = computeRemediationScore(findings)
  const mitigationBonus = computeMitigationBonus(findings)
  const validationBonus = computeValidationBonus(findings)
  const memoryHealthBonus = computeMemoryHealthBonus(repositoryMemory)
  const sbomBonus = hasActiveSbom ? 5 : 0
  const noValidatedCriticalBonus = computeNoValidatedCriticalBonus(findings)

  const rawScore =
    remediationScore * 50 +
    mitigationBonus +
    validationBonus +
    memoryHealthBonus +
    sbomBonus +
    noValidatedCriticalBonus

  const score = Math.min(100, Math.max(0, Math.round(rawScore)))

  // ── Derived counts ─────────────────────────────────────────────────────────
  const openCriticalCount = findings.filter(
    (f) => f.severity === 'critical' && OPEN_STATUSES.has(f.status),
  ).length

  const openHighCount = findings.filter(
    (f) => f.severity === 'high' && OPEN_STATUSES.has(f.status),
  ).length

  const activeMitigationCount = findings.filter(
    (f) => f.status === 'pr_opened',
  ).length

  const resolvedFindings = findings.filter((f) =>
    RESOLVED_STATUSES.has(f.status),
  ).length

  const totalFindings = findings.length

  // ── Trend ──────────────────────────────────────────────────────────────────
  const trend = computeTrend(score, previousScore)

  // ── Summary ────────────────────────────────────────────────────────────────
  const summary = buildSummary({
    repositoryName,
    score,
    openCriticalCount,
    openHighCount,
    activeMitigationCount,
    resolvedFindings,
    totalFindings,
    trend,
  })

  return {
    score,
    remediationRate: remediationScore,
    openCriticalCount,
    openHighCount,
    activeMitigationCount,
    totalFindings,
    resolvedFindings,
    trend,
    summary,
  }
}
