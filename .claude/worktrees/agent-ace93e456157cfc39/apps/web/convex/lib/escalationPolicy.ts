// Finding Severity Escalation Policy — pure library with no Convex imports.
//
// Computes whether a finding's severity should be automatically upgraded
// based on newly available threat context.  Severity escalation is strictly
// monotone — the engine never downgrades severity.
//
// Escalation triggers and their maximum effect on severity:
//
//   Trigger                   Condition                     Max target severity
//   ─────────────────────     ────────────────────────────  ────────────────────
//   exploit_available         exploitAvailable = true        critical  (full climb)
//   blast_radius_critical     blastRadiusScore ≥ 80          high      (one below critical)
//   blast_radius_high         blastRadiusScore ≥ 60          medium    (one level up)
//   cross_repo_spread         affectedRepoCount ≥ threshold  high      (spread = material risk)
//   sla_breach                slaStatus = breached_sla       medium    (urgency, not threat)
//
// Multiple triggers apply simultaneously; the highest proposed severity wins.

// ─── Types ─────────────────────────────────────────────────────────────────────

export type EscalationTrigger =
  | 'exploit_available'
  | 'blast_radius_critical'
  | 'blast_radius_high'
  | 'cross_repo_spread'
  | 'sla_breach'

export type EscalationSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export type EscalationContext = {
  currentSeverity: EscalationSeverity
  exploitAvailable: boolean
  /**
   * businessImpactScore from the most recent blastRadiusSnapshot (0–100).
   * Pass -1 when no blast radius snapshot is available.
   */
  blastRadiusScore: number
  /**
   * affectedRepositoryCount from the crossRepoImpactEvents record for this
   * finding's source package.  Pass 0 when no cross-repo record exists.
   */
  affectedRepoCount: number
  slaStatus: 'within_sla' | 'approaching_sla' | 'breached_sla' | 'not_applicable'
}

export type EscalationAssessment = {
  shouldEscalate: boolean
  currentSeverity: EscalationSeverity
  /** Equals currentSeverity when shouldEscalate = false. */
  newSeverity: EscalationSeverity
  triggers: EscalationTrigger[]
  rationale: string[]
}

export type EscalationPolicy = {
  /**
   * businessImpactScore threshold for the blast_radius_critical trigger (default 80).
   */
  blastRadiusCriticalThreshold: number
  /**
   * businessImpactScore threshold for the blast_radius_high trigger (default 60).
   * Must be < blastRadiusCriticalThreshold to avoid ambiguity.
   */
  blastRadiusHighThreshold: number
  /**
   * Minimum number of affected cross-repository repositories to trigger
   * the cross_repo_spread escalation (default 3).
   */
  crossRepoSpreadThreshold: number
}

export const DEFAULT_ESCALATION_POLICY: EscalationPolicy = {
  blastRadiusCriticalThreshold: 80,
  blastRadiusHighThreshold: 60,
  crossRepoSpreadThreshold: 3,
}

// ─── Severity ladder ────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<EscalationSeverity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const RANK_TO_SEVERITY: EscalationSeverity[] = [
  'informational',
  'low',
  'medium',
  'high',
  'critical',
]

/**
 * Returns the numeric rank for a severity level (higher = more severe).
 */
export function getSeverityRank(severity: EscalationSeverity): number {
  return SEVERITY_RANK[severity]
}

/**
 * Returns the higher of two severity levels.
 */
function maxSeverity(
  a: EscalationSeverity,
  b: EscalationSeverity,
): EscalationSeverity {
  return getSeverityRank(a) >= getSeverityRank(b) ? a : b
}

// ─── Per-trigger escalation ceiling ────────────────────────────────────────────

/**
 * Returns the highest severity this trigger is allowed to push the finding to.
 * If the finding is already at or above the ceiling, the trigger has no effect.
 *
 * Ceiling table:
 *   exploit_available       → critical   (confirmed threat, full ladder)
 *   blast_radius_critical   → high       (impact, not threat — stop before critical)
 *   blast_radius_high       → medium     (moderate impact boost only)
 *   cross_repo_spread       → high       (organisational risk amplifier)
 *   sla_breach              → medium     (urgency signal only)
 */
function triggerCeiling(trigger: EscalationTrigger): EscalationSeverity {
  switch (trigger) {
    case 'exploit_available':
      return 'critical'
    case 'blast_radius_critical':
      return 'high'
    case 'cross_repo_spread':
      return 'high'
    case 'blast_radius_high':
      return 'medium'
    case 'sla_breach':
      return 'medium'
  }
}

/**
 * Given a current severity and a single trigger, returns the severity this
 * trigger would escalate to (or the same severity if already at/above ceiling).
 */
export function escalateSeverityForTrigger(
  current: EscalationSeverity,
  trigger: EscalationTrigger,
): EscalationSeverity {
  const ceiling = triggerCeiling(trigger)
  const currentRank = getSeverityRank(current)
  const ceilingRank = getSeverityRank(ceiling)

  // Already at or above the ceiling for this trigger — no change.
  if (currentRank >= ceilingRank) return current

  // Escalate one level above current (cap at ceiling).
  const nextRank = Math.min(currentRank + 1, ceilingRank)
  return RANK_TO_SEVERITY[nextRank]
}

// ─── Rationale strings ─────────────────────────────────────────────────────────

function triggerRationale(trigger: EscalationTrigger, score?: number, repoCount?: number): string {
  switch (trigger) {
    case 'exploit_available':
      return 'Public exploit code is now available — finding is immediately actionable'
    case 'blast_radius_critical':
      return `Very high blast radius (impact score ${score ?? '≥80'}) — exploitation would have critical business impact`
    case 'blast_radius_high':
      return `High blast radius (impact score ${score ?? '≥60'}) — exploitation would have elevated business impact`
    case 'cross_repo_spread':
      return `Package affects ${repoCount ?? 'multiple'} other repositories — lateral exposure is confirmed`
    case 'sla_breach':
      return 'SLA deadline has been breached — remediation urgency requires immediate attention'
  }
}

// ─── Core assessment function ──────────────────────────────────────────────────

/**
 * Evaluates all escalation triggers for a single finding and returns an
 * assessment indicating whether severity should be upgraded and why.
 *
 * Severity escalation is monotone — the engine only ever increases severity,
 * never reduces it.  Escalation stops at `critical`; `informational` findings
 * are never escalated (they are not vulnerability findings).
 */
export function assessEscalation(
  ctx: EscalationContext,
  policy: EscalationPolicy = DEFAULT_ESCALATION_POLICY,
): EscalationAssessment {
  const { currentSeverity } = ctx

  // Boundaries — never escalate informational or already-critical findings.
  if (currentSeverity === 'informational' || currentSeverity === 'critical') {
    return {
      shouldEscalate: false,
      currentSeverity,
      newSeverity: currentSeverity,
      triggers: [],
      rationale: [],
    }
  }

  const activeTriggers: EscalationTrigger[] = []
  const rationaleEntries: string[] = []

  // ── Collect active triggers ────────────────────────────────────────────────

  if (ctx.exploitAvailable) {
    activeTriggers.push('exploit_available')
    rationaleEntries.push(triggerRationale('exploit_available'))
  }

  if (ctx.blastRadiusScore >= 0) {
    if (ctx.blastRadiusScore >= policy.blastRadiusCriticalThreshold) {
      activeTriggers.push('blast_radius_critical')
      rationaleEntries.push(triggerRationale('blast_radius_critical', ctx.blastRadiusScore))
    } else if (ctx.blastRadiusScore >= policy.blastRadiusHighThreshold) {
      activeTriggers.push('blast_radius_high')
      rationaleEntries.push(triggerRationale('blast_radius_high', ctx.blastRadiusScore))
    }
  }

  if (ctx.affectedRepoCount >= policy.crossRepoSpreadThreshold) {
    activeTriggers.push('cross_repo_spread')
    rationaleEntries.push(triggerRationale('cross_repo_spread', undefined, ctx.affectedRepoCount))
  }

  if (ctx.slaStatus === 'breached_sla') {
    activeTriggers.push('sla_breach')
    rationaleEntries.push(triggerRationale('sla_breach'))
  }

  // ── Compute maximum proposed severity across all active triggers ───────────

  if (activeTriggers.length === 0) {
    return {
      shouldEscalate: false,
      currentSeverity,
      newSeverity: currentSeverity,
      triggers: [],
      rationale: [],
    }
  }

  let proposedSeverity: EscalationSeverity = currentSeverity
  for (const trigger of activeTriggers) {
    const proposed = escalateSeverityForTrigger(currentSeverity, trigger)
    proposedSeverity = maxSeverity(proposedSeverity, proposed)
  }

  const shouldEscalate = getSeverityRank(proposedSeverity) > getSeverityRank(currentSeverity)

  return {
    shouldEscalate,
    currentSeverity,
    newSeverity: proposedSeverity,
    triggers: shouldEscalate ? activeTriggers : [],
    rationale: shouldEscalate ? rationaleEntries : [],
  }
}
