// SLA Enforcement Policy — pure library with no Convex imports.
//
// Tracks time-to-remediate against configurable per-severity thresholds.
// Active findings (open / pr_opened / merged) count against SLA; resolved,
// accepted-risk, false-positive, and ignored findings are not applicable.
//
// Default SLA thresholds (can be overridden per tenant in future):
//   critical:      24 hours
//   high:          72 hours
//   medium:       168 hours  (7 days)
//   low:          720 hours  (30 days)
//   informational:  exempt   (not tracked)
//
// SLA status transitions:
//   within_sla     → percentElapsed < approachingThreshold
//   approaching_sla → percentElapsed >= approachingThreshold AND not yet breached
//   breached_sla   → nowMs >= deadlineAt
//   not_applicable → inactive status or informational severity

export type SlaThresholdMap = Readonly<
  Record<'critical' | 'high' | 'medium' | 'low', number>
>

export type SlaPolicy = {
  /** SLA window in hours per severity level. */
  thresholdHours: SlaThresholdMap
  /** Fraction of the window elapsed at which status becomes "approaching" (0–1). */
  approachingThreshold: number
}

export type SlaStatus =
  | 'within_sla'
  | 'approaching_sla'
  | 'breached_sla'
  | 'not_applicable'

export type SlaFindingAssessment = {
  findingId: string
  severity: string
  status: string
  openedAt: number
  /** Null for informational / not-tracked severities. */
  deadlineAt: number | null
  slaStatus: SlaStatus
  /** Hours since the finding was opened. */
  hoursElapsed: number
  /** Null when breached or not tracked. */
  hoursRemaining: number | null
  /** Null when not tracked (informational). */
  percentElapsed: number | null
}

export type SlaSummary = {
  /** Active findings with an SLA threshold (excludes informational + inactive). */
  totalTracked: number
  withinSla: number
  approachingSla: number
  breachedSla: number
  /** Inactive or informational findings. */
  notApplicable: number
  /**
   * 0–1 compliance rate.
   * Formula: (withinSla + approachingSla) / totalTracked
   * Returns 1.0 when no findings are tracked (vacuous compliance).
   */
  complianceRate: number
  /** Mean time-to-remediate in hours for resolved findings; null if none. */
  mttrHours: number | null
}

// Active statuses that count against SLA deadlines.
const ACTIVE_STATUSES = new Set(['open', 'pr_opened', 'merged'])

export const DEFAULT_SLA_POLICY: SlaPolicy = {
  thresholdHours: {
    critical: 24,
    high: 72,
    medium: 168,
    low: 720,
  } as const,
  approachingThreshold: 0.75,
}

// Return the SLA threshold in hours for a given severity, or null if exempt.
export function getSlaThresholdHours(
  severity: string,
  policy: SlaPolicy,
): number | null {
  if (severity === 'informational') return null
  const s = severity as keyof SlaThresholdMap
  return policy.thresholdHours[s] ?? null
}

// Return the ms timestamp at which a finding breaches SLA, or null if exempt.
export function computeSlaDeadline(
  openedAt: number,
  severity: string,
  policy: SlaPolicy,
): number | null {
  const hours = getSlaThresholdHours(severity, policy)
  if (hours === null) return null
  return openedAt + hours * 3_600_000
}

// Assess a single finding against the SLA policy.
export function assessSlaFinding(args: {
  findingId: string
  severity: string
  status: string
  openedAt: number
  policy: SlaPolicy
  nowMs: number
}): SlaFindingAssessment {
  const { findingId, severity, status, openedAt, policy, nowMs } = args

  const hours = getSlaThresholdHours(severity, policy)
  const hoursElapsed = (nowMs - openedAt) / 3_600_000

  // Inactive or informational findings are not SLA-applicable.
  if (!ACTIVE_STATUSES.has(status) || hours === null) {
    return {
      findingId,
      severity,
      status,
      openedAt,
      deadlineAt: null,
      slaStatus: 'not_applicable',
      hoursElapsed,
      hoursRemaining: null,
      percentElapsed: null,
    }
  }

  const deadlineAt = openedAt + hours * 3_600_000
  const percentElapsed = hoursElapsed / hours
  const isBreached = nowMs >= deadlineAt

  return {
    findingId,
    severity,
    status,
    openedAt,
    deadlineAt,
    slaStatus: isBreached
      ? 'breached_sla'
      : percentElapsed >= policy.approachingThreshold
        ? 'approaching_sla'
        : 'within_sla',
    hoursElapsed,
    hoursRemaining: isBreached ? null : (deadlineAt - nowMs) / 3_600_000,
    percentElapsed,
  }
}

// Aggregate per-finding assessments + resolved findings into a single SLA summary.
export function computeSlaSummary(
  assessments: SlaFindingAssessment[],
  resolvedFindings: ReadonlyArray<{ createdAt: number; resolvedAt: number }>,
): SlaSummary {
  let withinSla = 0
  let approachingSla = 0
  let breachedSla = 0
  let notApplicable = 0

  for (const a of assessments) {
    if (a.slaStatus === 'within_sla') withinSla++
    else if (a.slaStatus === 'approaching_sla') approachingSla++
    else if (a.slaStatus === 'breached_sla') breachedSla++
    else notApplicable++
  }

  const totalTracked = withinSla + approachingSla + breachedSla
  const complianceRate =
    totalTracked === 0 ? 1.0 : (withinSla + approachingSla) / totalTracked

  let mttrHours: number | null = null
  if (resolvedFindings.length > 0) {
    const total = resolvedFindings.reduce(
      (sum, f) => sum + (f.resolvedAt - f.createdAt) / 3_600_000,
      0,
    )
    mttrHours = total / resolvedFindings.length
  }

  return {
    totalTracked,
    withinSla,
    approachingSla,
    breachedSla,
    notApplicable,
    complianceRate,
    mttrHours,
  }
}
