// Security Debt Velocity Tracker — pure library, no Convex dependencies.
//
// Tracks how quickly security findings accumulate versus get resolved,
// surfaces overdue SLA breaches, and produces a 0–100 debt score per
// repository. The debt score feeds into the executive summary and alerts.
//
// Design goals:
//   - "Velocity" (new/day − resolved/day) is the leading indicator; the
//     absolute backlog count is the lagging indicator.
//   - SLA thresholds (critical 24h / high 72h / medium 7d / low 30d) match
//     the existing slaPolicy.ts defaults for consistency.
//   - debtScore penalises: open backlog size, overdue findings, open
//     criticals, and positive velocity (accumulating faster than resolving).

// ---------------------------------------------------------------------------
// SLA thresholds (mirror of slaPolicy.ts DEFAULT_SLA_POLICY)
// ---------------------------------------------------------------------------

const SLA_MS: Record<string, number> = {
  critical: 24 * 60 * 60 * 1000,       // 24 hours
  high: 3 * 24 * 60 * 60 * 1000,       // 72 hours
  medium: 7 * 24 * 60 * 60 * 1000,     // 7 days
  low: 30 * 24 * 60 * 60 * 1000,       // 30 days
}

/** Finding statuses that count as "still open" (not fully closed). */
const OPEN_STATUSES = new Set(['open', 'pr_opened', 'merged'])

/** Finding statuses that count as "closed" for velocity purposes. */
const CLOSED_STATUSES = new Set(['resolved', 'accepted_risk', 'false_positive', 'ignored'])

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FindingInput {
  /** Unix timestamp in milliseconds when the finding was created. */
  createdAt: number
  /** Unix timestamp in milliseconds when the finding was resolved (if ever). */
  resolvedAt?: number
  /** Severity string: 'critical' | 'high' | 'medium' | 'low' */
  severity: string
  /** Status string: 'open' | 'pr_opened' | 'merged' | 'resolved' | ... */
  status: string
}

/** Human-readable debt trend classification. */
export type DebtTrend = 'improving' | 'stable' | 'degrading' | 'critical'

export interface DebtVelocityResult {
  /** Analysis window in days (default 30). */
  windowDays: number

  // --- Window metrics --------------------------------------------------
  /** Findings created within the analysis window. */
  newFindingsInWindow: number
  /** Findings resolved/closed within the analysis window. */
  resolvedFindingsInWindow: number
  /** Net velocity: new/day − resolved/day (positive = accumulating). */
  netVelocityPerDay: number
  /** Raw rate: new findings per day within window. */
  newPerDay: number
  /** Raw rate: resolved findings per day within window. */
  resolvedPerDay: number

  // --- Backlog snapshot ------------------------------------------------
  /** Total open findings (status in open/pr_opened/merged). */
  openFindings: number
  /** Open findings with severity 'critical'. */
  openCritical: number
  /** Open findings with severity 'high'. */
  openHigh: number

  // --- SLA overdue -----------------------------------------------------
  /** Open findings past their severity SLA deadline. */
  overdueFindings: number
  /** Open critical findings past the 24-hour SLA. */
  overdueCritical: number

  // --- Classification --------------------------------------------------
  /** Trend based on net velocity per day. */
  trend: DebtTrend
  /**
   * Projected days to clear all open findings at the current resolution
   * rate. Null when no findings are being resolved (division by zero).
   */
  projectedClearanceDays: number | null
  /** 0–100 debt score (100 = no debt, 0 = worst possible). */
  debtScore: number
  /** Human-readable summary sentence. */
  summary: string
}

// ---------------------------------------------------------------------------
// classifyTrend
// ---------------------------------------------------------------------------

/**
 * Converts net velocity (new/day − resolved/day) into a trend label.
 *
 * Thresholds:
 *   ≤ −1.0/day  → improving  (resolving faster than accumulating)
 *   −1 to +1    → stable     (roughly balanced)
 *   +1 to +3    → degrading  (slowly accumulating)
 *   > +3        → critical   (rapidly accumulating)
 */
export function classifyTrend(netVelocityPerDay: number): DebtTrend {
  if (netVelocityPerDay <= -1) return 'improving'
  if (netVelocityPerDay <= 1) return 'stable'
  if (netVelocityPerDay <= 3) return 'degrading'
  return 'critical'
}

// ---------------------------------------------------------------------------
// computeDebtScore
// ---------------------------------------------------------------------------

/**
 * Computes a 0–100 debt score from the four main debt signals.
 *
 * Penalties (each capped to prevent single-signal collapse):
 *   Open backlog  :  −2 per finding,  cap −30
 *   Overdue       :  −5 per finding,  cap −30
 *   Open critical :  −10 per finding, cap −25
 *   Velocity (pos):  −3 per unit/day, cap −15
 *
 * Score is clamped to [0, 100].
 */
export function computeDebtScore(
  openFindings: number,
  overdueFindings: number,
  openCritical: number,
  netVelocityPerDay: number,
): number {
  let score = 100
  score -= Math.min(30, openFindings * 2)
  score -= Math.min(30, overdueFindings * 5)
  score -= Math.min(25, openCritical * 10)
  score -= Math.min(15, Math.max(0, netVelocityPerDay * 3))
  return Math.max(0, Math.min(100, Math.round(score)))
}

// ---------------------------------------------------------------------------
// computeSecurityDebtVelocity
// ---------------------------------------------------------------------------

/**
 * Main entry point. Accepts the full finding list for a repository and
 * produces a point-in-time debt velocity snapshot.
 *
 * @param findings  All findings for the repository (no pre-filtering required)
 * @param now       Current timestamp in ms (defaults to Date.now())
 * @param windowDays  Analysis window for velocity metrics (default 30)
 */
export function computeSecurityDebtVelocity(
  findings: FindingInput[],
  now: number = Date.now(),
  windowDays = 30,
): DebtVelocityResult {
  const windowMs = windowDays * 24 * 60 * 60 * 1000
  const windowStart = now - windowMs

  // --- Open backlog (not yet fully closed) --------------------------------
  const openList = findings.filter((f) => OPEN_STATUSES.has(f.status))
  const openCritical = openList.filter((f) => f.severity === 'critical').length
  const openHigh = openList.filter((f) => f.severity === 'high').length

  // --- New findings in window --------------------------------------------
  const newInWindow = findings.filter((f) => f.createdAt >= windowStart)

  // --- Resolved findings in window ---------------------------------------
  const resolvedInWindow = findings.filter(
    (f) =>
      CLOSED_STATUSES.has(f.status) &&
      f.resolvedAt !== undefined &&
      f.resolvedAt >= windowStart,
  )

  // --- Overdue: open findings past SLA -----------------------------------
  const overdueList = openList.filter((f) => {
    const sla = SLA_MS[f.severity] ?? SLA_MS.low
    return now - f.createdAt > sla
  })
  const overdueCritical = overdueList.filter((f) => f.severity === 'critical').length

  // --- Velocity math -----------------------------------------------------
  const newPerDay = windowDays > 0 ? newInWindow.length / windowDays : 0
  const resolvedPerDay = windowDays > 0 ? resolvedInWindow.length / windowDays : 0
  const netVelocityPerDay = newPerDay - resolvedPerDay

  // --- Derived fields ----------------------------------------------------
  const trend = classifyTrend(netVelocityPerDay)

  const projectedClearanceDays =
    resolvedPerDay > 0 ? Math.ceil(openList.length / resolvedPerDay) : null

  const debtScore = computeDebtScore(
    openList.length,
    overdueList.length,
    openCritical,
    netVelocityPerDay,
  )

  // --- Summary -----------------------------------------------------------
  let summary: string
  if (openList.length === 0) {
    summary = 'No open security findings. Security debt is fully cleared.'
  } else if (trend === 'improving') {
    summary = `Resolving faster than new findings arrive (+${newInWindow.length} new / −${resolvedInWindow.length} resolved in ${windowDays}d). ${openList.length} open remaining.`
  } else if (trend === 'stable') {
    summary = `${openList.length} open finding(s), stable pace. ${overdueList.length} overdue past SLA deadline.`
  } else if (trend === 'degrading') {
    summary = `Debt growing: +${newInWindow.length} new vs ${resolvedInWindow.length} resolved in last ${windowDays}d. ${openCritical} critical open.`
  } else {
    summary = `CRITICAL: Rapid debt accumulation (+${newInWindow.length} new, ${resolvedInWindow.length} resolved). ${overdueCritical} critical overdue — immediate action required.`
  }

  return {
    windowDays,
    newFindingsInWindow: newInWindow.length,
    resolvedFindingsInWindow: resolvedInWindow.length,
    netVelocityPerDay: Math.round(netVelocityPerDay * 100) / 100,
    newPerDay: Math.round(newPerDay * 100) / 100,
    resolvedPerDay: Math.round(resolvedPerDay * 100) / 100,
    openFindings: openList.length,
    openCritical,
    openHigh,
    overdueFindings: overdueList.length,
    overdueCritical,
    trend,
    projectedClearanceDays,
    debtScore,
    summary,
  }
}
