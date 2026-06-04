/**
 * Security Event Timeline — pure computation library (WS-51)
 *
 * Merges events from 10+ Convex tables into a unified, chronologically-sorted
 * incident timeline.  Designed as a pure function so it can be tested without
 * a Convex runtime.
 *
 * Event sources:
 *   findings              → finding_created
 *   severityEscalations   → finding_escalated
 *   findingTriageEvents   → finding_triaged
 *   gateDecisions         → gate_blocked / gate_approved / gate_overridden
 *   prProposals           → pr_opened / pr_merged
 *   slaBreachEvents       → sla_breached
 *   riskAcceptances       → risk_accepted / risk_revoked
 *   redBlueRounds         → red_agent_win
 *   autoRemediationRuns   → auto_remediation_dispatched
 *   secretScanResults     → secret_detected
 */

// ── Event type taxonomy ────────────────────────────────────────────────────

export type TimelineEventType =
  | 'finding_created'
  | 'finding_escalated'
  | 'finding_triaged'
  | 'gate_blocked'
  | 'gate_approved'
  | 'gate_overridden'
  | 'pr_opened'
  | 'pr_merged'
  | 'sla_breached'
  | 'risk_accepted'
  | 'risk_revoked'
  | 'red_agent_win'
  | 'auto_remediation_dispatched'
  | 'secret_detected'

export type TimelineSeverity = 'critical' | 'high' | 'medium' | 'low'

/** A single unified timeline entry, suitable for display in a security audit log. */
export interface TimelineEntry {
  /** Stable unique key for React reconciliation and deduplication. */
  id: string
  eventType: TimelineEventType
  /** Unix milliseconds — sort key for chronological display. */
  timestamp: number
  /** Optional severity for colour-coded pills. */
  severity?: TimelineSeverity
  /** Short one-line title shown in the event row. */
  title: string
  /** Supporting detail (reason, affected package, metric, etc.). */
  detail: string
  /** Arbitrary key→value pairs for downstream filtering or export. */
  metadata: Record<string, string>
}

// ── Input source types ─────────────────────────────────────────────────────

export interface FindingEvent {
  id: string
  title: string
  severity: string
  status: string
  createdAt: number
  resolvedAt?: number | null
}

export interface EscalationEvent {
  id: string
  previousSeverity: string
  newSeverity: string
  triggers: string[]
  computedAt: number
}

export interface TriageEvent {
  id: string
  action: string
  note?: string | null
  analyst?: string | null
  createdAt: number
}

export interface GateDecisionEvent {
  id: string
  stage: string
  decision: string
  createdAt: number
}

export interface PrProposalEvent {
  id: string
  status: string
  prUrl?: string | null
  prTitle: string
  createdAt: number
  mergedAt?: number | null
  mergedBy?: string | null
}

export interface SlaBreachEvent {
  id: string
  severity: string
  title: string
  breachedAt: number
  slaThresholdHours: number
}

export interface RiskAcceptanceEvent {
  id: string
  approver: string
  level: string
  status: string
  createdAt: number
  revokedAt?: number | null
}

export interface RedBlueRoundEvent {
  id: string
  roundOutcome: string
  ranAt: number
  simulatedFindingsGenerated?: number
}

export interface AutoRemediationEvent {
  id: string
  dispatchedCount: number
  candidateCount: number
  computedAt: number
}

export interface SecretScanEvent {
  id: string
  criticalCount: number
  highCount: number
  scannedAt: number
}

/** Complete input bag passed to `buildSecurityTimeline`. */
export interface SecurityTimelineInput {
  findings: FindingEvent[]
  escalations: EscalationEvent[]
  triageEvents: TriageEvent[]
  gateDecisions: GateDecisionEvent[]
  prProposals: PrProposalEvent[]
  slaBreaches: SlaBreachEvent[]
  riskAcceptances: RiskAcceptanceEvent[]
  redBlueRounds: RedBlueRoundEvent[]
  autoRemediationRuns: AutoRemediationEvent[]
  secretScans: SecretScanEvent[]
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Cast a raw severity string to the typed union, or return undefined. */
function safeSeverity(s: string): TimelineSeverity | undefined {
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s
  return undefined
}

/** Human-readable label for finding triage actions. */
const TRIAGE_ACTION_LABEL: Record<string, string> = {
  mark_false_positive: 'Marked as false positive',
  mark_accepted_risk: 'Accepted as known risk',
  reopen: 'Reopened by analyst',
  add_note: 'Analyst note added',
  ignore: 'Ignored by analyst',
}

/** Human-readable label for gate decisions. */
const GATE_DECISION_LABEL: Record<string, string> = {
  blocked: 'CI gate blocked deployment',
  approved: 'CI gate approved deployment',
  overridden: 'CI gate override recorded',
}

/** Map gate decision string → TimelineEventType. */
function gateEventType(decision: string): TimelineEventType {
  if (decision === 'blocked') return 'gate_blocked'
  if (decision === 'overridden') return 'gate_overridden'
  return 'gate_approved'
}

// ── Core function ──────────────────────────────────────────────────────────

/**
 * Merge events from all security data sources into a chronological timeline.
 *
 * @param input   Raw events from each Convex table (pre-mapped to lean types)
 * @param limit   Maximum entries to return (default 50, max 100)
 * @returns       Entries sorted newest-first, sliced to `limit`
 */
export function buildSecurityTimeline(
  input: SecurityTimelineInput,
  limit = 50,
): TimelineEntry[] {
  const entries: TimelineEntry[] = []
  const cap = Math.min(limit, 100)

  // ── Findings → finding_created ──────────────────────────────────────────
  for (const f of input.findings) {
    entries.push({
      id: `finding_created:${f.id}`,
      eventType: 'finding_created',
      timestamp: f.createdAt,
      severity: safeSeverity(f.severity),
      title: `Finding detected: ${f.title}`,
      detail: `Severity: ${f.severity}`,
      metadata: { findingId: f.id, status: f.status },
    })
  }

  // ── Escalations → finding_escalated ────────────────────────────────────
  for (const e of input.escalations) {
    const triggerText = e.triggers.length > 0 ? e.triggers.join(', ') : 'automatic'
    entries.push({
      id: `finding_escalated:${e.id}`,
      eventType: 'finding_escalated',
      timestamp: e.computedAt,
      severity: safeSeverity(e.newSeverity),
      title: `Severity escalated: ${e.previousSeverity} → ${e.newSeverity}`,
      detail: `Triggers: ${triggerText}`,
      metadata: {
        previousSeverity: e.previousSeverity,
        newSeverity: e.newSeverity,
      },
    })
  }

  // ── Triage events → finding_triaged ────────────────────────────────────
  for (const t of input.triageEvents) {
    const label = TRIAGE_ACTION_LABEL[t.action] ?? `Analyst action: ${t.action}`
    const detail = t.note ?? (t.analyst ? `Analyst: ${t.analyst}` : t.action)
    entries.push({
      id: `finding_triaged:${t.id}`,
      eventType: 'finding_triaged',
      timestamp: t.createdAt,
      title: label,
      detail,
      metadata: {
        action: t.action,
        ...(t.analyst ? { analyst: t.analyst } : {}),
      },
    })
  }

  // ── Gate decisions → gate_blocked / gate_approved / gate_overridden ─────
  for (const g of input.gateDecisions) {
    entries.push({
      id: `gate_decision:${g.id}`,
      eventType: gateEventType(g.decision),
      timestamp: g.createdAt,
      severity: g.decision === 'blocked' ? 'high' : undefined,
      title: GATE_DECISION_LABEL[g.decision] ?? `Gate decision: ${g.decision}`,
      detail: `Stage: ${g.stage}`,
      metadata: { stage: g.stage, decision: g.decision },
    })
  }

  // ── PR proposals → pr_opened (and pr_merged when mergedAt is set) ───────
  for (const p of input.prProposals) {
    entries.push({
      id: `pr_opened:${p.id}`,
      eventType: 'pr_opened',
      timestamp: p.createdAt,
      title: `Fix PR proposed: ${p.prTitle}`,
      detail: p.prUrl ? `PR: ${p.prUrl}` : 'Fix proposal created',
      metadata: {
        status: p.status,
        ...(p.prUrl ? { prUrl: p.prUrl } : {}),
      },
    })
    if (p.mergedAt) {
      entries.push({
        id: `pr_merged:${p.id}`,
        eventType: 'pr_merged',
        timestamp: p.mergedAt,
        title: `Fix PR merged: ${p.prTitle}`,
        detail: p.mergedBy ? `Merged by: ${p.mergedBy}` : 'PR merged',
        metadata: {
          ...(p.prUrl ? { prUrl: p.prUrl } : {}),
          ...(p.mergedBy ? { mergedBy: p.mergedBy } : {}),
        },
      })
    }
  }

  // ── SLA breaches → sla_breached ────────────────────────────────────────
  for (const s of input.slaBreaches) {
    const hoursText = s.slaThresholdHours >= 24
      ? `${(s.slaThresholdHours / 24).toFixed(0)}d deadline`
      : `${s.slaThresholdHours}h deadline`
    entries.push({
      id: `sla_breached:${s.id}`,
      eventType: 'sla_breached',
      timestamp: s.breachedAt,
      severity: safeSeverity(s.severity),
      title: `SLA breached: ${s.severity} finding overdue`,
      detail: `Exceeded ${hoursText} — ${s.title}`,
      metadata: {
        severity: s.severity,
        slaThresholdHours: String(s.slaThresholdHours),
      },
    })
  }

  // ── Risk acceptances → risk_accepted (+ risk_revoked if applicable) ─────
  for (const r of input.riskAcceptances) {
    entries.push({
      id: `risk_accepted:${r.id}`,
      eventType: 'risk_accepted',
      timestamp: r.createdAt,
      title: `Risk formally accepted (${r.level})`,
      detail: `Approver: ${r.approver}`,
      metadata: { level: r.level, approver: r.approver },
    })
    if (r.status === 'revoked' && r.revokedAt) {
      entries.push({
        id: `risk_revoked:${r.id}`,
        eventType: 'risk_revoked',
        timestamp: r.revokedAt,
        title: 'Risk acceptance revoked',
        detail: `Original approver: ${r.approver}`,
        metadata: { level: r.level, approver: r.approver },
      })
    }
  }

  // ── Red/Blue rounds → red_agent_win (only red_wins rounds) ─────────────
  for (const rb of input.redBlueRounds) {
    if (rb.roundOutcome === 'red_wins') {
      const count = rb.simulatedFindingsGenerated ?? 0
      entries.push({
        id: `red_agent_win:${rb.id}`,
        eventType: 'red_agent_win',
        timestamp: rb.ranAt,
        severity: 'high',
        title: 'Red agent won adversarial round',
        detail: count > 0
          ? `${count} simulated finding${count > 1 ? 's' : ''} generated`
          : 'Exploit paths discovered',
        metadata: { outcome: rb.roundOutcome },
      })
    }
  }

  // ── Auto-remediation runs → auto_remediation_dispatched (if dispatched>0) ─
  for (const ar of input.autoRemediationRuns) {
    if (ar.dispatchedCount > 0) {
      entries.push({
        id: `auto_remediation:${ar.id}`,
        eventType: 'auto_remediation_dispatched',
        timestamp: ar.computedAt,
        title: `Auto-remediation dispatched ${ar.dispatchedCount} fix PR${ar.dispatchedCount > 1 ? 's' : ''}`,
        detail: `${ar.candidateCount} candidates assessed`,
        metadata: {
          dispatched: String(ar.dispatchedCount),
          candidates: String(ar.candidateCount),
        },
      })
    }
  }

  // ── Secret scans → secret_detected (only when critical or high found) ───
  for (const ss of input.secretScans) {
    const totalSensitive = ss.criticalCount + ss.highCount
    if (totalSensitive > 0) {
      entries.push({
        id: `secret_detected:${ss.id}`,
        eventType: 'secret_detected',
        timestamp: ss.scannedAt,
        severity: ss.criticalCount > 0 ? 'critical' : 'high',
        title: `${totalSensitive} exposed secret${totalSensitive > 1 ? 's' : ''} detected`,
        detail: ss.criticalCount > 0
          ? `${ss.criticalCount} critical credential${ss.criticalCount > 1 ? 's' : ''} in push`
          : `${ss.highCount} high-severity secret${ss.highCount > 1 ? 's' : ''} found`,
        metadata: {
          criticalCount: String(ss.criticalCount),
          highCount: String(ss.highCount),
        },
      })
    }
  }

  // ── Sort newest-first, then slice to limit ──────────────────────────────
  entries.sort((a, b) => b.timestamp - a.timestamp)

  return entries.slice(0, cap)
}

// ── Utility: count events by type ──────────────────────────────────────────

/** Summary counts of each event type in a pre-built timeline. */
export interface TimelineTypeCounts {
  finding_created: number
  finding_escalated: number
  finding_triaged: number
  gate_blocked: number
  gate_approved: number
  gate_overridden: number
  pr_opened: number
  pr_merged: number
  sla_breached: number
  risk_accepted: number
  risk_revoked: number
  red_agent_win: number
  auto_remediation_dispatched: number
  secret_detected: number
  total: number
}

/** Count events by type for summary pills in the dashboard. */
export function countTimelineEventsByType(entries: TimelineEntry[]): TimelineTypeCounts {
  const counts: TimelineTypeCounts = {
    finding_created: 0,
    finding_escalated: 0,
    finding_triaged: 0,
    gate_blocked: 0,
    gate_approved: 0,
    gate_overridden: 0,
    pr_opened: 0,
    pr_merged: 0,
    sla_breached: 0,
    risk_accepted: 0,
    risk_revoked: 0,
    red_agent_win: 0,
    auto_remediation_dispatched: 0,
    secret_detected: 0,
    total: 0,
  }
  for (const e of entries) {
    counts[e.eventType]++
    counts.total++
  }
  return counts
}
