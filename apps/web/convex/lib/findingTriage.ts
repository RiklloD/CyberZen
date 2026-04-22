// Analyst triage logic for security findings.
//
// Tracks explicit analyst feedback (false positives, notes, re-opens) as a
// structured event log separate from the automated validation pipeline.  The
// computed triage summary is used by the learning loop to raise/lower
// confidence multipliers for a vuln-class when analysts repeatedly correct
// automated classifications.
//
// Pure library — no Convex imports, fully unit-testable.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TriageAction =
  | 'mark_false_positive'
  | 'mark_accepted_risk'
  | 'reopen'
  | 'add_note'
  | 'ignore'

export type TriageEvent = {
  action: TriageAction
  note?: string
  analyst?: string   // free-form label or email — not auth-linked at library level
  createdAt: number  // ms epoch
}

export type TriageSummary = {
  /** Total number of triage events recorded. */
  totalEvents: number
  /** The most recently applied action (ignoring add_note). */
  lastStatusAction?: TriageAction
  /** Timestamp of the last status-changing action. */
  lastActedAt?: number
  /** Analyst identifier from the last status-changing action. */
  lastAnalyst?: string
  /** All non-empty note strings, in chronological order. */
  notes: string[]
  /** True when at least one status-changing action has been applied. */
  isReviewed: boolean
  /** How many times this finding has been marked false_positive. */
  falsePositiveCount: number
  /** Whether the CURRENT effective status marks this as a false positive. */
  isFalsePositive: boolean
}

// ---------------------------------------------------------------------------
// findingStatus mapping
// ---------------------------------------------------------------------------

/**
 * Maps a triage action to the finding status it produces, or null when the
 * action does not change status (add_note).
 */
export function triageActionToStatus(
  action: TriageAction,
): 'false_positive' | 'accepted_risk' | 'open' | 'ignored' | null {
  switch (action) {
    case 'mark_false_positive':
      return 'false_positive'
    case 'mark_accepted_risk':
      return 'accepted_risk'
    case 'reopen':
      return 'open'
    case 'ignore':
      return 'ignored'
    case 'add_note':
      return null
  }
}

// ---------------------------------------------------------------------------
// computeTriageSummary
// ---------------------------------------------------------------------------

/**
 * Derives a read-only TriageSummary from the full event log.
 * Events must be in ascending createdAt order (the DB index guarantees this).
 */
export function computeTriageSummary(events: TriageEvent[]): TriageSummary {
  let lastStatusAction: TriageAction | undefined
  let lastActedAt: number | undefined
  let lastAnalyst: string | undefined
  let falsePositiveCount = 0
  const notes: string[] = []

  for (const ev of events) {
    if (ev.note?.trim()) {
      notes.push(ev.note.trim())
    }

    if (ev.action === 'add_note') continue  // notes don't change effective status

    lastStatusAction = ev.action
    lastActedAt = ev.createdAt
    lastAnalyst = ev.analyst

    if (ev.action === 'mark_false_positive') {
      falsePositiveCount++
    }
  }

  // Effective false-positive state is based on LAST status-changing action only
  const isFalsePositive = lastStatusAction === 'mark_false_positive'

  return {
    totalEvents: events.length,
    lastStatusAction,
    lastActedAt,
    lastAnalyst,
    notes,
    isReviewed: lastStatusAction !== undefined,
    falsePositiveCount,
    isFalsePositive,
  }
}

// ---------------------------------------------------------------------------
// FP rate helper (used by learning loop)
// ---------------------------------------------------------------------------

/**
 * Given a list of triage summaries for all findings of a vuln-class, computes
 * the analyst-confirmed false-positive rate.
 *
 * Returns a number in [0, 1].  Returns 0 when there are no reviewed findings.
 */
export function analystFpRate(summaries: Pick<TriageSummary, 'isReviewed' | 'isFalsePositive'>[]): number {
  const reviewed = summaries.filter((s) => s.isReviewed)
  if (reviewed.length === 0) return 0
  const fps = reviewed.filter((s) => s.isFalsePositive).length
  return fps / reviewed.length
}

// ---------------------------------------------------------------------------
// Confidence adjustment from analyst feedback
// ---------------------------------------------------------------------------

/**
 * Returns a multiplier in [0.4, 1.0] that scales down the system confidence
 * for a vuln-class based on analyst feedback.
 *
 * High FP rate → low multiplier → new findings of this class get lower scores.
 * No feedback yet → no adjustment (1.0).
 */
export function analystConfidenceMultiplier(fpRate: number): number {
  // Linear interpolation: 0% FP → 1.0×, 80%+ FP → 0.4×
  const clamped = Math.max(0, Math.min(1, fpRate))
  return 1.0 - clamped * 0.75
}
