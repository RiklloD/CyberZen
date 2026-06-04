import { describe, expect, it } from 'vitest'
import {
  buildSecurityTimeline,
  countTimelineEventsByType,
} from './securityTimeline'
import type {
  SecurityTimelineInput,
  TimelineEntry,
} from './securityTimeline'

// ── Helpers ───────────────────────────────────────────────────────────────

function emptyInput(): SecurityTimelineInput {
  return {
    findings: [],
    escalations: [],
    triageEvents: [],
    gateDecisions: [],
    prProposals: [],
    slaBreaches: [],
    riskAcceptances: [],
    redBlueRounds: [],
    autoRemediationRuns: [],
    secretScans: [],
  }
}

const NOW = 1_700_000_000_000

// ── Tests ─────────────────────────────────────────────────────────────────

describe('buildSecurityTimeline', () => {
  // ── Empty inputs ────────────────────────────────────────────────────────

  it('returns an empty array when all sources are empty', () => {
    expect(buildSecurityTimeline(emptyInput())).toEqual([])
  })

  // ── finding_created ─────────────────────────────────────────────────────

  it('produces a finding_created entry for each finding', () => {
    const input = emptyInput()
    input.findings = [
      { id: 'f1', title: 'Log4Shell in log4j', severity: 'critical', status: 'open', createdAt: NOW },
    ]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('finding_created')
    expect(result[0].severity).toBe('critical')
    expect(result[0].id).toBe('finding_created:f1')
    expect(result[0].title).toContain('Log4Shell')
  })

  it('includes status in finding_created metadata', () => {
    const input = emptyInput()
    input.findings = [{ id: 'f1', title: 'T', severity: 'high', status: 'pr_opened', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].metadata.status).toBe('pr_opened')
  })

  // ── finding_escalated ──────────────────────────────────────────────────

  it('produces a finding_escalated entry for each escalation', () => {
    const input = emptyInput()
    input.escalations = [
      {
        id: 'e1',
        previousSeverity: 'medium',
        newSeverity: 'critical',
        triggers: ['exploit_available', 'blast_radius_critical'],
        computedAt: NOW,
      },
    ]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('finding_escalated')
    expect(result[0].severity).toBe('critical')
    expect(result[0].title).toBe('Severity escalated: medium → critical')
    expect(result[0].detail).toContain('exploit_available')
    expect(result[0].detail).toContain('blast_radius_critical')
  })

  it('uses "automatic" as trigger text when triggers array is empty', () => {
    const input = emptyInput()
    input.escalations = [{ id: 'e1', previousSeverity: 'low', newSeverity: 'medium', triggers: [], computedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].detail).toContain('automatic')
  })

  // ── finding_triaged ────────────────────────────────────────────────────

  it('produces a finding_triaged entry with human-readable label', () => {
    const input = emptyInput()
    input.triageEvents = [
      { id: 't1', action: 'mark_false_positive', note: 'Not exploitable in our setup', analyst: 'alice@corp.com', createdAt: NOW },
    ]
    const result = buildSecurityTimeline(input)
    expect(result[0].eventType).toBe('finding_triaged')
    expect(result[0].title).toBe('Marked as false positive')
    expect(result[0].detail).toBe('Not exploitable in our setup')
  })

  it('falls back to action string for unknown triage actions', () => {
    const input = emptyInput()
    input.triageEvents = [{ id: 't1', action: 'custom_action', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].title).toContain('custom_action')
  })

  it('uses analyst name in detail when note is absent', () => {
    const input = emptyInput()
    input.triageEvents = [{ id: 't1', action: 'reopen', analyst: 'bob@corp.com', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].detail).toContain('bob@corp.com')
  })

  // ── gate decisions ─────────────────────────────────────────────────────

  it('maps gate blocked decision to gate_blocked event type', () => {
    const input = emptyInput()
    input.gateDecisions = [{ id: 'g1', stage: 'production', decision: 'blocked', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].eventType).toBe('gate_blocked')
    expect(result[0].severity).toBe('high')
    expect(result[0].title).toContain('blocked')
    expect(result[0].metadata.stage).toBe('production')
  })

  it('maps gate approved decision to gate_approved event type (no severity)', () => {
    const input = emptyInput()
    input.gateDecisions = [{ id: 'g1', stage: 'staging', decision: 'approved', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].eventType).toBe('gate_approved')
    expect(result[0].severity).toBeUndefined()
  })

  it('maps gate overridden decision to gate_overridden event type', () => {
    const input = emptyInput()
    input.gateDecisions = [{ id: 'g1', stage: 'production', decision: 'overridden', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].eventType).toBe('gate_overridden')
  })

  // ── PR proposals ───────────────────────────────────────────────────────

  it('produces a pr_opened entry from a PR proposal', () => {
    const input = emptyInput()
    input.prProposals = [{
      id: 'p1',
      status: 'open',
      prUrl: 'https://github.com/org/repo/pull/42',
      prTitle: 'fix: bump lodash to 4.17.21',
      createdAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('pr_opened')
    expect(result[0].title).toContain('bump lodash')
    expect(result[0].metadata.prUrl).toBe('https://github.com/org/repo/pull/42')
  })

  it('produces an additional pr_merged entry when mergedAt is set', () => {
    const input = emptyInput()
    input.prProposals = [{
      id: 'p1',
      status: 'merged',
      prUrl: 'https://github.com/org/repo/pull/42',
      prTitle: 'fix: bump lodash',
      createdAt: NOW - 10_000,
      mergedAt: NOW,
      mergedBy: 'carol',
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(2)
    const types = result.map((e) => e.eventType)
    expect(types).toContain('pr_opened')
    expect(types).toContain('pr_merged')
    const merged = result.find((e) => e.eventType === 'pr_merged')!
    expect(merged.timestamp).toBe(NOW)
    expect(merged.detail).toContain('carol')
  })

  it('does not emit pr_merged when mergedAt is absent', () => {
    const input = emptyInput()
    input.prProposals = [{
      id: 'p1', status: 'open', prTitle: 'fix', createdAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('pr_opened')
  })

  // ── SLA breaches ───────────────────────────────────────────────────────

  it('produces a sla_breached entry with threshold text', () => {
    const input = emptyInput()
    input.slaBreaches = [{
      id: 's1',
      severity: 'critical',
      title: 'XSS in auth form',
      breachedAt: NOW,
      slaThresholdHours: 24,
    }]
    const result = buildSecurityTimeline(input)
    expect(result[0].eventType).toBe('sla_breached')
    expect(result[0].severity).toBe('critical')
    expect(result[0].detail).toContain('1d deadline')
    expect(result[0].detail).toContain('XSS in auth form')
  })

  it('formats sub-day SLA thresholds in hours', () => {
    const input = emptyInput()
    input.slaBreaches = [{ id: 's1', severity: 'high', title: 'T', breachedAt: NOW, slaThresholdHours: 4 }]
    const result = buildSecurityTimeline(input)
    expect(result[0].detail).toContain('4h deadline')
  })

  // ── Risk acceptances ───────────────────────────────────────────────────

  it('produces a risk_accepted entry', () => {
    const input = emptyInput()
    input.riskAcceptances = [{
      id: 'r1', approver: 'ciso@corp.com', level: 'temporary',
      status: 'active', createdAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('risk_accepted')
    expect(result[0].title).toContain('temporary')
    expect(result[0].detail).toContain('ciso@corp.com')
  })

  it('produces an additional risk_revoked entry when status is revoked', () => {
    const input = emptyInput()
    input.riskAcceptances = [{
      id: 'r1', approver: 'ciso@corp.com', level: 'permanent',
      status: 'revoked', createdAt: NOW - 50_000, revokedAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(2)
    const types = result.map((e) => e.eventType)
    expect(types).toContain('risk_accepted')
    expect(types).toContain('risk_revoked')
  })

  it('does not emit risk_revoked when status is active', () => {
    const input = emptyInput()
    input.riskAcceptances = [{
      id: 'r1', approver: 'a', level: 'temporary', status: 'active', createdAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
  })

  // ── Red agent wins ─────────────────────────────────────────────────────

  it('produces a red_agent_win entry for red_wins outcome', () => {
    const input = emptyInput()
    input.redBlueRounds = [{
      id: 'rb1', roundOutcome: 'red_wins', ranAt: NOW, simulatedFindingsGenerated: 3,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('red_agent_win')
    expect(result[0].severity).toBe('high')
    expect(result[0].detail).toContain('3 simulated findings')
  })

  it('suppresses red/blue rounds that are not red_wins', () => {
    const input = emptyInput()
    input.redBlueRounds = [
      { id: 'rb1', roundOutcome: 'blue_wins', ranAt: NOW },
      { id: 'rb2', roundOutcome: 'draw', ranAt: NOW - 1000 },
    ]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(0)
  })

  it('uses "Exploit paths discovered" when simulatedFindingsGenerated is 0', () => {
    const input = emptyInput()
    input.redBlueRounds = [{ id: 'rb1', roundOutcome: 'red_wins', ranAt: NOW, simulatedFindingsGenerated: 0 }]
    const result = buildSecurityTimeline(input)
    expect(result[0].detail).toBe('Exploit paths discovered')
  })

  // ── Auto-remediation ────────────────────────────────────────────────────

  it('produces auto_remediation_dispatched when dispatchedCount > 0', () => {
    const input = emptyInput()
    input.autoRemediationRuns = [{ id: 'ar1', dispatchedCount: 2, candidateCount: 5, computedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('auto_remediation_dispatched')
    expect(result[0].title).toContain('2 fix PRs')
    expect(result[0].detail).toContain('5 candidates')
  })

  it('suppresses auto-remediation runs where dispatchedCount is 0', () => {
    const input = emptyInput()
    input.autoRemediationRuns = [{ id: 'ar1', dispatchedCount: 0, candidateCount: 3, computedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(0)
  })

  it('uses singular "fix PR" when dispatchedCount is 1', () => {
    const input = emptyInput()
    input.autoRemediationRuns = [{ id: 'ar1', dispatchedCount: 1, candidateCount: 2, computedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].title).toContain('1 fix PR')
    expect(result[0].title).not.toContain('PRs')
  })

  // ── Secret detection ────────────────────────────────────────────────────

  it('produces secret_detected entry when critical secrets found', () => {
    const input = emptyInput()
    input.secretScans = [{ id: 'ss1', criticalCount: 2, highCount: 0, scannedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(1)
    expect(result[0].eventType).toBe('secret_detected')
    expect(result[0].severity).toBe('critical')
    expect(result[0].detail).toContain('2 critical credentials')
  })

  it('uses high severity when only high secrets found', () => {
    const input = emptyInput()
    input.secretScans = [{ id: 'ss1', criticalCount: 0, highCount: 3, scannedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].severity).toBe('high')
    expect(result[0].detail).toContain('3 high-severity secrets')
  })

  it('suppresses secret scans with no critical or high findings', () => {
    const input = emptyInput()
    input.secretScans = [{ id: 'ss1', criticalCount: 0, highCount: 0, scannedAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(0)
  })

  // ── Sorting and limit ──────────────────────────────────────────────────

  it('sorts events newest-first across all sources', () => {
    const input = emptyInput()
    input.findings = [{ id: 'f1', title: 'A', severity: 'high', status: 'open', createdAt: NOW - 3000 }]
    input.slaBreaches = [{ id: 's1', severity: 'critical', title: 'B', breachedAt: NOW, slaThresholdHours: 24 }]
    input.escalations = [{ id: 'e1', previousSeverity: 'low', newSeverity: 'high', triggers: [], computedAt: NOW - 1000 }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(3)
    expect(result[0].eventType).toBe('sla_breached')     // newest: NOW
    expect(result[1].eventType).toBe('finding_escalated') // NOW - 1000
    expect(result[2].eventType).toBe('finding_created')   // oldest: NOW - 3000
  })

  it('enforces the limit parameter', () => {
    const input = emptyInput()
    input.findings = Array.from({ length: 20 }, (_, i) => ({
      id: `f${i}`, title: `F${i}`, severity: 'low', status: 'open', createdAt: NOW - i * 1000,
    }))
    const result = buildSecurityTimeline(input, 5)
    expect(result).toHaveLength(5)
  })

  it('caps limit at 100', () => {
    const input = emptyInput()
    input.findings = Array.from({ length: 200 }, (_, i) => ({
      id: `f${i}`, title: `F${i}`, severity: 'low', status: 'open', createdAt: NOW - i * 1000,
    }))
    const result = buildSecurityTimeline(input, 999)
    expect(result.length).toBeLessThanOrEqual(100)
  })

  it('returns all events when count is below default limit', () => {
    const input = emptyInput()
    input.findings = [{ id: 'f1', title: 'A', severity: 'high', status: 'open', createdAt: NOW }]
    input.slaBreaches = [{ id: 's1', severity: 'critical', title: 'B', breachedAt: NOW - 1, slaThresholdHours: 24 }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(2)
  })

  // ── ID uniqueness ─────────────────────────────────────────────────────

  it('generates unique IDs across different event types with the same source ID', () => {
    // A risk acceptance that is also revoked → two entries from one source record
    const input = emptyInput()
    input.riskAcceptances = [{
      id: 'r1', approver: 'a', level: 'temporary',
      status: 'revoked', createdAt: NOW - 5000, revokedAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    expect(result).toHaveLength(2)
    const ids = result.map((e) => e.id)
    expect(new Set(ids).size).toBe(2)
    expect(ids).toContain('risk_accepted:r1')
    expect(ids).toContain('risk_revoked:r1')
  })

  it('generates unique IDs for pr_opened and pr_merged from same PR proposal', () => {
    const input = emptyInput()
    input.prProposals = [{
      id: 'p1', status: 'merged', prTitle: 'fix', createdAt: NOW - 5000, mergedAt: NOW,
    }]
    const result = buildSecurityTimeline(input)
    const ids = result.map((e) => e.id)
    expect(ids).toContain('pr_opened:p1')
    expect(ids).toContain('pr_merged:p1')
  })

  // ── Unknown severity handling ─────────────────────────────────────────

  it('omits severity field for events with unknown severity strings', () => {
    const input = emptyInput()
    input.findings = [{ id: 'f1', title: 'T', severity: 'informational', status: 'open', createdAt: NOW }]
    const result = buildSecurityTimeline(input)
    expect(result[0].severity).toBeUndefined()
  })
})

// ── countTimelineEventsByType ─────────────────────────────────────────────

describe('countTimelineEventsByType', () => {
  it('returns all-zero counts for an empty array', () => {
    const counts = countTimelineEventsByType([])
    expect(counts.total).toBe(0)
    expect(counts.finding_created).toBe(0)
    expect(counts.sla_breached).toBe(0)
  })

  it('counts each event type correctly', () => {
    const entries: TimelineEntry[] = [
      { id: '1', eventType: 'finding_created', timestamp: NOW, title: '', detail: '', metadata: {} },
      { id: '2', eventType: 'finding_created', timestamp: NOW, title: '', detail: '', metadata: {} },
      { id: '3', eventType: 'gate_blocked', timestamp: NOW, title: '', detail: '', metadata: {} },
      { id: '4', eventType: 'sla_breached', timestamp: NOW, title: '', detail: '', severity: 'critical', metadata: {} },
    ]
    const counts = countTimelineEventsByType(entries)
    expect(counts.finding_created).toBe(2)
    expect(counts.gate_blocked).toBe(1)
    expect(counts.sla_breached).toBe(1)
    expect(counts.total).toBe(4)
    expect(counts.pr_opened).toBe(0)
  })

  it('handles all 14 event types without error', () => {
    const allTypes: Array<TimelineEntry['eventType']> = [
      'finding_created', 'finding_escalated', 'finding_triaged',
      'gate_blocked', 'gate_approved', 'gate_overridden',
      'pr_opened', 'pr_merged',
      'sla_breached',
      'risk_accepted', 'risk_revoked',
      'red_agent_win',
      'auto_remediation_dispatched',
      'secret_detected',
    ]
    const entries: TimelineEntry[] = allTypes.map((t, i) => ({
      id: String(i), eventType: t, timestamp: NOW, title: '', detail: '', metadata: {},
    }))
    const counts = countTimelineEventsByType(entries)
    expect(counts.total).toBe(14)
    for (const t of allTypes) expect(counts[t]).toBe(1)
  })
})
