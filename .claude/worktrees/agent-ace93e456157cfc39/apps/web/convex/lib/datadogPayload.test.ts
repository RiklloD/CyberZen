import { describe, expect, test } from 'vitest'
import { buildTags, buildDatadogSeries, buildDatadogPayload } from './datadogPayload'
import type { SentinelDatadogInput } from './datadogPayload'

// ── buildTags ─────────────────────────────────────────────────────────────────

describe('buildTags', () => {
  test('produces tenant, repository, and service:sentinel tags', () => {
    const tags = buildTags('atlas-fintech', 'atlas-fintech/payments-api')
    expect(tags).toContain('tenant:atlas-fintech')
    expect(tags).toContain('repository:atlas-fintech/payments-api')
    expect(tags).toContain('service:sentinel')
  })

  test('service:sentinel is always present even when no extra tags', () => {
    const tags = buildTags('acme', 'acme/api')
    expect(tags.some((t) => t === 'service:sentinel')).toBe(true)
  })

  test('extra tags are appended after the base tags', () => {
    const tags = buildTags('acme', 'acme/api', ['severity:critical', 'env:prod'])
    expect(tags).toContain('severity:critical')
    expect(tags).toContain('env:prod')
    // base tags still present
    expect(tags).toContain('tenant:acme')
    expect(tags).toContain('service:sentinel')
  })

  test('no extra tags → exactly three base tags', () => {
    const tags = buildTags('t', 'r')
    expect(tags).toHaveLength(3)
  })
})

// ── buildDatadogSeries ────────────────────────────────────────────────────────

const fullInput: SentinelDatadogInput = {
  tenantSlug: 'atlas-fintech',
  repositoryFullName: 'atlas-fintech/payments-api',
  attackSurfaceScore: 72,
  openCritical: 1,
  openHigh: 4,
  openMedium: 9,
  openLow: 12,
  gateBlockedCount: 3,
  averageTrustScore: 85.5,
  redAgentWinRate: 0.35,
  provenanceScore: 91,
  complianceScores: { SOC2: 88, ISO27001: 76 },
  timestampMs: 1744934400000,
}

describe('buildDatadogSeries', () => {
  test('produces correct total series count when all fields present (2 compliance frameworks)', () => {
    // attack_surface(1) + findings(4) + gate(1) + trust(1) + win_rate(1) + provenance(1) + compliance(2) = 11
    const series = buildDatadogSeries(fullInput)
    expect(series).toHaveLength(11)
  })

  test('skips attack_surface.score series when null', () => {
    const input: SentinelDatadogInput = { ...fullInput, attackSurfaceScore: null }
    const series = buildDatadogSeries(input)
    expect(series.some((s) => s.metric === 'sentinel.attack_surface.score')).toBe(false)
  })

  test('skips trust_score.average series when null', () => {
    const input: SentinelDatadogInput = { ...fullInput, averageTrustScore: null }
    const series = buildDatadogSeries(input)
    expect(series.some((s) => s.metric === 'sentinel.trust_score.average')).toBe(false)
  })

  test('skips red_agent.win_rate series when null', () => {
    const input: SentinelDatadogInput = { ...fullInput, redAgentWinRate: null }
    const series = buildDatadogSeries(input)
    expect(series.some((s) => s.metric === 'sentinel.red_agent.win_rate')).toBe(false)
  })

  test('skips provenance.score series when null', () => {
    const input: SentinelDatadogInput = { ...fullInput, provenanceScore: null }
    const series = buildDatadogSeries(input)
    expect(series.some((s) => s.metric === 'sentinel.provenance.score')).toBe(false)
  })

  test('metric names are correct', () => {
    const series = buildDatadogSeries(fullInput)
    const names = series.map((s) => s.metric)
    expect(names).toContain('sentinel.attack_surface.score')
    expect(names).toContain('sentinel.findings.open')
    expect(names).toContain('sentinel.gate.blocked_total')
    expect(names).toContain('sentinel.trust_score.average')
    expect(names).toContain('sentinel.red_agent.win_rate')
    expect(names).toContain('sentinel.provenance.score')
    expect(names).toContain('sentinel.compliance.evidence_score')
  })

  test('timestamps are in Unix epoch SECONDS, not milliseconds', () => {
    const series = buildDatadogSeries(fullInput)
    const expectedSec = Math.floor(fullInput.timestampMs / 1000)
    for (const s of series) {
      expect(s.points[0].timestamp).toBe(expectedSec)
    }
  })

  test('sentinel.findings.open series include severity tags', () => {
    const series = buildDatadogSeries(fullInput)
    const findings = series.filter((s) => s.metric === 'sentinel.findings.open')
    expect(findings).toHaveLength(4)
    const severityTags = findings.map((s) => s.tags.find((t) => t.startsWith('severity:')))
    expect(severityTags).toContain('severity:critical')
    expect(severityTags).toContain('severity:high')
    expect(severityTags).toContain('severity:medium')
    expect(severityTags).toContain('severity:low')
  })

  test('compliance series include framework tags', () => {
    const series = buildDatadogSeries(fullInput)
    const compliance = series.filter((s) => s.metric === 'sentinel.compliance.evidence_score')
    expect(compliance).toHaveLength(2)
    const frameworkTags = compliance.map((s) => s.tags.find((t) => t.startsWith('framework:')))
    expect(frameworkTags).toContain('framework:SOC2')
    expect(frameworkTags).toContain('framework:ISO27001')
  })

  test('all series have type 3 (gauge)', () => {
    const series = buildDatadogSeries(fullInput)
    for (const s of series) {
      expect(s.type).toBe(3)
    }
  })
})

// ── buildDatadogPayload ───────────────────────────────────────────────────────

describe('buildDatadogPayload', () => {
  test('wraps series correctly inside the payload envelope', () => {
    const payload = buildDatadogPayload(fullInput)
    expect(payload).toHaveProperty('series')
    expect(Array.isArray(payload.series)).toBe(true)
    expect(payload.series.length).toBe(buildDatadogSeries(fullInput).length)
  })

  test('series in payload match buildDatadogSeries output', () => {
    const payload = buildDatadogPayload(fullInput)
    const direct = buildDatadogSeries(fullInput)
    expect(payload.series).toEqual(direct)
  })

  test('when all nullable fields are null only gate + 4 open findings series remain', () => {
    const minInput: SentinelDatadogInput = {
      ...fullInput,
      attackSurfaceScore: null,
      averageTrustScore: null,
      redAgentWinRate: null,
      provenanceScore: null,
      complianceScores: {},
    }
    const payload = buildDatadogPayload(minInput)
    // gate(1) + findings(4) = 5
    expect(payload.series).toHaveLength(5)
    const names = payload.series.map((s) => s.metric)
    expect(names).toContain('sentinel.gate.blocked_total')
    expect(names.filter((n) => n === 'sentinel.findings.open')).toHaveLength(4)
    expect(names).not.toContain('sentinel.attack_surface.score')
    expect(names).not.toContain('sentinel.trust_score.average')
    expect(names).not.toContain('sentinel.red_agent.win_rate')
    expect(names).not.toContain('sentinel.provenance.score')
    expect(names).not.toContain('sentinel.compliance.evidence_score')
  })
})
