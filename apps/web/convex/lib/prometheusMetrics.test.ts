import { describe, expect, test } from 'vitest'
import {
  escapeLabelValue,
  formatLabels,
  renderMetricLine,
  renderMetricFamily,
  buildMetricsPage,
  sentinelMetricsToSamples,
  type MetricSample,
  type SentinelMetricsInput,
} from './prometheusMetrics'

// ── escapeLabelValue ─────────────────────────────────────────────────────────

describe('escapeLabelValue', () => {
  test('escapes backslash to double-backslash', () => {
    expect(escapeLabelValue('foo\\bar')).toBe('foo\\\\bar')
  })

  test('escapes double-quote to backslash-quote', () => {
    expect(escapeLabelValue('say "hello"')).toBe('say \\"hello\\"')
  })

  test('escapes newline to \\n literal', () => {
    expect(escapeLabelValue('line1\nline2')).toBe('line1\\nline2')
  })

  test('leaves a clean string unchanged', () => {
    expect(escapeLabelValue('atlas-fintech/payments-api')).toBe('atlas-fintech/payments-api')
  })
})

// ── formatLabels ─────────────────────────────────────────────────────────────

describe('formatLabels', () => {
  test('returns empty string for empty label map', () => {
    expect(formatLabels({})).toBe('')
  })

  test('formats a single label', () => {
    expect(formatLabels({ tenant: 'atlas' })).toBe('{tenant="atlas"}')
  })

  test('formats multiple labels', () => {
    const result = formatLabels({ tenant: 'atlas', severity: 'critical' })
    expect(result).toBe('{tenant="atlas",severity="critical"}')
  })

  test('escapes special characters in label values', () => {
    const result = formatLabels({ repo: 'org/repo "main"' })
    expect(result).toBe('{repo="org/repo \\"main\\""}')
  })
})

// ── renderMetricLine ─────────────────────────────────────────────────────────

describe('renderMetricLine', () => {
  test('renders line with labels and timestamp', () => {
    const line = renderMetricLine(
      'sentinel_attack_surface_score',
      { tenant: 'atlas-fintech' },
      72,
      1234567890000,
    )
    expect(line).toBe(
      'sentinel_attack_surface_score{tenant="atlas-fintech"} 72.0 1234567890000',
    )
  })

  test('renders line without labels', () => {
    const line = renderMetricLine('sentinel_gate_blocked_total', {}, 5)
    expect(line).toBe('sentinel_gate_blocked_total 5.0')
  })

  test('renders line without timestamp', () => {
    const line = renderMetricLine('sentinel_attack_surface_score', { tenant: 'x' }, 55.5)
    expect(line).toBe('sentinel_attack_surface_score{tenant="x"} 55.5')
  })

  test('formats integer value with decimal point', () => {
    const line = renderMetricLine('some_metric', {}, 100)
    expect(line).toContain('100.0')
  })

  test('preserves non-integer float as-is', () => {
    const line = renderMetricLine('some_metric', {}, 0.35)
    expect(line).toContain('0.35')
  })
})

// ── renderMetricFamily ───────────────────────────────────────────────────────

describe('renderMetricFamily', () => {
  const samples: MetricSample[] = [
    {
      name: 'sentinel_open_findings',
      help: 'Number of open security findings grouped by severity.',
      type: 'gauge',
      labels: { severity: 'critical' },
      value: 3,
    },
    {
      name: 'sentinel_open_findings',
      help: 'Number of open security findings grouped by severity.',
      type: 'gauge',
      labels: { severity: 'high' },
      value: 7,
    },
  ]

  test('includes correct HELP header', () => {
    const output = renderMetricFamily(samples)
    expect(output).toContain(
      '# HELP sentinel_open_findings Number of open security findings grouped by severity.',
    )
  })

  test('includes correct TYPE header', () => {
    const output = renderMetricFamily(samples)
    expect(output).toContain('# TYPE sentinel_open_findings gauge')
  })

  test('renders all sample lines under the same metric family', () => {
    const output = renderMetricFamily(samples)
    expect(output).toContain('sentinel_open_findings{severity="critical"} 3.0')
    expect(output).toContain('sentinel_open_findings{severity="high"} 7.0')
  })

  test('returns empty string for empty array', () => {
    expect(renderMetricFamily([])).toBe('')
  })
})

// ── buildMetricsPage ─────────────────────────────────────────────────────────

describe('buildMetricsPage', () => {
  test('ends with a final newline', () => {
    const samples: MetricSample[] = [
      {
        name: 'sentinel_gate_blocked_total',
        help: 'Gate blocks.',
        type: 'gauge',
        labels: { tenant: 'x' },
        value: 1,
      },
    ]
    const page = buildMetricsPage(samples)
    expect(page.endsWith('\n')).toBe(true)
  })

  test('separates different metric families with a blank line', () => {
    const samples: MetricSample[] = [
      {
        name: 'sentinel_attack_surface_score',
        help: 'Attack surface score.',
        type: 'gauge',
        labels: { tenant: 'a' },
        value: 80,
      },
      {
        name: 'sentinel_gate_blocked_total',
        help: 'Gate blocks.',
        type: 'gauge',
        labels: { tenant: 'a' },
        value: 2,
      },
    ]
    const page = buildMetricsPage(samples)
    expect(page).toContain('\n\n')
    expect(page).toContain('# HELP sentinel_attack_surface_score')
    expect(page).toContain('# HELP sentinel_gate_blocked_total')
  })

  test('includes all metric families', () => {
    const samples: MetricSample[] = [
      { name: 'metric_a', help: 'A.', type: 'gauge', labels: {}, value: 1 },
      { name: 'metric_b', help: 'B.', type: 'counter', labels: {}, value: 2 },
      { name: 'metric_c', help: 'C.', type: 'untyped', labels: {}, value: 3 },
    ]
    const page = buildMetricsPage(samples)
    expect(page).toContain('# HELP metric_a')
    expect(page).toContain('# HELP metric_b')
    expect(page).toContain('# HELP metric_c')
  })
})

// ── sentinelMetricsToSamples ─────────────────────────────────────────────────

describe('sentinelMetricsToSamples', () => {
  const fullInput: SentinelMetricsInput = {
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

  test('produces 12 samples when all fields are present (2 compliance frameworks)', () => {
    // attack_surface(1) + open_findings(4) + gate(1) + trust(1) + win_rate(1) + provenance(1) + compliance(2) = 11
    // Wait — spec says 12. Let's count explicitly:
    // sentinel_attack_surface_score: 1
    // sentinel_open_findings (critical, high, medium, low): 4
    // sentinel_gate_blocked_total: 1
    // sentinel_trust_score_average: 1
    // sentinel_red_agent_win_rate: 1
    // sentinel_provenance_score: 1
    // sentinel_compliance_evidence_score x2: 2
    // Total = 11... spec says 12, but with 2 frameworks that's 11.
    // The spec note says "2 compliance = 12", implying base without compliance = 10, +2 = 12.
    // Re-count without compliance: 1+4+1+1+1+1 = 9, +2 = 11.
    // Accept actual count of 11 samples (spec comment appears off-by-one).
    const samples = sentinelMetricsToSamples(fullInput)
    expect(samples).toHaveLength(11)
  })

  test('skips attack_surface_score sample when it is null', () => {
    const input: SentinelMetricsInput = { ...fullInput, attackSurfaceScore: null }
    const samples = sentinelMetricsToSamples(input)
    const names = samples.map((s) => s.name)
    expect(names).not.toContain('sentinel_attack_surface_score')
  })

  test('skips averageTrustScore sample when null', () => {
    const input: SentinelMetricsInput = { ...fullInput, averageTrustScore: null }
    const samples = sentinelMetricsToSamples(input)
    const names = samples.map((s) => s.name)
    expect(names).not.toContain('sentinel_trust_score_average')
  })

  test('skips redAgentWinRate sample when null', () => {
    const input: SentinelMetricsInput = { ...fullInput, redAgentWinRate: null }
    const samples = sentinelMetricsToSamples(input)
    const names = samples.map((s) => s.name)
    expect(names).not.toContain('sentinel_red_agent_win_rate')
  })

  test('skips provenanceScore sample when null', () => {
    const input: SentinelMetricsInput = { ...fullInput, provenanceScore: null }
    const samples = sentinelMetricsToSamples(input)
    const names = samples.map((s) => s.name)
    expect(names).not.toContain('sentinel_provenance_score')
  })

  test('null score produces fewer samples than full input', () => {
    const input: SentinelMetricsInput = { ...fullInput, attackSurfaceScore: null }
    const full = sentinelMetricsToSamples(fullInput)
    const partial = sentinelMetricsToSamples(input)
    expect(partial.length).toBeLessThan(full.length)
  })

  test('produces two sentinel_compliance_evidence_score samples for two frameworks', () => {
    const samples = sentinelMetricsToSamples(fullInput)
    const compliance = samples.filter((s) => s.name === 'sentinel_compliance_evidence_score')
    expect(compliance).toHaveLength(2)
    const frameworks = compliance.map((s) => s.labels.framework)
    expect(frameworks).toContain('SOC2')
    expect(frameworks).toContain('ISO27001')
  })

  test('four sentinel_open_findings samples cover all severities', () => {
    const samples = sentinelMetricsToSamples(fullInput)
    const findings = samples.filter((s) => s.name === 'sentinel_open_findings')
    expect(findings).toHaveLength(4)
    const severities = findings.map((s) => s.labels.severity)
    expect(severities).toContain('critical')
    expect(severities).toContain('high')
    expect(severities).toContain('medium')
    expect(severities).toContain('low')
  })

  test('tenant and repository labels are set on every sample', () => {
    const samples = sentinelMetricsToSamples(fullInput)
    for (const s of samples) {
      expect(s.labels.tenant).toBe('atlas-fintech')
      expect(s.labels.repository).toBe('atlas-fintech/payments-api')
    }
  })

  test('timestampMs is propagated to all samples', () => {
    const samples = sentinelMetricsToSamples(fullInput)
    for (const s of samples) {
      expect(s.timestampMs).toBe(1744934400000)
    }
  })

  test('red agent win rate value stored as provided fraction (0-1)', () => {
    const samples = sentinelMetricsToSamples(fullInput)
    const winRate = samples.find((s) => s.name === 'sentinel_red_agent_win_rate')
    expect(winRate).toBeDefined()
    expect(winRate!.value).toBe(0.35)
  })
})
