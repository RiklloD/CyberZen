// Prometheus Metrics Builder — pure library, no Convex dependencies.
//
// Spec §4.6.5 — Observability Integrations:
//   Grafana: Sentinel dashboard panels via Prometheus metrics endpoint
//
// Builds the text exposition format for scraping by Prometheus / Grafana Agent.
// GET /metrics endpoint in http.ts consumes this library.

export type PrometheusMetricType = 'gauge' | 'counter' | 'untyped'

export interface MetricSample {
  /** Prometheus metric name — only [a-zA-Z_:][a-zA-Z0-9_:]* */
  name: string
  /** HELP comment (one-liner). */
  help: string
  type: PrometheusMetricType
  /** Label key-value pairs. Values are escaped automatically. */
  labels: Record<string, string>
  value: number
  /** Unix epoch milliseconds. Included in the exposition line when present. */
  timestampMs?: number
}

export interface SentinelMetricsInput {
  tenantSlug: string
  repositoryFullName: string
  attackSurfaceScore: number | null
  openCritical: number
  openHigh: number
  openMedium: number
  openLow: number
  gateBlockedCount: number
  averageTrustScore: number | null
  redAgentWinRate: number | null
  provenanceScore: number | null
  complianceScores: Record<string, number>  // framework → score
  timestampMs: number
}

/**
 * Escapes a label value per the Prometheus text format spec:
 *   backslash → \\, double-quote → \", newline → \n
 */
export function escapeLabelValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
}

/**
 * Formats a label set as the `{key="val",...}` suffix.
 * Returns an empty string when there are no labels.
 */
export function formatLabels(labels: Record<string, string>): string {
  const keys = Object.keys(labels)
  if (keys.length === 0) return ''
  const pairs = keys.map((k) => `${k}="${escapeLabelValue(labels[k])}"`)
  return `{${pairs.join(',')}}`
}

/**
 * Renders a single Prometheus exposition line.
 * Value is formatted as a float (at least one decimal place).
 * Timestamp (ms) is appended when provided.
 */
export function renderMetricLine(
  name: string,
  labels: Record<string, string>,
  value: number,
  timestampMs?: number,
): string {
  const labelStr = formatLabels(labels)
  const valueStr = Number.isInteger(value) ? `${value}.0` : String(value)
  const tsStr = timestampMs !== undefined ? ` ${timestampMs}` : ''
  return `${name}${labelStr} ${valueStr}${tsStr}`
}

/**
 * Renders a complete metric family: # HELP, # TYPE, and all sample lines.
 * All samples in the array must share the same name/help/type.
 */
export function renderMetricFamily(samples: MetricSample[]): string {
  if (samples.length === 0) return ''
  const { name, help, type } = samples[0]
  const lines: string[] = [
    `# HELP ${name} ${help}`,
    `# TYPE ${name} ${type}`,
  ]
  for (const s of samples) {
    lines.push(renderMetricLine(s.name, s.labels, s.value, s.timestampMs))
  }
  return lines.join('\n')
}

/**
 * Renders all metric families separated by blank lines, ending with a final newline.
 */
export function buildMetricsPage(allSamples: MetricSample[]): string {
  if (allSamples.length === 0) return '\n'

  // Group by metric name (families share the same name)
  const familyMap = new Map<string, MetricSample[]>()
  for (const s of allSamples) {
    const group = familyMap.get(s.name)
    if (group) {
      group.push(s)
    } else {
      familyMap.set(s.name, [s])
    }
  }

  const families = Array.from(familyMap.values())
  const rendered = families.map((f) => renderMetricFamily(f))
  return rendered.join('\n\n') + '\n'
}

/**
 * Converts a SentinelMetricsInput to a flat array of MetricSamples ready for
 * buildMetricsPage / renderMetricFamily.
 */
export function sentinelMetricsToSamples(input: SentinelMetricsInput): MetricSample[] {
  const samples: MetricSample[] = []
  const baseLabelsTR: Record<string, string> = {
    tenant: input.tenantSlug,
    repository: input.repositoryFullName,
  }
  const ts = input.timestampMs

  // sentinel_attack_surface_score
  if (input.attackSurfaceScore !== null) {
    samples.push({
      name: 'sentinel_attack_surface_score',
      help: 'Composite attack surface risk score for the repository (0-100).',
      type: 'gauge',
      labels: { ...baseLabelsTR },
      value: input.attackSurfaceScore,
      timestampMs: ts,
    })
  }

  // sentinel_open_findings — one sample per severity
  const severities: Array<[string, number]> = [
    ['critical', input.openCritical],
    ['high', input.openHigh],
    ['medium', input.openMedium],
    ['low', input.openLow],
  ]
  for (const [severity, count] of severities) {
    samples.push({
      name: 'sentinel_open_findings',
      help: 'Number of open security findings grouped by severity.',
      type: 'gauge',
      labels: { ...baseLabelsTR, severity },
      value: count,
      timestampMs: ts,
    })
  }

  // sentinel_gate_blocked_total
  samples.push({
    name: 'sentinel_gate_blocked_total',
    help: 'Cumulative number of CI/CD gate enforcement blocks for the repository.',
    type: 'gauge',
    labels: { ...baseLabelsTR },
    value: input.gateBlockedCount,
    timestampMs: ts,
  })

  // sentinel_trust_score_average
  if (input.averageTrustScore !== null) {
    samples.push({
      name: 'sentinel_trust_score_average',
      help: 'Average contributor trust score across the repository (0-100).',
      type: 'gauge',
      labels: { ...baseLabelsTR },
      value: input.averageTrustScore,
      timestampMs: ts,
    })
  }

  // sentinel_red_agent_win_rate
  if (input.redAgentWinRate !== null) {
    samples.push({
      name: 'sentinel_red_agent_win_rate',
      help: 'Red agent simulation win rate as a fraction (0-1).',
      type: 'gauge',
      labels: { ...baseLabelsTR },
      value: input.redAgentWinRate,
      timestampMs: ts,
    })
  }

  // sentinel_provenance_score
  if (input.provenanceScore !== null) {
    samples.push({
      name: 'sentinel_provenance_score',
      help: 'Supply chain provenance score for the repository (0-100).',
      type: 'gauge',
      labels: { ...baseLabelsTR },
      value: input.provenanceScore,
      timestampMs: ts,
    })
  }

  // sentinel_compliance_evidence_score — one sample per framework
  for (const [framework, score] of Object.entries(input.complianceScores)) {
    samples.push({
      name: 'sentinel_compliance_evidence_score',
      help: 'Compliance evidence completeness score per framework (0-100).',
      type: 'gauge',
      labels: { ...baseLabelsTR, framework },
      value: score,
      timestampMs: ts,
    })
  }

  return samples
}
