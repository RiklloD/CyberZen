// Datadog Custom Metrics Payload Builder — pure library, no Convex dependencies.
//
// Spec §4.6.5 — Observability Integrations:
//   Datadog: Attack Surface Score and finding rate as custom metrics
//
// Uses the Datadog Metrics API v2:
//   POST https://api.datadoghq.com/api/v2/metrics
//   Headers: DD-API-KEY: <key>

export type DatadogMetricType = 0 | 1 | 2 | 3
// 0 = unspecified, 1 = count, 2 = rate, 3 = gauge

export interface DatadogPoint {
  timestamp: number   // Unix epoch seconds
  value: number
}

export interface DatadogSeries {
  metric: string          // "sentinel.attack_surface.score"
  type: DatadogMetricType // 3 = gauge
  points: DatadogPoint[]
  tags: string[]          // ["tenant:atlas-fintech", "repository:payments-api"]
  unit?: string           // optional unit label
}

export interface DatadogMetricsPayload {
  series: DatadogSeries[]
}

export interface SentinelDatadogInput {
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
  complianceScores: Record<string, number>
  timestampMs: number
}

/**
 * Builds the standard tag array for a Sentinel metric series.
 * Always includes service:sentinel, tenant:<slug>, and repository:<reponame>.
 * Additional tags can be appended via extraTags.
 */
export function buildTags(
  tenantSlug: string,
  repositoryFullName: string,
  extraTags?: string[],
): string[] {
  const base = [
    `tenant:${tenantSlug}`,
    `repository:${repositoryFullName}`,
    'service:sentinel',
  ]
  if (extraTags && extraTags.length > 0) {
    return [...base, ...extraTags]
  }
  return base
}

/**
 * Builds the array of DatadogSeries for a given SentinelDatadogInput.
 * Nullable fields are skipped when null.
 * All timestamps are in Unix epoch seconds (Math.floor(timestampMs / 1000)).
 */
export function buildDatadogSeries(input: SentinelDatadogInput): DatadogSeries[] {
  const series: DatadogSeries[] = []
  const timestampSec = Math.floor(input.timestampMs / 1000)
  const baseTags = buildTags(input.tenantSlug, input.repositoryFullName)

  // sentinel.attack_surface.score
  if (input.attackSurfaceScore !== null) {
    series.push({
      metric: 'sentinel.attack_surface.score',
      type: 3,
      points: [{ timestamp: timestampSec, value: input.attackSurfaceScore }],
      tags: baseTags,
    })
  }

  // sentinel.findings.open — four series, one per severity
  const severityFindings: Array<[string, number]> = [
    ['critical', input.openCritical],
    ['high', input.openHigh],
    ['medium', input.openMedium],
    ['low', input.openLow],
  ]
  for (const [severity, count] of severityFindings) {
    series.push({
      metric: 'sentinel.findings.open',
      type: 3,
      points: [{ timestamp: timestampSec, value: count }],
      tags: buildTags(input.tenantSlug, input.repositoryFullName, [`severity:${severity}`]),
    })
  }

  // sentinel.gate.blocked_total
  series.push({
    metric: 'sentinel.gate.blocked_total',
    type: 3,
    points: [{ timestamp: timestampSec, value: input.gateBlockedCount }],
    tags: baseTags,
  })

  // sentinel.trust_score.average
  if (input.averageTrustScore !== null) {
    series.push({
      metric: 'sentinel.trust_score.average',
      type: 3,
      points: [{ timestamp: timestampSec, value: input.averageTrustScore }],
      tags: baseTags,
    })
  }

  // sentinel.red_agent.win_rate
  if (input.redAgentWinRate !== null) {
    series.push({
      metric: 'sentinel.red_agent.win_rate',
      type: 3,
      points: [{ timestamp: timestampSec, value: input.redAgentWinRate }],
      tags: baseTags,
    })
  }

  // sentinel.provenance.score
  if (input.provenanceScore !== null) {
    series.push({
      metric: 'sentinel.provenance.score',
      type: 3,
      points: [{ timestamp: timestampSec, value: input.provenanceScore }],
      tags: baseTags,
    })
  }

  // sentinel.compliance.evidence_score — one series per framework
  for (const [framework, score] of Object.entries(input.complianceScores)) {
    series.push({
      metric: 'sentinel.compliance.evidence_score',
      type: 3,
      points: [{ timestamp: timestampSec, value: score }],
      tags: buildTags(input.tenantSlug, input.repositoryFullName, [`framework:${framework}`]),
    })
  }

  return series
}

/**
 * Wraps buildDatadogSeries in the top-level DatadogMetricsPayload envelope.
 */
export function buildDatadogPayload(input: SentinelDatadogInput): DatadogMetricsPayload {
  return { series: buildDatadogSeries(input) }
}
