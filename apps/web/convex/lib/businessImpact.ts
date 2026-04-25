/**
 * WS-100 — Business Impact Assessment: pure computation library (spec §3.5.4)
 *
 * Aggregates findings, blast-radius scores, attack surface, and compliance
 * posture into a five-dimension business risk picture:
 *
 *   dataExposureScore      — sensitivity of exposed data layers
 *   regulatoryExposureScore — compliance/fine risk from open findings
 *   revenueImpactScore     — revenue-critical service exposure
 *   reputationScore        — reputational blast radius
 *   remediationCostScore   — effort/cost to close open gaps
 *
 * Overall score = weighted average (higher = worse).
 * No DB access — fully testable without Convex.
 */

// ---------------------------------------------------------------------------
// Input / Output types
// ---------------------------------------------------------------------------

export type ImpactLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal'

export interface BusinessImpactInput {
  /** Open finding counts by severity */
  criticalFindings: number
  highFindings: number
  mediumFindings: number
  lowFindings: number
  /** Highest per-finding blast-radius score (0–100) from blastRadiusSnapshots */
  maxBlastRadiusScore: number
  /** Average per-finding blast-radius score (0–100), or 0 when no data */
  avgBlastRadiusScore: number
  /** Union of reachableServices strings across all blast-radius snapshots */
  reachableServiceNames: string[]
  /** Latest attack-surface composite score (0–100, higher = better), null if absent */
  attackSurfaceScore: number | null
  /** Count of non-compliant regulatory frameworks from compliance attestation */
  nonCompliantFrameworkCount: number
  /** Count of at-risk regulatory frameworks */
  atRiskFrameworkCount: number
  /** Regulatory drift level from WS-15 */
  regulatoryDriftLevel: 'none' | 'low' | 'medium' | 'high' | 'critical' | null
}

export interface BusinessImpactResult {
  // ── Five spec §3.5.4 sub-scores (0–100, higher = worse) ──
  dataExposureScore: number
  regulatoryExposureScore: number
  revenueImpactScore: number
  reputationScore: number
  remediationCostScore: number
  // ── Aggregate ──
  overallScore: number
  impactLevel: ImpactLevel
  // ── Financial estimates ──
  estimatedRecordsAtRisk: number
  estimatedFineRangeMin: number
  estimatedFineRangeMax: number
  estimatedRemediationCostMin: number
  estimatedRemediationCostMax: number
  // ── Human-readable context ──
  topExposures: string[]
  assessedAt: number
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const REVENUE_SERVICE_KEYWORDS = [
  'payment', 'billing', 'checkout', 'stripe', 'order', 'commerce',
  'subscription', 'invoice', 'pricing', 'cart',
]

const AUTH_SERVICE_KEYWORDS = [
  'auth', 'login', 'identity', 'oauth', 'sso', 'session', 'token', 'jwt',
]

const DRIFT_PENALTIES: Record<NonNullable<BusinessImpactInput['regulatoryDriftLevel']>, number> = {
  none: 0, low: 5, medium: 15, high: 30, critical: 45,
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function cap(value: number, max: number): number {
  return Math.min(value, max)
}

function clamp(value: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, value))
}

function scoreDataExposure(input: BusinessImpactInput): number {
  let score = 0
  // Severity contribution
  score += cap(input.criticalFindings * 15, 40)
  score += cap(input.highFindings * 5, 20)
  // Blast radius contribution
  score += input.maxBlastRadiusScore * 0.35
  // Poor attack surface
  if (input.attackSurfaceScore !== null && input.attackSurfaceScore < 30) score += 20
  else if (input.attackSurfaceScore !== null && input.attackSurfaceScore < 50) score += 10
  return clamp(Math.round(score))
}

function scoreRegulatoryExposure(input: BusinessImpactInput): number {
  let score = 0
  score += cap(input.nonCompliantFrameworkCount * 15, 45)
  score += cap(input.atRiskFrameworkCount * 8, 24)
  score += DRIFT_PENALTIES[input.regulatoryDriftLevel ?? 'none']
  if (input.criticalFindings > 0 && input.nonCompliantFrameworkCount > 0) score += 20
  return clamp(Math.round(score))
}

function scoreRevenueImpact(input: BusinessImpactInput): number {
  let score = 0
  const lowerServices = input.reachableServiceNames.map((s) => s.toLowerCase())
  const hasRevenue = lowerServices.some((s) =>
    REVENUE_SERVICE_KEYWORDS.some((kw) => s.includes(kw)),
  )
  const hasAuth = lowerServices.some((s) =>
    AUTH_SERVICE_KEYWORDS.some((kw) => s.includes(kw)),
  )
  if (hasRevenue) score += 35
  if (hasAuth) score += 20
  score += cap(input.criticalFindings * 10, 35)
  // Inverse attack surface: poor surface = higher revenue risk
  if (input.attackSurfaceScore !== null) {
    score += Math.round((100 - input.attackSurfaceScore) * 0.2)
  } else if (input.criticalFindings > 0 || input.highFindings > 0) {
    score += 15 // unknown surface with active high-severity findings
  }
  return clamp(Math.round(score))
}

function scoreReputation(input: BusinessImpactInput): number {
  let score = 0
  if (input.criticalFindings > 10) score += 70
  else if (input.criticalFindings > 5) score += 55
  else if (input.criticalFindings > 2) score += 40
  else if (input.criticalFindings > 0) score += 30
  score += cap(Math.round(input.highFindings * 1.5), 25)
  if (input.attackSurfaceScore !== null) {
    if (input.attackSurfaceScore < 20) score += 25
    else if (input.attackSurfaceScore < 40) score += 15
    else if (input.attackSurfaceScore < 60) score += 5
  }
  return clamp(Math.round(score))
}

function scoreRemediationCost(input: BusinessImpactInput): number {
  let score = 0
  score += cap(input.criticalFindings * 12, 50)
  score += cap(input.highFindings * 4, 30)
  score += cap(input.mediumFindings * 1, 15)
  score += cap(Math.round(input.lowFindings * 0.3), 5)
  return clamp(Math.round(score))
}

// ---------------------------------------------------------------------------
// Financial estimates
// ---------------------------------------------------------------------------

function estimateRecordsAtRisk(input: BusinessImpactInput): number {
  let records =
    input.criticalFindings * 8_000 +
    input.highFindings * 1_500 +
    input.mediumFindings * 200
  if (input.maxBlastRadiusScore > 70) records = Math.round(records * 1.5)
  return Math.min(records, 1_000_000)
}

function estimateFineRange(
  regulatoryScore: number,
): { min: number; max: number } {
  if (regulatoryScore >= 80) return { min: 500_000, max: 10_000_000 }
  if (regulatoryScore >= 60) return { min: 100_000, max: 2_000_000 }
  if (regulatoryScore >= 40) return { min: 25_000, max: 500_000 }
  if (regulatoryScore >= 20) return { min: 5_000, max: 100_000 }
  return { min: 0, max: 10_000 }
}

function estimateRemediationCost(
  input: BusinessImpactInput,
): { min: number; max: number } {
  const base =
    input.criticalFindings * 8_000 +
    input.highFindings * 2_500 +
    input.mediumFindings * 500 +
    input.lowFindings * 100 +
    2_500 // base overhead
  return { min: Math.round(base * 0.7), max: Math.round(base * 1.6) }
}

// ---------------------------------------------------------------------------
// Narrative exposures
// ---------------------------------------------------------------------------

function buildTopExposures(
  input: BusinessImpactInput,
  scores: {
    regulatory: number
    revenue: number
    blast: number
    surface: number | null
  },
): string[] {
  const items: string[] = []
  if (input.criticalFindings > 0) {
    items.push(
      `${input.criticalFindings} critical finding${input.criticalFindings > 1 ? 's' : ''} require immediate remediation`,
    )
  }
  if (input.nonCompliantFrameworkCount > 0) {
    items.push(
      `Non-compliance across ${input.nonCompliantFrameworkCount} regulatory framework${input.nonCompliantFrameworkCount > 1 ? 's' : ''}`,
    )
  }
  if (scores.blast > 70) {
    items.push('High blast-radius exposure across service dependencies')
  }
  if (scores.revenue >= 60) {
    items.push('Revenue-critical service paths exposed to vulnerability chains')
  }
  if (scores.surface !== null && scores.surface < 30) {
    items.push('Poor attack surface hygiene widens the exploitation window')
  }
  if (input.regulatoryDriftLevel && ['high', 'critical'].includes(input.regulatoryDriftLevel)) {
    items.push('High regulatory drift increases potential fine exposure')
  }
  return items.slice(0, 5)
}

// ---------------------------------------------------------------------------
// Overall level
// ---------------------------------------------------------------------------

function deriveImpactLevel(score: number): ImpactLevel {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'minimal'
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function computeBusinessImpact(input: BusinessImpactInput): BusinessImpactResult {
  const dataExposureScore      = scoreDataExposure(input)
  const regulatoryExposureScore = scoreRegulatoryExposure(input)
  const revenueImpactScore     = scoreRevenueImpact(input)
  const reputationScore        = scoreReputation(input)
  const remediationCostScore   = scoreRemediationCost(input)

  // Weighted average (spec: financial impact most critical)
  const overallScore = clamp(
    Math.round(
      dataExposureScore * 0.25 +
      regulatoryExposureScore * 0.25 +
      revenueImpactScore * 0.20 +
      reputationScore * 0.20 +
      remediationCostScore * 0.10,
    ),
  )

  const impactLevel = deriveImpactLevel(overallScore)

  const fineRange = estimateFineRange(regulatoryExposureScore)
  const remediationRange = estimateRemediationCost(input)

  const topExposures = buildTopExposures(input, {
    regulatory: regulatoryExposureScore,
    revenue: revenueImpactScore,
    blast: input.maxBlastRadiusScore,
    surface: input.attackSurfaceScore,
  })

  return {
    dataExposureScore,
    regulatoryExposureScore,
    revenueImpactScore,
    reputationScore,
    remediationCostScore,
    overallScore,
    impactLevel,
    estimatedRecordsAtRisk: estimateRecordsAtRisk(input),
    estimatedFineRangeMin: fineRange.min,
    estimatedFineRangeMax: fineRange.max,
    estimatedRemediationCostMin: remediationRange.min,
    estimatedRemediationCostMax: remediationRange.max,
    topExposures,
    assessedAt: Date.now(),
  }
}
