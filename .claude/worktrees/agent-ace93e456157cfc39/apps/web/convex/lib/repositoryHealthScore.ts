/**
 * WS-49 — Repository Security Health Score: pure computation library.
 *
 * Master synthesis layer that reads computed results from all major scanners
 * and produces a single weighted 0–100 health score with an A–F grade and
 * per-category breakdown. This is the executive-level "how secure is this
 * repository?" answer.
 *
 * Seven weighted categories:
 *   Supply Chain           25%  — from WS-44 posture score
 *   Vulnerability Mgmt     20%  — from WS-43 CVE + WS-38 EOL + WS-39 abandonment
 *   Code Security           15%  — from WS-37 crypto + WS-30 secrets + WS-33 IaC + WS-35 CI/CD
 *   Compliance              15%  — from WS-46 attestation
 *   Container Security      10%  — from WS-45 container image
 *   License Risk            10%  — from WS-48 license scan
 *   SBOM Quality             5%  — from WS-32 quality snapshot
 *
 * Each category starts at 100 and applies capped penalties for critical/high
 * findings. The overall score is the weighted average, floored at 0.
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type HealthCategory =
  | 'supply_chain'
  | 'vulnerability_management'
  | 'code_security'
  | 'compliance'
  | 'container_security'
  | 'license_risk'
  | 'sbom_quality'

export type HealthGrade = 'A' | 'B' | 'C' | 'D' | 'F'

export type HealthTrend = 'improving' | 'declining' | 'stable' | 'new'

export type CategoryScore = {
  category: HealthCategory
  label: string
  score: number
  weight: number
  grade: HealthGrade
  /** Human-readable signals explaining the deductions. */
  signals: string[]
}

export type RepositoryHealthReport = {
  overallScore: number
  overallGrade: HealthGrade
  categories: CategoryScore[]
  trend: HealthTrend
  /** Top risk signals across all categories (max 5). */
  topRisks: string[]
  summary: string
}

/**
 * Scanner inputs gathered from the latest persisted results for a repository.
 * All fields are optional — missing data defaults to "no risk detected" (100).
 */
export type HealthScannerInputs = {
  // ── WS-44: Supply Chain Posture ──────────────────────────────────────
  supplyChainScore?: number | null       // 0–100
  supplyChainRisk?: string | null        // none/low/medium/high/critical

  // ── WS-43: CVE Scanner ───────────────────────────────────────────────
  cveCriticalCount?: number | null
  cveHighCount?: number | null

  // ── WS-38: EOL Detection ─────────────────────────────────────────────
  eolCriticalCount?: number | null

  // ── WS-39: Abandonment ───────────────────────────────────────────────
  abandonmentCriticalCount?: number | null

  // ── WS-37: Cryptography Weakness ─────────────────────────────────────
  cryptoCriticalCount?: number | null
  cryptoHighCount?: number | null

  // ── WS-30: Secret Detection ──────────────────────────────────────────
  secretCriticalCount?: number | null
  secretHighCount?: number | null

  // ── WS-33: IaC Security ──────────────────────────────────────────────
  iacCriticalCount?: number | null

  // ── WS-35: CI/CD Pipeline Security ───────────────────────────────────
  cicdCriticalCount?: number | null

  // ── WS-46: Compliance Attestation ────────────────────────────────────
  complianceOverallStatus?: string | null // compliant/at_risk/non_compliant
  complianceCriticalGaps?: number | null
  complianceHighGaps?: number | null

  // ── WS-45: Container Image ───────────────────────────────────────────
  containerCriticalCount?: number | null
  containerHighCount?: number | null

  // ── WS-48: License Scan ──────────────────────────────────────────────
  licenseCriticalCount?: number | null
  licenseHighCount?: number | null

  // ── WS-32: SBOM Quality ──────────────────────────────────────────────
  sbomQualityScore?: number | null       // 0–100
  sbomQualityGrade?: string | null       // excellent/good/fair/poor

  // ── Previous report (for trend calculation) ──────────────────────────
  previousOverallScore?: number | null
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const CATEGORY_WEIGHTS: Record<HealthCategory, number> = {
  supply_chain: 0.25,
  vulnerability_management: 0.20,
  code_security: 0.15,
  compliance: 0.15,
  container_security: 0.10,
  license_risk: 0.10,
  sbom_quality: 0.05,
}

export const CATEGORY_LABELS: Record<HealthCategory, string> = {
  supply_chain: 'Supply Chain',
  vulnerability_management: 'Vulnerability Management',
  code_security: 'Code Security',
  compliance: 'Compliance',
  container_security: 'Container Security',
  license_risk: 'License Risk',
  sbom_quality: 'SBOM Quality',
}

/** Grade thresholds: score must be ≥ the boundary. */
export function scoreToGrade(score: number): HealthGrade {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

// ---------------------------------------------------------------------------
// Internal per-category scorers
// ---------------------------------------------------------------------------

function clamp(value: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, value))
}

function n(v: number | null | undefined): number {
  return v ?? 0
}

function computeSupplyChainScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score: number

  if (input.supplyChainScore != null) {
    score = input.supplyChainScore
    if (score < 50) signals.push(`Supply chain posture score is critically low (${score}/100)`)
    else if (score < 75) signals.push(`Supply chain posture score needs improvement (${score}/100)`)
  } else {
    score = 100 // No data = no risk detected yet
  }

  if (input.supplyChainRisk === 'critical') {
    score = Math.min(score, 25)
    signals.push('Supply chain risk is critical')
  } else if (input.supplyChainRisk === 'high') {
    score = Math.min(score, 50)
    if (!signals.length) signals.push('Supply chain risk is high')
  }

  score = clamp(score)
  return {
    category: 'supply_chain',
    label: CATEGORY_LABELS.supply_chain,
    score,
    weight: CATEGORY_WEIGHTS.supply_chain,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeVulnerabilityScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score = 100

  // CVE penalties
  const cveCrit = n(input.cveCriticalCount)
  const cveHigh = n(input.cveHighCount)
  if (cveCrit > 0) {
    const penalty = Math.min(cveCrit * 20, 60)
    score -= penalty
    signals.push(`${cveCrit} critical CVE${cveCrit > 1 ? 's' : ''} detected`)
  }
  if (cveHigh > 0) {
    const penalty = Math.min(cveHigh * 10, 30)
    score -= penalty
    signals.push(`${cveHigh} high-severity CVE${cveHigh > 1 ? 's' : ''} detected`)
  }

  // EOL penalties
  const eolCrit = n(input.eolCriticalCount)
  if (eolCrit > 0) {
    const penalty = Math.min(eolCrit * 15, 45)
    score -= penalty
    signals.push(`${eolCrit} end-of-life dependenc${eolCrit > 1 ? 'ies' : 'y'}`)
  }

  // Abandonment penalties
  const abandCrit = n(input.abandonmentCriticalCount)
  if (abandCrit > 0) {
    const penalty = Math.min(abandCrit * 15, 30)
    score -= penalty
    signals.push(`${abandCrit} abandoned/compromised package${abandCrit > 1 ? 's' : ''}`)
  }

  score = clamp(score)
  return {
    category: 'vulnerability_management',
    label: CATEGORY_LABELS.vulnerability_management,
    score,
    weight: CATEGORY_WEIGHTS.vulnerability_management,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeCodeSecurityScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score = 100

  // Secret detection penalties (most severe — secrets are immediate exploitable risk)
  const secCrit = n(input.secretCriticalCount)
  const secHigh = n(input.secretHighCount)
  if (secCrit > 0) {
    const penalty = Math.min(secCrit * 20, 60)
    score -= penalty
    signals.push(`${secCrit} hardcoded secret${secCrit > 1 ? 's' : ''} exposed`)
  }
  if (secHigh > 0) {
    const penalty = Math.min(secHigh * 10, 30)
    score -= penalty
    signals.push(`${secHigh} high-risk credential${secHigh > 1 ? 's' : ''}`)
  }

  // Crypto weakness penalties
  const cryptCrit = n(input.cryptoCriticalCount)
  const cryptHigh = n(input.cryptoHighCount)
  if (cryptCrit > 0) {
    const penalty = Math.min(cryptCrit * 15, 45)
    score -= penalty
    signals.push(`${cryptCrit} critical crypto weakness${cryptCrit > 1 ? 'es' : ''}`)
  }
  if (cryptHigh > 0) {
    const penalty = Math.min(cryptHigh * 8, 24)
    score -= penalty
    signals.push(`${cryptHigh} high-risk crypto usage${cryptHigh > 1 ? 's' : ''}`)
  }

  // IaC penalties
  const iacCrit = n(input.iacCriticalCount)
  if (iacCrit > 0) {
    const penalty = Math.min(iacCrit * 15, 30)
    score -= penalty
    signals.push(`${iacCrit} critical IaC misconfiguration${iacCrit > 1 ? 's' : ''}`)
  }

  // CI/CD penalties
  const cicdCrit = n(input.cicdCriticalCount)
  if (cicdCrit > 0) {
    const penalty = Math.min(cicdCrit * 15, 30)
    score -= penalty
    signals.push(`${cicdCrit} critical CI/CD pipeline issue${cicdCrit > 1 ? 's' : ''}`)
  }

  score = clamp(score)
  return {
    category: 'code_security',
    label: CATEGORY_LABELS.code_security,
    score,
    weight: CATEGORY_WEIGHTS.code_security,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeComplianceScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score: number

  // Base score from status
  const status = input.complianceOverallStatus
  if (status === 'non_compliant') {
    score = 20
    signals.push('Overall compliance status is non-compliant')
  } else if (status === 'at_risk') {
    score = 55
    signals.push('Overall compliance status is at-risk')
  } else {
    score = 100 // compliant or no data
  }

  // Additional gap penalties
  const critGaps = n(input.complianceCriticalGaps)
  const highGaps = n(input.complianceHighGaps)
  if (critGaps > 0) {
    score -= Math.min(critGaps * 10, 30)
    signals.push(`${critGaps} critical compliance gap${critGaps > 1 ? 's' : ''}`)
  }
  if (highGaps > 0) {
    score -= Math.min(highGaps * 5, 20)
    signals.push(`${highGaps} high-priority compliance gap${highGaps > 1 ? 's' : ''}`)
  }

  score = clamp(score)
  return {
    category: 'compliance',
    label: CATEGORY_LABELS.compliance,
    score,
    weight: CATEGORY_WEIGHTS.compliance,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeContainerSecurityScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score = 100

  const contCrit = n(input.containerCriticalCount)
  const contHigh = n(input.containerHighCount)
  if (contCrit > 0) {
    const penalty = Math.min(contCrit * 20, 60)
    score -= penalty
    signals.push(`${contCrit} critical container image issue${contCrit > 1 ? 's' : ''}`)
  }
  if (contHigh > 0) {
    const penalty = Math.min(contHigh * 10, 30)
    score -= penalty
    signals.push(`${contHigh} high-risk container image${contHigh > 1 ? 's' : ''}`)
  }

  score = clamp(score)
  return {
    category: 'container_security',
    label: CATEGORY_LABELS.container_security,
    score,
    weight: CATEGORY_WEIGHTS.container_security,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeLicenseRiskScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score = 100

  const licCrit = n(input.licenseCriticalCount)
  const licHigh = n(input.licenseHighCount)
  if (licCrit > 0) {
    const penalty = Math.min(licCrit * 20, 60)
    score -= penalty
    signals.push(`${licCrit} strong copyleft license${licCrit > 1 ? 's' : ''} (GPL/AGPL/SSPL)`)
  }
  if (licHigh > 0) {
    const penalty = Math.min(licHigh * 10, 30)
    score -= penalty
    signals.push(`${licHigh} weak copyleft or proprietary license${licHigh > 1 ? 's' : ''}`)
  }

  score = clamp(score)
  return {
    category: 'license_risk',
    label: CATEGORY_LABELS.license_risk,
    score,
    weight: CATEGORY_WEIGHTS.license_risk,
    grade: scoreToGrade(score),
    signals,
  }
}

function computeSbomQualityScore(input: HealthScannerInputs): CategoryScore {
  const signals: string[] = []
  let score: number

  if (input.sbomQualityScore != null) {
    score = input.sbomQualityScore
  } else {
    // Fall back to grade mapping
    const gradeMap: Record<string, number> = {
      excellent: 100,
      good: 80,
      fair: 55,
      poor: 25,
    }
    score = (input.sbomQualityGrade ? gradeMap[input.sbomQualityGrade] : null) ?? 75
  }

  if (score < 40) signals.push('SBOM quality is poor — completeness and version-pinning gaps')
  else if (score < 60) signals.push('SBOM quality is fair — room for improvement')

  score = clamp(score)
  return {
    category: 'sbom_quality',
    label: CATEGORY_LABELS.sbom_quality,
    score,
    weight: CATEGORY_WEIGHTS.sbom_quality,
    grade: scoreToGrade(score),
    signals,
  }
}

// ---------------------------------------------------------------------------
// Trend detection
// ---------------------------------------------------------------------------

function detectTrend(currentScore: number, previousScore: number | null | undefined): HealthTrend {
  if (previousScore == null) return 'new'
  const delta = currentScore - previousScore
  if (delta >= 5) return 'improving'
  if (delta <= -5) return 'declining'
  return 'stable'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildSummary(report: {
  overallScore: number
  overallGrade: HealthGrade
  trend: HealthTrend
  topRisks: string[]
}): string {
  const { overallScore, overallGrade, trend, topRisks } = report

  if (overallGrade === 'A') {
    const trendNote =
      trend === 'improving'
        ? ' Security posture is improving.'
        : trend === 'stable'
          ? ' Posture is stable.'
          : ''
    return `Excellent security health (${overallScore}/100, grade A).${trendNote} No critical issues detected.`
  }

  const trendText =
    trend === 'improving'
      ? 'Posture is improving.'
      : trend === 'declining'
        ? 'Posture is declining — attention required.'
        : trend === 'stable'
          ? 'Posture is stable.'
          : ''

  const riskNote =
    topRisks.length > 0
      ? ` Top risk: ${topRisks[0]}.`
      : ''

  return `Security health score ${overallScore}/100 (grade ${overallGrade}). ${trendText}${riskNote}`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute a holistic security health report from the latest scanner results.
 *
 * @param inputs — Scanner output fields read from persisted result tables.
 * @returns A `RepositoryHealthReport` with weighted overall score, grade,
 *          per-category breakdown, trend, and prioritised risk signals.
 */
export function computeRepositoryHealthScore(
  inputs: HealthScannerInputs,
): RepositoryHealthReport {
  const categories: CategoryScore[] = [
    computeSupplyChainScore(inputs),
    computeVulnerabilityScore(inputs),
    computeCodeSecurityScore(inputs),
    computeComplianceScore(inputs),
    computeContainerSecurityScore(inputs),
    computeLicenseRiskScore(inputs),
    computeSbomQualityScore(inputs),
  ]

  // Weighted average
  const overallScore = clamp(
    Math.round(
      categories.reduce((sum, cat) => sum + cat.score * cat.weight, 0),
    ),
  )

  const overallGrade = scoreToGrade(overallScore)

  // Trend
  const trend = detectTrend(overallScore, inputs.previousOverallScore)

  // Top risks: collect all signals, sort by category severity (lowest score first)
  const sortedCategories = [...categories].sort((a, b) => a.score - b.score)
  const topRisks: string[] = []
  for (const cat of sortedCategories) {
    for (const signal of cat.signals) {
      if (topRisks.length < 5) topRisks.push(signal)
    }
  }

  const summary = buildSummary({ overallScore, overallGrade, trend, topRisks })

  return {
    overallScore,
    overallGrade,
    categories,
    trend,
    topRisks,
    summary,
  }
}
