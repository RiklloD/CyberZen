/**
 * WS-96 — Configuration Drift Aggregate Health Score: pure computation library.
 *
 * Synthesis layer that reads the latest results from all 41 configuration-drift
 * detectors (WS-60 through WS-95, plus WS-101, WS-103, WS-105, WS-107, WS-109)
 * and produces a single weighted 0–100 drift posture score with an A–F grade,
 * per-category breakdown, and trend direction.
 *
 * Eight weighted categories:
 *   Application Security     22%  — WS-60, WS-61, WS-65, WS-75, WS-76, WS-103, WS-109
 *   Infrastructure           20%  — WS-62, WS-63, WS-64, WS-66, WS-87, WS-105
 *   Runtime & Policy         15%  — WS-67, WS-68, WS-72, WS-73, WS-107
 *   Identity & Access        15%  — WS-69, WS-70, WS-79
 *   Platform Services        10%  — WS-77, WS-78, WS-80, WS-81, WS-82, WS-83, WS-101
 *   Observability & SIEM      7%  — WS-71, WS-86, WS-94
 *   Network & Connectivity    6%  — WS-84, WS-85, WS-88, WS-90
 *   Endpoint & Device         5%  — WS-74, WS-91, WS-92, WS-93, WS-95
 *
 * Category score = mean of (100 − riskScore) across scanners with data, capped
 * down to 30 on any critical finding and 60 on any high finding.
 * Overall = weighted average. Grade: A≥90 / B≥75 / C≥60 / D≥40 / F<40.
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DriftCategory =
  | 'application_security'
  | 'infrastructure'
  | 'runtime_policy'
  | 'identity_access'
  | 'platform_services'
  | 'observability_siem'
  | 'network_connectivity'
  | 'endpoint_device'

export type DriftGrade = 'A' | 'B' | 'C' | 'D' | 'F'
export type DriftTrend = 'improving' | 'stable' | 'degrading' | 'new'

export type DriftRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

/** Normalised result from one drift scanner. */
export type DriftScannerResult = {
  riskScore: number       // 0–100
  riskLevel: DriftRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
}

/** Per-category breakdown returned in the posture report. */
export type DriftCategoryScore = {
  category: DriftCategory
  label: string
  score: number           // 0–100, higher = safer
  weight: number          // fraction 0–1
  grade: DriftGrade
  workstreamsScanned: number
  worstRiskLevel: DriftRiskLevel
  signals: string[]
}

export type DriftPostureReport = {
  overallScore: number
  overallGrade: DriftGrade
  trend: DriftTrend
  categoryScores: DriftCategoryScore[]
  totalWorkstreamsScanned: number
  criticalDriftCount: number
  highDriftCount: number
  topRisks: string[]
  summary: string
}

/**
 * All scanner inputs gathered from the latest persisted results per repo.
 * Fields named ws<N>_riskScore / ws<N>_riskLevel. Missing = no data (clean).
 */
export type DriftPostureScannerInputs = {
  // ── Category 1: Application Security ──────────────────────────────────
  ws60_riskScore?: number | null; ws60_riskLevel?: DriftRiskLevel | null  // App security config
  ws61_riskScore?: number | null; ws61_riskLevel?: DriftRiskLevel | null  // Test coverage gap
  ws65_riskScore?: number | null; ws65_riskLevel?: DriftRiskLevel | null  // API security config
  ws75_riskScore?: number | null; ws75_riskLevel?: DriftRiskLevel | null  // Web server & reverse proxy
  ws76_riskScore?: number | null; ws76_riskLevel?: DriftRiskLevel | null  // Email security

  // ── Category 2: Infrastructure ─────────────────────────────────────────
  ws62_riskScore?: number | null; ws62_riskLevel?: DriftRiskLevel | null  // Cloud security
  ws63_riskScore?: number | null; ws63_riskLevel?: DriftRiskLevel | null  // K8s/container hardening
  ws64_riskScore?: number | null; ws64_riskLevel?: DriftRiskLevel | null  // Database security
  ws66_riskScore?: number | null; ws66_riskLevel?: DriftRiskLevel | null  // Cert & PKI
  ws87_riskScore?: number | null; ws87_riskLevel?: DriftRiskLevel | null  // Storage & data security

  // ── Category 3: Runtime & Policy ──────────────────────────────────────
  ws67_riskScore?: number | null; ws67_riskLevel?: DriftRiskLevel | null  // Runtime security policy
  ws68_riskScore?: number | null; ws68_riskLevel?: DriftRiskLevel | null  // Network perimeter & firewall
  ws72_riskScore?: number | null; ws72_riskLevel?: DriftRiskLevel | null  // Service mesh & zero-trust
  ws73_riskScore?: number | null; ws73_riskLevel?: DriftRiskLevel | null  // CI/CD pipeline security
  ws107_riskScore?: number | null; ws107_riskLevel?: DriftRiskLevel | null // K8s admission controller & policy engine drift

  // ── Category 4: Identity & Access ─────────────────────────────────────
  ws69_riskScore?: number | null; ws69_riskLevel?: DriftRiskLevel | null  // Dev security tooling/SAST
  ws70_riskScore?: number | null; ws70_riskLevel?: DriftRiskLevel | null  // IAM & privileged access
  ws79_riskScore?: number | null; ws79_riskLevel?: DriftRiskLevel | null  // SSO provider & auth

  // ── Category 5: Platform Services ─────────────────────────────────────
  ws77_riskScore?: number | null; ws77_riskLevel?: DriftRiskLevel | null  // Serverless & FaaS
  ws78_riskScore?: number | null; ws78_riskLevel?: DriftRiskLevel | null  // Messaging & event streaming
  ws80_riskScore?: number | null; ws80_riskLevel?: DriftRiskLevel | null  // Data pipeline & ETL
  ws81_riskScore?: number | null; ws81_riskLevel?: DriftRiskLevel | null  // ML/AI platform
  ws82_riskScore?: number | null; ws82_riskLevel?: DriftRiskLevel | null  // Package & artifact registry
  ws83_riskScore?: number | null; ws83_riskLevel?: DriftRiskLevel | null  // Config management
  ws101_riskScore?: number | null; ws101_riskLevel?: DriftRiskLevel | null // AI/ML dependency security drift
  ws103_riskScore?: number | null; ws103_riskLevel?: DriftRiskLevel | null // Dependency manager security config drift
  ws105_riskScore?: number | null; ws105_riskLevel?: DriftRiskLevel | null // Secret management config drift
  ws109_riskScore?: number | null; ws109_riskLevel?: DriftRiskLevel | null // Supply chain build integrity & attestation drift

  // ── Category 6: Observability & SIEM ──────────────────────────────────
  ws71_riskScore?: number | null; ws71_riskLevel?: DriftRiskLevel | null  // Observability & monitoring
  ws86_riskScore?: number | null; ws86_riskLevel?: DriftRiskLevel | null  // SIEM & security analytics
  ws94_riskScore?: number | null; ws94_riskLevel?: DriftRiskLevel | null  // Network monitoring & SNMP

  // ── Category 7: Network & Connectivity ────────────────────────────────
  ws84_riskScore?: number | null; ws84_riskLevel?: DriftRiskLevel | null  // VPN & remote access
  ws85_riskScore?: number | null; ws85_riskLevel?: DriftRiskLevel | null  // Backup & DR security
  ws88_riskScore?: number | null; ws88_riskLevel?: DriftRiskLevel | null  // DNS security
  ws90_riskScore?: number | null; ws90_riskLevel?: DriftRiskLevel | null  // Wireless & RADIUS

  // ── Category 8: Endpoint & Device ─────────────────────────────────────
  ws74_riskScore?: number | null; ws74_riskLevel?: DriftRiskLevel | null  // Mobile app security
  ws89_riskScore?: number | null; ws89_riskLevel?: DriftRiskLevel | null  // OS security hardening
  ws91_riskScore?: number | null; ws91_riskLevel?: DriftRiskLevel | null  // IoT & embedded device
  ws92_riskScore?: number | null; ws92_riskLevel?: DriftRiskLevel | null  // Virtualization & hypervisor
  ws93_riskScore?: number | null; ws93_riskLevel?: DriftRiskLevel | null  // VoIP & unified comms
  ws95_riskScore?: number | null; ws95_riskLevel?: DriftRiskLevel | null  // Endpoint security & EDR

  /** Previous overall score for trend calculation (null = first scan). */
  previousOverallScore?: number | null
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DRIFT_CATEGORY_WEIGHTS: Record<DriftCategory, number> = {
  application_security:  0.22,
  infrastructure:        0.20,
  runtime_policy:        0.15,
  identity_access:       0.15,
  platform_services:     0.10,
  observability_siem:    0.07,
  network_connectivity:  0.06,
  endpoint_device:       0.05,
}

export const DRIFT_CATEGORY_LABELS: Record<DriftCategory, string> = {
  application_security:  'Application Security',
  infrastructure:        'Infrastructure',
  runtime_policy:        'Runtime & Policy',
  identity_access:       'Identity & Access',
  platform_services:     'Platform Services',
  observability_siem:    'Observability & SIEM',
  network_connectivity:  'Network & Connectivity',
  endpoint_device:       'Endpoint & Device',
}

/** Score must be ≥ the boundary to earn the grade. */
export function scoreToGrade(score: number): DriftGrade {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

/** ±5 point threshold for trend classification. */
export function detectTrend(current: number, previous: number | null | undefined): DriftTrend {
  if (previous == null) return 'new'
  const delta = current - previous
  if (delta >= 5) return 'improving'
  if (delta <= -5) return 'degrading'
  return 'stable'
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function clamp(v: number, lo = 0, hi = 100): number {
  return Math.max(lo, Math.min(hi, v))
}

function rs(score: number | null | undefined): number | null {
  return score != null ? score : null
}

function rl(level: DriftRiskLevel | null | undefined): DriftRiskLevel | null {
  return level ?? null
}

const RISK_LEVEL_ORDER: Record<DriftRiskLevel, number> = {
  none: 0, low: 1, medium: 2, high: 3, critical: 4,
}

function worstLevel(levels: (DriftRiskLevel | null)[]): DriftRiskLevel {
  let worst: DriftRiskLevel = 'none'
  for (const l of levels) {
    if (l && RISK_LEVEL_ORDER[l] > RISK_LEVEL_ORDER[worst]) worst = l
  }
  return worst
}

// ---------------------------------------------------------------------------
// Category scorer
// ---------------------------------------------------------------------------

type ScannerEntry = { riskScore: number | null; riskLevel: DriftRiskLevel | null; label: string }

function computeCategory(
  category: DriftCategory,
  scanners: ScannerEntry[],
): DriftCategoryScore {
  const signals: string[] = []
  const scoresWithData: number[] = []
  const levels: (DriftRiskLevel | null)[] = []

  for (const s of scanners) {
    if (s.riskScore != null) {
      scoresWithData.push(s.riskScore)
      levels.push(s.riskLevel)
      if (s.riskLevel === 'critical') {
        signals.push(`${s.label}: critical drift detected`)
      } else if (s.riskLevel === 'high' && s.riskScore >= 50) {
        signals.push(`${s.label}: high-severity drift (score ${s.riskScore})`)
      } else if (s.riskScore >= 60) {
        signals.push(`${s.label}: elevated drift risk (score ${s.riskScore})`)
      }
    }
  }

  const worst = worstLevel(levels)
  let score: number

  if (scoresWithData.length === 0) {
    // No data for this category → assume clean
    score = 100
  } else {
    const avgRisk = scoresWithData.reduce((a, b) => a + b, 0) / scoresWithData.length
    score = clamp(100 - avgRisk)
  }

  // Apply worst-case caps
  if (worst === 'critical') score = Math.min(score, 30)
  else if (worst === 'high')   score = Math.min(score, 60)

  score = clamp(Math.round(score))

  return {
    category,
    label: DRIFT_CATEGORY_LABELS[category],
    score,
    weight: DRIFT_CATEGORY_WEIGHTS[category],
    grade: scoreToGrade(score),
    workstreamsScanned: scoresWithData.length,
    worstRiskLevel: worst,
    signals: signals.slice(0, 5),
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function computeDriftPostureScore(
  inputs: DriftPostureScannerInputs,
  previousOverallScore?: number | null,
): DriftPostureReport {

  // ── Category 1: Application Security ──────────────────────────────────
  const appSec = computeCategory('application_security', [
    { riskScore: rs(inputs.ws60_riskScore), riskLevel: rl(inputs.ws60_riskLevel), label: 'App Security Config' },
    { riskScore: rs(inputs.ws61_riskScore), riskLevel: rl(inputs.ws61_riskLevel), label: 'Test Coverage Gap' },
    { riskScore: rs(inputs.ws65_riskScore), riskLevel: rl(inputs.ws65_riskLevel), label: 'API Security Config' },
    { riskScore: rs(inputs.ws75_riskScore), riskLevel: rl(inputs.ws75_riskLevel), label: 'Web Server Security' },
    { riskScore: rs(inputs.ws76_riskScore), riskLevel: rl(inputs.ws76_riskLevel), label: 'Email Security' },
    { riskScore: rs(inputs.ws103_riskScore), riskLevel: rl(inputs.ws103_riskLevel), label: 'Dep. Manager Config' },
    { riskScore: rs(inputs.ws109_riskScore), riskLevel: rl(inputs.ws109_riskLevel), label: 'Supply Chain Attestation' },
  ])

  // ── Category 2: Infrastructure ─────────────────────────────────────────
  const infra = computeCategory('infrastructure', [
    { riskScore: rs(inputs.ws62_riskScore), riskLevel: rl(inputs.ws62_riskLevel), label: 'Cloud Security' },
    { riskScore: rs(inputs.ws63_riskScore), riskLevel: rl(inputs.ws63_riskLevel), label: 'K8s/Container Hardening' },
    { riskScore: rs(inputs.ws64_riskScore), riskLevel: rl(inputs.ws64_riskLevel), label: 'Database Security' },
    { riskScore: rs(inputs.ws66_riskScore), riskLevel: rl(inputs.ws66_riskLevel), label: 'Cert & PKI' },
    { riskScore: rs(inputs.ws87_riskScore), riskLevel: rl(inputs.ws87_riskLevel), label: 'Storage & Data Security' },
    { riskScore: rs(inputs.ws105_riskScore), riskLevel: rl(inputs.ws105_riskLevel), label: 'Secret Management' },
  ])

  // ── Category 3: Runtime & Policy ──────────────────────────────────────
  const runtime = computeCategory('runtime_policy', [
    { riskScore: rs(inputs.ws67_riskScore), riskLevel: rl(inputs.ws67_riskLevel), label: 'Runtime Security Policy' },
    { riskScore: rs(inputs.ws68_riskScore), riskLevel: rl(inputs.ws68_riskLevel), label: 'Network Firewall' },
    { riskScore: rs(inputs.ws72_riskScore), riskLevel: rl(inputs.ws72_riskLevel), label: 'Service Mesh' },
    { riskScore: rs(inputs.ws73_riskScore), riskLevel: rl(inputs.ws73_riskLevel), label: 'CI/CD Pipeline Security' },
    { riskScore: rs(inputs.ws107_riskScore), riskLevel: rl(inputs.ws107_riskLevel), label: 'K8s Admission Controller' },
  ])

  // ── Category 4: Identity & Access ─────────────────────────────────────
  const identity = computeCategory('identity_access', [
    { riskScore: rs(inputs.ws69_riskScore), riskLevel: rl(inputs.ws69_riskLevel), label: 'DevSec Tooling/SAST' },
    { riskScore: rs(inputs.ws70_riskScore), riskLevel: rl(inputs.ws70_riskLevel), label: 'IAM & Privileged Access' },
    { riskScore: rs(inputs.ws79_riskScore), riskLevel: rl(inputs.ws79_riskLevel), label: 'SSO & Authentication' },
  ])

  // ── Category 5: Platform Services ─────────────────────────────────────
  const platform = computeCategory('platform_services', [
    { riskScore: rs(inputs.ws77_riskScore), riskLevel: rl(inputs.ws77_riskLevel), label: 'Serverless & FaaS' },
    { riskScore: rs(inputs.ws78_riskScore), riskLevel: rl(inputs.ws78_riskLevel), label: 'Messaging & Event Streaming' },
    { riskScore: rs(inputs.ws80_riskScore), riskLevel: rl(inputs.ws80_riskLevel), label: 'Data Pipeline & ETL' },
    { riskScore: rs(inputs.ws81_riskScore), riskLevel: rl(inputs.ws81_riskLevel), label: 'ML/AI Platform' },
    { riskScore: rs(inputs.ws82_riskScore), riskLevel: rl(inputs.ws82_riskLevel), label: 'Artifact Registry' },
    { riskScore: rs(inputs.ws83_riskScore), riskLevel: rl(inputs.ws83_riskLevel), label: 'Config Management' },
    { riskScore: rs(inputs.ws101_riskScore), riskLevel: rl(inputs.ws101_riskLevel), label: 'AI/ML Dependency Security' },
  ])

  // ── Category 6: Observability & SIEM ──────────────────────────────────
  const observability = computeCategory('observability_siem', [
    { riskScore: rs(inputs.ws71_riskScore), riskLevel: rl(inputs.ws71_riskLevel), label: 'Observability & Monitoring' },
    { riskScore: rs(inputs.ws86_riskScore), riskLevel: rl(inputs.ws86_riskLevel), label: 'SIEM & Analytics' },
    { riskScore: rs(inputs.ws94_riskScore), riskLevel: rl(inputs.ws94_riskLevel), label: 'Network Monitoring & SNMP' },
  ])

  // ── Category 7: Network & Connectivity ────────────────────────────────
  const network = computeCategory('network_connectivity', [
    { riskScore: rs(inputs.ws84_riskScore), riskLevel: rl(inputs.ws84_riskLevel), label: 'VPN & Remote Access' },
    { riskScore: rs(inputs.ws85_riskScore), riskLevel: rl(inputs.ws85_riskLevel), label: 'Backup & DR Security' },
    { riskScore: rs(inputs.ws88_riskScore), riskLevel: rl(inputs.ws88_riskLevel), label: 'DNS Security' },
    { riskScore: rs(inputs.ws90_riskScore), riskLevel: rl(inputs.ws90_riskLevel), label: 'Wireless & RADIUS' },
  ])

  // ── Category 8: Endpoint & Device ─────────────────────────────────────
  const endpoint = computeCategory('endpoint_device', [
    { riskScore: rs(inputs.ws74_riskScore), riskLevel: rl(inputs.ws74_riskLevel), label: 'Mobile App Security' },
    { riskScore: rs(inputs.ws89_riskScore), riskLevel: rl(inputs.ws89_riskLevel), label: 'OS Security Hardening' },
    { riskScore: rs(inputs.ws91_riskScore), riskLevel: rl(inputs.ws91_riskLevel), label: 'IoT & Embedded' },
    { riskScore: rs(inputs.ws92_riskScore), riskLevel: rl(inputs.ws92_riskLevel), label: 'Virtualization & Hypervisor' },
    { riskScore: rs(inputs.ws93_riskScore), riskLevel: rl(inputs.ws93_riskLevel), label: 'VoIP & Unified Comms' },
    { riskScore: rs(inputs.ws95_riskScore), riskLevel: rl(inputs.ws95_riskLevel), label: 'Endpoint Security & EDR' },
  ])

  const categoryScores: DriftCategoryScore[] = [
    appSec, infra, runtime, identity, platform, observability, network, endpoint,
  ]

  // ── Weighted overall score ─────────────────────────────────────────────
  const rawOverall = categoryScores.reduce(
    (acc, cat) => acc + cat.score * cat.weight,
    0,
  )
  const overallScore = clamp(Math.round(rawOverall))
  const overallGrade = scoreToGrade(overallScore)

  // ── Trend ──────────────────────────────────────────────────────────────
  const trend = detectTrend(overallScore, previousOverallScore ?? inputs.previousOverallScore)

  // ── Aggregate counts ───────────────────────────────────────────────────
  const totalWorkstreamsScanned = categoryScores.reduce(
    (acc, cat) => acc + cat.workstreamsScanned,
    0,
  )
  const criticalDriftCount = categoryScores.filter(
    (c) => c.worstRiskLevel === 'critical',
  ).length
  const highDriftCount = categoryScores.filter(
    (c) => c.worstRiskLevel === 'high',
  ).length

  // ── Top risks (worst-scoring categories, max 5) ────────────────────────
  const topRisks = [...categoryScores]
    .filter((c) => c.workstreamsScanned > 0 && c.score < 80)
    .sort((a, b) => a.score - b.score)
    .slice(0, 5)
    .flatMap((c) => c.signals.slice(0, 2))
    .slice(0, 5)

  // ── Summary ────────────────────────────────────────────────────────────
  const worstCat = [...categoryScores].sort((a, b) => a.score - b.score)[0]
  let summary: string
  if (overallScore >= 90) {
    summary = `Configuration drift posture is excellent (${overallScore}/100, grade ${overallGrade}). All monitored categories show minimal drift.`
  } else if (overallScore >= 75) {
    summary = `Configuration drift posture is good (${overallScore}/100, grade ${overallGrade}). Minor drift detected; review ${worstCat?.label ?? 'flagged areas'}.`
  } else if (overallScore >= 60) {
    summary = `Configuration drift posture needs attention (${overallScore}/100, grade ${overallGrade}). ${criticalDriftCount + highDriftCount} categories have elevated drift risk.`
  } else if (overallScore >= 40) {
    summary = `Configuration drift posture is poor (${overallScore}/100, grade ${overallGrade}). Significant drift detected across ${criticalDriftCount + highDriftCount} categories.`
  } else {
    summary = `Configuration drift posture is critical (${overallScore}/100, grade ${overallGrade}). Immediate remediation required across multiple security domains.`
  }

  return {
    overallScore,
    overallGrade,
    trend,
    categoryScores,
    totalWorkstreamsScanned,
    criticalDriftCount,
    highDriftCount,
    topRisks,
    summary,
  }
}
