/**
 * WS-99 — Security Program Maturity Model
 *
 * CMMI-style 5-level maturity assessment that maps existing scanner outputs
 * to a progression framework, giving operators a clear roadmap from ad-hoc
 * to optimising security posture.
 *
 * Levels:
 *   1 — Initial:                    Ad-hoc, minimal tooling, reactive only
 *   2 — Managed:                    Basic scanning, reacts to findings
 *   3 — Defined:                    Systematic processes, compliance tracking
 *   4 — Quantitatively Managed:     Metrics-driven, SLA enforcement, measurement
 *   5 — Optimising:                 Continuous improvement, predictive security
 *
 * Dimensions (6):
 *   vulnerability_management        — finding resolution speed & quality
 *   supply_chain_security           — SBOM completeness, posture, attestation
 *   compliance_readiness            — framework attestation scores
 *   incident_response               — triage speed, SLA, honeypot coverage
 *   security_automation             — CI/CD gates, auto-remediation, drift detection
 *   proactive_defense               — red/blue loops, attack surface, enrichment
 *
 * The overall maturity level equals the lowest (bottleneck) dimension level.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type MaturityLevel = 1 | 2 | 3 | 4 | 5

export const MATURITY_LABELS: Record<MaturityLevel, string> = {
  1: 'Initial',
  2: 'Managed',
  3: 'Defined',
  4: 'Quantitatively Managed',
  5: 'Optimising',
}

export type MaturityDimension =
  | 'vulnerability_management'
  | 'supply_chain_security'
  | 'compliance_readiness'
  | 'incident_response'
  | 'security_automation'
  | 'proactive_defense'

export type DimensionAssessment = {
  dimension: MaturityDimension
  label: string
  level: MaturityLevel
  /** 0–100 score within the level (drives trend/progress within a band). */
  score: number
  gaps: string[]         // what's preventing advancement to next level
}

export type MaturityAssessment = {
  overallLevel: MaturityLevel
  overallScore: number              // weighted average 0–100 across all dimensions
  dimensions: DimensionAssessment[]
  /** Dimension whose level is lowest — the programme bottleneck. */
  bottleneck: MaturityDimension
  /** Up to 5 concrete actions to reach the next maturity level. */
  advancementRoadmap: string[]
  assessedAt: number
}

// ── Input ─────────────────────────────────────────────────────────────────────

export type Finding = {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  status: 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' | 'false_positive' | 'ignored'
  createdAt: number
  resolvedAt?: number
}

export type SlaData = {
  /** Fraction of findings resolved within SLA (0–1). */
  overallComplianceRate: number
  /** Mean time to remediate in hours. */
  mttrHours: number
}

export type GradeInput = 'A' | 'B' | 'C' | 'D' | 'F' | null

export type MaturityInput = {
  findings: Finding[]
  sla: SlaData | null
  /** Supply chain posture grade from WS-44. */
  supplyChainGrade: GradeInput
  /** SBOM quality grade from WS-32. */
  sbomQualityGrade: GradeInput
  /** Number of attestation records: tampered/unverified affect score. */
  attestation: { total: number; valid: number; tampered: number } | null
  /** Compliance attestation from WS-46. */
  compliance: {
    compliantFrameworks: number
    atRiskFrameworks: number
    nonCompliantFrameworks: number
  } | null
  /** Regulatory drift level from WS-15. */
  regulatoryDriftLevel: 'none' | 'low' | 'medium' | 'high' | 'critical' | null
  /** Number of analyst triage events (proxy for triage activity). */
  triageEventCount: number
  /** Number of total findings that have a triage event. */
  triagedFindingCount: number
  /** Analyst false-positive rate (0–1). */
  analystFpRate: number | null
  /** Whether a CI/CD gate is configured. */
  cicdGateEnabled: boolean
  /** Whether auto-remediation dispatch is configured. */
  autoRemediationEnabled: boolean
  /** Whether any drift detection scan has fired for this repo. */
  driftDetectionEnabled: boolean
  /** Number of completed red/blue simulation rounds. */
  redBlueRoundsCompleted: number
  /** Attack surface score 0–100 (higher = more surface). */
  attackSurfaceScore: number | null
  /** Whether EPSS enrichment is running on breach disclosures. */
  epssEnrichmentEnabled: boolean
  /** Whether secrets scanning has run at least once. */
  secretsScanningEnabled: boolean
  /** Whether at least one honeypot is configured. */
  honeypotConfigured: boolean
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const GRADE_SCORE: Record<NonNullable<GradeInput>, number> = {
  A: 100, B: 80, C: 60, D: 40, F: 0,
}

function gradeToScore(grade: GradeInput): number {
  return grade === null ? 0 : GRADE_SCORE[grade]
}

function scoreToLevel(score: number): MaturityLevel {
  if (score >= 80) return 5
  if (score >= 60) return 4
  if (score >= 40) return 3
  if (score >= 20) return 2
  return 1
}

const DIMENSION_LABELS: Record<MaturityDimension, string> = {
  vulnerability_management: 'Vulnerability Management',
  supply_chain_security: 'Supply Chain Security',
  compliance_readiness: 'Compliance Readiness',
  incident_response: 'Incident Response',
  security_automation: 'Security Automation',
  proactive_defense: 'Proactive Defense',
}

// ── Dimension scorers ─────────────────────────────────────────────────────────

function scoreVulnerabilityManagement(input: MaturityInput): DimensionAssessment {
  const { findings, sla } = input
  const total = findings.length
  const resolved = findings.filter(
    (f) => f.status === 'resolved' || f.status === 'merged',
  ).length

  // Resolution rate (50 pts)
  const resolutionRate = total === 0 ? 0 : resolved / total
  const resolutionScore = Math.round(resolutionRate * 50)

  // SLA compliance (30 pts)
  const slaScore = sla ? Math.round(sla.overallComplianceRate * 30) : 0

  // MTTR bonus (20 pts)
  let mttrScore = 0
  if (sla) {
    if (sla.mttrHours <= 24) mttrScore = 20
    else if (sla.mttrHours <= 72) mttrScore = 12
    else if (sla.mttrHours <= 168) mttrScore = 6
  }

  const score = Math.min(100, resolutionScore + slaScore + mttrScore)
  const gaps: string[] = []
  if (resolutionRate < 0.5) gaps.push('Remediate more than half of open findings')
  if (!sla || sla.overallComplianceRate < 0.8) gaps.push('Achieve 80 %+ SLA compliance rate')
  if (!sla || sla.mttrHours > 72) gaps.push('Reduce mean-time-to-remediate below 72 h')

  return { dimension: 'vulnerability_management', label: DIMENSION_LABELS['vulnerability_management'], level: scoreToLevel(score), score, gaps }
}

function scoreSupplyChainSecurity(input: MaturityInput): DimensionAssessment {
  // SBOM quality (25 pts)
  const sbomScore = Math.round(gradeToScore(input.sbomQualityGrade) * 0.25)

  // Supply chain posture (25 pts)
  const postureScore = Math.round(gradeToScore(input.supplyChainGrade) * 0.25)

  // Attestation (25 pts)
  let attestationScore = 0
  if (input.attestation) {
    if (input.attestation.tampered > 0) {
      attestationScore = 5
    } else if (input.attestation.valid === input.attestation.total && input.attestation.total > 0) {
      attestationScore = 25
    } else if (input.attestation.total > 0) {
      attestationScore = 15
    }
  }

  // Coverage: has drift + abandonment + EOL detection (25 pts)
  const coverageScore = input.driftDetectionEnabled ? 25 : 0

  const score = Math.min(100, sbomScore + postureScore + attestationScore + coverageScore)
  const gaps: string[] = []
  if (!input.sbomQualityGrade || gradeToScore(input.sbomQualityGrade) < 60) {
    gaps.push('Improve SBOM quality to grade C or above')
  }
  if (!input.supplyChainGrade || gradeToScore(input.supplyChainGrade) < 60) {
    gaps.push('Resolve supply chain posture issues (malicious packages, EOL, abandonment)')
  }
  if (input.attestation && input.attestation.tampered > 0) {
    gaps.push('Re-attest tampered SBOM snapshots')
  }
  if (!input.driftDetectionEnabled) {
    gaps.push('Enable supply chain drift detection (EOL, abandonment, malicious package scanning)')
  }

  return { dimension: 'supply_chain_security', label: DIMENSION_LABELS['supply_chain_security'], level: scoreToLevel(score), score, gaps }
}

function scoreComplianceReadiness(input: MaturityInput): DimensionAssessment {
  const comp = input.compliance
  if (!comp) {
    return {
      dimension: 'compliance_readiness',
      label: DIMENSION_LABELS['compliance_readiness'],
      level: 1,
      score: 0,
      gaps: ['Run compliance attestation (WS-46) to establish a baseline'],
    }
  }

  const totalFrameworks = comp.compliantFrameworks + comp.atRiskFrameworks + comp.nonCompliantFrameworks
  const score = Math.max(
    0,
    100 - comp.nonCompliantFrameworks * 20 - comp.atRiskFrameworks * 10,
  )

  // Drift penalty
  const driftPenalties: Record<NonNullable<MaturityInput['regulatoryDriftLevel']>, number> = {
    none: 0, low: 5, medium: 10, high: 20, critical: 30,
  }
  const driftPenalty = input.regulatoryDriftLevel ? driftPenalties[input.regulatoryDriftLevel] : 0
  const finalScore = Math.max(0, Math.min(100, score - driftPenalty))

  const gaps: string[] = []
  if (comp.nonCompliantFrameworks > 0) {
    gaps.push(`Address ${comp.nonCompliantFrameworks} non-compliant regulatory framework(s)`)
  }
  if (comp.atRiskFrameworks > 0) {
    gaps.push(`Resolve at-risk compliance gaps in ${comp.atRiskFrameworks} framework(s)`)
  }
  if (input.regulatoryDriftLevel && ['high', 'critical'].includes(input.regulatoryDriftLevel)) {
    gaps.push('Remediate high/critical regulatory drift findings')
  }
  if (totalFrameworks === 0) {
    gaps.push('Configure compliance framework mapping')
  }

  return { dimension: 'compliance_readiness', label: DIMENSION_LABELS['compliance_readiness'], level: scoreToLevel(finalScore), score: finalScore, gaps }
}

function scoreIncidentResponse(input: MaturityInput): DimensionAssessment {
  const total = input.findings.length
  // Triage coverage (30 pts)
  const triageCoverage = total === 0 ? 0 : Math.min(1, input.triagedFindingCount / total)
  const triageScore = Math.round(triageCoverage * 30)

  // SLA compliance proxy (30 pts)
  const slaScore = input.sla ? Math.round(input.sla.overallComplianceRate * 30) : 0

  // Honeypot deployment (20 pts)
  const honeypotScore = input.honeypotConfigured ? 20 : 0

  // FP rate management (20 pts)
  let fpScore = 0
  if (input.analystFpRate !== null) {
    if (input.analystFpRate < 0.1) fpScore = 20
    else if (input.analystFpRate < 0.3) fpScore = 10
    else fpScore = 0
  }

  const score = Math.min(100, triageScore + slaScore + honeypotScore + fpScore)
  const gaps: string[] = []
  if (triageCoverage < 0.5) gaps.push('Triage at least 50 % of open findings')
  if (!input.sla || input.sla.overallComplianceRate < 0.8) {
    gaps.push('Enforce SLA deadlines and track compliance rate')
  }
  if (!input.honeypotConfigured) gaps.push('Deploy at least one honeypot trap')
  if (input.analystFpRate === null || input.analystFpRate > 0.3) {
    gaps.push('Improve false-positive triage accuracy below 30 %')
  }

  return { dimension: 'incident_response', label: DIMENSION_LABELS['incident_response'], level: scoreToLevel(score), score, gaps }
}

function scoreSecurityAutomation(input: MaturityInput): DimensionAssessment {
  // CI/CD gate (35 pts)
  const cicdScore = input.cicdGateEnabled ? 35 : 0
  // Auto-remediation (35 pts)
  const autoScore = input.autoRemediationEnabled ? 35 : 0
  // Drift detection (30 pts)
  const driftScore = input.driftDetectionEnabled ? 30 : 0

  const score = Math.min(100, cicdScore + autoScore + driftScore)
  const gaps: string[] = []
  if (!input.cicdGateEnabled) gaps.push('Enable CI/CD security gate to block vulnerable deploys')
  if (!input.autoRemediationEnabled) gaps.push('Enable autonomous remediation dispatch for P0 findings')
  if (!input.driftDetectionEnabled) gaps.push('Enable configuration drift detection across all categories')

  return { dimension: 'security_automation', label: DIMENSION_LABELS['security_automation'], level: scoreToLevel(score), score, gaps }
}

function scoreProactiveDefense(input: MaturityInput): DimensionAssessment {
  // Red/Blue rounds (30 pts — capped at 10 rounds for full points)
  const roundScore = Math.min(30, input.redBlueRoundsCompleted * 3)

  // Attack surface score (20 pts — inverted: lower surface = better)
  const surfaceScore =
    input.attackSurfaceScore === null
      ? 0
      : Math.round((1 - input.attackSurfaceScore / 100) * 20)

  // EPSS enrichment (20 pts)
  const epssScore = input.epssEnrichmentEnabled ? 20 : 0

  // Secrets scanning (15 pts)
  const secretsScore = input.secretsScanningEnabled ? 15 : 0

  // Honeypot (15 pts — shared credit, already in incident_response)
  const honeypotScore = input.honeypotConfigured ? 15 : 0

  const score = Math.min(100, roundScore + surfaceScore + epssScore + secretsScore + honeypotScore)
  const gaps: string[] = []
  if (input.redBlueRoundsCompleted < 3) {
    gaps.push('Run at least 3 adversarial red/blue simulation rounds')
  }
  if (!input.epssEnrichmentEnabled) {
    gaps.push('Enable EPSS enrichment to prioritise by real-world exploit probability')
  }
  if (!input.secretsScanningEnabled) gaps.push('Enable secrets scanning on all push events')
  if (!input.honeypotConfigured) gaps.push('Deploy honeypot code to detect active exploitation')

  return { dimension: 'proactive_defense', label: DIMENSION_LABELS['proactive_defense'], level: scoreToLevel(score), score, gaps }
}

// ── Roadmap builder ───────────────────────────────────────────────────────────

function buildAdvancementRoadmap(
  dimensions: DimensionAssessment[],
  currentLevel: MaturityLevel,
): string[] {
  if (currentLevel === 5) return ['Your programme is at the highest maturity level. Continue monitoring and improving.']

  const nextLevel = (currentLevel + 1) as MaturityLevel
  const bottleneckDims = dimensions.filter((d) => d.level === currentLevel)

  const actions: string[] = []
  for (const dim of bottleneckDims) {
    for (const gap of dim.gaps.slice(0, 2)) {
      actions.push(`[${dim.label}] ${gap}`)
      if (actions.length >= 5) break
    }
    if (actions.length >= 5) break
  }

  if (actions.length === 0) {
    actions.push(`Improve all dimensions to reach Level ${nextLevel} (${MATURITY_LABELS[nextLevel]})`)
  }

  return actions
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Compute the Security Program Maturity assessment for a repository.
 */
export function computeSecurityMaturity(input: MaturityInput): MaturityAssessment {
  const dimensions: DimensionAssessment[] = [
    scoreVulnerabilityManagement(input),
    scoreSupplyChainSecurity(input),
    scoreComplianceReadiness(input),
    scoreIncidentResponse(input),
    scoreSecurityAutomation(input),
    scoreProactiveDefense(input),
  ]

  const levels = dimensions.map((d) => d.level)
  const overallLevel = Math.min(...levels) as MaturityLevel

  const overallScore = Math.round(
    dimensions.reduce((sum, d) => sum + d.score, 0) / dimensions.length,
  )

  const bottleneckDim = dimensions.reduce(
    (worst, d) => (d.level < worst.level ? d : worst),
    dimensions[0],
  )

  const advancementRoadmap = buildAdvancementRoadmap(dimensions, overallLevel)

  return {
    overallLevel,
    overallScore,
    dimensions,
    bottleneck: bottleneckDim.dimension,
    advancementRoadmap,
    assessedAt: Date.now(),
  }
}
