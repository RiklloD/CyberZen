// WS-15 Phase 1 — Regulatory Drift Detection (spec 3.8): pure computation
// library.
//
// No DB access. Maps open findings (by vulnClass + severity + validationStatus)
// to regulatory framework compliance scores, producing a per-framework
// compliance health picture and a list of affected controls.
//
// Supported frameworks:
//   soc2    — SOC 2 Type II (Trust Services Criteria CC6/CC7/CC8/CC9)
//   gdpr    — GDPR Article 32 (technical security measures)
//   hipaa   — HIPAA Technical Safeguards (45 CFR §164.312)
//   pci_dss — PCI-DSS v4.0 (Requirements 6, 7, 8, 10)
//   nis2    — NIS2 Directive Article 21 (minimum security measures)
//
// Score per framework: 100 − Σ penalties for active findings affecting that
// framework, floored at 0. Higher = more compliant.
//
// Penalty per finding = severityPenalty × validationMultiplier
//   pr_opened findings count at 0.5× (mitigation in progress)
//
// Overall drift level = derived from the minimum framework score:
//   ≥80 → compliant | ≥60 → drifting | ≥40 → at_risk | <40 → non_compliant

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

export type RegulatoryFramework = 'soc2' | 'gdpr' | 'hipaa' | 'pci_dss' | 'nis2'

export type FindingForDriftInput = {
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  /** 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' */
  status: string
  /** 'pending' | 'validated' | 'likely_exploitable' | 'unexploitable' | 'dismissed' */
  validationStatus: string
}

export type RegulatoryDriftInput = {
  findings: FindingForDriftInput[]
  repositoryName: string
}

export type FrameworkScore = {
  framework: RegulatoryFramework
  /** Human-readable label for display. */
  label: string
  /** 0–100 compliance score. Higher = more compliant. */
  score: number
  /** Count of open findings mapped to this framework. */
  openGaps: number
}

export type DriftLevel = 'compliant' | 'drifting' | 'at_risk' | 'non_compliant'

export type RegulatoryDriftResult = {
  frameworkScores: FrameworkScore[]
  /** Derived from the minimum score across all frameworks. */
  overallDriftLevel: DriftLevel
  /** Total open findings that map to at least one framework. */
  openGapCount: number
  /** Open findings with severity='critical' that map to at least one framework. */
  criticalGapCount: number
  /** Unique framework names with at least one open gap. */
  affectedFrameworks: string[]
  summary: string
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

export const FRAMEWORK_LABELS: Record<RegulatoryFramework, string> = {
  soc2: 'SOC 2 Type II',
  gdpr: 'GDPR Art. 32',
  hipaa: 'HIPAA Technical Safeguards',
  pci_dss: 'PCI-DSS v4.0',
  nis2: 'NIS2 Art. 21',
}

const ALL_FRAMEWORKS: RegulatoryFramework[] = [
  'soc2',
  'gdpr',
  'hipaa',
  'pci_dss',
  'nis2',
]

// Broad security controls in SOC 2, GDPR, NIS2 apply to virtually every
// exploitable finding class. HIPAA and PCI-DSS apply when findings relate to
// data access, authentication, or cryptographic failures.
//
// Unknown vuln classes fall back to the GENERIC_FRAMEWORKS set so that
// red_agent or custom findings are never silently ignored.
const VULN_CLASS_FRAMEWORKS: Record<string, RegulatoryFramework[]> = {
  injection: ALL_FRAMEWORKS,
  sql_injection: ALL_FRAMEWORKS,
  command_injection: ALL_FRAMEWORKS,
  xss: ['soc2', 'gdpr', 'pci_dss', 'nis2'],
  csrf: ['soc2', 'gdpr', 'pci_dss', 'nis2'],
  ssrf: ALL_FRAMEWORKS,
  authentication_bypass: ALL_FRAMEWORKS,
  broken_access_control: ALL_FRAMEWORKS,
  insecure_direct_object_reference: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'],
  cryptographic_failure: ALL_FRAMEWORKS,
  weak_cryptography: ALL_FRAMEWORKS,
  data_exposure: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'],
  sensitive_data_exposure: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'],
  secret_exposure: ALL_FRAMEWORKS,
  vulnerable_dependency: ALL_FRAMEWORKS,
  supply_chain_traversal: ALL_FRAMEWORKS,
  insecure_configuration: ['soc2', 'pci_dss', 'nis2'],
  security_misconfiguration: ['soc2', 'pci_dss', 'nis2'],
  logging_failure: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'],
  audit_log_missing: ['soc2', 'gdpr', 'hipaa', 'pci_dss', 'nis2'],
  race_condition: ['soc2', 'gdpr', 'nis2'],
  deserialization: ['soc2', 'gdpr', 'pci_dss', 'nis2'],
  prompt_injection: ['soc2', 'gdpr', 'nis2'],
  rag_poisoning: ['soc2', 'gdpr', 'nis2'],
}

// Frameworks that apply when no specific mapping is found.
const GENERIC_FRAMEWORKS: RegulatoryFramework[] = ['soc2', 'gdpr', 'nis2']

// Severity → base penalty points (before validation multiplier).
// Sized so that one unvalidated critical finding pushes a score from 100 to 80,
// and two push it to 60 (crossing from compliant into drifting).
const SEVERITY_PENALTY: Record<string, number> = {
  critical: 20,
  high: 12,
  medium: 6,
  low: 2,
  informational: 0,
}

// Validation amplifiers: confirmed / likely findings penalise more heavily.
const VALIDATION_MULTIPLIER: Record<string, number> = {
  validated: 1.5,
  likely_exploitable: 1.2,
}

// Statuses treated as "active" (contributing to drift).
const ACTIVE_STATUSES = new Set(['open', 'pr_opened'])
const PR_OPENED = 'pr_opened'

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function frameworksForVulnClass(vulnClass: string): RegulatoryFramework[] {
  // Normalise separators so 'supply-chain-traversal' matches the same key as
  // 'supply_chain_traversal'.
  const key = vulnClass.toLowerCase().replaceAll('-', '_').replaceAll(' ', '_')
  return VULN_CLASS_FRAMEWORKS[key] ?? GENERIC_FRAMEWORKS
}

function penaltyForFinding(finding: FindingForDriftInput): number {
  const base = SEVERITY_PENALTY[finding.severity] ?? 2
  if (base === 0) return 0
  const mult = VALIDATION_MULTIPLIER[finding.validationStatus] ?? 1.0
  const statusMult = finding.status === PR_OPENED ? 0.5 : 1.0
  return base * mult * statusMult
}

function driftLevelFromScore(score: number): DriftLevel {
  if (score >= 80) return 'compliant'
  if (score >= 60) return 'drifting'
  if (score >= 40) return 'at_risk'
  return 'non_compliant'
}

function buildSummary(
  repositoryName: string,
  overallDriftLevel: DriftLevel,
  minScore: number,
  openGapCount: number,
  criticalGapCount: number,
  affectedFrameworks: string[],
): string {
  if (openGapCount === 0) {
    return `${repositoryName} has no open regulatory compliance gaps; all tracked frameworks appear compliant.`
  }

  const levelPhrase =
    overallDriftLevel === 'compliant'
      ? 'compliant'
      : overallDriftLevel === 'drifting'
        ? 'showing early drift'
        : overallDriftLevel === 'at_risk'
          ? 'at regulatory risk'
          : 'non-compliant'

  const criticalNote =
    criticalGapCount > 0
      ? ` ${criticalGapCount} critical finding${criticalGapCount === 1 ? '' : 's'} require immediate attention.`
      : ''

  return `${repositoryName} is ${levelPhrase} (lowest framework score ${minScore}/100) across ${affectedFrameworks.join(', ')}.${criticalNote} ${openGapCount} open finding${openGapCount === 1 ? '' : 's'} mapped to regulatory controls.`
}

// ---------------------------------------------------------------------------
// Core export
// ---------------------------------------------------------------------------

export function computeRegulatoryDrift(
  input: RegulatoryDriftInput,
): RegulatoryDriftResult {
  const { findings, repositoryName } = input

  // Only active findings contribute to drift.
  const activeFindings = findings.filter((f) => ACTIVE_STATUSES.has(f.status))

  // Accumulate penalty per framework and open-gap counts.
  const penaltyMap: Record<RegulatoryFramework, number> = {
    soc2: 0,
    gdpr: 0,
    hipaa: 0,
    pci_dss: 0,
    nis2: 0,
  }
  const gapCountMap: Record<RegulatoryFramework, number> = {
    soc2: 0,
    gdpr: 0,
    hipaa: 0,
    pci_dss: 0,
    nis2: 0,
  }

  const gapFindingSet = new Set<FindingForDriftInput>()
  let criticalGapCount = 0

  for (const f of activeFindings) {
    const frameworks = frameworksForVulnClass(f.vulnClass)
    if (frameworks.length === 0) continue

    const penalty = penaltyForFinding(f)
    let isGap = false

    for (const fw of frameworks) {
      penaltyMap[fw] += penalty
      gapCountMap[fw]++
      isGap = true
    }

    if (isGap && !gapFindingSet.has(f)) {
      gapFindingSet.add(f)
      if (f.severity === 'critical') criticalGapCount++
    }
  }

  // Build per-framework scores (floored at 0).
  const frameworkScores: FrameworkScore[] = ALL_FRAMEWORKS.map((fw) => ({
    framework: fw,
    label: FRAMEWORK_LABELS[fw],
    score: Math.max(0, Math.round(100 - penaltyMap[fw])),
    openGaps: gapCountMap[fw],
  }))

  // Derive overall drift level from the worst-performing framework.
  const minScore = Math.min(...frameworkScores.map((f) => f.score))
  const overallDriftLevel = driftLevelFromScore(minScore)

  const openGapCount = gapFindingSet.size
  const affectedFrameworks = frameworkScores
    .filter((f) => f.openGaps > 0)
    .map((f) => f.label)

  const summary = buildSummary(
    repositoryName,
    overallDriftLevel,
    minScore,
    openGapCount,
    criticalGapCount,
    affectedFrameworks,
  )

  return {
    frameworkScores,
    overallDriftLevel,
    openGapCount,
    criticalGapCount,
    affectedFrameworks,
    summary,
  }
}
