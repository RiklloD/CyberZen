/**
 * WS-26 — LLM-Native Application Security Certification (spec §10 Phase 4)
 *
 * Pure computation library.  No Convex runtime imports — safe to test with
 * plain vitest.
 *
 * The certification synthesises seven security signal domains into a single
 * tiered verdict (Gold / Silver / Bronze / Uncertified) that can serve as a
 * machine-readable security seal for LLM-native applications.
 *
 * Domain sources:
 *   prompt_injection       ← promptInjectionScans
 *   supply_chain_integrity ← supplyChainAnalyses
 *   agentic_pipeline_safety← agenticWorkflowScans
 *   exploit_validation     ← exploitValidationRuns
 *   regulatory_compliance  ← regulatoryDriftSnapshots
 *   attack_surface         ← attackSurfaceSnapshots
 *   dependency_trust       ← sbomComponents (aggregated trust scores)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type CertificationDomain =
  | 'prompt_injection'
  | 'supply_chain_integrity'
  | 'agentic_pipeline_safety'
  | 'exploit_validation'
  | 'regulatory_compliance'
  | 'attack_surface'
  | 'dependency_trust'

export type CertCheckOutcome = 'pass' | 'warn' | 'fail'
export type CertificationTier = 'gold' | 'silver' | 'bronze' | 'uncertified'

/** Result for a single evaluated domain. */
export interface CertDomainResult {
  domain: CertificationDomain
  outcome: CertCheckOutcome
  /** 0–100 signal health score for this domain (higher = better). */
  score: number
  rationale: string
}

// ── Input shape — pre-fetched snapshots from Convex queries ──────────────────

export interface CertificationInput {
  // promptInjectionScans — latest scan for the repository
  promptInjection: {
    riskLevel: string  // 'clean' | 'suspicious' | 'likely_injection' | 'confirmed_injection'
    score: number      // 0 = clean, 100 = confirmed injection
  } | null

  // supplyChainAnalyses — aggregated over all packages in latest snapshot
  supplyChain: {
    totalPackages: number
    compromisedCount: number
    suspiciousCount: number
    atRiskCount: number
    highestRiskLevel: string  // 'trusted' | 'monitor' | 'at_risk' | 'suspicious' | 'compromised'
  } | null

  // agenticWorkflowScans — latest scan for the repository
  agenticPipeline: {
    criticalCount: number
    highCount: number
    mediumCount: number
  } | null

  // exploitValidationRuns — aggregated over recent runs
  exploitValidation: {
    totalRuns: number
    validatedCount: number
    likelyExploitableCount: number
  } | null

  // regulatoryDriftSnapshots — latest snapshot
  regulatoryCompliance: {
    overallDriftLevel: string  // 'compliant' | 'drifting' | 'at_risk' | 'non_compliant'
    criticalGapCount: number
    openGapCount: number
  } | null

  // attackSurfaceSnapshots — latest snapshot
  attackSurface: {
    score: number           // 0–100 (higher = better surface reduction)
    openCriticalCount: number
    openHighCount: number
    trend: string           // 'improving' | 'stable' | 'degrading'
  } | null

  // sbomComponents — aggregated trust scores from latest snapshot
  dependencyTrust: {
    avgTrustScore: number   // 0–100 composite trust score
    untrustedCount: number  // components with trustScore < 30
    totalComponents: number
  } | null
}

/** Full certification result returned by computeCertificationResult(). */
export interface CertificationResult {
  tier: CertificationTier
  domainResults: CertDomainResult[]
  passCount: number
  warnCount: number
  failCount: number
  /** Critical domains that received a 'fail' outcome. */
  criticalFailedDomains: CertificationDomain[]
  /** 0–100 weighted average of all domain scores. */
  overallScore: number
  summary: string
}

// ── Domain weights (must sum to 100) ─────────────────────────────────────────

const DOMAIN_WEIGHTS: Record<CertificationDomain, number> = {
  prompt_injection: 20,
  supply_chain_integrity: 20,
  exploit_validation: 20,
  agentic_pipeline_safety: 15,
  attack_surface: 10,
  regulatory_compliance: 10,
  dependency_trust: 5,
}

// Critical domains — a 'fail' in any of these blocks Silver and above.
const CRITICAL_DOMAINS = new Set<CertificationDomain>([
  'prompt_injection',
  'supply_chain_integrity',
  'exploit_validation',
])

// ── Per-domain evaluators ─────────────────────────────────────────────────────

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n))
}

function evalPromptInjection(
  input: CertificationInput['promptInjection'],
): CertDomainResult {
  const domain = 'prompt_injection' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No prompt injection scans on record — scan coverage unknown.' }
  }
  const { riskLevel, score } = input
  const certScore = clamp(100 - score, 0, 100)
  if (riskLevel === 'confirmed_injection') {
    return { domain, outcome: 'fail', score: 0, rationale: `Confirmed injection detected (raw score ${score}). Immediate remediation required.` }
  }
  if (riskLevel === 'likely_injection') {
    return { domain, outcome: 'fail', score: clamp(certScore, 0, 30), rationale: `Likely injection pattern detected (raw score ${score}).` }
  }
  if (riskLevel === 'suspicious' || score >= 20) {
    return { domain, outcome: 'warn', score: clamp(certScore, 40, 70), rationale: `Suspicious injection signals detected (raw score ${score}).` }
  }
  return { domain, outcome: 'pass', score: certScore, rationale: `No injection signals detected (raw score ${score}).` }
}

function evalSupplyChainIntegrity(
  input: CertificationInput['supplyChain'],
): CertDomainResult {
  const domain = 'supply_chain_integrity' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No supply chain analysis on record.' }
  }
  const { compromisedCount, suspiciousCount, atRiskCount, highestRiskLevel } = input
  if (compromisedCount > 0 || highestRiskLevel === 'compromised') {
    return { domain, outcome: 'fail', score: 0, rationale: `${compromisedCount} compromised package${compromisedCount === 1 ? '' : 's'} detected.` }
  }
  const penaltyScore = clamp(100 - suspiciousCount * 20 - atRiskCount * 10, 0, 100)
  if (suspiciousCount > 0 || highestRiskLevel === 'suspicious') {
    return { domain, outcome: 'warn', score: clamp(penaltyScore, 30, 65), rationale: `${suspiciousCount} suspicious package${suspiciousCount === 1 ? '' : 's'} detected.` }
  }
  if (atRiskCount > 0 || highestRiskLevel === 'at_risk') {
    return { domain, outcome: 'warn', score: clamp(penaltyScore, 55, 75), rationale: `${atRiskCount} at-risk package${atRiskCount === 1 ? '' : 's'} detected.` }
  }
  return { domain, outcome: 'pass', score: 100, rationale: 'All analysed packages are trusted or monitored.' }
}

function evalAgenticPipelineSafety(
  input: CertificationInput['agenticPipeline'],
): CertDomainResult {
  const domain = 'agentic_pipeline_safety' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'Agentic workflow scan has not run yet.' }
  }
  const { criticalCount, highCount, mediumCount } = input
  if (criticalCount > 0) {
    return {
      domain, outcome: 'fail',
      score: clamp(100 - criticalCount * 40 - highCount * 20 - mediumCount * 5, 0, 20),
      rationale: `${criticalCount} critical agentic pipeline vulnerability${criticalCount === 1 ? '' : 'ies'} found.`,
    }
  }
  if (highCount > 0) {
    return {
      domain, outcome: 'warn',
      score: clamp(100 - highCount * 20 - mediumCount * 5, 30, 70),
      rationale: `${highCount} high-severity agentic pipeline finding${highCount === 1 ? '' : 's'}.`,
    }
  }
  if (mediumCount > 0) {
    return {
      domain, outcome: 'warn',
      score: clamp(100 - mediumCount * 5, 75, 90),
      rationale: `${mediumCount} medium-severity agentic pipeline finding${mediumCount === 1 ? '' : 's'}.`,
    }
  }
  return { domain, outcome: 'pass', score: 100, rationale: 'No agentic pipeline vulnerabilities found.' }
}

function evalExploitValidation(
  input: CertificationInput['exploitValidation'],
): CertDomainResult {
  const domain = 'exploit_validation' as const
  if (input === null || input.totalRuns === 0) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No exploit validation runs on record.' }
  }
  const { validatedCount, likelyExploitableCount, totalRuns } = input
  if (validatedCount > 0) {
    return {
      domain, outcome: 'fail',
      score: clamp(100 - validatedCount * 50 - likelyExploitableCount * 30, 0, 15),
      rationale: `${validatedCount} validated exploit${validatedCount === 1 ? '' : 's'} confirmed across ${totalRuns} run${totalRuns === 1 ? '' : 's'}.`,
    }
  }
  if (likelyExploitableCount > 0) {
    return {
      domain, outcome: 'fail',
      score: clamp(100 - likelyExploitableCount * 30, 10, 35),
      rationale: `${likelyExploitableCount} likely-exploitable finding${likelyExploitableCount === 1 ? '' : 's'} confirmed.`,
    }
  }
  return { domain, outcome: 'pass', score: 95, rationale: `All ${totalRuns} exploit validation run${totalRuns === 1 ? '' : 's'} returned unexploitable.` }
}

function evalRegulatoryCompliance(
  input: CertificationInput['regulatoryCompliance'],
): CertDomainResult {
  const domain = 'regulatory_compliance' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No regulatory drift snapshot on record.' }
  }
  const { overallDriftLevel, criticalGapCount, openGapCount } = input
  if (overallDriftLevel === 'non_compliant') {
    return { domain, outcome: 'fail', score: 10, rationale: `Non-compliant: ${openGapCount} open gap${openGapCount === 1 ? '' : 's'} including ${criticalGapCount} critical.` }
  }
  if (overallDriftLevel === 'at_risk') {
    return { domain, outcome: 'fail', score: 30, rationale: `Regulatory posture at risk: ${criticalGapCount} critical gap${criticalGapCount === 1 ? '' : 's'}.` }
  }
  if (overallDriftLevel === 'drifting' || criticalGapCount > 0) {
    return { domain, outcome: 'warn', score: 65, rationale: `Drifting: ${openGapCount} open regulatory gap${openGapCount === 1 ? '' : 's'}.` }
  }
  return { domain, outcome: 'pass', score: 100, rationale: 'All monitored frameworks report no open gaps.' }
}

function evalAttackSurface(
  input: CertificationInput['attackSurface'],
): CertDomainResult {
  const domain = 'attack_surface' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No attack surface snapshot on record.' }
  }
  const { score, openCriticalCount, openHighCount, trend } = input
  if (openCriticalCount > 0 || score < 40) {
    return {
      domain, outcome: 'fail',
      score: clamp(score, 0, 35),
      rationale: `Attack surface score ${score}/100 with ${openCriticalCount} open critical finding${openCriticalCount === 1 ? '' : 's'}.`,
    }
  }
  const trendPenalty = trend === 'degrading' ? 10 : 0
  const adjScore = clamp(score - trendPenalty, 0, 100)
  if (score < 70 || openHighCount > 5) {
    return {
      domain, outcome: 'warn',
      score: clamp(adjScore, 40, 72),
      rationale: `Attack surface score ${score}/100 — ${openHighCount} open high-severity findings.`,
    }
  }
  return {
    domain, outcome: 'pass',
    score: adjScore,
    rationale: `Attack surface score ${score}/100, trend: ${trend}.`,
  }
}

function evalDependencyTrust(
  input: CertificationInput['dependencyTrust'],
): CertDomainResult {
  const domain = 'dependency_trust' as const
  if (input === null) {
    return { domain, outcome: 'warn', score: 50, rationale: 'No SBOM components on record.' }
  }
  const { avgTrustScore, untrustedCount, totalComponents } = input
  if (totalComponents === 0) {
    return { domain, outcome: 'pass', score: 100, rationale: 'No dependencies to evaluate.' }
  }
  const adjScore = clamp(avgTrustScore - untrustedCount * 5, 0, 100)
  if (avgTrustScore < 40 || untrustedCount > 5) {
    return { domain, outcome: 'fail', score: clamp(adjScore, 0, 30), rationale: `Low dependency trust: avg ${avgTrustScore}/100 with ${untrustedCount} untrusted component${untrustedCount === 1 ? '' : 's'}.` }
  }
  if (avgTrustScore < 65 || untrustedCount > 2) {
    return { domain, outcome: 'warn', score: clamp(adjScore, 35, 72), rationale: `Moderate dependency trust: avg ${avgTrustScore}/100, ${untrustedCount} untrusted component${untrustedCount === 1 ? '' : 's'}.` }
  }
  return { domain, outcome: 'pass', score: adjScore, rationale: `Dependency trust avg ${avgTrustScore}/100 across ${totalComponents} component${totalComponents === 1 ? '' : 's'}.` }
}

// ── Tier classification policy ────────────────────────────────────────────────

/**
 * Classify the certification tier from aggregated domain outcomes.
 *
 * This function represents a *policy decision* — the thresholds below reflect
 * a balanced default.  Adjust them to match your organisation's risk appetite:
 *
 *   - Stricter Gold:   increase passCount requirement to 7 (all must pass)
 *   - Looser Silver:   allow failedCriticalDomains.length === 1 (not recommended)
 *   - Attainable Bronze: lower passCount threshold to >= 1
 *
 * Critical domains (prompt_injection, supply_chain_integrity, exploit_validation)
 * represent the non-negotiable security baseline for LLM-native applications.
 * A 'fail' in any critical domain caps certification at Uncertified regardless
 * of other domain scores.
 *
 * @param passCount           Number of domains with 'pass' outcome (0–7)
 * @param failedCriticalDomains Domains that are both critical AND failed
 * @param warnCount           Number of domains with 'warn' outcome (0–7)
 */
export function computeCertificationTier(
  passCount: number,
  failedCriticalDomains: CertificationDomain[],
  warnCount: number,
): CertificationTier {
  // Any critical domain failure blocks Silver and above
  if (failedCriticalDomains.length > 0) return 'uncertified'

  // Gold: all 7 pass, or 6 pass + 1 warn (near-perfect posture)
  if (passCount === 7) return 'gold'
  if (passCount === 6 && warnCount <= 1) return 'gold'

  // Silver: no critical failures, majority of domains pass
  if (passCount >= 4) return 'silver'

  // Bronze: at least 2 domains pass, no critical failures
  if (passCount >= 2) return 'bronze'

  return 'uncertified'
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Compute a full LLM-native application security certification report.
 *
 * Evaluates all seven domains, classifies the tier via computeCertificationTier,
 * and returns a human-readable summary alongside machine-readable domain results.
 */
export function computeCertificationResult(
  input: CertificationInput,
): CertificationResult {
  const domainResults: CertDomainResult[] = [
    evalPromptInjection(input.promptInjection),
    evalSupplyChainIntegrity(input.supplyChain),
    evalAgenticPipelineSafety(input.agenticPipeline),
    evalExploitValidation(input.exploitValidation),
    evalRegulatoryCompliance(input.regulatoryCompliance),
    evalAttackSurface(input.attackSurface),
    evalDependencyTrust(input.dependencyTrust),
  ]

  const passCount = domainResults.filter((d) => d.outcome === 'pass').length
  const warnCount = domainResults.filter((d) => d.outcome === 'warn').length
  const failCount = domainResults.filter((d) => d.outcome === 'fail').length

  const criticalFailedDomains = domainResults
    .filter((d) => d.outcome === 'fail' && CRITICAL_DOMAINS.has(d.domain))
    .map((d) => d.domain)

  const tier = computeCertificationTier(passCount, criticalFailedDomains, warnCount)

  // Weighted score — each domain contributes weight * (score/100)
  const overallScore = Math.round(
    domainResults.reduce((sum, d) => sum + (DOMAIN_WEIGHTS[d.domain] * d.score) / 100, 0),
  )

  const failedNames = domainResults
    .filter((d) => d.outcome === 'fail')
    .map((d) => d.domain.replaceAll('_', ' '))

  const warnNames = domainResults
    .filter((d) => d.outcome === 'warn')
    .map((d) => d.domain.replaceAll('_', ' '))

  let summary: string
  switch (tier) {
    case 'gold':
      summary = `Gold certification achieved. Overall security score ${overallScore}/100 across all 7 domains.`
      break
    case 'silver':
      summary = `Silver certification. Score ${overallScore}/100. ${warnCount} domain${warnCount === 1 ? '' : 's'} require attention: ${warnNames.join(', ')}.`
      break
    case 'bronze':
      summary = `Bronze certification. Score ${overallScore}/100. Failed domains: ${failedNames.join(', ')}.`
      break
    default:
      summary = `Uncertified. Score ${overallScore}/100. Critical failures in: ${criticalFailedDomains.length > 0 ? criticalFailedDomains.map((d) => d.replaceAll('_', ' ')).join(', ') : failedNames.join(', ')}.`
  }

  return { tier, domainResults, passCount, warnCount, failCount, criticalFailedDomains, overallScore, summary }
}
