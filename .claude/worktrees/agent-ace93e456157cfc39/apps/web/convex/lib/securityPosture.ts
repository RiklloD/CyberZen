/**
 * Security Posture Report — pure computation library (spec §7.1 /reports/security-posture)
 *
 * Aggregates every intelligence signal produced by the platform into a single
 * 0–100 posture score with a tier label and a prioritised action list.
 *
 * Score model: starts at 100, deductions applied per signal:
 *   • Open findings      — up to 50 pts
 *   • Attack surface     — up to 25 pts
 *   • Regulatory drift   — up to 20 pts
 *   • Red agent wins     — up to 10 pts
 *   • Learning maturity  — +5 pts bonus (only additive term)
 *
 * All signal inputs are optional; missing signals apply no deduction.
 */

// ─── Input types ──────────────────────────────────────────────────────────────

export type PostureFindings = {
  openCritical: number
  openHigh: number
  openMedium: number
  openLow: number
}

export type PostureAttackSurface = {
  /** 0–100 attack surface score (higher = better). */
  score: number
  trend: 'improving' | 'stable' | 'degrading' | 'unknown'
}

export type PostureRegulatoryDrift = {
  overallDriftLevel: 'compliant' | 'drifting' | 'at_risk' | 'non_compliant'
  criticalGapCount: number
  /** Human-readable framework labels with open gaps. */
  affectedFrameworks: string[]
}

export type PostureRedBlue = {
  latestOutcome: 'red_wins' | 'blue_wins' | 'draw'
  redAgentWinRate: number
  totalRounds: number
}

export type PostureLearningProfile = {
  /** 0–100 learning maturity score. */
  adaptedConfidenceScore: number
  recurringVulnClasses: string[]
  successfulExploitPaths: number
}

export type PostureHoneypot = {
  totalProposals: number
  topAttractiveness: number
}

export type SecurityPostureInput = {
  repositoryName: string
  /** Required — findings are always available (zero counts if none). */
  findings: PostureFindings
  /** null when no attack surface snapshot has been computed yet. */
  attackSurface: PostureAttackSurface | null
  /** null when no regulatory drift snapshot exists. */
  regulatoryDrift: PostureRegulatoryDrift | null
  /** null when no red/blue rounds have been run. */
  redBlue: PostureRedBlue | null
  /** null when no learning profile has been computed. */
  learningProfile: PostureLearningProfile | null
  /** null when no honeypot plan has been computed. */
  honeypot: PostureHoneypot | null
}

// ─── Output types ─────────────────────────────────────────────────────────────

export type PostureLevel = 'excellent' | 'good' | 'fair' | 'at_risk' | 'critical'

export type SecurityPostureReport = {
  /** 0–100 overall posture score. Higher is better. */
  overallScore: number
  postureLevel: PostureLevel
  /** Deduction from open findings (0–50). */
  findingPenalty: number
  /** Deduction from attack surface (0–25), null if no data. */
  attackSurfacePenalty: number | null
  /** Deduction from regulatory drift (0–20), null if no data. */
  regulatoryPenalty: number | null
  /** Deduction from red agent win rate (0–10), null if no data. */
  redAgentPenalty: number | null
  /** Bonus from learning maturity (0–5). */
  learningBonus: number
  /** Up to 4 prioritised recommended actions, most urgent first. */
  topActions: string[]
  summary: string
}

// ─── Penalty tables ───────────────────────────────────────────────────────────

const FINDING_PENALTY: Record<string, number> = {
  critical: 12,
  high: 6,
  medium: 2,
  low: 0,  // fractional — handled via floor(low * 0.5) separately
}

const MAX_FINDING_PENALTY = 50

const ATTACK_SURFACE_PENALTY: Record<string, number> = {
  lt40: 25,
  lt60: 15,
  lt80: 5,
  ok: 0,
}

const REGULATORY_PENALTY: Record<string, number> = {
  non_compliant: 20,
  at_risk: 15,
  drifting: 8,
  compliant: 0,
}

const RED_AGENT_PENALTY = { gt70: 10, gt50: 6, gt30: 3, ok: 0 }

const MAX_TOP_ACTIONS = 4

// ─── Main computation ─────────────────────────────────────────────────────────

export function computeSecurityPosture(input: SecurityPostureInput): SecurityPostureReport {
  const actions: string[] = []

  // ── 1. Finding penalty ───────────────────────────────────────────────────
  const rawFindingPenalty =
    input.findings.openCritical * FINDING_PENALTY.critical +
    input.findings.openHigh * FINDING_PENALTY.high +
    input.findings.openMedium * FINDING_PENALTY.medium +
    Math.floor(input.findings.openLow * 0.5)

  const findingPenalty = Math.min(MAX_FINDING_PENALTY, rawFindingPenalty)

  if (input.findings.openCritical > 0) {
    const n = input.findings.openCritical
    actions.push(`Remediate ${n} open critical finding${n > 1 ? 's' : ''} immediately`)
  } else if (input.findings.openHigh > 0) {
    const n = input.findings.openHigh
    actions.push(`Address ${n} open high-severity finding${n > 1 ? 's' : ''}`)
  }

  // ── 2. Attack surface penalty ────────────────────────────────────────────
  let attackSurfacePenalty: number | null = null

  if (input.attackSurface !== null) {
    const s = input.attackSurface.score
    if (s < 40) attackSurfacePenalty = ATTACK_SURFACE_PENALTY.lt40
    else if (s < 60) attackSurfacePenalty = ATTACK_SURFACE_PENALTY.lt60
    else if (s < 80) attackSurfacePenalty = ATTACK_SURFACE_PENALTY.lt80
    else attackSurfacePenalty = ATTACK_SURFACE_PENALTY.ok

    if (input.attackSurface.score < 60) {
      actions.push('Reduce attack surface — remediate open findings to improve exposure score')
    }
    if (input.attackSurface.trend === 'degrading') {
      actions.push('Attack surface is degrading — review recent pushes for new exposures')
    }
  }

  // ── 3. Regulatory drift penalty ──────────────────────────────────────────
  let regulatoryPenalty: number | null = null

  if (input.regulatoryDrift !== null) {
    regulatoryPenalty = REGULATORY_PENALTY[input.regulatoryDrift.overallDriftLevel] ?? 0

    if (regulatoryPenalty > 0) {
      const level = input.regulatoryDrift.overallDriftLevel.replaceAll('_', ' ')
      const frameworks =
        input.regulatoryDrift.affectedFrameworks.length > 0
          ? input.regulatoryDrift.affectedFrameworks.join(', ')
          : 'affected frameworks'
      actions.push(`Resolve ${level} regulatory gaps across ${frameworks}`)
    }
  }

  // ── 4. Red agent penalty ─────────────────────────────────────────────────
  let redAgentPenalty: number | null = null

  if (input.redBlue !== null && input.redBlue.totalRounds > 0) {
    const rate = input.redBlue.redAgentWinRate
    if (rate > 0.7) redAgentPenalty = RED_AGENT_PENALTY.gt70
    else if (rate > 0.5) redAgentPenalty = RED_AGENT_PENALTY.gt50
    else if (rate > 0.3) redAgentPenalty = RED_AGENT_PENALTY.gt30
    else redAgentPenalty = RED_AGENT_PENALTY.ok

    if (input.redBlue.latestOutcome === 'red_wins') {
      actions.push('Latest adversarial round ended in red-agent win — review escalated findings')
    }
  }

  // ── 5. Learning maturity bonus ────────────────────────────────────────────
  let learningBonus = 0
  if (input.learningProfile !== null) {
    if (input.learningProfile.adaptedConfidenceScore >= 75) learningBonus = 5
    else if (input.learningProfile.adaptedConfidenceScore >= 50) learningBonus = 3
  }

  // ── 6. Final score ────────────────────────────────────────────────────────
  const totalPenalty =
    findingPenalty +
    (attackSurfacePenalty ?? 0) +
    (regulatoryPenalty ?? 0) +
    (redAgentPenalty ?? 0)

  const overallScore = Math.max(0, Math.min(100, Math.round(100 - totalPenalty + learningBonus)))

  let postureLevel: PostureLevel
  if (overallScore >= 80) postureLevel = 'excellent'
  else if (overallScore >= 65) postureLevel = 'good'
  else if (overallScore >= 50) postureLevel = 'fair'
  else if (overallScore >= 35) postureLevel = 'at_risk'
  else postureLevel = 'critical'

  // Default action when everything is healthy
  if (actions.length === 0) {
    actions.push('Security posture is healthy — maintain current scanning and remediation cadence')
  }

  const topActions = actions.slice(0, MAX_TOP_ACTIONS)

  // ── 7. Summary ────────────────────────────────────────────────────────────
  const totalOpen =
    input.findings.openCritical +
    input.findings.openHigh +
    input.findings.openMedium +
    input.findings.openLow

  const summary =
    `Score ${overallScore}/100 (${postureLevel}). ` +
    `${totalOpen} open finding${totalOpen !== 1 ? 's' : ''} ` +
    `(${input.findings.openCritical} critical, ${input.findings.openHigh} high).` +
    (input.attackSurface
      ? ` Attack surface ${input.attackSurface.score}/100 (${input.attackSurface.trend}).`
      : '') +
    (input.regulatoryDrift
      ? ` Regulatory: ${input.regulatoryDrift.overallDriftLevel.replaceAll('_', ' ')}.`
      : '')

  return {
    overallScore,
    postureLevel,
    findingPenalty,
    attackSurfacePenalty,
    regulatoryPenalty,
    redAgentPenalty,
    learningBonus,
    topActions,
    summary,
  }
}
