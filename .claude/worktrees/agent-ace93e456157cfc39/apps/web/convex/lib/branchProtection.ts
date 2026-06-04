// WS-53 — GitHub Branch Protection Analyzer: pure computation library.
//
// Evaluates a repository's default-branch protection configuration against
// 8 security rules and produces a scored result with actionable findings.
// No network calls are made — all logic is deterministic on the input.
//
// Exports:
//   computeBranchProtection  — runs all rules, returns BranchProtectionResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BranchProtectionRuleId =
  | 'NO_BRANCH_PROTECTION'
  | 'NO_REQUIRED_REVIEWS'
  | 'FORCE_PUSH_ALLOWED'
  | 'NO_REQUIRED_STATUS_CHECKS'
  | 'STALE_REVIEWS_NOT_DISMISSED'
  | 'NO_CODEOWNERS'
  | 'ADMIN_BYPASS_ALLOWED'
  | 'DELETIONS_ALLOWED'

export type BranchProtectionSeverity = 'critical' | 'high' | 'medium' | 'low'
export type BranchProtectionRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

/** Represents the protection state of a repository's default branch.
 *  This can be populated from the GitHub Branch Protection API or simulated
 *  for testing. When `enabled` is false, all other fields are ignored. */
export interface BranchProtectionInput {
  /** Branch protection rules are configured and active. */
  enabled: boolean
  /** Minimum number of required PR approvals before merge (0 = none required). */
  requiredReviewerCount: number
  /** Force-pushing to this branch is permitted. */
  allowForcePushes: boolean
  /** At least one required CI/CD status check is configured. */
  hasRequiredStatusChecks: boolean
  /** Previously approved PR reviews are dismissed when new commits are pushed. */
  dismissStaleReviews: boolean
  /** A CODEOWNERS file exists in the repository root or .github/. */
  hasCodeowners: boolean
  /** Repository administrators can bypass branch protection rules. */
  adminsBypass: boolean
  /** The branch can be deleted. */
  allowDeletions: boolean
  /** All commits must be signed (GPG/SSH). */
  requireSignedCommits: boolean
  /** Only squash or rebase merges are allowed (no merge commits). */
  requireLinearHistory: boolean
}

export interface BranchProtectionFinding {
  ruleId: BranchProtectionRuleId
  severity: BranchProtectionSeverity
  title: string
  detail: string
  recommendation: string
}

export interface BranchProtectionResult {
  /** 0 = safe, 100 = maximally risky. */
  riskScore: number
  riskLevel: BranchProtectionRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: BranchProtectionFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

interface Rule {
  id: BranchProtectionRuleId
  severity: BranchProtectionSeverity
  title: string
  detail: string
  recommendation: string
  /** Returns true when the misconfiguration is detected. */
  check: (cfg: BranchProtectionInput) => boolean
}

const RULES: Rule[] = [
  {
    id: 'NO_BRANCH_PROTECTION',
    severity: 'critical',
    title: 'Default branch has no protection rules',
    detail:
      'Without branch protection, any contributor can push directly to the default branch, introduce malicious code, or delete history.',
    recommendation:
      'Enable branch protection on the default branch and configure at minimum: required PR reviews, required status checks, and disallow force pushes.',
    check: (cfg) => !cfg.enabled,
  },
  {
    id: 'NO_REQUIRED_REVIEWS',
    severity: 'high',
    title: 'No required pull-request reviewers',
    detail:
      'Merging without mandatory peer review allows unvetted code to reach the default branch, increasing the risk of supply-chain compromise.',
    recommendation: 'Require at least 1 approving review from a code owner before merges are allowed.',
    check: (cfg) => cfg.enabled && cfg.requiredReviewerCount === 0,
  },
  {
    id: 'FORCE_PUSH_ALLOWED',
    severity: 'high',
    title: 'Force push to protected branch is allowed',
    detail:
      'Force-pushing can rewrite history, remove audit trails, or inject malicious commits that obscure a supply-chain attack.',
    recommendation: 'Disable force pushes on the default branch for all users including administrators.',
    check: (cfg) => cfg.enabled && cfg.allowForcePushes,
  },
  {
    id: 'NO_REQUIRED_STATUS_CHECKS',
    severity: 'medium',
    title: 'No required CI status checks before merge',
    detail:
      'Without required status checks, code that fails tests or security scans can be merged, defeating automated gatekeeping.',
    recommendation:
      'Configure at least one required status check (e.g. build, test, Sentinel gate) on the default branch.',
    check: (cfg) => cfg.enabled && !cfg.hasRequiredStatusChecks,
  },
  {
    id: 'STALE_REVIEWS_NOT_DISMISSED',
    severity: 'medium',
    title: 'Stale PR approvals are not dismissed on new commits',
    detail:
      'If a reviewer approves a PR and then the author pushes additional commits, the original approval still counts — allowing unapproved code to slip through.',
    recommendation:
      'Enable "Dismiss stale pull request approvals when new commits are pushed" in branch protection settings.',
    check: (cfg) => cfg.enabled && cfg.requiredReviewerCount > 0 && !cfg.dismissStaleReviews,
  },
  {
    id: 'NO_CODEOWNERS',
    severity: 'medium',
    title: 'No CODEOWNERS file to enforce review ownership',
    detail:
      'Without a CODEOWNERS file, high-risk directories (CI scripts, dependency manifests, auth code) have no designated reviewers, making targeted supply-chain modifications easier.',
    recommendation:
      'Add a CODEOWNERS file in the repo root or .github/ that maps sensitive paths to required reviewer teams.',
    check: (cfg) => cfg.enabled && !cfg.hasCodeowners,
  },
  {
    id: 'ADMIN_BYPASS_ALLOWED',
    severity: 'low',
    title: 'Administrators can bypass branch protection',
    detail:
      'Admin bypass widens the attack surface: a compromised admin account or privileged CI token can merge unreviewed code without triggering protection rules.',
    recommendation:
      'Enable "Do not allow bypassing the above settings" to enforce branch protection for administrators too.',
    check: (cfg) => cfg.enabled && cfg.adminsBypass,
  },
  {
    id: 'DELETIONS_ALLOWED',
    severity: 'low',
    title: 'Protected branch can be deleted',
    detail:
      'Allowing deletions on a protected branch means a mistaken or malicious action could permanently destroy the default branch and its history.',
    recommendation: 'Disable "Allow deletions" on the default branch protection rule.',
    check: (cfg) => cfg.enabled && cfg.allowDeletions,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/** Penalty caps per severity level. */
const PENALTY: Record<BranchProtectionSeverity, number> = {
  critical: 75,
  high: 30,
  medium: 20,
  low: 10,
}

/** Per-finding contribution per severity level. */
const PENALTY_PER: Record<BranchProtectionSeverity, number> = {
  critical: 75, // NO_BRANCH_PROTECTION alone → 75 (max)
  high: 15,
  medium: 8,
  low: 3,
}

function severityToRiskLevel(score: number): BranchProtectionRiskLevel {
  if (score === 0) return 'none'
  if (score < 25) return 'low'
  if (score < 50) return 'medium'
  if (score < 75) return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/** Analyze a branch protection configuration and return a scored result. */
export function computeBranchProtection(input: BranchProtectionInput): BranchProtectionResult {
  const findings: BranchProtectionFinding[] = []

  for (const rule of RULES) {
    if (rule.check(input)) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        detail: rule.detail,
        recommendation: rule.recommendation,
      })
    }
  }

  // Compute capped severity contributions
  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  const rawScore =
    Math.min(PENALTY.critical, criticalCount * PENALTY_PER.critical) +
    Math.min(PENALTY.high, highCount * PENALTY_PER.high) +
    Math.min(PENALTY.medium, mediumCount * PENALTY_PER.medium) +
    Math.min(PENALTY.low, lowCount * PENALTY_PER.low)

  const riskScore = Math.min(100, rawScore)
  const riskLevel = severityToRiskLevel(riskScore)

  const summary = buildSummary(findings, riskLevel, input.enabled)

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}

function buildSummary(
  findings: BranchProtectionFinding[],
  riskLevel: BranchProtectionRiskLevel,
  enabled: boolean,
): string {
  if (!enabled) {
    return 'Default branch has no protection rules — any contributor can push or force-push directly.'
  }
  if (findings.length === 0) {
    return 'Branch protection is well configured. No misconfigurations detected.'
  }
  const criticals = findings.filter((f) => f.severity === 'critical')
  const highs = findings.filter((f) => f.severity === 'high')
  if (criticals.length > 0) {
    return `Critical branch protection gap: ${criticals[0].title}. Immediate remediation required.`
  }
  if (highs.length > 0) {
    return `High-severity branch protection issue: ${highs[0].title}. ${findings.length} misconfiguration${findings.length === 1 ? '' : 's'} found (risk level: ${riskLevel}).`
  }
  return `${findings.length} branch protection misconfiguration${findings.length === 1 ? '' : 's'} found (risk level: ${riskLevel}).`
}
