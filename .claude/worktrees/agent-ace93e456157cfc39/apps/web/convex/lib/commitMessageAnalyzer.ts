// WS-55 — Commit Message Security Analyzer: pure computation library.
//
// Analyses commit messages from a push event for security-relevant behavioral
// signals: explicit control bypasses, security fix reverts, force-merge
// indicators, CVE acknowledgments, security technical debt markers, debug-mode
// enables, emergency deployments, and sensitive data references.
//
// This is intentionally different from:
//   WS-13 promptInjection — looks for prompt-injection attacks in message text
//   WS-30 secretScanResults — looks for credential values in file content
//   WS-54 sensitiveFileResults — looks for sensitive file paths
//
// This scanner looks for *developer intent signals* that indicate a commit may
// weaken security posture or introduce risk through process shortcuts.
//
// Exports:
//   analyzeCommitMessages — runs all rules, returns CommitMessageScanResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CommitMessageRuleId =
  | 'SECURITY_BYPASS'
  | 'REVERT_SECURITY_FIX'
  | 'FORCE_MERGE_BYPASS'
  | 'CVE_ACKNOWLEDGED'
  | 'TODO_SECURITY_DEBT'
  | 'DEBUG_MODE_ENABLED'
  | 'EMERGENCY_DEPLOYMENT'
  | 'SENSITIVE_DATA_REFERENCE'

export type CommitMessageSeverity = 'critical' | 'high' | 'medium' | 'low'
export type CommitMessageRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface CommitMessageFinding {
  ruleId: CommitMessageRuleId
  severity: CommitMessageSeverity
  /** First 120 characters of the matching message (never the full message). */
  matchedMessage: string
  /** Human-readable description of why this fired. */
  description: string
  recommendation: string
}

export interface CommitMessageScanResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: CommitMessageRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: CommitMessageFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

interface Rule {
  id: CommitMessageRuleId
  severity: CommitMessageSeverity
  /** One or more patterns — at least one must match the message. */
  patterns: RegExp[]
  description: string
  recommendation: string
}

const RULES: Rule[] = [
  {
    id: 'SECURITY_BYPASS',
    severity: 'critical',
    patterns: [
      /\b(?:bypass|skip|disable|remove|delete|drop)\s+(?:\w+\s+)?(?:auth(?:entication|orization)?|security|validation|check|guard|middleware|csrf|cors|tls|ssl|2fa|mfa|captcha|rate.?limit)\b/i,
      /\b(?:auth(?:entication|orization)?|security|input\s+validation)\s+(?:bypass|disabled?|removed?|skipped?|circumvented?)\b/i,
      /\bno.?auth\b|\bwithout\s+auth(?:entication)?\b|\bauth(?:entication)?\s+off\b/i,
      /\bskip(?:ping)?\s+(?:tests?|validation|check|review|approval)\b.*(?:prod|deploy|release)/i,
    ],
    description:
      'Commit message indicates an explicit bypass of security controls (authentication, validation, rate limiting, etc.).',
    recommendation:
      'Review this commit carefully. Security controls must not be disabled without a compensating control and documented exception. Raise a finding and require a security review.',
  },
  {
    id: 'REVERT_SECURITY_FIX',
    severity: 'high',
    patterns: [
      /^revert\b.*\b(?:fix|patch|secur|vuln|cve|xss|sqli|injection|auth|csrf|dos|rce)\b/im,
      /\brevert(?:ing|ed)?\s+(?:security|auth|vulnerability|patch|fix|cve|xss|sqli|rce)\b/i,
      /\b(?:undo|rollback|revert)\s+(?:the\s+)?(?:security|auth(?:entication)?|vulnerability|patch|fix)\b/i,
    ],
    description:
      'Commit message suggests reverting a security fix or patch, which may re-open a known vulnerability.',
    recommendation:
      'Verify why a security fix is being reverted. If necessary, create a tracked risk acceptance and immediately re-open the original finding.',
  },
  {
    id: 'FORCE_MERGE_BYPASS',
    severity: 'high',
    patterns: [
      /\bforce\s+merge\b|\bmerge\s+without\s+review\b|\bskip(?:ping)?\s+review\b/i,
      /\bbypass(?:ing|ed)?\s+(?:review|approval|pr|pull.?request)\b/i,
      /\b(?:merged?|push(?:ed|ing)?)\s+(?:directly|without|bypassing)\s+(?:review|approval|checks?|tests?)\b/i,
      /\bno\s+(?:review|approval|pr)\s+(?:needed|required|done)\b/i,
    ],
    description:
      'Commit message indicates the normal PR review or approval process was bypassed, increasing the risk of unreviewed code reaching the default branch.',
    recommendation:
      'Require post-merge code review and investigate why the review process was bypassed. Consider enabling branch protection rules that enforce PR requirements.',
  },
  {
    id: 'CVE_ACKNOWLEDGED',
    severity: 'medium',
    patterns: [
      /\bCVE-\d{4}-\d{4,}\b/i,
      /\b(?:fix(?:es|ed|ing)?|patch(?:es|ed|ing)?|address(?:es|ed|ing)?|resolv(?:es|ed|ing)?)\s+CVE/i,
    ],
    description:
      'Commit message references a CVE identifier. The commit may address a known vulnerability or disclose one.',
    recommendation:
      'Ensure the referenced CVE is tracked as a finding in Sentinel and that the fix has been validated. Trigger a security debt recomputation.',
  },
  {
    id: 'TODO_SECURITY_DEBT',
    severity: 'medium',
    patterns: [
      /\b(?:TODO|FIXME|HACK|XXX)\b.*\b(?:auth(?:entication|orization)?|secur(?:ity|e)|validat(?:e|ion)|sanitize|escap(?:e|ing)|encrypt|csrf|injection|xss|input)\b/i,
      /\b(?:auth(?:entication|orization)?|secur(?:ity|e)|validat(?:e|ion)|sanitize)\b.*\b(?:TODO|FIXME|HACK|XXX|later|soon|eventually|temporary|temp)\b/i,
      /\btemporar(?:y|ily)\s+(?:disable|bypass|skip|remove)\b.*\b(?:auth|security|check|validat)/i,
    ],
    description:
      'Commit message contains a security-related TODO, FIXME, or HACK marker, indicating intentional security debt being deferred.',
    recommendation:
      'Convert this security TODO into a tracked finding with an SLA. Security debt marked as "temporary" often becomes permanent.',
  },
  {
    id: 'DEBUG_MODE_ENABLED',
    severity: 'medium',
    patterns: [
      /\b(?:enabl(?:e|ing|ed)|turn(?:ing)?\s+on|activat(?:e|ing|ed))\s+debug(?:\s+mode)?\s+(?:in\s+)?(?:prod(?:uction)?|live|staging)/i,
      /\bdebug\s+(?:mode|flag|logging|output)\s+(?:on|enabl(?:ed|ing)|activ(?:e|ated?))\b/i,
      /\bdisabl(?:e|ing|ed)\s+(?:production\s+)?(?:safeguard|safety|protect|rate.?limit|throttl)\b/i,
      /\b(?:verbose|debug)\s+logging\s+(?:on|enabl(?:ed|ing))\s+(?:in\s+)?(?:prod|production)\b/i,
    ],
    description:
      'Commit message indicates enabling debug mode or disabling production safeguards, which can expose sensitive information or reduce security posture.',
    recommendation:
      'Ensure debug modes are not left enabled in production. Create a follow-up task to revert this change before production deployment.',
  },
  {
    id: 'EMERGENCY_DEPLOYMENT',
    severity: 'low',
    patterns: [
      /\b(?:hotfix|hot.fix|emergency|urgent)\s+(?:for\s+)?(?:prod(?:uction)?|live)\b/i,
      /\b(?:emergency|critical)\s+(?:patch|fix|deploy(?:ment)?|release|push)\b/i,
      /\bdeploy(?:ing)?\s+(?:without|bypassing)\s+(?:tests?|qa|staging|review)\b/i,
      /\bskip(?:ping)?\s+(?:tests?|qa|staging)\s+(?:for\s+)?(?:emergency|hotfix|urgency|speed)\b/i,
    ],
    description:
      'Commit message indicates an emergency or hotfix deployment that may have bypassed normal testing and review gates.',
    recommendation:
      'Track this emergency deployment and schedule a post-mortem review. Validate that no security controls were skipped. Update runbooks to reduce future emergency pressure.',
  },
  {
    id: 'SENSITIVE_DATA_REFERENCE',
    severity: 'low',
    patterns: [
      /\b(?:add(?:ed|ing)?|commit(?:ting|ted)?|includ(?:e|ing|ed)?|push(?:ing|ed)?)\s+(?:real|actual|live|prod(?:uction)?)\s+(?:data|users?|credentials?|pii|ssn|card|payment)/i,
      /\b(?:test(?:ing)?|debug)\s+with\s+(?:real|actual|prod(?:uction)?|live)\s+(?:\w+\s+)?(?:data|users?|credentials?|emails?|phone|address)\b/i,
      /\b(?:copy|copied|dump|export(?:ed)?)\s+(?:from\s+)?(?:prod(?:uction)?|live)\s+(?:db|database|data)\b/i,
    ],
    description:
      'Commit message suggests real or production data may have been used in testing or committed to the repository.',
    recommendation:
      'Immediately verify whether any real user data (PII, credentials, payment data) was committed. If confirmed, engage your data-privacy response plan.',
  },
]

// ---------------------------------------------------------------------------
// Scoring (identical caps to WS-53 and WS-54 for consistency)
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<CommitMessageSeverity, number> = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 3,
}

const PENALTY_CAP: Record<CommitMessageSeverity, number> = {
  critical: 75,
  high: 30,
  medium: 20,
  low: 10,
}

function toRiskLevel(score: number): CommitMessageRiskLevel {
  if (score === 0) return 'none'
  if (score < 25) return 'low'
  if (score < 50) return 'medium'
  if (score < 75) return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse one or more commit messages from a push event and return a
 * risk-scored result with per-message findings and recommendations.
 *
 * - Empty and whitespace-only messages are skipped.
 * - Each message is tested against all 8 rules; a single message can produce
 *   multiple findings if it matches multiple rules.
 * - Duplicate rule firings across messages count separately (each commit is
 *   an independent risk signal).
 */
export function analyzeCommitMessages(messages: string[]): CommitMessageScanResult {
  const findings: CommitMessageFinding[] = []

  for (const rawMessage of messages) {
    const message = rawMessage.trim()
    if (!message) continue

    for (const rule of RULES) {
      const matched = rule.patterns.some((pattern) => pattern.test(message))
      if (!matched) continue

      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        matchedMessage: message.length > 120 ? `${message.slice(0, 117)}...` : message,
        description: rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  const rawScore =
    Math.min(PENALTY_CAP.critical, criticalCount * PENALTY_PER.critical) +
    Math.min(PENALTY_CAP.high, highCount * PENALTY_PER.high) +
    Math.min(PENALTY_CAP.medium, mediumCount * PENALTY_PER.medium) +
    Math.min(PENALTY_CAP.low, lowCount * PENALTY_PER.low)

  const riskScore = Math.min(100, rawScore)
  const riskLevel = toRiskLevel(riskScore)
  const summary = buildSummary(findings, riskLevel, messages.length)

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
  findings: CommitMessageFinding[],
  riskLevel: CommitMessageRiskLevel,
  messageCount: number,
): string {
  if (findings.length === 0) {
    return `Analysed ${messageCount} commit message${messageCount === 1 ? '' : 's'} — no security-relevant signals detected.`
  }
  const criticals = findings.filter((f) => f.severity === 'critical')
  const highs = findings.filter((f) => f.severity === 'high')
  if (criticals.length > 0) {
    return `Critical: ${criticals.length} commit message${criticals.length === 1 ? '' : 's'} indicate${criticals.length === 1 ? 's' : ''} a security control bypass. Immediate review required.`
  }
  if (highs.length > 0) {
    return `High-risk: ${findings.length} security signal${findings.length === 1 ? '' : 's'} detected across ${messageCount} commit message${messageCount === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  }
  return `${findings.length} security signal${findings.length === 1 ? '' : 's'} detected in ${messageCount} commit message${messageCount === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}
