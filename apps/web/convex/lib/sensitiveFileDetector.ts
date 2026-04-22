// WS-54 — Sensitive File Commit Detector: pure computation library.
//
// Detects accidentally committed sensitive files by matching file paths from a
// push event against 16 regex rules across four categories:
//   private_key  — private-key and certificate files (critical)
//   credentials  — credential configs, env files, AWS keys (critical/high)
//   app_config   — database configs, service accounts, Firebase (critical/high)
//   debug        — build artifacts and system noise (low)
//
// No file content is required — path-pattern matching is sufficient and avoids
// the need for GitHub Contents API calls on every push.
//
// Exports:
//   detectSensitiveFiles — runs all rules, returns SensitiveFileResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SensitiveFileCategory =
  | 'private_key'
  | 'credentials'
  | 'app_config'
  | 'debug'

export type SensitiveFileSeverity = 'critical' | 'high' | 'medium' | 'low'
export type SensitiveFileRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export type SensitiveFileRuleId =
  // ── private_key ─────────────────────────────────────────────────────────
  | 'PRIVATE_KEY_FILE'
  | 'CERTIFICATE_FILE'
  | 'KEYSTORE_FILE'
  | 'SSH_PRIVATE_KEY'
  // ── credentials ─────────────────────────────────────────────────────────
  | 'AWS_CREDENTIALS'
  | 'CREDENTIAL_FILE'
  | 'WP_CONFIG'
  | 'ENV_FILE'
  | 'SECRET_FILE'
  | 'DOCKER_CONFIG'
  | 'NETRC_FILE'
  // ── app_config ───────────────────────────────────────────────────────────
  | 'DATABASE_CONFIG'
  | 'SERVICE_ACCOUNT_KEY'
  | 'FIREBASE_CONFIG'
  | 'NPMRC_FILE'
  // ── debug ────────────────────────────────────────────────────────────────
  | 'DEBUG_ARTIFACT'

export interface SensitiveFileFinding {
  ruleId: SensitiveFileRuleId
  category: SensitiveFileCategory
  severity: SensitiveFileSeverity
  matchedPath: string
  description: string
  recommendation: string
}

export interface SensitiveFileResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: SensitiveFileRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: SensitiveFileFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

interface Rule {
  id: SensitiveFileRuleId
  category: SensitiveFileCategory
  severity: SensitiveFileSeverity
  /** Pattern matched against the full relative file path (case-insensitive). */
  pattern: RegExp
  /** Optional pattern — if provided, the path must also NOT match this to fire. */
  excludePattern?: RegExp
  description: string
  recommendation: string
}

const RULES: Rule[] = [
  // ── private_key ────────────────────────────────────────────────────────────
  {
    id: 'PRIVATE_KEY_FILE',
    category: 'private_key',
    severity: 'critical',
    pattern: /(?:^|[/\\])(id_rsa|id_ed25519|id_dsa|id_ecdsa|id_xmss|id_ecdsa_sk|id_ed25519_sk)$/i,
    description: 'SSH private key file committed to repository.',
    recommendation:
      'Remove this file from git history with `git filter-repo` or BFG Repo Cleaner, then rotate the key pair immediately.',
  },
  {
    id: 'CERTIFICATE_FILE',
    category: 'private_key',
    severity: 'critical',
    pattern: /\.(pem|p12|pfx|p8|der|p7b|pkcs12)$/i,
    // Public certificate exports (.crt/.cer) are not secret; exclude them.
    // However .pem can contain both — treat as critical and let operators verify.
    description: 'Certificate or private-key bundle file committed to repository.',
    recommendation:
      'Remove from git history and revoke the certificate. Store certificates in a secrets manager, not the repository.',
  },
  {
    id: 'KEYSTORE_FILE',
    category: 'private_key',
    severity: 'critical',
    pattern: /\.(jks|keystore|bks|bcfks)$/i,
    description: 'Java KeyStore file committed to repository.',
    recommendation:
      'Remove from git history, rotate all keys in the keystore, and store keystores in a secrets manager.',
  },
  {
    id: 'SSH_PRIVATE_KEY',
    category: 'private_key',
    severity: 'critical',
    pattern: /(?:^|[/\\])(?:\.|_)?(ssh[/\\]|openssh[/\\]|rsa_private|ec_private|ssh_host_\w+_key)(?:$|[/\\])/i,
    description: 'SSH key material directory or host-key file committed to repository.',
    recommendation:
      'Remove from git history and rotate all affected keys immediately.',
  },

  // ── credentials ────────────────────────────────────────────────────────────
  {
    id: 'AWS_CREDENTIALS',
    category: 'credentials',
    severity: 'critical',
    pattern: /(?:^|[/\\])\.aws[/\\](credentials|config)$/i,
    description: 'AWS credentials or config file committed to repository.',
    recommendation:
      'Remove from git history, rotate the AWS access keys immediately via the IAM console, and use IAM roles or environment variables instead.',
  },
  {
    id: 'CREDENTIAL_FILE',
    category: 'credentials',
    severity: 'critical',
    pattern: /(?:^|[/\\])credentials?\.(?:json|ya?ml|toml|cfg|ini)$/i,
    description: 'Generic credentials file committed to repository.',
    recommendation:
      'Remove from git history, rotate any credentials stored in this file, and use a secrets manager instead.',
  },
  {
    id: 'WP_CONFIG',
    category: 'credentials',
    severity: 'critical',
    pattern: /(?:^|[/\\])wp-config\.php$/i,
    description: 'WordPress configuration file with database credentials committed to repository.',
    recommendation:
      'Remove from git history, rotate the database password, and add wp-config.php to .gitignore.',
  },
  {
    id: 'ENV_FILE',
    category: 'credentials',
    severity: 'high',
    pattern: /(?:^|[/\\])\.env(?:\.(local|dev|development|prod|production|staging|stage|test|ci|build))?$/i,
    description: 'Environment file (.env) committed to repository — may contain secrets.',
    recommendation:
      'Add .env* to .gitignore, remove from git history if it contains secrets, and use a sample .env.example file instead.',
  },
  {
    id: 'SECRET_FILE',
    category: 'credentials',
    severity: 'high',
    pattern: /(?:^|[/\\])secrets?\.(?:json|ya?ml|toml|env|cfg|ini)$/i,
    description: 'File named "secret(s)" committed to repository — likely contains sensitive data.',
    recommendation:
      'Remove from git history if it contains live secrets and move secret values to a secrets manager.',
  },
  {
    id: 'DOCKER_CONFIG',
    category: 'credentials',
    severity: 'high',
    pattern: /(?:^|[/\\])\.docker[/\\]config\.json$/i,
    description: 'Docker daemon config with registry auth credentials committed to repository.',
    recommendation:
      'Remove from git history, revoke the registry tokens, and use docker credential helpers or CI secrets instead.',
  },
  {
    id: 'NETRC_FILE',
    category: 'credentials',
    severity: 'high',
    pattern: /(?:^|[/\\])(?:\.|_)netrc$/i,
    description: '.netrc file with plaintext credentials committed to repository.',
    recommendation:
      'Remove from git history, rotate affected credentials, and use credential helpers instead of .netrc.',
  },

  // ── app_config ──────────────────────────────────────────────────────────────
  {
    id: 'DATABASE_CONFIG',
    category: 'app_config',
    severity: 'high',
    pattern: /(?:^|[/\\])(?:config[/\\])?database\.(?:ya?ml|json|php|rb|toml)$/i,
    description: 'Database configuration file committed to repository — may contain credentials.',
    recommendation:
      'Use environment variables for database connection strings and add this file to .gitignore.',
  },
  {
    id: 'SERVICE_ACCOUNT_KEY',
    category: 'app_config',
    severity: 'critical',
    pattern: /(?:^|[/\\])(?:service[_-]?account[_-]?key|gcp[_-]?key|google[_-]?credentials).*\.(?:json|p12)$/i,
    description: 'GCP service account key file committed to repository.',
    recommendation:
      'Remove from git history, revoke the key in GCP IAM immediately, and use Workload Identity Federation or Secret Manager instead.',
  },
  {
    id: 'FIREBASE_CONFIG',
    category: 'app_config',
    severity: 'high',
    pattern: /(?:^|[/\\])(?:google-services\.json|GoogleService-Info\.plist)$/i,
    description: 'Firebase/Google service configuration file committed to repository.',
    recommendation:
      'While not always secret, ensure Firebase Security Rules are locked down and restrict API keys in the Google Cloud Console.',
  },
  {
    id: 'NPMRC_FILE',
    category: 'app_config',
    severity: 'medium',
    pattern: /(?:^|[/\\])\.npmrc$/i,
    description: '.npmrc file committed to repository — may contain registry authentication tokens.',
    recommendation:
      'Verify this file does not contain auth tokens. If it does, remove from git history and use CI secrets for npm authentication instead.',
  },

  // ── debug ────────────────────────────────────────────────────────────────────
  {
    id: 'DEBUG_ARTIFACT',
    category: 'debug',
    severity: 'low',
    pattern:
      /(?:^|[/\\])(?:npm-debug\.log.*|yarn-error\.log.*|pip-log\.txt|\.DS_Store|Thumbs\.db|desktop\.ini|ehthumbs\.db|\.Spotlight-V100|\.fseventsd)$/i,
    description: 'Build debug log or OS artifact file committed to repository.',
    recommendation:
      'Add these file patterns to .gitignore and remove them from the repository.',
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<SensitiveFileSeverity, number> = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 3,
}

const PENALTY_CAP: Record<SensitiveFileSeverity, number> = {
  critical: 75,
  high: 30,
  medium: 20,
  low: 10,
}

function toRiskLevel(score: number): SensitiveFileRiskLevel {
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
 * Analyse a list of file paths from a push event and return a risk-scored
 * result with per-file findings and remediation recommendations.
 *
 * Each file path is tested against all 16 rules in sequence; a single file
 * can trigger multiple rules (e.g. a `service_account_key.pem` would match
 * both SERVICE_ACCOUNT_KEY and CERTIFICATE_FILE).
 */
export function detectSensitiveFiles(filePaths: string[]): SensitiveFileResult {
  const findings: SensitiveFileFinding[] = []

  for (const filePath of filePaths) {
    // Normalise path separators to forward-slash for consistent matching
    const normalised = filePath.replace(/\\/g, '/')

    for (const rule of RULES) {
      if (!rule.pattern.test(normalised)) continue
      if (rule.excludePattern?.test(normalised)) continue

      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        matchedPath: filePath,
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

  const summary = buildSummary(findings, riskLevel)

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

function buildSummary(findings: SensitiveFileFinding[], riskLevel: SensitiveFileRiskLevel): string {
  if (findings.length === 0) {
    return 'No sensitive files detected in this push.'
  }
  const criticals = findings.filter((f) => f.severity === 'critical')
  const highs = findings.filter((f) => f.severity === 'high')
  if (criticals.length > 0) {
    const paths = [...new Set(criticals.map((f) => f.matchedPath))].slice(0, 2).join(', ')
    return `Critical: ${criticals.length} sensitive file${criticals.length === 1 ? '' : 's'} committed — ${paths}${criticals.length > 2 ? ' and more' : ''}. Rotate credentials immediately.`
  }
  if (highs.length > 0) {
    return `High-risk: ${findings.length} sensitive file${findings.length === 1 ? '' : 's'} detected (risk level: ${riskLevel}). Review and rotate any exposed secrets.`
  }
  return `${findings.length} sensitive file${findings.length === 1 ? '' : 's'} detected (risk level: ${riskLevel}).`
}
