// WS-69 — Developer Security Tooling & SAST Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to developer security tooling configuration files. This scanner focuses on
// the *security-tooling layer* — the configs that control what security checks
// are performed, what rules are enforced, and what thresholds are applied
// during development and CI.
//
// DISTINCT from:
//   WS-33  iacScanResults           — IaC *misconfiguration findings* (the scan
//                                      output), not the scanner configuration
//   WS-35  cicdScanResults          — CI/CD pipeline *misconfiguration findings*
//   WS-56  gitIntegrityResults      — git supply-chain attack patterns
//   WS-60  securityConfigDriftResults — application runtime security options
//   WS-66  certPkiDriftResults      — cryptographic certificates and signing keys
//   WS-67  runtimeSecurityDriftResults — OPA Rego enforcement rules (runtime)
//
// WS-69 vs WS-33: WS-33 detects *in* IaC files (Terraform/k8s bad config).
//   WS-69 detects changes to the *configuration of security scanners* that
//   would run against IaC (tfsec.yml, checkov.yml). Different failure mode:
//   if scanner config is weakened, all future scans pass even when they
//   shouldn't.
//
// WS-69 vs WS-67: WS-67 covers OPA Rego *enforcement policies* at runtime.
//   WS-69 covers Semgrep/Bandit/SonarQube *development-time* static analysis
//   rule configs. These run in CI, not at runtime.
//
// Covered rule groups (8 rules):
//
//   SECRET_SCAN_CONFIG_DRIFT    — gitleaks / gitguardian / detect-secrets / trufflehog
//   SAST_POLICY_DRIFT           — SonarQube / Semgrep / Bandit / gosec / tfsec / Checkov
//   SCA_POLICY_DRIFT            — Snyk / OWASP Dependency-Check / ORT / Dependency-Track
//   SECURITY_LINT_DRIFT         — Brakeman / SpotBugs / PMD security / ESLint-security
//   DAST_SCAN_CONFIG_DRIFT      — ZAP / Burp Suite / Nikto / Nuclei  ← user contribution
//   LICENSE_POLICY_CONFIG_DRIFT — FOSSA / license-finder / scancode / license-checker
//   CONTAINER_SCAN_POLICY_DRIFT — Trivy / Grype / Anchore / Clair
//   SECURITY_BASELINE_DRIFT     — Talisman / Hadolint / Safety / MegaLinter
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–68 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Dot-prefixed exact filenames (.gitleaks.toml, .snyk, .brakeman.yml) are
//     unambiguous signals — they carry a tool-name or tool-owner identity.
//   • Generic config filenames (bandit.yml, trivy.yaml) are matched by exact
//     basename to avoid broad false-positive matching on config.yml.
//   • DAST tool output files (reports, results, scan logs) are excluded in
//     isDastScanConfigFile via result-keyword detection.
//
// Exports:
//   isDastScanConfigFile         — user contribution point (see JSDoc below)
//   DEV_SEC_TOOLS_RULES          — readonly rule registry
//   scanDevSecToolsDrift         — main scanner, returns DevSecToolsDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DevSecToolsRuleId =
  | 'SECRET_SCAN_CONFIG_DRIFT'
  | 'SAST_POLICY_DRIFT'
  | 'SCA_POLICY_DRIFT'
  | 'SECURITY_LINT_DRIFT'
  | 'DAST_SCAN_CONFIG_DRIFT'
  | 'LICENSE_POLICY_CONFIG_DRIFT'
  | 'CONTAINER_SCAN_POLICY_DRIFT'
  | 'SECURITY_BASELINE_DRIFT'

export type DevSecToolsSeverity = 'high' | 'medium' | 'low'
export type DevSecToolsRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type DevSecToolsDriftFinding = {
  ruleId: DevSecToolsRuleId
  severity: DevSecToolsSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type DevSecToolsDriftResult = {
  riskScore: number
  riskLevel: DevSecToolsRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: DevSecToolsDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// ---------------------------------------------------------------------------
// Detection helpers — SECRET_SCAN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const SECRET_SCAN_EXACT = new Set([
  '.gitleaks.toml', 'gitleaks.toml', 'gitleaks.yaml', 'gitleaks.yml',
  '.gitguardian.yml', 'gitguardian.yml', '.gitguardian.yaml', 'gitguardian.yaml',
  '.secrets.baseline',                         // detect-secrets
  'trufflehog.toml', '.trufflehog.toml',
  '.trufflehog.yml', 'trufflehog.yml',
  '.trufflehog.yaml', 'trufflehog.yaml',
  'git-secrets.cfg', '.git-secrets',
])

const SECRET_SCAN_DIRS = ['gitleaks/', '.gitleaks/']

function isSecretScanConfig(pathLower: string, base: string): boolean {
  if (SECRET_SCAN_EXACT.has(base)) return true
  for (const dir of SECRET_SCAN_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // Tool-prefixed config files (e.g. gitleaks-config.toml, trufflehog-custom.yml)
  if (base.startsWith('gitleaks-') || base.startsWith('trufflehog-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SAST_POLICY_DRIFT
// ---------------------------------------------------------------------------

const SAST_EXACT = new Set([
  'sonar-project.properties', 'sonar-scanner.properties',
  '.semgrep.yml', 'semgrep.yml', 'semgrep.yaml', '.semgrep.yaml',
  '.bandit', 'bandit.yml', 'bandit.yaml', 'bandit.ini',
  'gosec.conf',
  // IaC security scanners — config changes weaken future IaC scans
  '.tfsec.yml', 'tfsec.yml', '.tfsec.yaml', 'tfsec.yaml',
  '.checkov.yml', 'checkov.yml', '.checkov.yaml', 'checkov.yaml',
  'kics.config', '.kics.config',
])

const SAST_DIRS = ['semgrep/', '.semgrep/', 'sonar/', '.sonar/']

function isSastPolicyConfig(pathLower: string, base: string): boolean {
  if (SAST_EXACT.has(base)) return true
  for (const dir of SAST_DIRS) {
    if (pathLower.includes(dir) && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.properties') || base.endsWith('.json'))) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SCA_POLICY_DRIFT
// ---------------------------------------------------------------------------

const SCA_EXACT = new Set([
  '.snyk',                                     // Snyk policy file (no extension)
  'snyk.yml', 'snyk.yaml',
  'dependency-check.xml', 'dependency-check.properties',
  '.ort.yml', 'ort.yml', '.ort.yaml', 'ort.yaml',
  'dependency-track.yml', 'dependency-track.yaml',
  'nancy.yml',                                  // Sonatype Nancy for Go
])

const SCA_DIRS = ['ort/', '.ort/', 'dependency-check/']

function isScaPolicyConfig(pathLower: string, base: string): boolean {
  if (SCA_EXACT.has(base)) return true
  for (const dir of SCA_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SECURITY_LINT_DRIFT
// ---------------------------------------------------------------------------

const SECURITY_LINT_EXACT = new Set([
  '.brakeman.yml', 'brakeman.yml', 'brakeman.yaml', '.brakeman.yaml',
  'spotbugs-security-include.xml', 'spotbugs-security-exclude.xml',
  'spotbugs-security.xml',
  'pmd-security.xml', 'pmd-security-ruleset.xml',
  'rubocop-security.yml', '.rubocop-security.yml',
])

const SECURITY_LINT_DIRS = ['brakeman/', 'spotbugs/']

function isSecurityLintConfig(pathLower: string, base: string): boolean {
  if (SECURITY_LINT_EXACT.has(base)) return true
  for (const dir of SECURITY_LINT_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // ESLint config with security in the filename (e.g. eslint-security.config.js)
  if (base.includes('eslint') && base.includes('security')) return true
  return false
}

// ---------------------------------------------------------------------------
// DAST_SCAN_CONFIG_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isDastScanConfigFile — determines whether a file path is a DAST or
 * security pentest tool *configuration* file (not a scan result or report).
 *
 * Covered tools: OWASP ZAP, Burp Suite, Nikto, Nuclei, OWASP Amass.
 *
 * The core ambiguity: DAST tools create both configuration files (scan
 * templates, tool settings, target lists) AND output artifacts (HTML/PDF
 * reports, JSON findings, XML results) that can have similar filenames and
 * live in the same directories. Committing a scan *result* file is benign
 * (or even useful); committing a weakened scan *config* is a security signal.
 *
 * Design trade-offs to consider:
 *
 *   (a) Result-keyword exclusion: basenames containing "report", "result",
 *       "output", "findings", "log", or "scan-log" are almost certainly
 *       output artifacts, not configuration. Excluding them first reduces
 *       false positives significantly.
 *
 *   (b) Config-keyword inclusion: basenames containing "config", "conf",
 *       "policy", "template", "options", or "settings" combined with a
 *       tool-name prefix are strong indicators of configuration files.
 *
 *   (c) Tool-directory context: files inside zap/, burp/, nuclei/, or dast/
 *       directories that pass the config-keyword check are more likely to
 *       be configuration rather than output (which often lives in reports/).
 *
 *   (d) Exact filenames: some tool config files have fixed canonical names
 *       (nikto.conf, nuclei-config.yml, zap.conf) that are unambiguous.
 *
 * Implement the function to return true for DAST tool configuration files
 * and false for result/report artifacts. The result-keyword exclusion
 * should take precedence over all other positive signals.
 */
export function isDastScanConfigFile(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

  // Canonical exact config filenames — unambiguous
  const DAST_EXACT = new Set([
    'nikto.conf', 'nuclei-config.yml', 'nuclei-config.yaml',
    '.nuclei-config.yml', '.nuclei-config.yaml',
    'zap.conf', 'owasp-zap.conf',
    'burpsuite.project.json', 'burp-project.json',
    'amass.ini', 'amass-config.ini',
  ])
  if (DAST_EXACT.has(base)) return true

  // Result/output keyword exclusion — takes precedence over all positive checks
  const RESULT_KEYWORDS = ['report', 'result', 'output', 'finding', 'log', 'scan-log', 'alert']
  for (const kw of RESULT_KEYWORDS) {
    if (base.includes(kw)) return false
  }

  // Tool-name prefixes used in DAST tool config files
  const DAST_PREFIXES = ['zap', 'burp', 'nikto', 'nuclei', 'owasp-zap', 'owaspzap']
  const CONFIG_KEYWORDS = ['config', 'conf', 'policy', 'template', 'options', 'settings', 'target']
  const CONFIG_EXTS = new Set(['.conf', '.yaml', '.yml', '.json', '.ini', '.xml'])

  for (const prefix of DAST_PREFIXES) {
    if (base.startsWith(prefix)) {
      // Strong signal: tool prefix + config keyword in basename
      for (const kw of CONFIG_KEYWORDS) {
        if (base.includes(kw)) return true
      }
      // Moderate signal: tool prefix + recognized config extension
      if (CONFIG_EXTS.has(ext)) return true
    }
  }

  // Tool directory context: config-looking files in DAST tool directories
  const DAST_DIRS = ['zap/', 'burp/', 'nuclei/', 'dast/', 'pentest/']
  for (const dir of DAST_DIRS) {
    if (pathLower.includes(dir)) {
      for (const kw of CONFIG_KEYWORDS) {
        if (base.includes(kw)) return true
      }
      if (ext === '.conf' || ext === '.yaml' || ext === '.yml' || ext === '.ini') return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — LICENSE_POLICY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const LICENSE_EXACT = new Set([
  '.fossa.yml', 'fossa.yml', '.fossa.yaml', 'fossa.yaml',
  'license-finder.yml', 'license-finder.yaml',
  '.licensechecker.json', 'license-checker.json', 'license-checker.config.js',
  'scancode.cfg', '.scancode.cfg',
  'about.yml',                                  // AboutCode
  'attribution.yml',
])

const LICENSE_DIRS = ['fossa/', '.fossa/']

function isLicensePolicyConfig(pathLower: string, base: string): boolean {
  if (LICENSE_EXACT.has(base)) return true
  for (const dir of LICENSE_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — CONTAINER_SCAN_POLICY_DRIFT
// ---------------------------------------------------------------------------

const CONTAINER_SCAN_EXACT = new Set([
  'trivy.yaml', '.trivy.yaml', 'trivy-config.yaml', '.trivy-config.yaml',
  'trivy.yml', '.trivy.yml', 'trivy-config.yml', '.trivy-config.yml',
  'grype.yaml', '.grype.yaml', 'grype.yml', '.grype.yml',
  'grype-config.yaml', 'grype-config.yml',
  'anchore-policy.json', 'anchore-engine.yml', 'anchore.yml',
  'clair-config.yaml', 'clair.conf',
  'snyk-container.yml', 'snyk-container.yaml',
])

const CONTAINER_SCAN_DIRS = ['.grype/', 'grype/', 'trivy/']

function isContainerScanPolicyConfig(pathLower: string, base: string): boolean {
  if (CONTAINER_SCAN_EXACT.has(base)) return true
  for (const dir of CONTAINER_SCAN_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SECURITY_BASELINE_DRIFT
// ---------------------------------------------------------------------------

const BASELINE_EXACT = new Set([
  '.talismanrc', 'talisman.yml', 'talisman.yaml', '.talisman.toml',
  '.hadolint.yaml', '.hadolint.yml', 'hadolint.yaml', 'hadolint.yml',
  'safety-policy.yml', 'safety-policy.yaml',
  '.mega-linter.yml', 'mega-linter.yml', '.mega-linter.yaml', 'mega-linter.yaml',
])

const BASELINE_DIRS = ['talisman/']

function isSecurityBaselineConfig(pathLower: string, base: string): boolean {
  if (BASELINE_EXACT.has(base)) return true
  for (const dir of BASELINE_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type DevSecToolsRule = {
  id: DevSecToolsRuleId
  severity: DevSecToolsSeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const DEV_SEC_TOOLS_RULES: readonly DevSecToolsRule[] = [
  {
    id: 'SECRET_SCAN_CONFIG_DRIFT',
    severity: 'high',
    description: 'Secret scanning tool configuration files (gitleaks, GitGuardian, detect-secrets, trufflehog) were modified. Weakening these configs can allow credential leaks to go undetected in commits.',
    recommendation: 'Review whether any allowlists were broadened, rules disabled, or entropy thresholds lowered. Confirm changes were reviewed by the security team.',
    matches: (p, b) => isSecretScanConfig(p, b),
  },
  {
    id: 'SAST_POLICY_DRIFT',
    severity: 'high',
    description: 'Static analysis security testing (SAST) tool configuration files (SonarQube, Semgrep, Bandit, gosec, tfsec, Checkov) were modified. Policy weakening can cause future scans to miss real vulnerabilities.',
    recommendation: 'Verify that no rule categories were disabled or severity thresholds lowered. Ensure any new exclusions are documented and approved.',
    matches: (p, b) => isSastPolicyConfig(p, b),
  },
  {
    id: 'SCA_POLICY_DRIFT',
    severity: 'high',
    description: 'Software composition analysis (SCA) tool policy files (Snyk, OWASP Dependency-Check, ORT, Dependency-Track) were modified. Changes can suppress vulnerability reports for known-affected packages.',
    recommendation: 'Review any new ignore rules, severity overrides, or excluded vulnerability IDs. Confirm suppressed issues have documented time-bound justifications.',
    matches: (p, b) => isScaPolicyConfig(p, b),
  },
  {
    id: 'SECURITY_LINT_DRIFT',
    severity: 'medium',
    description: 'Security linting tool configuration files (Brakeman, SpotBugs security rules, PMD security ruleset, ESLint-security, RuboCop security) were modified.',
    recommendation: 'Check whether any security-relevant rules were disabled or severity levels reduced. Security linting config changes should require peer review.',
    matches: (p, b) => isSecurityLintConfig(p, b),
  },
  {
    id: 'DAST_SCAN_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Dynamic application security testing (DAST) tool configuration files (OWASP ZAP, Burp Suite, Nikto, Nuclei) were modified. Config changes can reduce scan coverage or disable active checks.',
    recommendation: 'Review whether scan scope was narrowed, authentication configs were removed, or active scanner rules were disabled. Verify the change was intentional and peer-reviewed.',
    matches: (p) => isDastScanConfigFile(p),
  },
  {
    id: 'LICENSE_POLICY_CONFIG_DRIFT',
    severity: 'medium',
    description: 'License compliance tool configuration files (FOSSA, license-finder, scancode, license-checker) were modified. Changes may introduce unapproved open-source licenses into the project.',
    recommendation: 'Review added license exceptions or changed policy thresholds. Ensure any newly permitted license categories comply with legal and commercial requirements.',
    matches: (p, b) => isLicensePolicyConfig(p, b),
  },
  {
    id: 'CONTAINER_SCAN_POLICY_DRIFT',
    severity: 'medium',
    description: 'Container image scanning tool configuration files (Trivy, Grype, Anchore, Clair) were modified. Policy changes can suppress CVE reports for image vulnerabilities.',
    recommendation: 'Check whether severity thresholds were lowered, CVE IDs were added to ignore lists, or scan targets were excluded. Document and review any new suppressions.',
    matches: (p, b) => isContainerScanPolicyConfig(p, b),
  },
  {
    id: 'SECURITY_BASELINE_DRIFT',
    severity: 'low',
    description: 'Security baseline tool configuration files (Talisman secret detection, Hadolint Dockerfile linting, Python Safety policy, MegaLinter) were modified.',
    recommendation: 'Confirm that no baseline checks were disabled and that threshold changes are justified. Security tooling baselines should be reviewed before merging.',
    matches: (p, b) => isSecurityBaselineConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: DevSecToolsSeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): DevSecToolsRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanDevSecToolsDrift(filePaths: string[]): DevSecToolsDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<DevSecToolsRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of DEV_SEC_TOOLS_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<DevSecToolsSeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: DevSecToolsDriftFinding[] = []

  for (const rule of DEV_SEC_TOOLS_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

  return { riskScore, riskLevel, totalFindings: findings.length, highCount, mediumCount, lowCount, findings, summary }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): DevSecToolsDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No developer security tooling configuration drift detected.',
  }
}

function buildSummary(
  level: DevSecToolsRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: DevSecToolsDriftFinding[],
): string {
  if (level === 'none') return 'No developer security tooling configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'security tool config'

  return `Developer security tooling drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure no security checks were weakened or disabled.`
}
