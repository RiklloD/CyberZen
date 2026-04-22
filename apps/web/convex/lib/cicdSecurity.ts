// WS-35 — CI/CD Pipeline Security Scanner: pure computation library.
//
// Detects security misconfigurations in GitHub Actions, GitLab CI,
// CircleCI, and Bitbucket Pipelines YAML files via static regex-rule
// analysis.  No network calls are made.
//
// Exports:
//   detectCicdFileType   — infers CI/CD file type from filename
//   scanCicdFile         — runs all applicable rules against a single file
//   combineCicdResults   — aggregates per-file results into a summary

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CicdFileType =
  | 'github_actions'
  | 'gitlab_ci'
  | 'circleci'
  | 'bitbucket_pipelines'
  | 'unknown'

export type CicdSeverity = 'critical' | 'high' | 'medium' | 'low'

export type CicdRuleId =
  // ── GitHub Actions ────────────────────────────────────────────────────────
  /** Untrusted event payload used directly inside a `run:` shell step. */
  | 'GHACTIONS_SCRIPT_INJECTION'
  /** on: pull_request_target lets fork code run with repo secrets. */
  | 'GHACTIONS_PULL_REQUEST_TARGET'
  /** Action pinned to a mutable tag/branch instead of a full commit SHA. */
  | 'GHACTIONS_UNPINNED_ACTION'
  /** permissions: write-all grants all repository permissions. */
  | 'GHACTIONS_EXCESSIVE_PERMISSIONS'
  /** Secret value echoed to logs via echo or run context. */
  | 'GHACTIONS_SECRETS_IN_LOGGING'
  /** Job runs on a self-hosted runner (persistence & lateral-movement risk). */
  | 'GHACTIONS_SELF_HOSTED_RUNNER'
  // ── GitLab CI ─────────────────────────────────────────────────────────────
  /** Docker-in-Docker service with --privileged flag. */
  | 'GITLAB_DIND_PRIVILEGED'
  /** curl | bash or wget | sh executed in a script/before_script block. */
  | 'GITLAB_CURL_BASH_PIPE'
  /** Job artifacts defined without an expiry_in field. */
  | 'GITLAB_ARTIFACT_NO_EXPIRY'
  /** Job uses an image pulled from an unverified/external registry. */
  | 'GITLAB_UNVERIFIED_IMAGE'
  // ── CircleCI ──────────────────────────────────────────────────────────────
  /** curl | bash or wget | sh in a run step. */
  | 'CIRCLE_CURL_BASH_PIPE'
  /** machine executor image pinned to :latest or using a deprecated version. */
  | 'CIRCLE_MACHINE_LATEST_IMAGE'
  /** SSH keys added via add_ssh_keys without a whitelist of hosts. */
  | 'CIRCLE_SSH_NO_FINGERPRINT'
  // ── Bitbucket Pipelines ───────────────────────────────────────────────────
  /** Step runs with Docker in privileged mode. */
  | 'BB_PRIVILEGED_PIPELINE'
  /** curl | bash or wget | sh in a script block. */
  | 'BB_CURL_BASH_PIPE'
  // ── Cross-platform ────────────────────────────────────────────────────────
  /** Credential-like variable hardcoded as a literal value in CI YAML. */
  | 'CI_INLINE_SECRET'
  /** Job or step has no timeout defined (runaway build risk / cost spike). */
  | 'CI_MISSING_TIMEOUT'

export type CicdFinding = {
  ruleId: CicdRuleId
  severity: CicdSeverity
  title: string
  description: string
  remediation: string
}

export type CicdScanResult = {
  filename: string
  fileType: CicdFileType
  findings: CicdFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
}

export type CicdScanSummary = {
  totalFiles: number
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  fileResults: CicdScanResult[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

type CicdRule = {
  id: CicdRuleId
  severity: CicdSeverity
  title: string
  description: string
  remediation: string
  fileTypes: CicdFileType[]
  pattern: RegExp
  /** When true, the rule fires if the pattern is NOT found in the content. */
  negated?: boolean
}

const RULES: CicdRule[] = [
  // ── GitHub Actions ─────────────────────────────────────────────────────────

  {
    id: 'GHACTIONS_SCRIPT_INJECTION',
    severity: 'critical',
    title: 'GitHub Actions expression injection in shell step',
    description:
      'An untrusted event payload value (e.g. github.event.issue.title, github.event.head_commit.message) ' +
      'is interpolated directly inside a `run:` step. An attacker can craft a PR title or commit message ' +
      'containing shell metacharacters to execute arbitrary code in the runner context.',
    remediation:
      'Store the value in an intermediate environment variable (env: TITLE: ${{ github.event.pull_request.title }}) ' +
      'and reference it as $TITLE in the shell step, never via ${{ ... }} inside run:.',
    fileTypes: ['github_actions'],
    // Matches ${{ github.event.<anything> }} or ${{ github.head_ref }} etc. inside a run: block
    pattern:
      /run:.*\$\{\{.*github\.(?:event\.|head_ref|base_ref|ref_name|repository\.name)[^}]*\}\}/s,
  },

  {
    id: 'GHACTIONS_PULL_REQUEST_TARGET',
    severity: 'high',
    title: 'Workflow triggered by pull_request_target',
    description:
      '`on: pull_request_target` runs the workflow in the context of the base repository, ' +
      'giving it access to repository secrets even when triggered by a fork PR. ' +
      'If the workflow also checks out fork code (actions/checkout with the PR ref), ' +
      'an attacker can read or exfiltrate every secret in the repository.',
    remediation:
      'Prefer `on: pull_request` for workflows that check out untrusted code. ' +
      'If pull_request_target is required, never combine it with `ref: ${{ github.event.pull_request.head.sha }}`.',
    fileTypes: ['github_actions'],
    pattern: /on:\s*(?:\[[\s\S]*?\]|[\s\S]*?)pull_request_target/,
  },

  {
    id: 'GHACTIONS_UNPINNED_ACTION',
    severity: 'medium',
    title: 'Action pinned to mutable tag instead of commit SHA',
    description:
      'A `uses:` step references an action at a branch or version tag (e.g. @main, @v3). ' +
      'Tags are mutable — a compromised maintainer or tag overwrite can silently swap in ' +
      'malicious code on your next workflow run.',
    remediation:
      'Pin each third-party action to a full 40-character commit SHA ' +
      '(e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683). ' +
      'Use Dependabot to keep pinned SHAs up to date.',
    fileTypes: ['github_actions'],
    // Matches uses: owner/repo@<non-sha> — SHAs are exactly 40 hex chars
    pattern: /uses:\s*\S+@(?!([0-9a-f]{40}\b))\S+/i,
  },

  {
    id: 'GHACTIONS_EXCESSIVE_PERMISSIONS',
    severity: 'high',
    title: 'Workflow grants write-all permissions',
    description:
      '`permissions: write-all` grants every available GitHub token permission to every job in the workflow. ' +
      'If any step is compromised, the attacker gains write access to code, packages, pages, and more.',
    remediation:
      'Use the principle of least privilege: declare only the specific scopes each job needs ' +
      '(e.g. `permissions: contents: read`). Start from `permissions: {}` and add what is required.',
    fileTypes: ['github_actions'],
    pattern: /permissions:\s*write-all/i,
  },

  {
    id: 'GHACTIONS_SECRETS_IN_LOGGING',
    severity: 'medium',
    title: 'Secret value echoed to workflow logs',
    description:
      'A step runs `echo ${{ secrets.<name> }}` or similar, printing the raw secret value into the ' +
      'workflow log. GitHub masks known secret values but the mask can be bypassed with encoding tricks.',
    remediation:
      'Never echo or print secret values. If you must inspect a secret, hash or truncate it before logging.',
    fileTypes: ['github_actions'],
    pattern: /(?:echo|printf|run:.*echo)\s+['"$]*\$\{\{\s*secrets\./i,
  },

  {
    id: 'GHACTIONS_SELF_HOSTED_RUNNER',
    severity: 'medium',
    title: 'Job uses a self-hosted runner',
    description:
      'Self-hosted runners persist state between workflow runs and may share the host with other processes. ' +
      'A compromised workflow can plant malware, exfiltrate credentials from the runner file system, ' +
      'or pivot to internal network resources accessible from the runner host.',
    remediation:
      'Use ephemeral self-hosted runners (--ephemeral flag) or GitHub-hosted runners for untrusted workloads. ' +
      'Apply network egress restrictions and minimal IAM permissions to runner hosts.',
    fileTypes: ['github_actions'],
    pattern: /runs-on:\s*(?:\[[\s\S]*?\bself-hosted\b|\s*self-hosted)/i,
  },

  // ── GitLab CI ──────────────────────────────────────────────────────────────

  {
    id: 'GITLAB_DIND_PRIVILEGED',
    severity: 'critical',
    title: 'Docker-in-Docker service runs with --privileged',
    description:
      'A GitLab CI job starts a Docker daemon as a service with the --privileged flag, giving the container ' +
      'near-full access to the host kernel. A compromised job can escape the container and compromise the runner.',
    remediation:
      'Use Kaniko, Buildah, or img for container builds without root privileges. ' +
      'If DinD is required, restrict runner placement to dedicated, isolated hosts.',
    fileTypes: ['gitlab_ci'],
    pattern: /(?:--privileged|privileged:\s*true)/i,
  },

  {
    id: 'GITLAB_CURL_BASH_PIPE',
    severity: 'high',
    title: 'GitLab CI pipes curl/wget output to shell',
    description:
      'A script or before_script block fetches and immediately executes a remote script via `curl | bash` ' +
      'or `wget | sh`. This pattern bypasses checksum verification and executes untrusted remote code.',
    remediation:
      'Download the script to a file, verify its SHA-256 checksum against a known-good value, ' +
      'then execute it separately.',
    fileTypes: ['gitlab_ci'],
    pattern: /(?:curl|wget)\s+[^|#\n]+\|\s*(?:bash|sh)\b/i,
  },

  {
    id: 'GITLAB_ARTIFACT_NO_EXPIRY',
    severity: 'low',
    title: 'GitLab CI artifact has no expiry configured',
    description:
      'Job artifacts without an `expiry_in` field persist indefinitely. ' +
      'Sensitive build outputs (binaries, coverage reports, debug symbols) accumulate and may be accessed later.',
    remediation: 'Add `expiry_in: 30 days` (or appropriate duration) to all artifact definitions.',
    fileTypes: ['gitlab_ci'],
    // Fires when "artifacts:" is present but "expire_in:" is NOT found in the file
    pattern: /artifacts:/i,
    negated: false,
  },

  {
    id: 'GITLAB_UNVERIFIED_IMAGE',
    severity: 'medium',
    title: 'GitLab CI job uses an image without digest pinning',
    description:
      'A job `image:` field references a Docker image by name or tag rather than by SHA digest ' +
      '(e.g. `node:18` instead of `node@sha256:...`). Tag-based references can be replaced by ' +
      'a malicious image push to the registry.',
    remediation:
      'Pin images to their SHA-256 digest (e.g. `image: node@sha256:<64-char-hex>`). ' +
      'Use Renovate or Dependabot to keep digests current.',
    fileTypes: ['gitlab_ci'],
    // Matches image: <name>[:<tag>] but NOT image: <name>@sha256:
    pattern: /^\s*image:\s+["']?(?!.*@sha256:)\S+["']?\s*$/m,
  },

  // ── CircleCI ───────────────────────────────────────────────────────────────

  {
    id: 'CIRCLE_CURL_BASH_PIPE',
    severity: 'high',
    title: 'CircleCI step pipes curl/wget output to shell',
    description:
      'A run step fetches and immediately executes a remote script. This bypasses integrity checks ' +
      'and can introduce supply-chain compromise.',
    remediation:
      'Download, verify checksum, then execute scripts in separate commands.',
    fileTypes: ['circleci'],
    pattern: /(?:curl|wget)\s+[^|#\n]+\|\s*(?:bash|sh)\b/i,
  },

  {
    id: 'CIRCLE_MACHINE_LATEST_IMAGE',
    severity: 'medium',
    title: 'CircleCI machine executor uses unpinned or :latest image',
    description:
      'The machine executor image is set to `latest` or a rolling alias, making builds non-reproducible ' +
      'and susceptible to unexpected changes when the upstream image is updated.',
    remediation:
      'Pin the machine image to a specific version string ' +
      "(e.g. `ubuntu-2204:2023.10.1`) in the `machine: image:` field.",
    fileTypes: ['circleci'],
    pattern: /machine:\s*[\s\S]*?image:\s*["']?\S+:latest["']?/i,
  },

  {
    id: 'CIRCLE_SSH_NO_FINGERPRINT',
    severity: 'medium',
    title: 'CircleCI SSH key added without fingerprint',
    description:
      'The `add_ssh_keys` step adds all SSH keys from the project settings without specifying a ' +
      'fingerprint filter. This grants the job access to every SSH key stored in the project, ' +
      'which may include keys for unrelated systems.',
    remediation:
      'Specify the `fingerprints` list to restrict which keys are available to the job.',
    fileTypes: ['circleci'],
    // Fires when add_ssh_keys is present but no fingerprints: field follows on the next line(s)
    pattern: /add_ssh_keys:\s*(?![\s\S]*?fingerprints:)/,
  },

  // ── Bitbucket Pipelines ────────────────────────────────────────────────────

  {
    id: 'BB_PRIVILEGED_PIPELINE',
    severity: 'critical',
    title: 'Bitbucket Pipelines step runs in privileged mode',
    description:
      '`privileged: true` in a step definition gives the container near-full host access. ' +
      'A compromised build can escape isolation and compromise the runner.',
    remediation:
      'Remove `privileged: true`. Use Kaniko or Buildah for Docker builds in unprivileged containers.',
    fileTypes: ['bitbucket_pipelines'],
    pattern: /privileged:\s*true/i,
  },

  {
    id: 'BB_CURL_BASH_PIPE',
    severity: 'high',
    title: 'Bitbucket Pipelines pipes curl/wget to shell',
    description:
      'A pipeline script block fetches and immediately executes a remote script, ' +
      'bypassing integrity verification.',
    remediation: 'Download, checksum-verify, then execute in separate script lines.',
    fileTypes: ['bitbucket_pipelines'],
    pattern: /(?:curl|wget)\s+[^|#\n]+\|\s*(?:bash|sh)\b/i,
  },

  // ── Cross-platform ─────────────────────────────────────────────────────────

  {
    id: 'CI_INLINE_SECRET',
    severity: 'high',
    title: 'Credential-like value hardcoded in CI configuration',
    description:
      'An environment variable with a credential-like name (PASSWORD, SECRET, API_KEY, TOKEN, etc.) ' +
      'is assigned a non-empty literal value directly in the CI YAML. ' +
      'Hardcoded secrets in version-controlled files are routinely harvested by automated scanners.',
    remediation:
      'Store secrets in your CI platform\'s secrets manager and reference them as variable ' +
      'interpolations (e.g. ${{ secrets.MY_TOKEN }}, $MY_SECRET_VAR).',
    // Matches KEY: literal-value — excludes empty, ${{ }}, $VAR, and env-var references
    fileTypes: ['github_actions', 'gitlab_ci', 'circleci', 'bitbucket_pipelines'],
    pattern:
      /(?:PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|CREDENTIAL|PRIVATE_KEY)\s*:\s*(?!["']?\s*["']?$)(?!['"$%]?\$[\{(]?\s*\w)['"]?[A-Za-z0-9+/=_\-]{8,}['"]?/i,
  },

  {
    id: 'CI_MISSING_TIMEOUT',
    severity: 'low',
    title: 'CI job has no timeout configured',
    description:
      'Jobs without a timeout can run indefinitely if a step hangs, consuming runner minutes and ' +
      'blocking the pipeline queue.',
    remediation:
      'Set a sensible timeout (e.g. `timeout-minutes: 30` in GitHub Actions, ' +
      '`timeout: 30m` in GitLab CI) for every job.',
    fileTypes: ['github_actions', 'gitlab_ci', 'circleci', 'bitbucket_pipelines'],
    pattern: /timeout(?:-minutes|-seconds|_in_minutes)?:/i,
    negated: true,
  },
]

// ---------------------------------------------------------------------------
// detectCicdFileType
// ---------------------------------------------------------------------------

/**
 * Infers the CI/CD file type from the filename.
 *
 * Rules (first match wins):
 *   .github/workflows/<anything>.yml/.yaml   → github_actions
 *   .gitlab-ci.yml / .gitlab-ci.yaml         → gitlab_ci
 *   .circleci/config.yml / .yaml             → circleci
 *   bitbucket-pipelines.yml / .yaml          → bitbucket_pipelines
 *   everything else                          → unknown
 */
export function detectCicdFileType(filename: string): CicdFileType {
  const normalized = filename.replace(/\\/g, '/').toLowerCase()

  if (normalized.includes('.github/workflows/') && /\.ya?ml$/.test(normalized))
    return 'github_actions'
  if (/(?:^|\/)\.gitlab-ci\.ya?ml$/.test(normalized)) return 'gitlab_ci'
  if (/(?:^|\/)\.circleci\/config\.ya?ml$/.test(normalized)) return 'circleci'
  if (/(?:^|\/)bitbucket-pipelines\.ya?ml$/.test(normalized)) return 'bitbucket_pipelines'
  return 'unknown'
}

// ---------------------------------------------------------------------------
// scanCicdFile
// ---------------------------------------------------------------------------

/**
 * Runs all CI/CD security rules applicable to the detected file type
 * against the provided content string.
 *
 * @param filename  Used to infer the CI/CD platform type
 * @param content   Full text of the CI/CD configuration file
 */
export function scanCicdFile(filename: string, content: string): CicdScanResult {
  const fileType = detectCicdFileType(filename)

  // Only scan known CI/CD files
  const applicableRules =
    fileType === 'unknown' ? [] : RULES.filter((r) => r.fileTypes.includes(fileType))

  const findings: CicdFinding[] = []

  for (const rule of applicableRules) {
    const matched = rule.pattern.test(content)
    const triggered = rule.negated ? !matched : matched

    if (triggered) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        remediation: rule.remediation,
      })
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  return { filename, fileType, findings, criticalCount, highCount, mediumCount, lowCount }
}

// ---------------------------------------------------------------------------
// combineCicdResults
// ---------------------------------------------------------------------------

/**
 * Aggregates per-file scan results into a single summary.
 */
export function combineCicdResults(results: CicdScanResult[]): CicdScanSummary {
  const totalFindings = results.reduce((s, r) => s + r.findings.length, 0)
  const criticalCount = results.reduce((s, r) => s + r.criticalCount, 0)
  const highCount = results.reduce((s, r) => s + r.highCount, 0)
  const mediumCount = results.reduce((s, r) => s + r.mediumCount, 0)
  const lowCount = results.reduce((s, r) => s + r.lowCount, 0)

  const overallRisk: CicdScanSummary['overallRisk'] =
    criticalCount > 0
      ? 'critical'
      : highCount > 0
        ? 'high'
        : mediumCount > 0
          ? 'medium'
          : lowCount > 0
            ? 'low'
            : 'none'

  const summary =
    results.length === 0
      ? 'No CI/CD pipeline files scanned.'
      : totalFindings === 0
        ? `Scanned ${results.length} CI/CD file${results.length === 1 ? '' : 's'}. No misconfigurations found.`
        : `Scanned ${results.length} CI/CD file${results.length === 1 ? '' : 's'}. Found ${totalFindings} misconfiguration${totalFindings === 1 ? '' : 's'}` +
          (criticalCount > 0 ? ` (${criticalCount} critical)` : '') +
          '.'

  return {
    totalFiles: results.length,
    totalFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    overallRisk,
    fileResults: results,
    summary,
  }
}
