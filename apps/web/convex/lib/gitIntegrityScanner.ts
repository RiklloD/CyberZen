// WS-56 — Git Supply Chain Integrity Scanner: pure computation library.
//
// Analyses the list of changed file paths from a push event for supply-chain
// integrity signals: system-binary shadowing, submodule manipulation, binary
// executable smuggling, Git hook tampering, dependency registry overrides,
// gitconfig modifications, unusually large pushes, and archive file commits.
//
// This is intentionally distinct from:
//   WS-30 secretScanResults     — looks for credential VALUES in file content
//   WS-54 sensitiveFileResults  — looks for known sensitive file NAMES
//   WS-55 commitMessageScans    — looks for developer intent signals in messages
//
// This scanner looks for *structural* supply-chain attack patterns in the set
// of changed file paths — signals that suggest hijacking of the build or
// developer toolchain rather than accidental credential exposure.
//
// Exports:
//   scanGitIntegrity — runs all 8 rules, returns GitIntegrityScanResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type GitIntegrityRuleId =
  | 'SHADOW_SYSTEM_BINARY'
  | 'SUBMODULE_MANIPULATION'
  | 'EXECUTABLE_BINARY_COMMITTED'
  | 'GIT_HOOK_TAMPERING'
  | 'DEPENDENCY_REGISTRY_OVERRIDE'
  | 'GITCONFIG_MODIFIED'
  | 'LARGE_BLIND_PUSH'
  | 'ARCHIVE_COMMITTED'

export type GitIntegritySeverity = 'critical' | 'high' | 'medium' | 'low'
export type GitIntegrityRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface GitIntegrityFinding {
  ruleId: GitIntegrityRuleId
  severity: GitIntegritySeverity
  /** The file path that triggered this rule (or a synthetic description for count-based rules). */
  matchedPath: string
  description: string
  recommendation: string
}

export interface GitIntegrityScanInput {
  /** Changed file paths from the push event (may be capped by caller). */
  changedFiles: string[]
  /**
   * Total number of files changed in the push before any caller-side cap.
   * Used for LARGE_BLIND_PUSH detection when changedFiles is truncated.
   */
  totalFileCount?: number
}

export interface GitIntegrityScanResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: GitIntegrityRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: GitIntegrityFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(p: string): string {
  const normalized = normalizePath(p)
  const parts = normalized.split('/')
  return parts[parts.length - 1]
}

function getExtname(filePath: string): string {
  const name = getBasename(filePath)
  const dotIdx = name.lastIndexOf('.')
  // Hidden files like ".npmrc" have leading dot only — treat as no extension
  if (dotIdx <= 0) return ''
  return name.slice(dotIdx).toLowerCase()
}


// ---------------------------------------------------------------------------
// Rule predicates
// ---------------------------------------------------------------------------

/**
 * SHADOW_SYSTEM_BINARY — critical
 * Files at root or bin/usr-bin level whose name matches a common system binary
 * with no file extension. This is the PATH hijack / toolchain-poisoning signal.
 */
const SYSTEM_BINARIES = new Set([
  // Runtimes
  'node', 'python', 'python3', 'perl', 'ruby', 'java', 'javac',
  // Package managers
  'pip', 'pip3', 'npm', 'npx', 'yarn', 'pnpm', 'cargo', 'gem',
  // Shells
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh',
  // Network tools
  'curl', 'wget',
  // VCS
  'git',
  // Privilege tools
  'sudo', 'su', 'doas',
  // Build/language tools
  'go', 'rustc', 'make', 'cmake', 'cc', 'gcc', 'clang',
  // Cloud / infra
  'docker', 'kubectl', 'helm', 'terraform', 'ansible',
])

function isShadowSystemBinary(filePath: string): boolean {
  const normalized = normalizePath(filePath)
  const parts = normalized.split('/')
  const filename = parts[parts.length - 1]
  const dirs = parts.slice(0, -1)

  // Must have no extension (extension-less executables only)
  if (filename.lastIndexOf('.') !== -1) return false

  // Must be at root, bin/, or usr/bin/
  const inRootOrBin =
    dirs.length === 0 ||
    (dirs.length === 1 && dirs[0] === 'bin') ||
    (dirs.length === 2 && dirs[0] === 'usr' && dirs[1] === 'bin')

  if (!inRootOrBin) return false

  return SYSTEM_BINARIES.has(filename.toLowerCase())
}

/**
 * SUBMODULE_MANIPULATION — high
 * Modification of .gitmodules introduces or alters third-party submodule URLs —
 * a classic supply-chain injection vector.
 */
function isSubmoduleFile(filePath: string): boolean {
  return getBasename(filePath).toLowerCase() === '.gitmodules'
}

/**
 * EXECUTABLE_BINARY_COMMITTED — high
 * Compiled or platform-specific binary files committed to source control.
 * Binaries cannot be diffed and may conceal malicious payloads.
 */
const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.bin', '.elf',
  '.com', '.scr', '.pyd', '.ocx',
])

function isExecutableBinary(filePath: string): boolean {
  const ext = getExtname(filePath)
  return ext !== '' && BINARY_EXTENSIONS.has(ext)
}

/**
 * GIT_HOOK_TAMPERING — high
 * Changes to Git hook scripts (pre-commit, pre-push, etc.) or hook manager
 * directories (.husky, .git-hooks). Malicious hooks can intercept commits,
 * steal credentials, or silently bypass pre-push security checks.
 */
const HOOK_SCRIPT_NAMES = new Set([
  'pre-commit', 'pre-push', 'prepare-commit-msg', 'commit-msg',
  'post-commit', 'post-checkout', 'post-merge', 'pre-rebase',
  'pre-receive', 'update', 'post-receive', 'post-update',
  'pre-auto-gc', 'post-rewrite', 'sendemail-validate',
])

const HOOK_DIRECTORIES = new Set([
  '.husky', '.git-hooks', 'git-hooks', '.hooks',
])

function isGitHookFile(filePath: string): boolean {
  const normalized = normalizePath(filePath)
  const parts = normalized.split('/')
  const filename = parts[parts.length - 1].toLowerCase()
  const dirs = parts.slice(0, -1)

  // Root-level hook script (extension-less name matches a known hook)
  if (dirs.length === 0 && HOOK_SCRIPT_NAMES.has(filename)) return true

  // File inside a hook manager directory
  if (dirs.length >= 1 && HOOK_DIRECTORIES.has(dirs[0].toLowerCase())) return true

  return false
}

/**
 * DEPENDENCY_REGISTRY_OVERRIDE — medium
 * Modification of dependency manager configuration files that control which
 * registry packages are downloaded from. A changed registry URL can redirect
 * all dependency downloads to a malicious server (dependency confusion attack).
 */
const REGISTRY_CONFIG_NAMES = new Set([
  '.npmrc', '.yarnrc', '.yarnrc.yml', '.yarnrc.yaml',
  '.pypirc', 'pip.conf', 'pip.ini',
  '.gemrc',
  '.nuget', 'nuget.config',
  '.bun', 'bunfig.toml',
])

function isDependencyRegistryFile(filePath: string): boolean {
  return REGISTRY_CONFIG_NAMES.has(getBasename(filePath).toLowerCase())
}

/**
 * GITCONFIG_MODIFIED — medium
 * A .gitconfig file was modified. Attackers may inject credential helpers,
 * alter URL rewrites, change commit signing settings, or redirect remote URLs.
 */
function isGitconfigFile(filePath: string): boolean {
  const name = getBasename(filePath).toLowerCase()
  return name === '.gitconfig' || name.endsWith('.gitconfig')
}

/**
 * LARGE_BLIND_PUSH — medium
 * A push containing more than 200 changed files is difficult to review
 * meaningfully and may be used to hide malicious changes in a sea of noise.
 */
const LARGE_PUSH_THRESHOLD = 200

/**
 * ARCHIVE_COMMITTED — medium
 * Archive files (zip, tar, jar, whl, etc.) committed to source control may
 * conceal malicious payloads, hidden binaries, or sensitive data dumps.
 */
const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.tgz', '.zst',
  '.jar', '.war', '.ear', '.aar',
  '.whl', '.egg',
  '.gem', '.nupkg',
  '.apk', '.ipa',
])

function isArchiveFile(filePath: string): boolean {
  const name = getBasename(filePath).toLowerCase()
  // Handle compound extensions like .tar.gz before extname check
  if (
    name.endsWith('.tar.gz') ||
    name.endsWith('.tar.bz2') ||
    name.endsWith('.tar.xz') ||
    name.endsWith('.tar.zst')
  )
    return true
  const ext = getExtname(filePath)
  return ext !== '' && ARCHIVE_EXTENSIONS.has(ext)
}

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53, WS-54, WS-55 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<GitIntegritySeverity, number> = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 3,
}

const PENALTY_CAP: Record<GitIntegritySeverity, number> = {
  critical: 75,
  high: 30,
  medium: 20,
  low: 10,
}

function toRiskLevel(score: number): GitIntegrityRiskLevel {
  if (score === 0) return 'none'
  if (score < 25) return 'low'
  if (score < 50) return 'medium'
  if (score < 75) return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function buildSummary(
  findings: GitIntegrityFinding[],
  riskLevel: GitIntegrityRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no repository integrity signals detected.`
  }
  const criticals = findings.filter((f) => f.severity === 'critical')
  const highs = findings.filter((f) => f.severity === 'high')
  if (criticals.length > 0) {
    return `Critical: ${criticals.length} finding${criticals.length === 1 ? '' : 's'} indicate a potential supply-chain attack (PATH hijack or binary smuggling). Immediate investigation required.`
  }
  if (highs.length > 0) {
    return `High-risk: ${findings.length} repository integrity signal${findings.length === 1 ? '' : 's'} detected across ${fileCount} changed file${fileCount === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  }
  return `${findings.length} repository integrity signal${findings.length === 1 ? '' : 's'} detected across ${fileCount} changed file${fileCount === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Scan the changed file paths from a push event for supply-chain integrity
 * signals. Returns a risk-scored result with per-file findings and
 * actionable recommendations.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Each path is tested against all 8 rules independently.
 * - LARGE_BLIND_PUSH fires at most once per scan (count-based, not per-file).
 * - Multiple matches on different files for the same rule each produce their
 *   own finding (each commit is an independent risk signal).
 */
export function scanGitIntegrity(input: GitIntegrityScanInput): GitIntegrityScanResult {
  const findings: GitIntegrityFinding[] = []
  const { changedFiles, totalFileCount } = input

  // The effective count for LARGE_BLIND_PUSH uses the uncapped total if known
  const effectiveCount = Math.max(changedFiles.length, totalFileCount ?? 0)

  for (const rawPath of changedFiles) {
    const filePath = normalizePath(rawPath).trim()
    if (!filePath) continue

    // ── SHADOW_SYSTEM_BINARY (critical) ──────────────────────────────────
    if (isShadowSystemBinary(filePath)) {
      findings.push({
        ruleId: 'SHADOW_SYSTEM_BINARY',
        severity: 'critical',
        matchedPath: filePath,
        description:
          'A file with the same name as a common system binary was committed at the root or bin/ level. This is a classic PATH hijack attack: if the repository is checked out and the directory is in PATH, the malicious binary intercepts all calls to the real tool.',
        recommendation:
          'Remove this file immediately and audit all developer machines that cloned this repository. Verify that no developer executed the binary. If the file is legitimate, rename it with a unique prefix and document its purpose.',
      })
    }

    // ── SUBMODULE_MANIPULATION (high) ────────────────────────────────────
    if (isSubmoduleFile(filePath)) {
      findings.push({
        ruleId: 'SUBMODULE_MANIPULATION',
        severity: 'high',
        matchedPath: filePath,
        description:
          'The .gitmodules file was modified, potentially adding a new submodule or changing an existing submodule URL to a malicious repository. Submodule attacks are a well-documented supply-chain vector.',
        recommendation:
          'Review all submodule URL changes carefully. Verify each URL points to a trusted, expected repository. Pin submodules to specific commit SHAs rather than branch tips to prevent future tampering.',
      })
    }

    // ── EXECUTABLE_BINARY_COMMITTED (high) ───────────────────────────────
    if (isExecutableBinary(filePath)) {
      findings.push({
        ruleId: 'EXECUTABLE_BINARY_COMMITTED',
        severity: 'high',
        matchedPath: filePath,
        description:
          'A binary executable file was committed to the repository. Binary files cannot be diffed in meaningful code review and may conceal backdoors, malware, or stolen data. This is a common technique for hiding malicious payloads.',
        recommendation:
          'Remove binary executables from source control and use a package registry, artifact store, or release asset for distributing compiled binaries. Scan the committed file with antivirus/EDR tools before any use.',
      })
    }

    // ── GIT_HOOK_TAMPERING (high) ─────────────────────────────────────────
    if (isGitHookFile(filePath)) {
      findings.push({
        ruleId: 'GIT_HOOK_TAMPERING',
        severity: 'high',
        matchedPath: filePath,
        description:
          'A Git hook script was added or modified. Malicious hooks can intercept commits to steal credentials, modify code before it is committed, silently bypass pre-push security checks, or install persistence mechanisms on developer machines.',
        recommendation:
          'Carefully review the hook changes for credential theft, code modification, or security bypass logic. Consider signing hook scripts or enforcing hook integrity through your CI/CD pipeline rather than relying on local hooks.',
      })
    }

    // ── DEPENDENCY_REGISTRY_OVERRIDE (medium) ────────────────────────────
    if (isDependencyRegistryFile(filePath)) {
      findings.push({
        ruleId: 'DEPENDENCY_REGISTRY_OVERRIDE',
        severity: 'medium',
        matchedPath: filePath,
        description:
          'A dependency manager registry configuration file was modified. Attackers use this to redirect package downloads to a malicious private registry (dependency confusion attack) or to install a compromised dependency version.',
        recommendation:
          'Verify that all registry URLs in this file point to your trusted internal or public registry. Confirm no unknown or external registries were added. Review with your package management team before merging.',
      })
    }

    // ── GITCONFIG_MODIFIED (medium) ──────────────────────────────────────
    if (isGitconfigFile(filePath)) {
      findings.push({
        ruleId: 'GITCONFIG_MODIFIED',
        severity: 'medium',
        matchedPath: filePath,
        description:
          'A Git configuration file was added or modified. Attackers may inject malicious credential helpers, alter URL rewrites to redirect pushes to attacker-controlled remotes, disable commit signing, or change hook paths.',
        recommendation:
          'Audit all changes in this gitconfig for credential helper injections, URL rewrite rules, hook path changes, or remote URL alterations. Do not merge if any unexpected configuration is present.',
      })
    }

    // ── ARCHIVE_COMMITTED (medium) ───────────────────────────────────────
    if (isArchiveFile(filePath)) {
      findings.push({
        ruleId: 'ARCHIVE_COMMITTED',
        severity: 'medium',
        matchedPath: filePath,
        description:
          'An archive file was committed to the repository. Archives can conceal malicious binaries, hidden scripts, sensitive data dumps, or obfuscated payloads that bypass file-level security scanning.',
        recommendation:
          'Extract and inspect the archive contents. Verify the content is expected and scan for malware. Consider using a package registry or release asset host instead of committing archives to source control.',
      })
    }
  }

  // ── LARGE_BLIND_PUSH (medium) — fires at most once, count-based ──────
  if (effectiveCount > LARGE_PUSH_THRESHOLD) {
    findings.push({
      ruleId: 'LARGE_BLIND_PUSH',
      severity: 'medium',
      matchedPath: `(push: ${effectiveCount} files changed)`,
      description: `An unusually large push of ${effectiveCount} changed files was made in a single push event. Large diffs are difficult to review meaningfully and are sometimes used to conceal malicious changes in a sea of noise.`,
      recommendation:
        'Split large changes into smaller, focused pull requests. Enable automated diff-size limits in branch protection rules. Require senior engineer review for pushes exceeding 200 files.',
    })
  }

  // ---------------------------------------------------------------------------
  // Scoring
  // ---------------------------------------------------------------------------

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
  const summary = buildSummary(findings, riskLevel, effectiveCount)

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
