// WS-59 — Build Toolchain Integrity Scanner: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to build toolchain configuration files.  Build toolchain files are uniquely
// high-value attack targets because a single malicious change can silently
// corrupt every artifact the pipeline produces — long before any application
// security scanner (secrets, hotspot code, IaC) would notice.
//
// Covered rule groups:
//
//   MAKEFILE_MODIFIED        — Makefiles and task-runner files
//                              (Makefile, GNUmakefile, Taskfile.yml, Justfile)
//
//   SHELL_BUILD_SCRIPT       — Shell scripts used in build/install phases
//                              (build.sh, install.sh, setup.sh, configure.sh,
//                               bootstrap.sh, prebuild.sh, postbuild.sh,
//                               compile.sh, package.sh, publish.sh, etc.)
//
//   JS_BUNDLER_CONFIG        — JavaScript bundler configs that transform
//                              source code at build time (webpack, rollup,
//                              vite, esbuild, parcel, turbo, nx)
//
//   CODE_TRANSFORM_CONFIG    — Source-code transpiler configs (babel, swc)
//                              that can inject arbitrary transforms
//
//   JAVA_BUILD_CONFIG        — Gradle / Maven build descriptors
//
//   PYTHON_SETUP_MODIFIED    — Python package build configs (setup.py,
//                              setup.cfg, MANIFEST.in)
//
//   RUBY_BUILD_CONFIG        — Ruby gem specification files (*.gemspec)
//
// This scanner intentionally does NOT overlap with:
//   WS-33 iacScanResults     — covers Dockerfile, Terraform, Kubernetes, Docker Compose
//   WS-35 cicdScanResults    — covers GitHub Actions, GitLab CI, CircleCI, etc.
//   WS-58 depLockVerifyResults — covers dependency manifest/lock file integrity
//
// Design decisions:
//   • Path-segment / basename analysis only — no content reading.
//   • Paths inside vendor directories are excluded.
//   • Same penalty/cap scoring model as WS-53–58.
//   • Dedup-per-rule: one finding per triggered rule with matchedPath + matchCount.
//
// Exports:
//   scanBuildConfigChanges — runs all 7 rules, returns BuildConfigScanResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BuildConfigRuleId =
  | 'MAKEFILE_MODIFIED'
  | 'SHELL_BUILD_SCRIPT'
  | 'JS_BUNDLER_CONFIG'
  | 'CODE_TRANSFORM_CONFIG'
  | 'JAVA_BUILD_CONFIG'
  | 'PYTHON_SETUP_MODIFIED'
  | 'RUBY_BUILD_CONFIG'

export type BuildConfigSeverity = 'critical' | 'high' | 'medium' | 'low'
export type BuildConfigRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface BuildConfigFinding {
  ruleId: BuildConfigRuleId
  severity: BuildConfigSeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total number of changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface BuildConfigScanResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: BuildConfigRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: BuildConfigFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(normalised: string): string {
  const parts = normalised.split('/')
  return parts[parts.length - 1] ?? ''
}

const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

/** Strip the last extension from a basename (e.g. "build.sh" → "build"). */
function stripExtension(base: string): string {
  const dotIdx = base.lastIndexOf('.')
  // Don't strip if the dot is the first character (hidden files like ".babelrc")
  return dotIdx > 0 ? base.slice(0, dotIdx) : base
}

/** Return the extension (without the dot) of a basename, lowercased. */
function getExtension(base: string): string {
  const dotIdx = base.lastIndexOf('.')
  return dotIdx > 0 ? base.slice(dotIdx + 1).toLowerCase() : ''
}

// ---------------------------------------------------------------------------
// Rule matching helpers
// ---------------------------------------------------------------------------

// ── MAKEFILE_MODIFIED ────────────────────────────────────────────────────

const MAKEFILE_BASENAMES = new Set([
  'Makefile', 'makefile', 'GNUmakefile', 'GNUMakefile',
  'Makefile.am', 'Makefile.in', 'Makefile.dist',
  'Taskfile.yml', 'Taskfile.yaml',
  'Justfile', 'justfile',
])

function isMakefileMatch(normalised: string): boolean {
  return MAKEFILE_BASENAMES.has(getBasename(normalised))
}

// ── SHELL_BUILD_SCRIPT ───────────────────────────────────────────────────

const SHELL_EXTENSIONS = new Set(['sh', 'bash', 'zsh', 'ksh'])

const BUILD_SCRIPT_STEMS = new Set([
  'build', 'install', 'setup', 'configure', 'bootstrap',
  'prebuild', 'postbuild', 'preinstall', 'postinstall',
  'compile', 'package', 'bundle', 'publish', 'release',
  'prepare', 'prepack', 'postpack', 'make',
  'bootstrap_build', 'build_release', 'release_build',
])

function isShellBuildScript(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const ext = getExtension(base)
  if (!SHELL_EXTENSIONS.has(ext)) return false
  const stem = stripExtension(base)
  return BUILD_SCRIPT_STEMS.has(stem)
}

// ── JS_BUNDLER_CONFIG ────────────────────────────────────────────────────

// Exact-match basenames for single-name bundler config files
const BUNDLER_EXACT_BASENAMES = new Set([
  'turbo.json', 'nx.json',
  'parcel.config.js', 'parcel.config.cjs', 'parcel.config.mjs',
  '.parcelrc',
])

// Bundler config prefixes (e.g. "webpack.config" matches webpack.config.js, .ts, .mjs, …)
const BUNDLER_CONFIG_PREFIXES = [
  'webpack.config',
  'rollup.config',
  'vite.config',
  'esbuild.config',
  'rspack.config',
  'farm.config',
  'snowpack.config',
] as const

function isJsBundlerConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (BUNDLER_EXACT_BASENAMES.has(base)) return true
  return BUNDLER_CONFIG_PREFIXES.some(
    (prefix) => base === prefix || base.startsWith(`${prefix}.`),
  )
}

// ── CODE_TRANSFORM_CONFIG ────────────────────────────────────────────────

const TRANSFORM_EXACT_BASENAMES = new Set([
  '.babelrc',
  '.swcrc',
])

// Config file prefixes (matches babel.config.js, babel.config.ts, swc.config.js, …)
const TRANSFORM_CONFIG_PREFIXES = [
  'babel.config',
  'swc.config',
] as const

// Basenames that start with .babelrc (e.g. .babelrc.js, .babelrc.json)
function isCodeTransformConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  if (TRANSFORM_EXACT_BASENAMES.has(base)) return true
  if (base.startsWith('.babelrc.') || base.startsWith('.swcrc.')) return true
  return TRANSFORM_CONFIG_PREFIXES.some(
    (prefix) => base === prefix || base.startsWith(`${prefix}.`),
  )
}

// ── JAVA_BUILD_CONFIG ────────────────────────────────────────────────────

const JAVA_BUILD_EXACT_BASENAMES = new Set([
  'build.gradle', 'build.gradle.kts',
  'settings.gradle', 'settings.gradle.kts',
  'pom.xml',
  'gradle.properties',
])

function isJavaBuildConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  return JAVA_BUILD_EXACT_BASENAMES.has(base)
}

// ── PYTHON_SETUP_MODIFIED ────────────────────────────────────────────────

const PYTHON_SETUP_BASENAMES = new Set([
  'setup.py', 'setup.cfg', 'MANIFEST.in',
])

function isPythonSetup(normalised: string): boolean {
  return PYTHON_SETUP_BASENAMES.has(getBasename(normalised))
}

// ── RUBY_BUILD_CONFIG ────────────────────────────────────────────────────

function isRubyGemspec(normalised: string): boolean {
  return getBasename(normalised).toLowerCase().endsWith('.gemspec')
}

// ---------------------------------------------------------------------------
// Rule definitions (ordered for consistent output)
// ---------------------------------------------------------------------------

interface BuildConfigRule {
  id: BuildConfigRuleId
  severity: BuildConfigSeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

const RULES: readonly BuildConfigRule[] = [
  {
    id: 'MAKEFILE_MODIFIED',
    severity: 'high',
    description:
      'Makefile or task-runner configuration modified — these files execute arbitrary shell commands during the build process. A malicious change can inject backdoors into every artifact the CI pipeline produces.',
    recommendation:
      'Review the diff carefully for new shell command invocations, remote downloads (curl/wget), or unexpected variable substitutions. Ensure the change went through mandatory code review.',
    matches: isMakefileMatch,
  },
  {
    id: 'SHELL_BUILD_SCRIPT',
    severity: 'high',
    description:
      'Build or install shell script modified — shell scripts with build-phase names (build.sh, install.sh, setup.sh, etc.) run automatically during CI and package installation and can execute arbitrary commands.',
    recommendation:
      'Audit the script diff for new external downloads, obfuscated commands, or injection vectors. Verify the change was authored by a trusted contributor and approved in code review.',
    matches: isShellBuildScript,
  },
  {
    id: 'JS_BUNDLER_CONFIG',
    severity: 'high',
    description:
      'JavaScript bundler configuration modified (webpack, rollup, vite, esbuild, turbo, etc.) — bundler plugins and loaders execute arbitrary code during the build and can rewrite, replace, or proxy any imported module.',
    recommendation:
      'Inspect new plugins, loaders, and resolve.alias entries for module substitution or unexpected network calls. Validate that all new plugins come from trusted, pinned sources.',
    matches: isJsBundlerConfig,
  },
  {
    id: 'CODE_TRANSFORM_CONFIG',
    severity: 'high',
    description:
      'Babel or SWC transpiler configuration modified — transpiler plugins execute code transforms on every source file and can inject malicious code paths or strip security-sensitive assertions during compilation.',
    recommendation:
      'Audit added or modified plugins and presets. Confirm each plugin is pinned to a known-good version and comes from a trusted publisher. Review transform outputs for unexpected mutations.',
    matches: isCodeTransformConfig,
  },
  {
    id: 'JAVA_BUILD_CONFIG',
    severity: 'medium',
    description:
      'Gradle or Maven build descriptor modified (build.gradle, pom.xml, settings.gradle, etc.) — build plugins and repositories defined here run code during compilation and can introduce malicious dependencies or build-time hooks.',
    recommendation:
      'Verify any new plugins or repositories. Ensure plugin versions are pinned and sourced from trusted repositories (Maven Central, Google Maven). Check for new lifecycle hooks or exec-plugin invocations.',
    matches: isJavaBuildConfig,
  },
  {
    id: 'PYTHON_SETUP_MODIFIED',
    severity: 'medium',
    description:
      'Python package build configuration modified (setup.py, setup.cfg, MANIFEST.in) — setup.py is executed directly by pip during package installation and can run arbitrary code on the installing machine.',
    recommendation:
      'Review setup.py carefully for network calls or file writes in the top-level scope or in custom command classes. Prefer declarative pyproject.toml over executable setup.py.',
    matches: isPythonSetup,
  },
  {
    id: 'RUBY_BUILD_CONFIG',
    severity: 'medium',
    description:
      'Ruby gem specification file (*.gemspec) modified — gem specifications define build hooks and can include extensions that compile and run native C code during gem installation.',
    recommendation:
      'Audit for new extensions, `post_install_message`, or file patterns that expose unexpected paths. Validate the gemspec version bump is consistent with the actual change scope.',
    matches: isRubyGemspec,
  },
]

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–58 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<BuildConfigSeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
  low:       3,
}

const PENALTY_CAP: Record<BuildConfigSeverity, number> = {
  critical: 75,
  high:     30,
  medium:   20,
  low:      10,
}

function toRiskLevel(score: number): BuildConfigRiskLevel {
  if (score === 0)  return 'none'
  if (score < 25)   return 'low'
  if (score < 50)   return 'medium'
  if (score < 75)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function buildSummary(
  findings: BuildConfigFinding[],
  riskLevel: BuildConfigRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no build toolchain configuration changes detected.`
  }
  const highOrAbove = findings.filter((f) => f.severity === 'high' || f.severity === 'critical')
  if (highOrAbove.length > 0) {
    const labels = highOrAbove.map((f) => {
      const map: Record<string, string> = {
        MAKEFILE_MODIFIED: 'Makefile',
        SHELL_BUILD_SCRIPT: 'build script',
        JS_BUNDLER_CONFIG: 'bundler config',
        CODE_TRANSFORM_CONFIG: 'transpiler config',
      }
      return map[f.ruleId] ?? f.ruleId
    })
    const unique = [...new Set(labels)]
    const joined = unique.length <= 2
      ? unique.join(' and ')
      : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return `${findings.length} build toolchain file${findings.length === 1 ? '' : 's'} modified including ${joined} — mandatory security review required before merge.`
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return `${findings.length} build configuration change${findings.length === 1 ? '' : 's'} across ${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which build toolchain configuration files
 * were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor directories (node_modules, dist, build, vendor, etc.)
 *   are excluded to avoid false-positives from vendored build configs.
 * - Each rule fires at most once per scan (deduplicated). The finding records
 *   the first matched path and a count of all paths that matched.
 */
export function scanBuildConfigChanges(filePaths: string[]): BuildConfigScanResult {
  // Per-rule accumulator: first matched path + count
  const ruleAccumulator = new Map<BuildConfigRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of RULES) {
      if (!rule.matches(normalised)) continue

      const acc = ruleAccumulator.get(rule.id)
      if (acc) {
        acc.count++
      } else {
        ruleAccumulator.set(rule.id, { firstPath: rawPath, count: 1 })
      }
    }
  }

  // Build findings in rule definition order for consistent output
  const findings: BuildConfigFinding[] = []
  for (const rule of RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId: rule.id,
      severity: rule.severity,
      matchedPath: acc.firstPath,
      matchCount: acc.count,
      description: rule.description,
      recommendation: rule.recommendation,
    })
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount     = findings.filter((f) => f.severity === 'high').length
  const mediumCount   = findings.filter((f) => f.severity === 'medium').length
  const lowCount      = findings.filter((f) => f.severity === 'low').length

  const rawScore =
    Math.min(PENALTY_CAP.critical, criticalCount * PENALTY_PER.critical) +
    Math.min(PENALTY_CAP.high,     highCount     * PENALTY_PER.high) +
    Math.min(PENALTY_CAP.medium,   mediumCount   * PENALTY_PER.medium) +
    Math.min(PENALTY_CAP.low,      lowCount      * PENALTY_PER.low)

  const riskScore = Math.min(100, rawScore)
  const riskLevel = toRiskLevel(riskScore)
  const summary   = buildSummary(findings, riskLevel, filePaths.length)

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
