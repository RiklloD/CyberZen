// WS-58 — Dependency Lock File Integrity Verifier: pure computation library.
//
// Analyses the list of changed file paths from a push event for dependency
// lock-file integrity violations:
//
//   • DIRECT_LOCK_EDIT       — a pure lock file was modified without its
//     corresponding manifest also changing (same directory). Direct lock
//     edits are unusual; developers normally let tooling regenerate them.
//     Suspicious edits can silently inject malicious dependency pins.
//
//   • MIXED_NPM_LOCK_FILES   — multiple conflicting npm lock file formats
//     (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock) appear in
//     the same directory, causing non-deterministic installs.
//
//   • NPM_MANIFEST_WITHOUT_LOCK   — package.json changed with no npm lock
//     file updated. Dependencies may resolve to different versions.
//
//   • CARGO_MANIFEST_WITHOUT_LOCK — Cargo.toml changed without Cargo.lock.
//     `cargo audit` and supply-chain tools rely on the lock file.
//
//   • GO_MOD_WITHOUT_SUM          — go.mod changed without go.sum. The go.sum
//     file provides cryptographic verification of module downloads.
//
//   • PYTHON_MANIFEST_WITHOUT_LOCK — pyproject.toml or Pipfile changed without
//     a corresponding poetry.lock / Pipfile.lock update.
//
//   • RUBY_GEMFILE_WITHOUT_LOCK   — Gemfile changed without Gemfile.lock.
//     Bundler uses the lock file for reproducible gem installs.
//
// Design decisions:
//   • DIRECT_LOCK_EDIT uses same-directory matching so monorepo workspaces
//     are handled correctly (apps/api/yarn.lock ≠ apps/web/package.json).
//   • All other rules use global basename matching (presence anywhere in push).
//   • Paths inside vendor directories (node_modules, dist, build, vendor,
//     .yarn, .git, coverage, out, .next, .nuxt) are excluded.
//   • Findings are deduplicated per rule — one finding per triggered rule
//     with matchedPath (first matched file) and matchCount (total matches).
//   • Same penalty/cap scoring model as WS-53–57.
//
// Exports:
//   verifyDepLockIntegrity — runs all 7 rules, returns DepLockResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DepLockRuleId =
  | 'DIRECT_LOCK_EDIT'
  | 'MIXED_NPM_LOCK_FILES'
  | 'NPM_MANIFEST_WITHOUT_LOCK'
  | 'CARGO_MANIFEST_WITHOUT_LOCK'
  | 'GO_MOD_WITHOUT_SUM'
  | 'PYTHON_MANIFEST_WITHOUT_LOCK'
  | 'RUBY_GEMFILE_WITHOUT_LOCK'

export type DepLockSeverity = 'critical' | 'high' | 'medium' | 'low'
export type DepLockRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface DepLockFinding {
  ruleId: DepLockRuleId
  severity: DepLockSeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total number of changed files that contributed to this rule firing. */
  matchCount: number
  description: string
  recommendation: string
}

export interface DepLockResult {
  /** Number of non-vendored changed paths the scanner processed. */
  scannedPaths: number
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: DepLockRiskLevel
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule. */
  findings: DepLockFinding[]
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

function getDirname(normalised: string): string {
  const lastSlash = normalised.lastIndexOf('/')
  return lastSlash >= 0 ? normalised.slice(0, lastSlash) : ''
}

const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Lock-file / manifest databases
// ---------------------------------------------------------------------------

/** Pure lock files whose parent manifests we can identify. */
const LOCK_TO_MANIFEST_BASENAMES: ReadonlyMap<string, readonly string[]> = new Map([
  ['package-lock.json',  ['package.json']],
  ['yarn.lock',          ['package.json']],
  ['pnpm-lock.yaml',     ['package.json']],
  ['bun.lock',           ['package.json']],
  ['npm-shrinkwrap.json',['package.json']],
  ['Cargo.lock',         ['Cargo.toml']],
  ['go.sum',             ['go.mod']],
  ['Gemfile.lock',       ['Gemfile']],
  ['poetry.lock',        ['pyproject.toml']],
  ['Pipfile.lock',       ['Pipfile']],
])

const NPM_LOCK_BASENAMES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'npm-shrinkwrap.json',
])

const NPM_MANIFEST_BASENAMES    = new Set(['package.json'])
const CARGO_MANIFEST_BASENAMES  = new Set(['Cargo.toml'])
const CARGO_LOCK_BASENAMES      = new Set(['Cargo.lock'])
const GO_MOD_BASENAMES          = new Set(['go.mod'])
const GO_SUM_BASENAMES          = new Set(['go.sum'])
const PYTHON_MANIFEST_BASENAMES = new Set(['pyproject.toml', 'Pipfile'])
const PYTHON_LOCK_BASENAMES     = new Set(['poetry.lock', 'Pipfile.lock'])
const RUBY_MANIFEST_BASENAMES   = new Set(['Gemfile'])
const RUBY_LOCK_BASENAMES       = new Set(['Gemfile.lock'])

// ---------------------------------------------------------------------------
// Scoring — identical model to WS-53–57 for consistency
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<DepLockSeverity, number> = {
  critical: 30,
  high:     15,
  medium:    8,
  low:       3,
}

const PENALTY_CAP: Record<DepLockSeverity, number> = {
  critical: 75,
  high:     30,
  medium:   20,
  low:      10,
}

function toRiskLevel(score: number): DepLockRiskLevel {
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
  findings: DepLockFinding[],
  riskLevel: DepLockRiskLevel,
  scannedPaths: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${scannedPaths} changed path${scannedPaths === 1 ? '' : 's'} — all dependency lock files are consistent.`
  }
  const direct = findings.find((f) => f.ruleId === 'DIRECT_LOCK_EDIT')
  if (direct) {
    const extra = findings.length > 1 ? ` plus ${findings.length - 1} additional integrity issue${findings.length > 2 ? 's' : ''}.` : '.'
    return `${direct.matchCount} lock file${direct.matchCount === 1 ? '' : 's'} directly modified without a manifest change — possible supply-chain dependency pin injection${extra}`
  }
  const mixed = findings.find((f) => f.ruleId === 'MIXED_NPM_LOCK_FILES')
  if (mixed) {
    return `${mixed.matchCount} conflicting npm lock file format${mixed.matchCount === 1 ? '' : 's'} detected in the same push — non-deterministic dependency resolution risk.`
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return `${findings.length} dependency integrity issue${findings.length === 1 ? '' : 's'} across ${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating whether dependency lock files are consistent
 * with their manifests.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor directories (node_modules, dist, build, etc.) are
 *   excluded to avoid false-positives from vendored dependency lock files.
 * - DIRECT_LOCK_EDIT uses same-directory matching for monorepo correctness.
 * - All other rules use global basename matching across the entire push.
 * - Each rule fires at most once per scan (deduplicated).
 */
export function verifyDepLockIntegrity(filePaths: string[]): DepLockResult {
  // ── Normalise and filter ─────────────────────────────────────────────────
  const normalised: string[] = []
  /** Map normalised path → original raw path for human-readable matchedPath. */
  const rawByNorm = new Map<string, string>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue
    const norm = normalizePath(trimmed)
    if (isVendoredPath(norm)) continue
    normalised.push(norm)
    rawByNorm.set(norm, rawPath)
  }

  const pathSet = new Set(normalised)
  const findings: DepLockFinding[] = []

  // ── Rule 1: DIRECT_LOCK_EDIT (same-directory) ────────────────────────────
  // A pure lock file was changed without its manifest in the same directory.
  const directEdits: { norm: string }[] = []
  for (const norm of normalised) {
    const base = getBasename(norm)
    const manifestBasenames = LOCK_TO_MANIFEST_BASENAMES.get(base)
    if (!manifestBasenames) continue // not a tracked lock file

    const dir = getDirname(norm)
    const manifestPresent = manifestBasenames.some((mb) => {
      const manifestPath = dir ? `${dir}/${mb}` : mb
      return pathSet.has(manifestPath)
    })

    if (!manifestPresent) {
      directEdits.push({ norm })
    }
  }
  if (directEdits.length > 0) {
    const first = directEdits[0].norm
    findings.push({
      ruleId: 'DIRECT_LOCK_EDIT',
      severity: 'high',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: directEdits.length,
      description:
        'Lock file modified directly without a corresponding manifest change in the same directory — developers normally never hand-edit lock files. This pattern can silently inject malicious dependency pins into the build.',
      recommendation:
        'Investigate why the lock file was manually edited. Revert the change and regenerate the lock file using the package manager (e.g. `yarn install`, `cargo build`) to restore integrity.',
    })
  }

  // ── Rule 2: MIXED_NPM_LOCK_FILES ─────────────────────────────────────────
  // Multiple npm lock file types in the same directory.
  const npmLocksByDir = new Map<string, Set<string>>()
  for (const norm of normalised) {
    const base = getBasename(norm)
    if (!NPM_LOCK_BASENAMES.has(base)) continue
    const dir = getDirname(norm)
    let lockSet = npmLocksByDir.get(dir)
    if (!lockSet) {
      lockSet = new Set()
      npmLocksByDir.set(dir, lockSet)
    }
    lockSet.add(base)
  }

  let mixedFirstPath: string | null = null
  let mixedCount = 0
  for (const [dir, lockSet] of npmLocksByDir) {
    if (lockSet.size <= 1) continue
    const firstNorm = normalised.find(
      (n) => getDirname(n) === dir && NPM_LOCK_BASENAMES.has(getBasename(n)),
    )
    if (firstNorm && mixedFirstPath === null) {
      mixedFirstPath = rawByNorm.get(firstNorm) ?? firstNorm
    }
    mixedCount += lockSet.size
  }
  if (mixedFirstPath !== null) {
    findings.push({
      ruleId: 'MIXED_NPM_LOCK_FILES',
      severity: 'high',
      matchedPath: mixedFirstPath,
      matchCount: mixedCount,
      description:
        'Multiple conflicting npm lock file formats changed in the same directory — mixing package-lock.json, yarn.lock, pnpm-lock.yaml, and bun.lock causes non-deterministic dependency resolution and CI environment divergence.',
      recommendation:
        'Choose a single package manager for this repository and remove all other lock file formats. Enforce the canonical lock file in CI to prevent accidental format drift.',
    })
  }

  // ── Rules 3–7: manifest-without-lock (global basename matching) ───────────

  // Rule 3: NPM_MANIFEST_WITHOUT_LOCK
  const npmManifests = normalised.filter((n) => NPM_MANIFEST_BASENAMES.has(getBasename(n)))
  const npmLockPresent = normalised.some((n) => NPM_LOCK_BASENAMES.has(getBasename(n)))
  if (npmManifests.length > 0 && !npmLockPresent) {
    const first = npmManifests[0]
    findings.push({
      ruleId: 'NPM_MANIFEST_WITHOUT_LOCK',
      severity: 'medium',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: npmManifests.length,
      description:
        'package.json modified without a corresponding npm lock file update — CI environments and other developers may install different dependency versions than intended, breaking reproducibility.',
      recommendation:
        'Run `npm install`, `yarn install`, `pnpm install`, or `bun install` and commit the resulting lock file alongside the package.json change.',
    })
  }

  // Rule 4: CARGO_MANIFEST_WITHOUT_LOCK
  const cargoManifests = normalised.filter((n) => CARGO_MANIFEST_BASENAMES.has(getBasename(n)))
  const cargoLockPresent = normalised.some((n) => CARGO_LOCK_BASENAMES.has(getBasename(n)))
  if (cargoManifests.length > 0 && !cargoLockPresent) {
    const first = cargoManifests[0]
    findings.push({
      ruleId: 'CARGO_MANIFEST_WITHOUT_LOCK',
      severity: 'high',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: cargoManifests.length,
      description:
        'Cargo.toml modified without a corresponding Cargo.lock update — `cargo audit` and supply-chain security tools rely on the lock file for accurate, reproducible vulnerability matching.',
      recommendation:
        'Run `cargo build` or `cargo update` and commit Cargo.lock alongside the Cargo.toml change to maintain audit trail integrity.',
    })
  }

  // Rule 5: GO_MOD_WITHOUT_SUM
  const goMods = normalised.filter((n) => GO_MOD_BASENAMES.has(getBasename(n)))
  const goSumPresent = normalised.some((n) => GO_SUM_BASENAMES.has(getBasename(n)))
  if (goMods.length > 0 && !goSumPresent) {
    const first = goMods[0]
    findings.push({
      ruleId: 'GO_MOD_WITHOUT_SUM',
      severity: 'high',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: goMods.length,
      description:
        'go.mod modified without a corresponding go.sum update — go.sum provides cryptographic verification of module downloads and must stay in sync with go.mod to prevent module substitution attacks.',
      recommendation:
        'Run `go mod tidy` and commit go.sum alongside go.mod changes to restore module verification integrity.',
    })
  }

  // Rule 6: PYTHON_MANIFEST_WITHOUT_LOCK
  const pythonManifests = normalised.filter((n) => PYTHON_MANIFEST_BASENAMES.has(getBasename(n)))
  const pythonLockPresent = normalised.some((n) => PYTHON_LOCK_BASENAMES.has(getBasename(n)))
  if (pythonManifests.length > 0 && !pythonLockPresent) {
    const first = pythonManifests[0]
    findings.push({
      ruleId: 'PYTHON_MANIFEST_WITHOUT_LOCK',
      severity: 'medium',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: pythonManifests.length,
      description:
        'Python dependency manifest (pyproject.toml or Pipfile) modified without a corresponding lock file update — Python environments may resolve to different package versions on the next rebuild.',
      recommendation:
        'Run `poetry lock` or `pipenv lock` and commit the updated poetry.lock or Pipfile.lock alongside the manifest change.',
    })
  }

  // Rule 7: RUBY_GEMFILE_WITHOUT_LOCK
  const gemfiles = normalised.filter((n) => RUBY_MANIFEST_BASENAMES.has(getBasename(n)))
  const gemfileLockPresent = normalised.some((n) => RUBY_LOCK_BASENAMES.has(getBasename(n)))
  if (gemfiles.length > 0 && !gemfileLockPresent) {
    const first = gemfiles[0]
    findings.push({
      ruleId: 'RUBY_GEMFILE_WITHOUT_LOCK',
      severity: 'medium',
      matchedPath: rawByNorm.get(first) ?? first,
      matchCount: gemfiles.length,
      description:
        'Gemfile modified without a corresponding Gemfile.lock update — Bundler relies on the lock file for reproducible gem installs across development and production environments.',
      recommendation:
        'Run `bundle install` and commit Gemfile.lock alongside the Gemfile change.',
    })
  }

  // ── Score ────────────────────────────────────────────────────────────────
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
  const scannedPaths = normalised.length
  const summary = buildSummary(findings, riskLevel, scannedPaths)

  return {
    scannedPaths,
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
