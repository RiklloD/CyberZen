// Pure, Convex-free functions for generating pull-request proposal content.
// Keeping this layer dependency-free makes it easy to unit-test with Vitest
// and re-use across multiple Convex entry points without circular imports.

export type FixType = 'version_bump' | 'patch' | 'config_change' | 'manual'

export type PrProposalInput = {
  repositoryName: string
  findingTitle: string
  findingSummary: string
  findingSeverity: string
  affectedPackages: string[]
  disclosureRef: string | undefined
  packageName: string | undefined
  packageEcosystem: string | undefined
  currentVersion: string | undefined
  fixVersion: string | undefined
}

export type PrProposalContent = {
  proposedBranch: string
  prTitle: string
  prBody: string
  fixType: FixType
  fixSummary: string
  targetPackage: string | undefined
  targetEcosystem: string | undefined
  currentVersion: string | undefined
  fixVersion: string | undefined
}

// ---------------------------------------------------------------------------
// Branch naming
// ---------------------------------------------------------------------------

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 36)
}

// Deterministic-ish short token derived from the inputs so that two proposals
// for the same package+version in the same repo get the same branch name while
// still being unique enough to avoid cross-repo collisions.
function shortToken(seed: string): string {
  let h = 5381
  for (let i = 0; i < seed.length; i++) {
    h = ((h << 5) + h + seed.charCodeAt(i)) >>> 0
  }
  return h.toString(36).slice(0, 6)
}

export function generateProposedBranch(
  repositoryName: string,
  packageName: string | undefined,
  fixVersion: string | undefined,
): string {
  const token = shortToken(`${repositoryName}:${packageName ?? ''}:${fixVersion ?? ''}`)

  if (!packageName) {
    const repoSlug = slugify(repositoryName)
    return `sentinel/security-fix-${repoSlug}-${token}`
  }

  const pkgSlug = slugify(packageName)
  const versionSlug = fixVersion ? `-${slugify(fixVersion)}` : ''

  return `sentinel/fix-${pkgSlug}${versionSlug}-${token}`
}

// ---------------------------------------------------------------------------
// PR title
// ---------------------------------------------------------------------------

export function generatePrTitle(
  packageName: string | undefined,
  currentVersion: string | undefined,
  fixVersion: string | undefined,
): string {
  if (!packageName) {
    return 'fix(security): resolve Sentinel security finding'
  }

  if (currentVersion && fixVersion) {
    return `fix(deps): bump ${packageName} from ${currentVersion} to ${fixVersion}`
  }

  if (fixVersion) {
    return `fix(deps): upgrade ${packageName} to ${fixVersion}`
  }

  return `fix(security): patch ${packageName} vulnerability`
}

// ---------------------------------------------------------------------------
// PR body
// ---------------------------------------------------------------------------

export function generatePrBody(input: PrProposalInput): string {
  const {
    findingTitle,
    findingSeverity,
    findingSummary,
    packageName,
    packageEcosystem,
    currentVersion,
    fixVersion,
    disclosureRef,
    affectedPackages,
  } = input

  const lines: string[] = []

  lines.push('## Security Fix')
  lines.push('')
  lines.push(
    'This pull request was automatically proposed by **Sentinel** to address a confirmed security finding.',
  )
  lines.push('')

  lines.push('### Finding')
  lines.push('')
  lines.push(`| Field | Value |`)
  lines.push(`|---|---|`)
  lines.push(`| Title | ${findingTitle} |`)
  lines.push(`| Severity | \`${findingSeverity}\` |`)
  lines.push('')
  lines.push(findingSummary)
  lines.push('')

  if (packageName) {
    lines.push('### Proposed Fix')
    lines.push('')

    if (currentVersion && fixVersion) {
      lines.push(
        `Bumps \`${packageName}\` from **${currentVersion}** → **${fixVersion}**.`,
      )
    } else if (fixVersion) {
      lines.push(`Upgrades \`${packageName}\` to **${fixVersion}** (safe version).`)
    } else {
      lines.push(`Updates \`${packageName}\` to the current safe release.`)
    }

    if (packageEcosystem) {
      lines.push(`Ecosystem: \`${packageEcosystem}\``)
    }

    lines.push('')
  }

  const displayPackages = affectedPackages.slice(0, 10)

  if (displayPackages.length > 0) {
    lines.push('### Affected Packages')
    lines.push('')
    for (const pkg of displayPackages) {
      lines.push(`- \`${pkg}\``)
    }
    lines.push('')
  }

  if (disclosureRef) {
    lines.push('### References')
    lines.push('')
    lines.push(`- Advisory: \`${disclosureRef}\``)
    lines.push('')
  }

  lines.push('---')
  lines.push(
    '> **Review required before merging.** This PR was auto-generated from security telemetry — verify the fix is correct for your environment before approving.',
  )
  lines.push('')
  lines.push('*Generated by Sentinel — autonomous security platform.*')

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Fix type classification
// ---------------------------------------------------------------------------

export function detectFixType(
  packageName: string | undefined,
  fixVersion: string | undefined,
): FixType {
  if (packageName && fixVersion) {
    return 'version_bump'
  }

  if (packageName) {
    return 'patch'
  }

  return 'manual'
}

// ---------------------------------------------------------------------------
// Top-level composer
// ---------------------------------------------------------------------------

export function buildPrProposalContent(input: PrProposalInput): PrProposalContent {
  const fixType = detectFixType(input.packageName, input.fixVersion)

  const fixSummary =
    input.packageName && input.fixVersion
      ? `Bump ${input.packageName} from ${input.currentVersion ?? 'current'} to ${input.fixVersion}`
      : input.packageName
        ? `Patch ${input.packageName} vulnerability`
        : `Manual remediation required for: ${input.findingTitle}`

  return {
    proposedBranch: generateProposedBranch(
      input.repositoryName,
      input.packageName,
      input.fixVersion,
    ),
    prTitle: generatePrTitle(input.packageName, input.currentVersion, input.fixVersion),
    prBody: generatePrBody(input),
    fixType,
    fixSummary,
    targetPackage: input.packageName,
    targetEcosystem: input.packageEcosystem,
    currentVersion: input.currentVersion,
    fixVersion: input.fixVersion,
  }
}

// ---------------------------------------------------------------------------
// Manifest file patching (pure, no I/O — for version-bump PR generation)
// ---------------------------------------------------------------------------

/**
 * Ordered list of candidate manifest paths per ecosystem.
 * The first path that exists in the repository and contains the target package
 * will be edited. Paths are relative to the repository root.
 */
export const ECOSYSTEM_MANIFEST_PATHS: Record<string, string[]> = {
  pypi: [
    'requirements.txt',
    'requirements/base.txt',
    'requirements/common.txt',
    'requirements/prod.txt',
    'pyproject.toml',
    'Pipfile',
  ],
  npm: ['package.json'],
  yarn: ['package.json'],
  pnpm: ['package.json'],
  bun: ['package.json'],
}

/** Normalize a PyPI package name: lowercase, collapse [-_.] into '-'. */
function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

/**
 * Apply a security version pin to a pip-format requirements file.
 *
 * Strategy: always pins to `==fixVersion` regardless of the original specifier.
 * This gives the most explicit security guarantee for reproducible environments.
 *
 * Preserves: extras (`[crypto]`), environment markers (`; python_version…`),
 * and trailing inline comments (`# pinned for CVE-…`).
 *
 * Returns null when the package is not found in the file.
 */
export function patchRequirementsTxt(
  content: string,
  packageName: string,
  fixVersion: string,
): string | null {
  const target = normalizePypiName(packageName)
  const lines = content.split('\n')
  let changed = false

  const updated = lines.map((line) => {
    const trimmed = line.trim()
    // Skip blank lines, comment-only lines, and pip option flags (-r, --index-url, …)
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) return line

    // Isolate any trailing inline comment before parsing the requirement.
    const hashIdx = trimmed.indexOf('#')
    const reqPart = hashIdx >= 0 ? trimmed.slice(0, hashIdx).trim() : trimmed
    const trailingComment = hashIdx >= 0 ? `  ${trimmed.slice(hashIdx)}` : ''

    // PEP 508: name [extras] [specifier] [; env-markers]
    const match = reqPart.match(
      /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?([^;]*)?(;.*)?$/,
    )
    if (!match) return line

    const [, pkgName, extras, , markers] = match
    if (normalizePypiName(pkgName) !== target) return line

    changed = true
    const extrasStr = extras ?? ''
    const markersStr = markers ? ` ${markers.trim()}` : ''
    return `${pkgName}${extrasStr}==${fixVersion}${markersStr}${trailingComment}`
  })

  return changed ? updated.join('\n') : null
}

/**
 * Apply a security version floor to a pyproject.toml or Pipfile.
 *
 * Strategy: uses `>=fixVersion` — idiomatic for both PEP 517 and Poetry since
 * pinning to `==` in a resolver-managed file can break transitive constraints.
 *
 * Handles three formats:
 *   1. Poetry simple key-value:    `pyjwt = "^2.10.1"`
 *   2. Poetry inline table:        `pyjwt = {version = "^2.10.1", extras = [...]}`
 *   3. PEP 517 array string:       `"pyjwt>=2.6.0"` inside a TOML array
 *
 * Returns null when the package is not found.
 */
export function patchPyprojectToml(
  content: string,
  packageName: string,
  fixVersion: string,
): string | null {
  const target = normalizePypiName(packageName)
  const lines = content.split('\n')
  let changed = false

  const updated = lines.map((line) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return line

    // 1. Poetry / flit simple: `pkgname = "specifier"`
    //    Captures everything after the closing quote (inline comment, trailing comma, …).
    const poetrySimple = line.match(
      /^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*=\s*")([^"]*)(".*$)/,
    )
    if (poetrySimple) {
      const [, indent, pkgName, eq, , rest] = poetrySimple
      if (normalizePypiName(pkgName) === target) {
        changed = true
        return `${indent}${pkgName}${eq}>=${fixVersion}${rest}`
      }
    }

    // 2. Poetry inline table: `pkgname = {version = "specifier", extras = [...]}`
    //    Uses a lazy inner match so that key order does not matter.
    const poetryTable = line.match(
      /^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*=\s*\{[^}]*?version\s*=\s*")([^"]*)("[^}]*\}.*$)/,
    )
    if (poetryTable) {
      const [, indent, pkgName, prefix, , rest] = poetryTable
      if (normalizePypiName(pkgName) === target) {
        changed = true
        return `${indent}${pkgName}${prefix}>=${fixVersion}${rest}`
      }
    }

    // 3. PEP 517 array string: `"pkgname[extras]specifier"` inside a TOML dependency array.
    const pepPattern = /"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?([^"]*)"/
    const pepMatch = line.match(pepPattern)
    if (pepMatch) {
      const [, pkgName, extras] = pepMatch
      if (normalizePypiName(pkgName) === target) {
        changed = true
        const extrasStr = extras ?? ''
        return line.replace(pepPattern, `"${pkgName}${extrasStr}>=${fixVersion}"`)
      }
    }

    return line
  })

  return changed ? updated.join('\n') : null
}

/**
 * Apply a security version bump to a package.json file.
 *
 * Strategy: preserves the existing semver range prefix (`^` or `~`) so that
 * `^4.17.20` becomes `^4.17.21` and an exact pin `4.17.20` becomes `4.17.21`.
 * This respects the project's existing version management approach while
 * enforcing the minimum safe version.
 *
 * Searches dependencies, devDependencies, peerDependencies, and
 * optionalDependencies. Returns null when the package is not found.
 */
export function patchPackageJson(
  content: string,
  packageName: string,
  fixVersion: string,
): string | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null

  const pkg = parsed as Record<string, unknown>
  const depFields = [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
  ] as const

  let changed = false

  for (const field of depFields) {
    const deps = pkg[field]
    if (typeof deps !== 'object' || deps === null || Array.isArray(deps)) continue

    const depsRecord = deps as Record<string, string>
    if (!Object.prototype.hasOwnProperty.call(depsRecord, packageName)) continue

    const existing = depsRecord[packageName] ?? ''
    // Preserve leading range prefix (^ or ~) to minimise diff noise
    const prefix = /^[~^]/.test(existing) ? existing[0] : ''
    depsRecord[packageName] = `${prefix}${fixVersion}`
    changed = true
  }

  if (!changed) return null

  // Detect original indentation to avoid spurious whitespace-only diff lines
  const indentMatch = content.match(/^{\n([ \t]+)/)
  const indent = indentMatch?.[1] ?? '  '
  const trailingNewline = content.endsWith('\n') ? '\n' : ''
  return JSON.stringify(pkg, null, indent) + trailingNewline
}

/**
 * Dispatch manifest patching based on file name.
 * Returns null when no patcher exists for the given path or when the target
 * package is not found in the file.
 */
export function applyVersionBumpToManifest(
  manifestPath: string,
  content: string,
  packageName: string,
  fixVersion: string,
): string | null {
  const filename = manifestPath.split('/').pop() ?? manifestPath

  if (filename === 'package.json') {
    return patchPackageJson(content, packageName, fixVersion)
  }

  if (filename === 'pyproject.toml' || filename === 'Pipfile') {
    // Pipfile uses the same key = "specifier" / inline-table syntax as Poetry
    return patchPyprojectToml(content, packageName, fixVersion)
  }

  if (filename.endsWith('.txt') || filename.endsWith('.cfg')) {
    return patchRequirementsTxt(content, packageName, fixVersion)
  }

  return null
}
