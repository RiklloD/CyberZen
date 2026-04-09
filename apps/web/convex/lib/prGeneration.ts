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
