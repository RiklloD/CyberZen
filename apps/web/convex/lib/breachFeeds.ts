import {
  normalizeEcosystem,
  normalizePackageName,
  type InventoryComponentForBreachMatch,
} from './breachMatching'

export type NormalizedFeedSourceType =
  | 'manual'
  | 'github_security_advisory'
  | 'osv'

export type NormalizedDisclosure = {
  packageName: string
  ecosystem: string
  sourceName: string
  sourceRef: string
  sourceType: NormalizedFeedSourceType
  sourceTier: 'tier_1' | 'tier_2' | 'tier_3'
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  affectedVersions: string[]
  fixVersion?: string
  aliases: string[]
  exploitAvailable: boolean
  publishedAt?: number
}

export type GithubSecurityAdvisoryInput = {
  ghsaId: string
  summary: string
  description?: string
  severity: NormalizedDisclosure['severity']
  aliases?: string[]
  exploitAvailable?: boolean
  publishedAt?: number
  vulnerabilities: Array<{
    packageName: string
    ecosystem: string
    vulnerableVersionRange?: string
    firstPatchedVersion?: string
  }>
}

export type OsvAdvisoryInput = {
  id: string
  summary: string
  details?: string
  severity?: NormalizedDisclosure['severity']
  severityScore?: number
  aliases?: string[]
  exploitAvailable?: boolean
  publishedAt?: number
  affected: Array<{
    packageName: string
    ecosystem: string
    versions?: string[]
    ranges?: Array<{
      type?: string
      events: Array<{
        introduced?: string
        fixed?: string
        lastAffected?: string
        limit?: string
      }>
    }>
  }>
}

type FeedPackageCandidate = {
  packageName: string
  ecosystem: string
  affectedVersions: string[]
  fixVersion?: string
}

function chooseBestPackageCandidate(
  candidates: FeedPackageCandidate[],
  inventoryComponents: InventoryComponentForBreachMatch[],
) {
  if (candidates.length === 0) {
    throw new Error('The advisory did not contain any package candidates to normalize.')
  }

  if (candidates.length <= 1 || inventoryComponents.length === 0) {
    return candidates[0]
  }

  let bestCandidate = candidates[0]
  let bestScore = -1

  for (const candidate of candidates) {
    const normalizedName = normalizePackageName(candidate.packageName)
    const normalizedEcosystem = normalizeEcosystem(candidate.ecosystem)
    const score = inventoryComponents.filter((component) => {
      const componentName = normalizePackageName(component.name)
      if (componentName !== normalizedName) {
        return false
      }

      if (normalizedEcosystem === 'unknown') {
        return true
      }

      return normalizeEcosystem(component.ecosystem) === normalizedEcosystem
    }).length

    if (score > bestScore) {
      bestCandidate = candidate
      bestScore = score
    }
  }

  return bestCandidate
}

function normalizeSummary(summary: string, description?: string) {
  const trimmedSummary = summary.trim()
  if (trimmedSummary.length > 0) {
    return trimmedSummary
  }

  return description?.trim() || 'Advisory details were imported from the upstream feed.'
}

function severityFromScore(score?: number): NormalizedDisclosure['severity'] {
  if (score === undefined) {
    return 'medium'
  }

  if (score >= 9) {
    return 'critical'
  }

  if (score >= 7) {
    return 'high'
  }

  if (score >= 4) {
    return 'medium'
  }

  if (score > 0) {
    return 'low'
  }

  return 'informational'
}

function rangeFromEvents(
  events: Array<{
    introduced?: string
    fixed?: string
    lastAffected?: string
    limit?: string
  }>,
) {
  const affectedVersions: string[] = []
  let lowerBound: string | null = null

  for (const event of events) {
    if (event.introduced !== undefined) {
      lowerBound = event.introduced === '0' ? null : event.introduced
    }

    const upperBound = event.fixed ?? event.lastAffected ?? event.limit
    if (!upperBound) {
      continue
    }

    const upperOperator = event.lastAffected ? '<=' : '<'
    const lowerSegment = lowerBound ? `>=${lowerBound}` : ''
    const upperSegment = `${upperOperator}${upperBound}`
    affectedVersions.push(
      [lowerSegment, upperSegment].filter(Boolean).join(', '),
    )
    lowerBound = null
  }

  if (lowerBound) {
    affectedVersions.push(`>=${lowerBound}`)
  }

  return affectedVersions
}

export function normalizeGithubSecurityAdvisory(args: {
  advisory: GithubSecurityAdvisoryInput
  inventoryComponents?: InventoryComponentForBreachMatch[]
}): NormalizedDisclosure {
  const candidate = chooseBestPackageCandidate(
    args.advisory.vulnerabilities.map((vulnerability) => ({
      packageName: vulnerability.packageName,
      ecosystem: vulnerability.ecosystem,
      affectedVersions: vulnerability.vulnerableVersionRange
        ? [vulnerability.vulnerableVersionRange]
        : [],
      fixVersion: vulnerability.firstPatchedVersion,
    })),
    args.inventoryComponents ?? [],
  )

  return {
    packageName: candidate.packageName,
    ecosystem: normalizeEcosystem(candidate.ecosystem),
    sourceName: 'GitHub Security Advisories',
    sourceRef: args.advisory.ghsaId,
    sourceType: 'github_security_advisory',
    sourceTier: 'tier_1',
    summary: normalizeSummary(
      args.advisory.summary,
      args.advisory.description,
    ),
    severity: args.advisory.severity,
    affectedVersions: candidate.affectedVersions,
    fixVersion: candidate.fixVersion,
    aliases: [
      args.advisory.ghsaId,
      ...(args.advisory.aliases ?? []),
    ],
    exploitAvailable: args.advisory.exploitAvailable ?? false,
    publishedAt: args.advisory.publishedAt,
  }
}

export function normalizeOsvAdvisory(args: {
  advisory: OsvAdvisoryInput
  inventoryComponents?: InventoryComponentForBreachMatch[]
}): NormalizedDisclosure {
  const candidate = chooseBestPackageCandidate(
    args.advisory.affected.map((affectedPackage) => ({
      packageName: affectedPackage.packageName,
      ecosystem: affectedPackage.ecosystem,
      affectedVersions: [
        ...(affectedPackage.versions ?? []),
        ...((affectedPackage.ranges ?? [])
          .filter((range) =>
            !range.type ||
            range.type.toLowerCase() === 'ecosystem' ||
            range.type.toLowerCase() === 'semver',
          )
          .flatMap((range) => rangeFromEvents(range.events))),
      ],
      fixVersion: (affectedPackage.ranges ?? [])
        .flatMap((range) => range.events)
        .map((event) => event.fixed)
        .find((value): value is string => Boolean(value)),
    })),
    args.inventoryComponents ?? [],
  )

  return {
    packageName: candidate.packageName,
    ecosystem: normalizeEcosystem(candidate.ecosystem),
    sourceName: 'OSV',
    sourceRef: args.advisory.id,
    sourceType: 'osv',
    sourceTier: 'tier_1',
    summary: normalizeSummary(args.advisory.summary, args.advisory.details),
    severity: args.advisory.severity ?? severityFromScore(args.advisory.severityScore),
    affectedVersions: candidate.affectedVersions,
    fixVersion: candidate.fixVersion,
    aliases: [args.advisory.id, ...(args.advisory.aliases ?? [])],
    exploitAvailable: args.advisory.exploitAvailable ?? false,
    publishedAt: args.advisory.publishedAt,
  }
}
