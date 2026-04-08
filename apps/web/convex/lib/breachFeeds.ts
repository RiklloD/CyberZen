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

export type GithubSecurityAdvisoryApiResponse = {
  ghsa_id: string
  summary: string
  description?: string | null
  severity?: string | null
  identifiers?: Array<{
    type?: string | null
    value?: string | null
  }>
  vulnerabilities?: Array<{
    package?: {
      name?: string | null
      ecosystem?: string | null
    } | null
    package_name?: string | null
    ecosystem?: string | null
    vulnerable_version_range?: string | null
    first_patched_version?:
      | string
      | {
          identifier?: string | null
        }
      | null
  }>
  cvss?: {
    score?: number | null
  } | null
  cvss_severities?: {
    cvss_v3?: {
      score?: number | null
    } | null
    cvss_v4?: {
      score?: number | null
    } | null
  } | null
  published_at?: string | null
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

export type OsvApiVulnerabilityResponse = {
  id: string
  summary?: string | null
  details?: string | null
  aliases?: string[] | null
  published?: string | null
  severity?: Array<{
    type?: string | null
    score?: string | null
  }> | null
  database_specific?: {
    severity?: string | null
  } | null
  affected?: Array<{
    package?: {
      name?: string | null
      ecosystem?: string | null
    } | null
    versions?: string[] | null
    ranges?: Array<{
      type?: string | null
      events?: Array<{
        introduced?: string | null
        fixed?: string | null
        lastAffected?: string | null
        limit?: string | null
      }> | null
    }> | null
    ecosystem_specific?: {
      severity?: string | null
    } | null
  }> | null
}

type FeedPackageCandidate = {
  packageName: string
  ecosystem: string
  affectedVersions: string[]
  fixVersion?: string
}

type GithubApiVulnerability = NonNullable<
  GithubSecurityAdvisoryApiResponse['vulnerabilities']
>[number]

function uniqueNonEmptyStrings(values: Array<string | null | undefined>) {
  return [...new Set(values.map((value) => value?.trim()).filter(Boolean))] as string[]
}

function parsePublishedAt(value?: string | null) {
  if (!value) {
    return undefined
  }

  const timestamp = Date.parse(value)
  return Number.isNaN(timestamp) ? undefined : timestamp
}

function normalizeSeverityLabel(
  value?: string | null,
): NormalizedDisclosure['severity'] | undefined {
  if (!value) {
    return undefined
  }

  const normalized = value.trim().toLowerCase()
  if (
    normalized === 'critical' ||
    normalized === 'high' ||
    normalized === 'medium' ||
    normalized === 'low' ||
    normalized === 'informational'
  ) {
    return normalized
  }

  if (normalized === 'moderate') {
    return 'medium'
  }

  if (normalized === 'none') {
    return 'informational'
  }

  return undefined
}

function parseNumericSeverityScore(value?: string | null) {
  if (!value) {
    return undefined
  }

  if (!/^\d+(\.\d+)?$/.test(value.trim())) {
    return undefined
  }

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}

function extractGithubFixVersion(
  firstPatchedVersion?: GithubApiVulnerability['first_patched_version'],
) {
  if (!firstPatchedVersion) {
    return undefined
  }

  if (typeof firstPatchedVersion === 'string') {
    return firstPatchedVersion
  }

  return firstPatchedVersion.identifier ?? undefined
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

export function coerceGithubSecurityAdvisoryInput(
  advisory: GithubSecurityAdvisoryApiResponse,
): GithubSecurityAdvisoryInput {
  const severity =
    normalizeSeverityLabel(advisory.severity) ??
    severityFromScore(
      advisory.cvss_severities?.cvss_v4?.score ??
        advisory.cvss_severities?.cvss_v3?.score ??
        advisory.cvss?.score ??
        undefined,
    )

  return {
    ghsaId: advisory.ghsa_id,
    summary: advisory.summary,
    description: advisory.description ?? undefined,
    severity,
    aliases: uniqueNonEmptyStrings(
      (advisory.identifiers ?? []).map((identifier) => identifier.value),
    ).filter((alias) => alias !== advisory.ghsa_id),
    publishedAt: parsePublishedAt(advisory.published_at),
    vulnerabilities: (advisory.vulnerabilities ?? []).flatMap((vulnerability) => {
      const packageName =
        vulnerability.package?.name ?? vulnerability.package_name ?? undefined
      const ecosystem =
        vulnerability.package?.ecosystem ?? vulnerability.ecosystem ?? undefined

      if (!packageName || !ecosystem) {
        return []
      }

      return [
        {
          packageName,
          ecosystem,
          vulnerableVersionRange:
            vulnerability.vulnerable_version_range ?? undefined,
          firstPatchedVersion: extractGithubFixVersion(
            vulnerability.first_patched_version,
          ),
        },
      ]
    }),
  }
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

export function coerceOsvAdvisoryInput(
  advisory: OsvApiVulnerabilityResponse,
): OsvAdvisoryInput {
  const explicitSeverity =
    normalizeSeverityLabel(advisory.database_specific?.severity) ??
    (advisory.affected ?? [])
      .map((affectedPackage) =>
        normalizeSeverityLabel(affectedPackage.ecosystem_specific?.severity),
      )
      .find((value): value is NormalizedDisclosure['severity'] => Boolean(value))

  const numericSeverityScore = (advisory.severity ?? [])
    .map((severity) => parseNumericSeverityScore(severity.score))
    .find((score): score is number => score !== undefined)

  return {
    id: advisory.id,
    summary: advisory.summary ?? '',
    details: advisory.details ?? undefined,
    severity: explicitSeverity,
    severityScore: numericSeverityScore,
    aliases: advisory.aliases?.filter((alias) => alias !== advisory.id) ?? undefined,
    publishedAt: parsePublishedAt(advisory.published),
    affected: (advisory.affected ?? []).flatMap((affectedPackage) => {
      const packageName = affectedPackage.package?.name
      const ecosystem = affectedPackage.package?.ecosystem

      if (!packageName || !ecosystem) {
        return []
      }

      return [
        {
          packageName,
          ecosystem,
          versions: affectedPackage.versions ?? undefined,
          ranges: (affectedPackage.ranges ?? []).map((range) => ({
            type: range.type ?? undefined,
            events: (range.events ?? []).map((event) => ({
              introduced: event.introduced ?? undefined,
              fixed: event.fixed ?? undefined,
              lastAffected: event.lastAffected ?? undefined,
              limit: event.limit ?? undefined,
            })),
          })),
        },
      ]
    }),
  }
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
