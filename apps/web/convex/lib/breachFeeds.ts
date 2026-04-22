import {
  normalizeEcosystem,
  normalizePackageName,
  type InventoryComponentForBreachMatch,
} from './breachMatching'

export type NormalizedFeedSourceType =
  | 'manual'
  | 'github_security_advisory'
  | 'osv'
  | 'nvd'
  | 'npm_advisory'
  | 'pypi_safety'
  | 'rustsec'
  | 'go_vuln'
  // ── Tier 2 — pre-CVE early warning ───────────────────────────────────────
  | 'github_issues'
  | 'hackerone'
  | 'oss_security'
  | 'packet_storm'
  // ── Tier 3 — dark web intelligence ───────────────────────────────────────
  | 'paste_site'
  | 'credential_dump'
  | 'dark_web_mention'

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

// ── NVD / NIST CVE Feed ────────────────────────────────────────────────────

export type NvdCveItem = {
  id: string
  published: string
  lastModified?: string | null
  descriptions?: Array<{ lang: string; value: string }> | null
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData?: { baseScore?: number | null; baseSeverity?: string | null } | null
    }> | null
    cvssMetricV3?: Array<{
      cvssData?: { baseScore?: number | null; baseSeverity?: string | null } | null
    }> | null
  } | null
}

export function normalizeNvdCve(args: {
  cve: NvdCveItem
  packageName: string
  ecosystem: string
  affectedVersions?: string[]
  fixVersion?: string
}): NormalizedDisclosure {
  const englishDesc = args.cve.descriptions?.find((d) => d.lang === 'en')?.value
  const summary = englishDesc?.slice(0, 500) ?? `NVD advisory for ${args.cve.id}`
  const v31 = args.cve.metrics?.cvssMetricV31?.[0]?.cvssData
  const v3 = args.cve.metrics?.cvssMetricV3?.[0]?.cvssData
  const severity = normalizeSeverityLabel(v31?.baseSeverity ?? v3?.baseSeverity) ?? 'medium'

  return {
    packageName: normalizePackageName(args.packageName),
    ecosystem: normalizeEcosystem(args.ecosystem),
    sourceName: 'NVD',
    sourceRef: args.cve.id,
    sourceType: 'nvd',
    sourceTier: 'tier_1',
    summary,
    severity,
    affectedVersions: args.affectedVersions ?? [],
    fixVersion: args.fixVersion,
    aliases: [args.cve.id],
    exploitAvailable: false,
    publishedAt: parsePublishedAt(args.cve.published),
  }
}

// ── npm Security Advisories ────────────────────────────────────────────────

export type NpmAdvisory = {
  id?: number | string | null
  url?: string | null
  title?: string | null
  overview?: string | null
  severity?: string | null
  module_name?: string | null
  vulnerable_versions?: string | null
  patched_versions?: string | null
  cves?: string[] | null
  created?: string | null
}

export function normalizeNpmAdvisory(advisory: NpmAdvisory): NormalizedDisclosure | null {
  const packageName = advisory.module_name?.trim()
  if (!packageName) return null
  const sourceRef = advisory.url ?? `npm-advisory-${advisory.id ?? 'unknown'}`

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: 'npm',
    sourceName: 'npm Security Advisories',
    sourceRef,
    sourceType: 'npm_advisory',
    sourceTier: 'tier_1',
    summary: (advisory.title ?? advisory.overview ?? `npm advisory for ${packageName}`).slice(0, 500),
    severity: normalizeSeverityLabel(advisory.severity) ?? 'medium',
    affectedVersions: advisory.vulnerable_versions ? [advisory.vulnerable_versions] : [],
    fixVersion: advisory.patched_versions?.replace(/^[^0-9]*/, '') || undefined,
    aliases: uniqueNonEmptyStrings([sourceRef, ...(advisory.cves ?? [])]),
    exploitAvailable: false,
    publishedAt: parsePublishedAt(advisory.created),
  }
}

// ── PyPI Safety DB ─────────────────────────────────────────────────────────
// Format: [packageName, spec, vulnId, description]

export type PypiSafetyEntry = [string, string, string, string, ...unknown[]]

export function normalizePypiSafetyEntry(entry: PypiSafetyEntry): NormalizedDisclosure | null {
  const [packageName, spec, vulnId, description] = entry
  if (!packageName || !vulnId) return null

  const fixMatch = spec?.match(/[<>=!]+\s*([\d.]+)/)
  const fixVersion = fixMatch?.[1]

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: 'pip',
    sourceName: 'PyPI Safety DB',
    sourceRef: vulnId,
    sourceType: 'pypi_safety',
    sourceTier: 'tier_1',
    summary: (description ?? `PyPI safety advisory ${vulnId}`).slice(0, 500),
    severity: 'medium',
    affectedVersions: spec ? [spec] : [],
    fixVersion,
    aliases: [vulnId],
    exploitAvailable: false,
    publishedAt: undefined,
  }
}

// ── RustSec Advisory DB ────────────────────────────────────────────────────

export type RustSecAdvisory = {
  id: string
  package?: string | null
  date?: string | null
  title?: string | null
  description?: string | null
  severity?: { cvss?: string | null } | null
  versions?: { patched?: string[] | null } | null
  aliases?: string[] | null
}

export function normalizeRustSecAdvisory(advisory: RustSecAdvisory): NormalizedDisclosure | null {
  const packageName = advisory.package?.trim()
  if (!packageName) return null

  const patchedVersions = advisory.versions?.patched ?? []
  const fixVersion = patchedVersions.length > 0
    ? patchedVersions[0].replace(/^[^0-9]*/, '')
    : undefined

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: 'cargo',
    sourceName: 'RustSec',
    sourceRef: advisory.id,
    sourceType: 'rustsec',
    sourceTier: 'tier_1',
    summary: (advisory.title ?? advisory.description ?? `RustSec ${advisory.id}`).slice(0, 500),
    severity: 'medium',
    affectedVersions: [],
    fixVersion,
    aliases: uniqueNonEmptyStrings([advisory.id, ...(advisory.aliases ?? [])]),
    exploitAvailable: false,
    publishedAt: parsePublishedAt(advisory.date),
  }
}

// ── Go Vulnerability Database ──────────────────────────────────────────────

export type GoVulnEntry = {
  id: string
  published?: string | null
  aliases?: string[] | null
  summary?: string | null
  details?: string | null
  severity?: Array<{ type?: string | null; score?: string | null }> | null
  affected?: Array<{
    package?: { name?: string | null; ecosystem?: string | null } | null
    ranges?: Array<{
      type?: string | null
      events?: Array<{ introduced?: string | null; fixed?: string | null }> | null
    }> | null
    versions?: string[] | null
  }> | null
}

export function normalizeGoVulnEntry(
  entry: GoVulnEntry,
  packageName: string,
  affectedVersions: string[],
  fixVersion?: string,
): NormalizedDisclosure {
  const summary = entry.summary ?? entry.details?.slice(0, 500) ?? `Go advisory ${entry.id}`

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: 'go',
    sourceName: 'Go Vulnerability Database',
    sourceRef: entry.id,
    sourceType: 'go_vuln',
    sourceTier: 'tier_1',
    summary: summary.slice(0, 500),
    severity: 'medium',
    affectedVersions,
    fixVersion,
    aliases: uniqueNonEmptyStrings([entry.id, ...(entry.aliases ?? [])]),
    exploitAvailable: false,
    publishedAt: parsePublishedAt(entry.published),
  }
}

// ── Tier 2: GitHub Issues / PRs ────────────────────────────────────────────
//
// GitHub Issues tagged with security labels on monitored open source repos.
// These appear days/weeks before a CVE is assigned — the "CVE gap" window.

export type GitHubIssueDisclosure = {
  issueNumber: number
  title: string
  body?: string | null
  htmlUrl: string
  state: 'open' | 'closed'
  labels: string[]
  createdAt?: string | null
  closedAt?: string | null
  packageName: string        // inferred from repo name or issue body
  ecosystem: string
  repoFullName: string
}

export function normalizeGithubIssueDisclosure(
  issue: GitHubIssueDisclosure,
): NormalizedDisclosure {
  const summary = `[Pre-CVE] ${issue.title}`.slice(0, 500)
  const exploitAvailable = issue.labels.some((l) =>
    /exploit|poc|proof.of.concept|working/i.test(l),
  )

  // Infer severity from labels
  const severityFromLabel = (labels: string[]): NormalizedDisclosure['severity'] => {
    const joined = labels.join(' ').toLowerCase()
    if (/critical/.test(joined)) return 'critical'
    if (/high/.test(joined)) return 'high'
    if (/medium|moderate/.test(joined)) return 'medium'
    if (/low/.test(joined)) return 'low'
    return 'medium' // default for unassigned pre-CVE
  }

  return {
    packageName: normalizePackageName(issue.packageName),
    ecosystem: normalizeEcosystem(issue.ecosystem),
    sourceName: `GitHub Issues: ${issue.repoFullName}`,
    sourceRef: issue.htmlUrl,
    sourceType: 'github_issues',
    sourceTier: 'tier_2',
    summary,
    severity: severityFromLabel(issue.labels),
    affectedVersions: [],
    fixVersion: undefined,
    aliases: [`github-issue-${issue.repoFullName}#${issue.issueNumber}`],
    exploitAvailable,
    publishedAt: parsePublishedAt(issue.createdAt),
  }
}

// ── Tier 2: HackerOne Disclosed Reports ────────────────────────────────────
//
// HackerOne has a public API for disclosed vulnerability reports.
// We query reports tagged to programs that match SBOM package names.
// API docs: https://api.hackerone.com/docs/v1#introduction

export type HackerOneReport = {
  id: string
  title: string
  vulnerability_information?: string | null
  state: string
  severity?: { rating?: string | null } | null
  weakness?: { name?: string | null } | null
  program?: { handle?: string | null } | null
  structured_scope?: Array<{
    asset_identifier?: string | null
    asset_type?: string | null
  }> | null
  created_at?: string | null
  disclosed_at?: string | null
  cve_ids?: string[] | null
}

export function normalizeHackerOneReport(
  report: HackerOneReport,
  packageName: string,
  ecosystem: string,
): NormalizedDisclosure {
  const summary = report.title.slice(0, 500)
  const cveId = report.cve_ids?.[0]

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: normalizeEcosystem(ecosystem),
    sourceName: 'HackerOne Disclosed Reports',
    sourceRef: `https://hackerone.com/reports/${report.id}`,
    sourceType: 'hackerone',
    sourceTier: 'tier_2',
    summary,
    severity: normalizeSeverityLabel(report.severity?.rating) ?? 'medium',
    affectedVersions: [],
    fixVersion: undefined,
    aliases: uniqueNonEmptyStrings([
      `hackerone-${report.id}`,
      cveId ?? null,
    ]),
    exploitAvailable: true, // HackerOne reports have working PoC by definition
    publishedAt: parsePublishedAt(report.disclosed_at ?? report.created_at),
  }
}

// ── Tier 2: oss-security Mailing List ─────────────────────────────────────
//
// The oss-security mailing list (Openwall) is a primary pre-CVE disclosure channel.
// Accessible via mail-archive.com RSS or MARC.info.
// We parse the RSS title/description to extract package and advisory info.

export type OssSecurityPost = {
  title: string
  description?: string | null
  link: string
  pubDate?: string | null
  /** Package name extracted from title (may be approximate) */
  packageName?: string | null
  ecosystem?: string | null
}

// Title patterns: "[SECURITY] pkg 1.2.3 - XSS vulnerability"
//                 "Re: CVE-2024-XXXX - pkg"
const PKG_FROM_TITLE_PATTERNS = [
  /\[(?:security|vuln|advisory)\]\s+([a-z0-9._-]+)/i,
  /advisory.*?(?:for|in)\s+([a-z0-9._/-]+)/i,
  /CVE-\d{4}-\d+\s+.*?([a-z0-9._-]+)/i,
]

export function normalizeOssSecurityPost(
  post: OssSecurityPost,
): NormalizedDisclosure | null {
  // Try to extract package name from title if not provided
  let packageName = post.packageName?.trim()
  if (!packageName) {
    for (const pattern of PKG_FROM_TITLE_PATTERNS) {
      const match = post.title.match(pattern)
      if (match) {
        packageName = match[1]
        break
      }
    }
  }

  if (!packageName) return null  // Can't normalize without a package name

  const cveMatch = post.title.match(/CVE-\d{4}-\d+/) ??
    post.description?.match(/CVE-\d{4}-\d+/)
  const cveId = cveMatch?.[0]

  const summary = post.title.slice(0, 500)

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: normalizeEcosystem(post.ecosystem ?? 'unknown'),
    sourceName: 'oss-security Mailing List',
    sourceRef: post.link,
    sourceType: 'oss_security',
    sourceTier: 'tier_2',
    summary,
    severity: 'medium', // oss-security doesn't assign severity
    affectedVersions: [],
    fixVersion: undefined,
    aliases: uniqueNonEmptyStrings([post.link, cveId ?? null]),
    exploitAvailable: /exploit|poc|proof.of.concept/i.test(post.title + (post.description ?? '')),
    publishedAt: parsePublishedAt(post.pubDate),
  }
}

// ── Tier 2: Packet Storm Security ──────────────────────────────────────────
//
// Packet Storm (packetstormsecurity.com) publishes security advisories and PoCs.
// RSS feed: https://rss.packetstormsecurity.com/files/
// Advisory entries contain package names and CVE references.

export type PacketStormEntry = {
  title: string
  link: string
  description?: string | null
  pubDate?: string | null
  category?: string | null
}

export function normalizePacketStormEntry(
  entry: PacketStormEntry,
  packageName: string,
  ecosystem: string,
): NormalizedDisclosure | null {
  if (!packageName?.trim()) return null

  const cveMatch =
    entry.title.match(/CVE-\d{4}-\d+/) ??
    entry.description?.match(/CVE-\d{4}-\d+/)
  const cveId = cveMatch?.[0]

  const isExploit = /exploit|poc|proof.of.concept/i.test(
    entry.title + (entry.category ?? ''),
  )

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: normalizeEcosystem(ecosystem),
    sourceName: 'Packet Storm Security',
    sourceRef: entry.link,
    sourceType: 'packet_storm',
    sourceTier: 'tier_2',
    summary: entry.title.slice(0, 500),
    severity: isExploit ? 'high' : 'medium',
    affectedVersions: [],
    fixVersion: undefined,
    aliases: uniqueNonEmptyStrings([entry.link, cveId ?? null]),
    exploitAvailable: isExploit,
    publishedAt: parsePublishedAt(entry.pubDate),
  }
}

// ── Tier 3: Paste Site Mention ─────────────────────────────────────────────
//
// Paste sites (Pastebin, paste.ee, ix.io, dpaste.com) are used by threat
// actors to share credential dumps, exploit code, and vulnerability details
// before any formal disclosure. Monitoring for mentions of package names or
// customer domain strings gives the earliest possible warning signal.

export type PasteSiteMention = {
  pasteId: string
  title?: string | null
  content: string
  url: string
  pasteDate?: string | null
  /** The search term that matched — e.g. package name or customer domain */
  matchedTerm: string
  /** Whether the paste contains what looks like credentials */
  containsCredentials: boolean
  /** Estimated sensitivity of the content */
  sensitivityLevel: 'low' | 'medium' | 'high' | 'critical'
}

export function normalizePasteSiteMention(
  mention: PasteSiteMention,
  packageName: string,
  ecosystem: string,
): NormalizedDisclosure {
  const summary = (
    mention.title
      ? `Paste site mention: "${mention.title}" — ${mention.matchedTerm}`
      : `Paste site mention of ${mention.matchedTerm}`
  ).slice(0, 500)

  const severityMap: Record<PasteSiteMention['sensitivityLevel'], NormalizedDisclosure['severity']> = {
    low: 'low',
    medium: 'medium',
    high: 'high',
    critical: 'critical',
  }

  return {
    packageName: normalizePackageName(packageName),
    ecosystem: normalizeEcosystem(ecosystem),
    sourceName: 'Paste Site Intelligence',
    sourceRef: mention.url,
    sourceType: 'paste_site',
    sourceTier: 'tier_3',
    summary,
    severity: severityMap[mention.sensitivityLevel],
    affectedVersions: [],
    fixVersion: undefined,
    aliases: [mention.url, `paste-${mention.pasteId}`],
    exploitAvailable: mention.sensitivityLevel === 'critical' || mention.sensitivityLevel === 'high',
    publishedAt: parsePublishedAt(mention.pasteDate),
  }
}

// ── Tier 3: Credential Dump (HaveIBeenPwned Domain Search) ───────────────
//
// HaveIBeenPwned's domain search API identifies breached credentials for
// a customer domain. While not package-specific, a credential dump affecting
// engineers can enable supply chain attacks by compromising npm/PyPI accounts.
// API: https://haveibeenpwned.com/API/v3#BreachesForDomain (requires API key)

export type HibpDomainBreach = {
  Name: string
  Title: string
  Domain: string
  BreachDate: string
  AddedDate: string
  Description: string
  DataClasses: string[]
  PwnCount: number
  IsVerified: boolean
  IsFabricated: boolean
  IsSensitive: boolean
}

export function normalizeHibpDomainBreach(
  breach: HibpDomainBreach,
  customerDomain: string,
): NormalizedDisclosure {
  const hasCredentials = breach.DataClasses.some((dc) =>
    /password|credential|auth|token|key/i.test(dc),
  )
  const summary = `Credential breach affecting ${customerDomain}: ${breach.Title} (${breach.PwnCount.toLocaleString()} accounts, ${breach.BreachDate})`

  return {
    packageName: `domain:${customerDomain}`,
    ecosystem: 'unknown',
    sourceName: 'HaveIBeenPwned',
    sourceRef: `https://haveibeenpwned.com/account/${breach.Name}`,
    sourceType: 'credential_dump',
    sourceTier: 'tier_3',
    summary: summary.slice(0, 500),
    severity: hasCredentials ? 'high' : 'medium',
    affectedVersions: [],
    fixVersion: undefined,
    aliases: [`hibp-${breach.Name}`, customerDomain],
    exploitAvailable: false,
    publishedAt: parsePublishedAt(breach.AddedDate),
  }
}

// ── Tier 3: Dark Web Mention (scaffold) ────────────────────────────────────
//
// Represents a mention detected from dark web intelligence sources
// (Telegram channels, underground forums, etc.). In production this would
// be fed by a Tor-capable agent or third-party dark web intelligence feed.
// The structure allows future integration without changing the ingestion pipeline.

export type DarkWebMention = {
  id: string
  source: 'telegram_channel' | 'forum' | 'marketplace' | 'irc_channel'
  sourceName: string
  title: string
  snippet: string
  detectedAt?: string | null
  matchedPackage: string
  ecosystem: string
  exploitConfidence: 'low' | 'medium' | 'high'
  /** Optional CVE reference if mentioned */
  cveId?: string | null
}

export function normalizeDarkWebMention(mention: DarkWebMention): NormalizedDisclosure {
  const severity: NormalizedDisclosure['severity'] =
    mention.exploitConfidence === 'high' ? 'critical'
    : mention.exploitConfidence === 'medium' ? 'high'
    : 'medium'

  return {
    packageName: normalizePackageName(mention.matchedPackage),
    ecosystem: normalizeEcosystem(mention.ecosystem),
    sourceName: `Dark Web: ${mention.sourceName}`,
    sourceRef: `dark-web://${mention.source}/${mention.id}`,
    sourceType: 'dark_web_mention',
    sourceTier: 'tier_3',
    summary: `Dark web intelligence: ${mention.title} — ${mention.snippet.slice(0, 300)}`,
    severity,
    affectedVersions: [],
    fixVersion: undefined,
    aliases: uniqueNonEmptyStrings([`dark-web-${mention.id}`, mention.cveId ?? null]),
    exploitAvailable: true, // Dark web signals imply active exploitation
    publishedAt: parsePublishedAt(mention.detectedAt),
  }
}
