import { normalizeEcosystem, normalizePackageName } from './breachMatching'

export type TrackedAdvisoryPackage = {
  packageName: string
  ecosystem: string
  version: string
}

export type GithubAdvisoryBatch = {
  ecosystem: string
  affects: string[]
}

export type OsvPackageQuery = {
  package: {
    name: string
    ecosystem: string
  }
  version: string
}

const githubEcosystemMap: Record<string, string> = {
  composer: 'composer',
  go: 'go',
  maven: 'maven',
  npm: 'npm',
  nuget: 'nuget',
  pypi: 'pip',
  rubygems: 'rubygems',
  cargo: 'rust',
}

const osvEcosystemMap: Record<string, string> = {
  composer: 'Packagist',
  go: 'Go',
  maven: 'Maven',
  npm: 'npm',
  nuget: 'NuGet',
  pypi: 'PyPI',
  rubygems: 'RubyGems',
  cargo: 'crates.io',
}

function chunk<T>(values: T[], size: number) {
  const chunks: T[][] = []

  for (let index = 0; index < values.length; index += size) {
    chunks.push(values.slice(index, index + size))
  }

  return chunks
}

export function dedupeTrackedPackages(packages: TrackedAdvisoryPackage[]) {
  const uniquePackages = new Map<string, TrackedAdvisoryPackage>()

  for (const pkg of packages) {
    const packageName = pkg.packageName.trim()
    const version = pkg.version.trim()
    const ecosystem = normalizeEcosystem(pkg.ecosystem)

    if (!packageName || !version || ecosystem === 'unknown' || ecosystem === 'container') {
      continue
    }

    const key = [
      ecosystem,
      normalizePackageName(packageName),
      version,
    ].join(':')

    if (!uniquePackages.has(key)) {
      uniquePackages.set(key, {
        packageName,
        ecosystem,
        version,
      })
    }
  }

  return [...uniquePackages.values()]
}

export function buildGithubAdvisoryBatches(
  packages: TrackedAdvisoryPackage[],
  batchSize = 100,
) {
  const groupedAffects = new Map<string, string[]>()

  for (const pkg of dedupeTrackedPackages(packages)) {
    const ecosystem = githubEcosystemMap[pkg.ecosystem]

    if (!ecosystem) {
      continue
    }

    const affects = `${pkg.packageName}@${pkg.version}`
    const existing = groupedAffects.get(ecosystem) ?? []
    existing.push(affects)
    groupedAffects.set(ecosystem, existing)
  }

  const batches: GithubAdvisoryBatch[] = []

  for (const [ecosystem, affects] of groupedAffects) {
    for (const affectChunk of chunk(affects, batchSize)) {
      batches.push({
        ecosystem,
        affects: affectChunk,
      })
    }
  }

  return batches
}

export function buildOsvPackageQueries(
  packages: TrackedAdvisoryPackage[],
  batchSize = 100,
) {
  const queries = dedupeTrackedPackages(packages).flatMap((pkg): OsvPackageQuery[] => {
    const ecosystem = osvEcosystemMap[pkg.ecosystem]

    if (!ecosystem) {
      return []
    }

    return [
      {
        package: {
          name: pkg.packageName,
          ecosystem,
        },
        version: pkg.version,
      },
    ]
  })

  return chunk(queries, batchSize)
}

export function parseGithubNextCursor(linkHeader: string | null) {
  if (!linkHeader) {
    return undefined
  }

  for (const part of linkHeader.split(',')) {
    const trimmed = part.trim()

    if (!trimmed.includes('rel="next"')) {
      continue
    }

    const match = trimmed.match(/<([^>]+)>/)
    if (!match) {
      continue
    }

    const nextUrl = new URL(match[1])
    const cursor = nextUrl.searchParams.get('after')

    if (cursor) {
      return cursor
    }
  }

  return undefined
}

export function collectOsvVulnerabilityIds(
  results: Array<
    | {
        vulns?: Array<{
          id?: string | null
        }> | null
      }
    | null
    | undefined
  >,
) {
  const ids = new Set<string>()

  for (const result of results) {
    for (const vulnerability of result?.vulns ?? []) {
      const id = vulnerability.id?.trim()

      if (id) {
        ids.add(id)
      }
    }
  }

  return [...ids]
}
