import type { Id } from '../_generated/dataModel'

export type BreachMatchStatus =
  | 'matched'
  | 'version_unaffected'
  | 'version_unknown'
  | 'unmatched'
  | 'no_snapshot'

export type BreachVersionMatchStatus = 'affected' | 'unaffected' | 'unknown'

type SummaryParams = {
  packageName: string
  repositoryName: string
  matchStatus: BreachMatchStatus
  matchedComponentCount: number
  affectedComponentCount: number
  matchedVersions: string[]
  affectedMatchedVersions: string[]
  affectedVersions: string[]
  fixVersion?: string
}

export type InventoryComponentForBreachMatch = {
  _id?: Id<'sbomComponents'>
  name: string
  normalizedName?: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  sourceFile: string
  dependents: string[]
}

export type BreachInventoryMatch = {
  matchStatus: BreachMatchStatus
  versionMatchStatus: BreachVersionMatchStatus
  matchedComponents: InventoryComponentForBreachMatch[]
  affectedComponents: InventoryComponentForBreachMatch[]
  matchedComponentCount: number
  affectedComponentCount: number
  matchedVersions: string[]
  affectedMatchedVersions: string[]
  matchedSourceFiles: string[]
  directComponentCount: number
  transitiveComponentCount: number
  containerComponentCount: number
}

type ComparatorOperator =
  | '='
  | '!='
  | '<'
  | '<='
  | '>'
  | '>='
  | '^'
  | '~'
  | '~='

type VersionToken = number | string

type ParsedVersion = {
  raw: string
  tokens: VersionToken[]
}

type VersionEvaluation = 'affected' | 'unaffected' | 'unknown'

const comparatorPattern =
  /(<=|>=|<|>|==|=|!=|\^|~|~=)?\s*([0-9A-Za-z][0-9A-Za-z._+-]*)/g

export function normalizePackageName(name: string) {
  const trimmed = decodeURIComponent(name.trim().toLowerCase())
    .split('?')[0]
    .split('#')[0]

  if (trimmed.startsWith('pkg:')) {
    const packagePath = trimmed.slice(4)
    const slashIndex = packagePath.indexOf('/')
    if (slashIndex >= 0) {
      return packagePath.slice(slashIndex + 1).replace(/_/g, '-')
    }
  }

  return trimmed.replace(/_/g, '-')
}

export function normalizeEcosystem(ecosystem?: string) {
  const normalized = ecosystem?.trim().toLowerCase()

  if (!normalized) {
    return 'unknown'
  }

  if (
    normalized === 'pip' ||
    normalized === 'pypi' ||
    normalized === 'python'
  ) {
    return 'pypi'
  }

  if (
    normalized === 'npm' ||
    normalized === 'node' ||
    normalized === 'javascript' ||
    normalized === 'npmjs'
  ) {
    return 'npm'
  }

  if (
    normalized === 'cargo' ||
    normalized === 'crates.io' ||
    normalized === 'crates-io' ||
    normalized === 'rust'
  ) {
    return 'cargo'
  }

  if (
    normalized === 'go' ||
    normalized === 'golang' ||
    normalized === 'go modules' ||
    normalized === 'gomod'
  ) {
    return 'gomod'
  }

  if (normalized === 'docker' || normalized === 'oci' || normalized === 'container') {
    return 'container'
  }

  return normalized
}

export function uniqueStrings(values: string[]) {
  return [...new Set(values.filter((value) => value.trim().length > 0))]
}

function tokenizeVersion(rawVersion: string): VersionToken[] | null {
  const normalized = rawVersion
    .trim()
    .toLowerCase()
    .replace(/^v/, '')
    .split('+')[0]

  if (!normalized || normalized === 'unknown') {
    return null
  }

  const tokens = normalized.match(/[0-9]+|[a-z]+/g)
  if (!tokens || tokens.length === 0) {
    return null
  }

  return tokens.map((token) =>
    /^\d+$/.test(token) ? Number.parseInt(token, 10) : token,
  )
}

function parseVersion(rawVersion: string): ParsedVersion | null {
  const tokens = tokenizeVersion(rawVersion)
  if (!tokens) {
    return null
  }

  return {
    raw: rawVersion,
    tokens,
  }
}

function compareParsedVersions(
  left: ParsedVersion | null,
  right: ParsedVersion | null,
) {
  if (!left || !right) {
    return null
  }

  const maxLength = Math.max(left.tokens.length, right.tokens.length)
  for (let index = 0; index < maxLength; index += 1) {
    const leftToken = left.tokens[index]
    const rightToken = right.tokens[index]

    if (leftToken === undefined && rightToken === undefined) {
      continue
    }

    if (leftToken === undefined) {
      if (typeof rightToken === 'number' && rightToken === 0) {
        continue
      }

      return -1
    }

    if (rightToken === undefined) {
      if (typeof leftToken === 'number' && leftToken === 0) {
        continue
      }

      return 1
    }

    if (typeof leftToken === 'number' && typeof rightToken === 'number') {
      if (leftToken < rightToken) {
        return -1
      }

      if (leftToken > rightToken) {
        return 1
      }

      continue
    }

    if (typeof leftToken === 'number') {
      return 1
    }

    if (typeof rightToken === 'number') {
      return -1
    }

    const lexicalComparison = leftToken.localeCompare(rightToken)
    if (lexicalComparison !== 0) {
      return lexicalComparison
    }
  }

  return 0
}

function baseNumericSegments(parsedVersion: ParsedVersion) {
  const numericSegments: number[] = []

  for (const token of parsedVersion.tokens) {
    if (typeof token !== 'number') {
      break
    }

    numericSegments.push(token)
  }

  return numericSegments
}

function buildUpperBound(
  parsedVersion: ParsedVersion | null,
  operator: '^' | '~' | '~=',
) {
  if (!parsedVersion) {
    return null
  }

  const segments = baseNumericSegments(parsedVersion)
  if (segments.length === 0) {
    return null
  }

  const next = [...segments]
  if (operator === '^') {
    const bumpIndex = next.findIndex((segment) => segment !== 0)
    const safeIndex = bumpIndex >= 0 ? bumpIndex : 0
    next[safeIndex] += 1
    for (let index = safeIndex + 1; index < next.length; index += 1) {
      next[index] = 0
    }
    return parseVersion(next.join('.'))
  }

  const bumpIndex = next.length > 1 ? 1 : 0
  next[bumpIndex] += 1
  for (let index = bumpIndex + 1; index < next.length; index += 1) {
    next[index] = 0
  }
  return parseVersion(next.join('.'))
}

function compareVersionStrings(leftVersion: string, rightVersion: string) {
  const left = parseVersion(leftVersion)
  const right = parseVersion(rightVersion)
  return compareParsedVersions(left, right)
}

function matchesComparator(
  currentVersion: string,
  operator: ComparatorOperator,
  targetVersion: string,
) {
  const comparison = compareVersionStrings(currentVersion, targetVersion)
  if (comparison === null) {
    return null
  }

  if (operator === '=') {
    return comparison === 0
  }

  if (operator === '!=') {
    return comparison !== 0
  }

  if (operator === '<') {
    return comparison < 0
  }

  if (operator === '<=') {
    return comparison <= 0
  }

  if (operator === '>') {
    return comparison > 0
  }

  if (operator === '>=') {
    return comparison >= 0
  }

  const current = parseVersion(currentVersion)
  const lower = parseVersion(targetVersion)
  const upper = buildUpperBound(lower, operator)
  const lowerComparison = compareParsedVersions(current, lower)
  const upperComparison = compareParsedVersions(current, upper)

  if (lowerComparison === null || upperComparison === null) {
    return null
  }

  return lowerComparison >= 0 && upperComparison < 0
}

function evaluateRangeExpression(version: string, expression: string): VersionEvaluation {
  const rawExpression = expression.trim()
  if (!rawExpression) {
    return 'unknown'
  }

  if (rawExpression.includes('||')) {
    let sawUnknown = false

    for (const branch of rawExpression.split('||')) {
      const result = evaluateRangeExpression(version, branch)
      if (result === 'affected') {
        return 'affected'
      }

      if (result === 'unknown') {
        sawUnknown = true
      }
    }

    return sawUnknown ? 'unknown' : 'unaffected'
  }

  const normalizedExpression = rawExpression.replace(/,\s*/g, ' ')
  const comparators = [...normalizedExpression.matchAll(comparatorPattern)]

  if (comparators.length === 0) {
    return normalizePackageName(version) === normalizePackageName(rawExpression)
      ? 'affected'
      : 'unknown'
  }

  let sawUnknown = false

  for (const comparator of comparators) {
    const operator = (comparator[1] ?? '=') as ComparatorOperator
    const targetVersion = comparator[2]
    const result = matchesComparator(version, operator, targetVersion)

    if (result === null) {
      sawUnknown = true
      continue
    }

    if (!result) {
      return 'unaffected'
    }
  }

  return sawUnknown ? 'unknown' : 'affected'
}

function normalizeAffectedVersionExpressions(affectedVersions: string[]) {
  const normalizedValues = affectedVersions
    .map((value) => value.trim())
    .filter((value) => value.length > 0)

  if (
    normalizedValues.length > 1 &&
    normalizedValues.every(
      (value) =>
        /^(<=|>=|<|>|==|=|!=|\^|~|~=)/.test(value) &&
        !value.includes(',') &&
        !value.includes(' '),
    )
  ) {
    return [normalizedValues.join(', ')]
  }

  return normalizedValues
}

function evaluateVersionAgainstDisclosure(args: {
  componentVersion: string
  affectedVersions: string[]
  fixVersion?: string
}) {
  const normalizedAffectedVersions = normalizeAffectedVersionExpressions(
    args.affectedVersions,
  )

  if (normalizedAffectedVersions.length > 0) {
    let sawUnknown = false

    for (const affectedVersion of normalizedAffectedVersions) {
      const evaluation = evaluateRangeExpression(
        args.componentVersion,
        affectedVersion,
      )

      if (evaluation === 'affected') {
        return 'affected' as const
      }

      if (evaluation === 'unknown') {
        sawUnknown = true
      }
    }

    return sawUnknown ? ('unknown' as const) : ('unaffected' as const)
  }

  if (!args.fixVersion) {
    return 'unknown' as const
  }

  const comparison = compareVersionStrings(args.componentVersion, args.fixVersion)
  if (comparison === null) {
    return 'unknown' as const
  }

  return comparison < 0 ? ('affected' as const) : ('unaffected' as const)
}

export function matchDisclosureToInventory(args: {
  packageName: string
  ecosystem?: string
  affectedVersions: string[]
  fixVersion?: string
  components: InventoryComponentForBreachMatch[]
}) {
  const normalizedPackageName = normalizePackageName(args.packageName)
  const normalizedEcosystem = normalizeEcosystem(args.ecosystem)
  const matchedComponents = args.components.filter((component) => {
    const componentName = component.normalizedName
      ? normalizePackageName(component.normalizedName)
      : normalizePackageName(component.name)

    if (componentName !== normalizedPackageName) {
      return false
    }

    if (normalizedEcosystem === 'unknown') {
      return true
    }

    return normalizeEcosystem(component.ecosystem) === normalizedEcosystem
  })

  if (matchedComponents.length === 0) {
    return {
      matchStatus: 'unmatched' as const,
      versionMatchStatus: 'unknown' as const,
      matchedComponents: [],
      affectedComponents: [],
      matchedComponentCount: 0,
      affectedComponentCount: 0,
      matchedVersions: [],
      affectedMatchedVersions: [],
      matchedSourceFiles: [],
      directComponentCount: 0,
      transitiveComponentCount: 0,
      containerComponentCount: 0,
    }
  }

  const affectedComponents: InventoryComponentForBreachMatch[] = []
  let sawUnknown = false

  for (const component of matchedComponents) {
    const evaluation = evaluateVersionAgainstDisclosure({
      componentVersion: component.version,
      affectedVersions: args.affectedVersions,
      fixVersion: args.fixVersion,
    })

    if (evaluation === 'affected') {
      affectedComponents.push(component)
      continue
    }

    if (evaluation === 'unknown') {
      sawUnknown = true
    }
  }

  const versionMatchStatus: BreachVersionMatchStatus =
    affectedComponents.length > 0
      ? 'affected'
      : sawUnknown
        ? 'unknown'
        : 'unaffected'

  return {
    matchStatus:
      affectedComponents.length > 0
        ? ('matched' as const)
        : sawUnknown
          ? ('version_unknown' as const)
          : ('version_unaffected' as const),
    versionMatchStatus,
    matchedComponents,
    affectedComponents,
    matchedComponentCount: matchedComponents.length,
    affectedComponentCount: affectedComponents.length,
    matchedVersions: uniqueStrings(
      matchedComponents.map((component) => component.version),
    ),
    affectedMatchedVersions: uniqueStrings(
      affectedComponents.map((component) => component.version),
    ),
    matchedSourceFiles: uniqueStrings(
      affectedComponents.map((component) => component.sourceFile),
    ),
    directComponentCount: affectedComponents.filter(
      (component) => component.isDirect || component.layer === 'direct',
    ).length,
    transitiveComponentCount: affectedComponents.filter(
      (component) => component.layer === 'transitive',
    ).length,
    containerComponentCount: affectedComponents.filter(
      (component) => component.layer === 'container',
    ).length,
  }
}

export function buildDisclosureMatchSummary({
  packageName,
  repositoryName,
  matchStatus,
  matchedComponentCount,
  affectedComponentCount,
  matchedVersions,
  affectedMatchedVersions,
  affectedVersions,
  fixVersion,
}: SummaryParams) {
  const normalizedAffectedVersions = normalizeAffectedVersionExpressions(
    affectedVersions,
  )

  if (matchStatus === 'no_snapshot') {
    return `No SBOM snapshot is available for ${repositoryName}, so ${packageName} could not be matched yet.`
  }

  if (matchStatus === 'unmatched') {
    return `${packageName} was not found in the latest SBOM snapshot for ${repositoryName}.`
  }

  const observedVersionSummary =
    matchedVersions.length > 0
      ? ` Observed versions: ${matchedVersions.join(', ')}.`
      : ''
  const affectedRangeSummary =
    normalizedAffectedVersions.length > 0
      ? ` Advisory ranges: ${normalizedAffectedVersions.join(' ; ')}.`
      : ''
  const fixVersionSummary = fixVersion ? ` Fixed in ${fixVersion}.` : ''

  if (matchStatus === 'version_unaffected') {
    return `Observed ${packageName} in ${repositoryName}, but ${matchedComponentCount} tracked component(s) are outside the affected advisory range.${observedVersionSummary}${affectedRangeSummary}${fixVersionSummary}`.trim()
  }

  if (matchStatus === 'version_unknown') {
    return `Observed ${packageName} in ${repositoryName}, but Sentinel could not prove whether the installed version is affected yet.${observedVersionSummary}${affectedRangeSummary}${fixVersionSummary}`.trim()
  }

  const affectedVersionSummary =
    affectedMatchedVersions.length > 0
      ? ` Affected installed versions: ${affectedMatchedVersions.join(', ')}.`
      : ''

  return `Matched ${packageName} to ${affectedComponentCount} affected tracked component(s) in ${repositoryName}.${affectedVersionSummary}${affectedRangeSummary}${fixVersionSummary}`.trim()
}

export function businessImpactScoreForSeverity(
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational',
  hasDirectExposure: boolean,
  exploitAvailable: boolean,
) {
  const baseScore =
    severity === 'critical'
      ? 94
      : severity === 'high'
        ? 82
        : severity === 'medium'
          ? 64
          : severity === 'low'
            ? 41
            : 22

  const directExposureBonus = hasDirectExposure ? 8 : 0
  const exploitBonus = exploitAvailable ? 6 : 0

  return Math.min(99, baseScore + directExposureBonus + exploitBonus)
}
