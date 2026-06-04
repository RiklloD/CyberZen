// WS-41 — Dependency Confusion Attack Detector: pure computation library.
//
// A dependency confusion attack (Alex Birsan, 2021) exploits how package managers
// resolve names present in both private and public registries: many tools pick
// the highest version. The attacker registers a public package named after an
// internal dependency at an artificially inflated version (e.g. 9999.0.1) and
// waits for CI/CD pipelines to pull it.
//
// Detection strategy (purely static — no network calls):
//   1. Extract the major version from the component's version string.
//   2. Flag packages whose major version exceeds suspicious thresholds.
//   3. Weight signals by whether the name looks internal (scope, prefix, suffix).
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/**
 * Npm scopes known to belong to legitimate public open-source projects.
 * Scoped packages NOT in this list that carry a high major version are
 * candidates for dependency confusion.
 */
export const KNOWN_PUBLIC_NPM_SCOPES = new Set<string>([
  '@babel', '@jest', '@types', '@typescript-eslint', '@jridgewell', '@nicolo-ribaudo',
  '@angular', '@angular-devkit', '@angular-eslint',
  '@vue', '@nuxt', '@vueuse',
  '@react', '@reactflow',
  '@storybook', '@chromatic',
  '@firebase', '@google-cloud', '@google', '@googleapis',
  '@microsoft', '@azure', '@fluentui',
  '@aws-sdk', '@aws-amplify', '@smithy', '@aws-cdk',
  '@mui', '@emotion', '@radix-ui', '@headlessui', '@heroicons',
  '@tailwindcss', '@shadcn',
  '@prisma',
  '@supabase',
  '@convex-dev',
  '@planetscale',
  '@vercel', '@sveltejs', '@remix-run',
  '@tanstack', '@trpc',
  '@next',
  '@sentry', '@amplitude', '@segment',
  '@rollup', '@vite', '@vitest', '@esbuild', '@turbopack',
  '@testing-library', '@playwright', '@cypress',
  '@graphql-tools', '@graphql-codegen', '@apollo',
  '@hono', '@fastify', '@nestjs', '@grpc',
  '@deno', '@bun',
  '@opentelemetry', '@datadog', '@honeycombio',
  '@nrwl', '@nx',
  '@octokit',
  '@noble', '@scure', '@ethersproject', '@openzeppelin',
  '@capacitor', '@ionic',
  '@reduxjs',
  '@clerk', '@auth0', '@workos-inc',
  '@stripe',
  '@upstash', '@neon-tech',
  '@langchain', '@anthropic-ai', '@openai',
])

/**
 * Name patterns (applied to bare name, stripping scope) that suggest
 * the package is intended to be internal/private.
 */
export const INTERNAL_NAME_PATTERNS: RegExp[] = [
  /^internal[_-]/i,
  /[_-]internal$/i,
  /^private[_-]/i,
  /[_-]private$/i,
  /^corp[_-]/i,
  /[_-]corp$/i,
  /^company[_-]/i,
  /[_-]company$/i,
  /^enterprise[_-]/i,
  /[_-]enterprise$/i,
  /^intranet[_-]/i,
  /[_-]intranet$/i,
]

/** Major version >= this is a textbook confusion attack signature. */
export const EXTREME_VERSION_THRESHOLD = 9000

/** Major version >= this AND scope not known public is high risk. */
export const HIGH_VERSION_THRESHOLD = 99

/** Major version >= this AND name matches internal pattern is medium risk. */
export const MEDIUM_VERSION_THRESHOLD = 49

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ConfusionSignal =
  | 'extreme_version'            // major ≥ 9000: textbook Birsan attack
  | 'high_version_unknown_scope' // npm-scoped, scope not known public, major ≥ 99
  | 'high_version_internal_name' // name matches internal pattern, major ≥ 49

export type ConfusionRiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type ConfusionFinding = {
  packageName: string
  ecosystem: string
  version: string
  signals: ConfusionSignal[]
  riskLevel: ConfusionRiskLevel
  title: string
  description: string
  /** Machine-readable evidence string for audit logs. */
  evidence: string
}

export type ConfusionReport = {
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalSuspicious: number
  overallRisk: ConfusionRiskLevel | 'none'
  findings: ConfusionFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

/**
 * Extract the npm scope from a scoped package name.
 * `@babel/core` → `@babel`; `express` → null.
 */
export function parseNpmScope(name: string): string | null {
  if (!name.startsWith('@')) return null
  const slashIdx = name.indexOf('/')
  if (slashIdx <= 1) return null // bare `@` or `@/` edge cases
  return name.slice(0, slashIdx).toLowerCase()
}

/**
 * Return true when the scope belongs to a known legitimate public project.
 * Case-insensitive.
 */
export function isKnownPublicNpmScope(scope: string): boolean {
  return KNOWN_PUBLIC_NPM_SCOPES.has(scope.toLowerCase())
}

/**
 * Parse the major version number from a version string.
 * Handles semver (`1.2.3`), v-prefixed (`v1.2.3`), and partial (`1.2`, `1`).
 * Returns null for unparseable strings (e.g., `latest`, `*`).
 */
export function parseMajorVersion(version: string): number | null {
  const match = /^v?(\d+)/.exec(version.trim())
  if (!match) return null
  const n = parseInt(match[1], 10)
  return isNaN(n) ? null : n
}

/**
 * Return true when the package name (or its bare name after stripping scope)
 * matches any internal/private naming convention.
 */
export function looksLikeInternalPackage(name: string): boolean {
  // Strip scope to get the bare package name
  const bare = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name
  return INTERNAL_NAME_PATTERNS.some((re) => re.test(bare))
}

// ---------------------------------------------------------------------------
// Core detector
// ---------------------------------------------------------------------------

/**
 * Examine a single SBOM component for dependency confusion indicators.
 * Returns a `ConfusionFinding` when one or more signals fire, null otherwise.
 */
export function checkConfusionAttack(component: {
  name: string
  version: string
  ecosystem: string
}): ConfusionFinding | null {
  const { name, version, ecosystem } = component

  const majorVersion = parseMajorVersion(version)
  if (majorVersion === null) return null

  const signals: ConfusionSignal[] = []

  // ── Signal 1: Extreme version (all ecosystems) ───────────────────────────
  if (majorVersion >= EXTREME_VERSION_THRESHOLD) {
    signals.push('extreme_version')
  }

  // ── Signal 2: npm-scoped package with unknown scope + high version ───────
  if (ecosystem === 'npm') {
    const scope = parseNpmScope(name)
    if (scope !== null && !isKnownPublicNpmScope(scope) && majorVersion >= HIGH_VERSION_THRESHOLD) {
      signals.push('high_version_unknown_scope')
    }
  }

  // ── Signal 3: Name matches internal pattern + suspicious version (all ecosystems) ──
  if (looksLikeInternalPackage(name) && majorVersion >= MEDIUM_VERSION_THRESHOLD) {
    signals.push('high_version_internal_name')
  }

  if (signals.length === 0) return null

  // ── Classify risk level ───────────────────────────────────────────────────
  let riskLevel: ConfusionRiskLevel

  if (signals.includes('extreme_version')) {
    riskLevel = 'critical'
  } else if (
    signals.includes('high_version_unknown_scope') && majorVersion >= 500
  ) {
    riskLevel = 'high'
  } else if (
    signals.includes('high_version_internal_name') && majorVersion >= HIGH_VERSION_THRESHOLD
  ) {
    riskLevel = 'high'
  } else if (
    signals.includes('high_version_unknown_scope') ||
    signals.includes('high_version_internal_name')
  ) {
    riskLevel = 'medium'
  } else {
    riskLevel = 'low'
  }

  const scope = ecosystem === 'npm' ? parseNpmScope(name) : null

  return {
    packageName: name,
    ecosystem,
    version,
    signals,
    riskLevel,
    title: buildTitle(riskLevel, signals),
    description: buildDescription(name, signals, majorVersion, ecosystem, scope),
    evidence: `package=${name} version=${version} major=${majorVersion} ecosystem=${ecosystem} signals=[${signals.join(',')}]`,
  }
}

// ---------------------------------------------------------------------------
// Report aggregator
// ---------------------------------------------------------------------------

/**
 * Run confusion attack detection across the full SBOM component list.
 * Deduplicates by `ecosystem:name:version` before scanning.
 */
export function computeConfusionReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
): ConfusionReport {
  // Deduplicate
  const seen = new Set<string>()
  const unique: typeof components = []
  for (const c of components) {
    const key = `${c.ecosystem.toLowerCase()}:${c.name.toLowerCase()}@${c.version}`
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(c)
    }
  }

  const findings: ConfusionFinding[] = []
  for (const c of unique) {
    const finding = checkConfusionAttack(c)
    if (finding) findings.push(finding)
  }

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length
  const totalSuspicious = findings.length

  let overallRisk: ConfusionRiskLevel | 'none' = 'none'
  if (criticalCount > 0) overallRisk = 'critical'
  else if (highCount > 0) overallRisk = 'high'
  else if (mediumCount > 0) overallRisk = 'medium'
  else if (lowCount > 0) overallRisk = 'low'

  return {
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalSuspicious,
    overallRisk,
    findings,
    summary: buildReportSummary(totalSuspicious, criticalCount, highCount, mediumCount),
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function buildTitle(_riskLevel: ConfusionRiskLevel, signals: ConfusionSignal[]): string {
  if (signals.includes('extreme_version')) {
    return 'Possible dependency confusion attack — extreme version number'
  }
  if (signals.includes('high_version_unknown_scope')) {
    return 'Possible dependency confusion attack — suspicious scoped package version'
  }
  return 'Internal-looking package with suspicious version'
}

function buildDescription(
  name: string,
  signals: ConfusionSignal[],
  majorVersion: number,
  ecosystem: string,
  scope: string | null,
): string {
  if (signals.includes('extreme_version')) {
    return (
      `"${name}" has a major version of ${majorVersion}, which is an extreme outlier consistent with a dependency confusion attack — where a malicious actor publishes to a public ${ecosystem} registry at an artificially inflated version to hijack resolution over an internal private package.`
    )
  }
  if (signals.includes('high_version_unknown_scope')) {
    return (
      `"${name}" belongs to the ${scope ?? 'unknown'} scope, which is not a recognised public open-source npm scope, yet its major version (${majorVersion}) is unusually high. This pattern suggests a possible dependency confusion attack against an internal ${scope} package.`
    )
  }
  return (
    `"${name}" appears to be an internal or private package based on its name, yet carries a major version of ${majorVersion}. Legitimate internal packages rarely exceed major version 10–20. This may indicate a public package with a similar name has been injected at an elevated version.`
  )
}

function buildReportSummary(
  total: number,
  critical: number,
  high: number,
  medium: number,
): string {
  if (total === 0) return 'No dependency confusion indicators detected.'
  const parts: string[] = [
    `${total} package${total === 1 ? '' : 's'} with dependency confusion indicators detected.`,
  ]
  if (critical > 0) parts.push(`${critical} critical (extreme version numbers consistent with a confusion attack).`)
  if (high > 0) parts.push(`${high} high (suspicious version/scope combination).`)
  if (medium > 0) parts.push(`${medium} medium (internal naming with elevated version).`)
  return parts.join(' ')
}
