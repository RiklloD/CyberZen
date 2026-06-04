// Supply-chain intelligence — pure, no Convex dependencies.
// Analyses SBOM component metadata for maintainer trust signals and dependency
// chain characteristics that indicate elevated supply-chain risk:
//
//   - Typosquatting: package name ≤2 Levenshtein edits from a well-known target
//   - Suspicious name: single/two-char or random-hex name (malicious pack pattern)
//   - Vulnerable direct dep: CVE-tagged package the operator explicitly chose
//   - Untrusted direct dep: low trust-score on an explicitly chosen package
//   - High blast radius: widely-depended-on component amplifies any compromise
//
// Chain depth is estimated from the direct:transitive ratio and reported as a
// coarse 1–5 scale so the dashboard can show a single risk indicator.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SupplyChainComponentInput = {
  name: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  trustScore: number
  hasKnownVulnerabilities: boolean
  dependents: string[]
}

export type SupplyChainSignalKind =
  | 'typosquat_risk'
  | 'suspicious_name'
  | 'vulnerable_direct'
  | 'untrusted_direct_dep'
  | 'high_blast_radius'

export type SupplyChainSignalDetail = {
  kind: SupplyChainSignalKind
  weight: number
  description: string
}

export type ComponentSignal = {
  name: string
  version: string
  ecosystem: string
  isDirect: boolean
  riskScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  signals: SupplyChainSignalDetail[]
  summary: string
}

export type SupplyChainAnalysis = {
  /** Repository-level supply-chain risk score (0 = clean, 100 = high risk). */
  overallRiskScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  /** Components that triggered at least one risk signal, sorted by riskScore desc. */
  flaggedComponents: ComponentSignal[]
  /** Names of components identified as potential typosquats. */
  typosquatCandidates: string[]
  /**
   * Estimated transitive dependency chain depth (1–5 coarse scale).
   * Derived from the direct:transitive component ratio.
   */
  deepChainDepth: number
  summary: string
}

// ---------------------------------------------------------------------------
// Well-known package corpus for typosquat detection.
// These are the highest-value impersonation targets in each ecosystem.
// Keep alphabetically sorted within each list for maintainability.
// ---------------------------------------------------------------------------

const WELL_KNOWN: Record<string, string[]> = {
  npm: [
    'angular', 'axios', 'babel-core', 'chalk', 'commander', 'concurrently',
    'cors', 'cross-env', 'dotenv', 'eslint', 'express', 'helmet',
    'jest', 'jsonwebtoken', 'lodash', 'moment', 'mongoose', 'mocha',
    'next', 'nodemon', 'nuxt', 'passport', 'pm2', 'prettier',
    'prisma', 'react', 'rimraf', 'rollup', 'sequelize', 'svelte',
    'typescript', 'uuid', 'vite', 'vue', 'webpack',
  ],
  pypi: [
    'aiohttp', 'anthropic', 'black', 'boto3', 'celery', 'cryptography',
    'django', 'fastapi', 'flake8', 'flask', 'gunicorn', 'httpx',
    'mypy', 'numpy', 'openai', 'pandas', 'paramiko', 'pillow',
    'pip', 'pydantic', 'pytest', 'redis', 'requests', 'setuptools',
    'sqlalchemy', 'starlette', 'twine', 'uvicorn', 'wheel',
  ],
  cargo: [
    'actix-web', 'anyhow', 'axum', 'base64', 'chrono', 'clap',
    'env_logger', 'hex', 'hyper', 'log', 'rand', 'reqwest',
    'serde', 'thiserror', 'tokio', 'tracing', 'uuid',
  ],
  go: [
    'chi', 'cobra', 'echo', 'fiber', 'gin', 'gorm',
    'logrus', 'prometheus', 'testify', 'viper', 'zap',
  ],
}

// ---------------------------------------------------------------------------
// Levenshtein distance, bounded at `bound` for early exit performance.
// Returns bound+1 when the true distance exceeds the bound.
// ---------------------------------------------------------------------------

function levenshteinBounded(a: string, b: string, bound: number): number {
  if (Math.abs(a.length - b.length) > bound) return bound + 1

  const prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  const curr = new Array<number>(b.length + 1)

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i
    for (let j = 1; j <= b.length; j++) {
      curr[j] =
        a[i - 1] === b[j - 1]
          ? prev[j - 1]
          : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1])
    }
    for (let k = 0; k <= b.length; k++) prev[k] = curr[k]
  }

  return prev[b.length]
}

function normalizePackageName(name: string): string {
  // Strip npm scope (@scope/), lower-case, collapse separators
  return name
    .replace(/^@[^/]+\//, '')
    .toLowerCase()
    .replace(/[-_.]/g, '')
}

function isTyposquatRisk(name: string, ecosystem: string): boolean {
  const normalized = normalizePackageName(name)
  const corpus = WELL_KNOWN[ecosystem] ?? []

  for (const known of corpus) {
    const normalizedKnown = normalizePackageName(known)
    if (normalized === normalizedKnown) return false // exact match → not a typosquat
    const dist = levenshteinBounded(normalized, normalizedKnown, 2)
    if (dist > 0 && dist <= 2) return true
  }
  return false
}

function isSuspiciousName(name: string): boolean {
  const bare = normalizePackageName(name)
  if (bare.length <= 2) return true         // single/two-char names
  if (/^\d+$/.test(bare)) return true        // purely numeric
  if (/^[0-9a-f]{8,}$/.test(bare)) return true // random-looking hex string
  return false
}

function riskScoreToLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 70) return 'critical'
  if (score >= 45) return 'high'
  if (score >= 20) return 'medium'
  return 'low'
}

// ---------------------------------------------------------------------------
// Per-component analysis
// ---------------------------------------------------------------------------

function analyzeComponent(c: SupplyChainComponentInput): ComponentSignal | null {
  const signals: SupplyChainSignalDetail[] = []

  if (isTyposquatRisk(c.name, c.ecosystem)) {
    signals.push({
      kind: 'typosquat_risk',
      weight: 40,
      description:
        `"${c.name}" is typographically close to a well-known ${c.ecosystem} package — ` +
        `possible typosquat. Verify the package origin before allowing it into the build.`,
    })
  }

  if (isSuspiciousName(c.name)) {
    signals.push({
      kind: 'suspicious_name',
      weight: 25,
      description:
        `"${c.name}" has an unusually short or opaque name — a pattern common in ` +
        `malicious packages designed to blend in.`,
    })
  }

  if (c.isDirect && c.hasKnownVulnerabilities) {
    signals.push({
      kind: 'vulnerable_direct',
      weight: 35,
      description:
        `Direct dependency "${c.name}" has known vulnerabilities and is an explicit ` +
        `operator choice — this is the highest-exposure supply-chain risk.`,
    })
  }

  if (c.isDirect && c.trustScore < 40) {
    signals.push({
      kind: 'untrusted_direct_dep',
      weight: 28,
      description:
        `Direct dependency "${c.name}" has a low trust score (${c.trustScore}/100), ` +
        `indicating maintenance, reputation, or age concerns.`,
    })
  }

  if (c.dependents.length >= 5) {
    signals.push({
      kind: 'high_blast_radius',
      weight: 15,
      description:
        `"${c.name}" is depended on by ${c.dependents.length} downstream ` +
        `services or packages — a compromise would have wide blast radius.`,
    })
  }

  if (signals.length === 0) return null

  const rawScore = signals.reduce((acc, s) => acc + s.weight, 0)
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = riskScoreToLevel(riskScore)

  // Sort signals by weight so the top signal is reported as the component summary
  const sorted = [...signals].sort((a, b) => b.weight - a.weight)

  return {
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    isDirect: c.isDirect,
    riskScore,
    riskLevel,
    signals: sorted,
    summary: sorted[0].description,
  }
}

// ---------------------------------------------------------------------------
// Chain depth estimator
// ---------------------------------------------------------------------------

function estimateChainDepth(components: SupplyChainComponentInput[]): number {
  const directCount = components.filter((c) => c.isDirect).length
  const transitiveCount = components.filter((c) => !c.isDirect).length
  if (directCount === 0) return 0
  const ratio = transitiveCount / directCount
  if (ratio > 20) return 5
  if (ratio > 10) return 4
  if (ratio > 5) return 3
  if (ratio > 2) return 2
  return 1
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function analyzeSupplyChain(
  components: SupplyChainComponentInput[],
): SupplyChainAnalysis {
  if (components.length === 0) {
    return {
      overallRiskScore: 0,
      riskLevel: 'low',
      flaggedComponents: [],
      typosquatCandidates: [],
      deepChainDepth: 0,
      summary: 'No components to analyse.',
    }
  }

  const flaggedComponents: ComponentSignal[] = []
  const typosquatCandidates: string[] = []

  for (const component of components) {
    const signal = analyzeComponent(component)
    if (signal) {
      flaggedComponents.push(signal)
      if (signal.signals.some((s) => s.kind === 'typosquat_risk')) {
        typosquatCandidates.push(component.name)
      }
    }
  }

  // Sort flagged components by risk score descending
  flaggedComponents.sort((a, b) => b.riskScore - a.riskScore)

  const deepChainDepth = estimateChainDepth(components)

  // Repository-level risk: weight average flagged score by the flagged proportion.
  // A repo where 5% of components are flagged is safer than one where 50% are.
  const flaggedRatio = flaggedComponents.length / components.length
  const avgFlaggedScore =
    flaggedComponents.length > 0
      ? Math.round(
          flaggedComponents.reduce((acc, c) => acc + c.riskScore, 0) / flaggedComponents.length,
        )
      : 0
  const overallRiskScore = Math.round(avgFlaggedScore * flaggedRatio)
  const riskLevel = riskScoreToLevel(overallRiskScore)

  const criticalCount = flaggedComponents.filter((c) => c.riskLevel === 'critical').length
  const highCount = flaggedComponents.filter((c) => c.riskLevel === 'high').length

  const summary =
    flaggedComponents.length === 0
      ? `Supply chain appears healthy: ${components.length} component(s) analysed, no risk signals detected.`
      : [
          `Supply chain risk detected: ${flaggedComponents.length}/${components.length} component(s) flagged.`,
          criticalCount > 0 ? ` ${criticalCount} critical.` : '',
          highCount > 0 ? ` ${highCount} high.` : '',
          typosquatCandidates.length > 0
            ? ` Possible typosquats: ${typosquatCandidates.join(', ')}.`
            : '',
        ].join('')

  return {
    overallRiskScore,
    riskLevel,
    flaggedComponents,
    typosquatCandidates,
    deepChainDepth,
    summary,
  }
}
