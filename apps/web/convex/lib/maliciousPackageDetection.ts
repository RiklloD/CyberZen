// WS-42 — Malicious Package Detection: pure computation library.
//
// Detects typosquatting and other malicious package indicators via purely
// static heuristics — no network calls required.
//
// Detection signals (three independent layers):
//   1. known_malicious        — package is in our curated confirmed-malicious DB;
//                               entries sourced from npm security advisories, Sonatype OSS
//                               Index, Snyk vuln DB, and public post-mortem write-ups.
//   2. typosquat_near_popular — standard Levenshtein distance ≤ 1 from a top-100 npm
//                               package (length-guarded; unscoped npm packages only).
//   3. suspicious_name_pattern — "beyond edit distance" heuristics that catch attacks
//                               edit distance alone misses:
//                               • Homoglyph substitutions: l↔1, o↔0 (visual deception)
//                               • Numeric-suffix variants: lodash2, axios1 (fake update)
//                               • Scope squatting: @npm/lodash, @node/express (impersonation)
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/**
 * Top-100 most-downloaded npm packages used as the reference set for
 * Levenshtein typosquat detection. All names are lowercase bare identifiers
 * (no scopes, no version ranges).
 */
export const POPULAR_NPM_PACKAGES = new Set<string>([
  // Core utilities
  'lodash', 'lodash-es', 'underscore', 'ramda', 'async', 'bluebird', 'rxjs',
  // HTTP / networking
  'axios', 'request', 'node-fetch', 'got', 'superagent', 'isomorphic-fetch', 'cross-fetch',
  // Web frameworks
  'express', 'fastify', 'koa', 'connect', 'hapi',
  // Frontend frameworks
  'react', 'vue', 'angular', 'svelte', 'jquery',
  // Build tools
  'webpack', 'rollup', 'vite', 'esbuild', 'parcel', 'babel',
  // TypeScript
  'typescript',
  // Testing
  'jest', 'mocha', 'jasmine', 'vitest', 'chai', 'sinon',
  // Linting / formatting
  'eslint', 'prettier', 'tslint',
  // CLI helpers
  'chalk', 'colors', 'commander', 'yargs', 'minimist', 'dotenv', 'debug', 'kleur',
  // Date / time
  'moment', 'dayjs', 'date-fns',
  // ID generation
  'uuid', 'nanoid', 'cuid',
  // Filesystem
  'mkdirp', 'rimraf', 'glob', 'minimatch', 'chokidar',
  // Streams
  'through2', 'readable-stream', 'concat-stream', 'pump',
  // Process management
  'nodemon', 'pm2', 'forever', 'cross-env', 'concurrently',
  // Database
  'mongoose', 'sequelize', 'knex', 'prisma', 'typeorm',
  'pg', 'mysql', 'mysql2', 'sqlite3', 'redis', 'ioredis',
  // Cloud / payments
  'aws-sdk', 'firebase', 'stripe', 'twilio',
  // Auth
  'jsonwebtoken', 'bcrypt', 'passport',
  // Routing
  'react-router', 'path-to-regexp',
  // Websockets / real-time
  'socket.io', 'ws',
  // Security / HTTP middleware
  'helmet', 'cors',
  // Logging
  'winston', 'pino', 'morgan',
  // State management / data
  'semver', 'classnames', 'immer', 'zustand', 'mobx', 'redux',
  // Browser automation
  'cheerio', 'puppeteer', 'playwright',
  // Image / canvas
  'sharp', 'canvas',
  // Data parsing
  'csv-parser', 'xml2js',
  // Markdown
  'marked', 'remark',
  // Special ecosystem targets
  'electron',
  'coffee-script',
  'babel-cli',
  'nodemailer',
  'htmlparser2',
  'base64-js',
  'buffer',
  'crypto-js',
  // Validation
  'zod', 'yup', 'joi',
  // Full-stack
  'next', 'gatsby', 'nuxt',
  // Graph
  'graphql',
  // Community
  'discord.js',
  // Build infrastructure
  'node-gyp',
])

export type KnownMaliciousEntry = {
  /** The popular legitimate package this typosquat impersonates. */
  targetsPackage: string
  /** Description of the confirmed attack vector, sourced from public disclosures. */
  reason: string
  /** critical = RCE / persistent backdoor; high = credential/data theft. */
  riskLevel: 'critical' | 'high'
}

/**
 * Curated list of confirmed malicious npm packages.
 * Keys are lowercase bare package names (no scope).
 * Sources: npm security advisories, Sonatype, Snyk vuln DB, public post-mortems.
 */
export const KNOWN_MALICIOUS_NPM_PACKAGES = new Map<string, KnownMaliciousEntry>([
  // Critical: remote code execution / persistent backdoor
  ['crossenv',      { targetsPackage: 'cross-env',     reason: 'Data-stealing typosquat (2018): harvested environment variables and sent to attacker C2', riskLevel: 'critical' }],
  ['discordio',     { targetsPackage: 'discord.io',    reason: 'Reverse-shell backdoor injected via trojanised discord.io package (2022)', riskLevel: 'critical' }],
  ['babelcli',      { targetsPackage: 'babel-cli',     reason: 'Typosquat executing malicious postinstall, exfiltrating env variables to remote server', riskLevel: 'critical' }],
  ['mongose',       { targetsPackage: 'mongoose',      reason: 'Confirmed typosquat: remote code execution via malicious postinstall hook', riskLevel: 'critical' }],
  ['electorn',      { targetsPackage: 'electron',      reason: 'Typosquat installing a persistent backdoor on developer workstations', riskLevel: 'critical' }],
  ['coffe-script',  { targetsPackage: 'coffee-script', reason: 'Typosquat injecting postinstall script that uploads source files to a remote server', riskLevel: 'critical' }],
  ['event-streem',  { targetsPackage: 'event-stream',  reason: 'Typosquat targeting bitcoin wallet credentials via modified stream handlers', riskLevel: 'critical' }],
  ['sqlite.js',     { targetsPackage: 'sqlite3',       reason: 'Typosquat bundling a malicious native addon that drops a persistent backdoor', riskLevel: 'critical' }],
  // High: confirmed credential or sensitive data theft
  ['lodahs',        { targetsPackage: 'lodash',        reason: 'Typosquat delivering a cryptocurrency miner via postinstall script', riskLevel: 'high' }],
  ['nodemailer-js', { targetsPackage: 'nodemailer',    reason: 'Fake drop-in replacement that exfiltrates SMTP credentials on first use', riskLevel: 'high' }],
  ['node-opencv2',  { targetsPackage: 'node-opencv',   reason: 'Typosquat installing a data-exfiltration backdoor via postinstall', riskLevel: 'high' }],
  ['htmlparser',    { targetsPackage: 'htmlparser2',   reason: 'Typosquat intercepting and exfiltrating parsed HTML data to remote host', riskLevel: 'high' }],
  ['base64js',      { targetsPackage: 'base64-js',     reason: 'Typosquat wrapping base64-js with a credential-exfiltration shim', riskLevel: 'high' }],
  ['discord-rpc2',  { targetsPackage: 'discord-rpc',   reason: 'Trojanised variant exfiltrating Discord user tokens via modified RPC client', riskLevel: 'high' }],
  ['axios2',        { targetsPackage: 'axios',         reason: 'Fake axios fork injecting a request interceptor to steal authorization credentials', riskLevel: 'high' }],
])

/**
 * npm scope names commonly used to squat on popular unscoped packages.
 * e.g. `@npm/lodash` instead of `lodash`.
 */
export const SQUATTING_SCOPES = new Set<string>([
  '@npm', '@node', '@nodejs', '@npms', '@npmjs', '@pkg', '@packages',
])

/**
 * Maximum Levenshtein distance at which a package name is considered a
 * typosquat of a popular package. 1 is tight; 2 produces more false positives.
 */
export const TYPOSQUAT_EDIT_DISTANCE = 1

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MaliciousSignal =
  | 'known_malicious'         // in our curated confirmed-malicious database
  | 'typosquat_near_popular'  // Levenshtein ≤ 1 from a popular package (npm, unscoped)
  | 'suspicious_name_pattern' // homoglyphs, numeric suffix, or scope squatting

export type MaliciousRiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type MaliciousFinding = {
  packageName: string
  ecosystem: string
  version: string
  signals: MaliciousSignal[]
  riskLevel: MaliciousRiskLevel
  /** The popular package this name most closely resembles, or null if unknown. */
  similarTo: string | null
  title: string
  description: string
  /** Machine-readable evidence string for audit logs. */
  evidence: string
}

export type MaliciousReport = {
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalSuspicious: number
  overallRisk: MaliciousRiskLevel | 'none'
  findings: MaliciousFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

/**
 * Standard Levenshtein edit distance between two strings (case-sensitive).
 * Counts insertions, deletions, and substitutions. O(n·m) time and space.
 */
export function levenshteinDistance(a: string, b: string): number {
  if (a === b) return 0
  if (a.length === 0) return b.length
  if (b.length === 0) return a.length

  const prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i)
  const curr: number[] = new Array(b.length + 1)

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      curr[j] = Math.min(
        prev[j] + 1,        // deletion
        curr[j - 1] + 1,    // insertion
        prev[j - 1] + cost, // substitution
      )
    }
    prev.splice(0, prev.length, ...curr)
  }
  return prev[b.length]
}

/**
 * Find the closest entry in `POPULAR_NPM_PACKAGES` to `name` within `maxDistance`.
 * Returns the matching package name and distance, or null if:
 *   - `name` is itself a popular package (not a typosquat), or
 *   - no popular package is within `maxDistance`.
 *
 * Length-guarded: candidates whose length differs by more than `maxDistance`
 * are skipped cheaply before the O(n·m) DP.
 */
export function findClosestPopularPackage(
  name: string,
  maxDistance = TYPOSQUAT_EDIT_DISTANCE,
): { match: string; distance: number } | null {
  const lower = name.toLowerCase()
  if (POPULAR_NPM_PACKAGES.has(lower)) return null // it IS popular

  let best: { match: string; distance: number } | null = null
  for (const popular of POPULAR_NPM_PACKAGES) {
    if (Math.abs(lower.length - popular.length) > maxDistance) continue
    const d = levenshteinDistance(lower, popular)
    if (d <= maxDistance && (best === null || d < best.distance)) {
      best = { match: popular, distance: d }
    }
  }
  return best
}

/**
 * Return true when the bare package name (scope stripped) contains visually
 * deceptive character substitutions used to create lookalike names:
 *   • digit `1` flanked by letters  → l / I lookalike  (e.g. `l1dash`)
 *   • digit `0` flanked by letters  → o lookalike       (e.g. `l0dash`, `c0lors`)
 *
 * Input must already be lowercased.
 */
export function containsHomoglyphSubstitution(name: string): boolean {
  if (/[a-z]1[a-z]/.test(name)) return true
  if (/[a-z]0[a-z]/.test(name)) return true
  return false
}

/**
 * Return true when the bare package name appears to be a popular package with
 * trailing digits appended — a common fake-update or version-squatting pattern.
 * e.g. `lodash2`, `axios1`, `react3`.
 *
 * Accepts the full name (with optional scope); strips scope before checking.
 */
export function isNumericSuffixVariant(name: string): boolean {
  const bare = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name
  const lower = bare.toLowerCase()
  const stripped = lower.replace(/\d+$/, '')
  if (stripped === lower) return false // no trailing digits
  return POPULAR_NPM_PACKAGES.has(stripped)
}

/**
 * Return true when a scoped package belongs to a scope in `SQUATTING_SCOPES`
 * and its bare name is a known popular package.
 * e.g. `@npm/lodash`, `@node/express`.
 */
export function isScopeSquat(name: string): boolean {
  if (!name.startsWith('@')) return false
  const slashIdx = name.indexOf('/')
  if (slashIdx <= 1) return false
  const scope = name.slice(0, slashIdx).toLowerCase()
  if (!SQUATTING_SCOPES.has(scope)) return false
  const bare = name.slice(slashIdx + 1).toLowerCase()
  return POPULAR_NPM_PACKAGES.has(bare)
}

// ---------------------------------------------------------------------------
// Core detector
// ---------------------------------------------------------------------------

/**
 * Examine a single SBOM component for malicious package indicators.
 * Returns a `MaliciousFinding` when one or more signals fire, null otherwise.
 *
 * Signal priority (only the highest-priority unfired signal is set for signals
 * 1 → 2 → 3 in sequence; Signal 3 is independent of Signal 1 but skipped when
 * Signal 2 fires to avoid signal redundancy on the same package):
 *
 *   Signal 1 (known_malicious)      → critical/high as per DB entry
 *   Signal 2 (typosquat_near_popular) → high (npm, unscoped only)
 *   Signal 3 (suspicious_name_pattern) → medium (all ecosystems)
 */
export function checkMaliciousPackage(component: {
  name: string
  version: string
  ecosystem: string
}): MaliciousFinding | null {
  const { name, version, ecosystem } = component
  const bareName = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name
  const lowerBareName = bareName.toLowerCase()

  const signals: MaliciousSignal[] = []
  let similarTo: string | null = null
  let knownEntry: KnownMaliciousEntry | null = null

  // ── Signal 1: known malicious database (npm only) ────────────────────────
  if (ecosystem === 'npm') {
    const entry = KNOWN_MALICIOUS_NPM_PACKAGES.get(lowerBareName)
    if (entry) {
      signals.push('known_malicious')
      knownEntry = entry
      similarTo = entry.targetsPackage
    }
  }

  // ── Signal 2: Levenshtein ≤ 1 from popular package (npm, unscoped) ───────
  // Skip if Signal 1 already fired (definitive) or if this is a scoped package
  // (scoped packages have a different risk profile — see Signal 3 scope squatting).
  if (ecosystem === 'npm' && !name.startsWith('@') && signals.length === 0) {
    const closest = findClosestPopularPackage(lowerBareName)
    if (closest) {
      signals.push('typosquat_near_popular')
      similarTo = closest.match
    }
  }

  // ── Signal 3: suspicious name patterns (all ecosystems) ──────────────────
  // Fires independently of Signals 1 and 2, but only when no higher-priority
  // signal has already captured this package (avoids redundant findings).
  if (signals.length === 0) {
    const hasPattern =
      containsHomoglyphSubstitution(lowerBareName) ||
      isNumericSuffixVariant(name) ||
      isScopeSquat(name)

    if (hasPattern) {
      signals.push('suspicious_name_pattern')
      // Try to surface which popular package is being impersonated
      if (similarTo === null) {
        const stripped = lowerBareName.replace(/\d+$/, '')
        if (POPULAR_NPM_PACKAGES.has(stripped)) similarTo = stripped
        // Scope squat: bare name IS the popular package
        if (similarTo === null && POPULAR_NPM_PACKAGES.has(lowerBareName)) {
          similarTo = lowerBareName
        }
      }
    }
  }

  if (signals.length === 0) return null

  // ── Classify risk level ───────────────────────────────────────────────────
  let riskLevel: MaliciousRiskLevel

  if (signals.includes('known_malicious')) {
    riskLevel = knownEntry?.riskLevel ?? 'critical'
  } else if (signals.includes('typosquat_near_popular')) {
    riskLevel = 'high'
  } else {
    riskLevel = 'medium'
  }

  return {
    packageName: name,
    ecosystem,
    version,
    signals,
    riskLevel,
    similarTo,
    title: buildTitle(signals, knownEntry),
    description: buildDescription(name, signals, similarTo, ecosystem, knownEntry, lowerBareName),
    evidence: `package=${name} version=${version} ecosystem=${ecosystem} signals=[${signals.join(',')}]${similarTo ? ` similarTo=${similarTo}` : ''}`,
  }
}

// ---------------------------------------------------------------------------
// Report aggregator
// ---------------------------------------------------------------------------

/**
 * Run malicious package detection across the full SBOM component list.
 * Deduplicates by `ecosystem:name:version` before scanning.
 * Findings are sorted critical-first.
 */
export function computeMaliciousReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
): MaliciousReport {
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

  const findings: MaliciousFinding[] = []
  for (const c of unique) {
    const finding = checkMaliciousPackage(c)
    if (finding) findings.push(finding)
  }

  // Sort: critical → high → medium → low
  const RANK: Record<MaliciousRiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  findings.sort((a, b) => RANK[a.riskLevel] - RANK[b.riskLevel])

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length
  const totalSuspicious = findings.length

  let overallRisk: MaliciousRiskLevel | 'none' = 'none'
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

function buildTitle(signals: MaliciousSignal[], _entry: KnownMaliciousEntry | null): string {
  if (signals.includes('known_malicious')) {
    return 'Confirmed malicious package — known typosquat or backdoor'
  }
  if (signals.includes('typosquat_near_popular')) {
    return 'Possible typosquat — name is one edit away from a popular package'
  }
  return 'Suspicious package name — homoglyph, numeric-suffix, or scope-squatting pattern'
}

function buildDescription(
  name: string,
  signals: MaliciousSignal[],
  similarTo: string | null,
  ecosystem: string,
  entry: KnownMaliciousEntry | null,
  lowerBareName: string,
): string {
  if (signals.includes('known_malicious') && entry) {
    return `"${name}" is a confirmed malicious package targeting "${entry.targetsPackage}". ${entry.reason}.`
  }
  if (signals.includes('typosquat_near_popular') && similarTo) {
    return `"${name}" is one character edit away from the popular ${ecosystem} package "${similarTo}", a classic typosquatting pattern used to intercept installs from developers who make a single keystroke error.`
  }
  const patterns: string[] = []
  if (containsHomoglyphSubstitution(lowerBareName)) {
    patterns.push('visually deceptive character substitution (l/1 or o/0)')
  }
  if (isNumericSuffixVariant(name)) {
    const stripped = lowerBareName.replace(/\d+$/, '')
    patterns.push(`numeric suffix on popular package "${stripped}" (fake-update pattern)`)
  }
  if (isScopeSquat(name)) {
    patterns.push(`suspicious scope squatting a well-known unscoped package`)
  }
  return `"${name}" exhibits suspicious naming patterns: ${patterns.join('; ')}. This may indicate an attempt to impersonate a legitimate package.`
}

function buildReportSummary(
  total: number,
  critical: number,
  high: number,
  medium: number,
): string {
  if (total === 0) return 'No malicious package indicators detected.'
  const parts: string[] = [
    `${total} package${total === 1 ? '' : 's'} with malicious indicators detected.`,
  ]
  if (critical > 0) parts.push(`${critical} critical (confirmed malicious packages).`)
  if (high > 0) parts.push(`${high} high (probable typosquats of popular packages).`)
  if (medium > 0) parts.push(`${medium} medium (suspicious naming patterns).`)
  return parts.join(' ')
}
