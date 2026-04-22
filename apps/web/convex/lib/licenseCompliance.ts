// WS-31 — Dependency License Compliance Engine
//
// Pure computation library. Zero Convex imports, zero network calls.
// Used by licenseComplianceIntel.ts to evaluate SBOM snapshots for
// open-source license risk.
//
// Detection strategy:
//  1. Static lookup: curated database of 200+ popular packages → known license
//  2. Passed-in license: uses the `license` field already stored on sbomComponents
//  3. Fallback: unknown / unresolved
//
// License categories:
//  permissive      MIT, Apache 2.0, BSD, ISC, Unlicense, CC0, Zlib
//  weak_copyleft   LGPL-2.0, LGPL-2.1, LGPL-3.0, MPL-2.0, CDDL, EUPL
//  strong_copyleft GPL-2.0, GPL-3.0
//  network_copyleft AGPL-3.0, SSPL, OSL (most restrictive for SaaS)
//  proprietary     Commercial / custom / unlicensed closed-source
//  unknown         No license data available
//
// Default commercial policy:
//  permissive       → allowed
//  weak_copyleft    → warn   (licence obligations apply but are manageable)
//  strong_copyleft  → blocked (copyleft contaminates combined work)
//  network_copyleft → blocked (any network use triggers copyleft)
//  proprietary      → warn   (needs legal review per dependency)
//  unknown          → warn   (unvetted; may have any terms)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LicenseCategory =
  | 'permissive'
  | 'weak_copyleft'
  | 'strong_copyleft'
  | 'network_copyleft'
  | 'proprietary'
  | 'unknown'

export type ComplianceOutcome = 'allowed' | 'warn' | 'blocked'

export interface LicensePolicy {
  permissive: ComplianceOutcome
  weak_copyleft: ComplianceOutcome
  strong_copyleft: ComplianceOutcome
  network_copyleft: ComplianceOutcome
  proprietary: ComplianceOutcome
  unknown: ComplianceOutcome
}

export const DEFAULT_COMMERCIAL_POLICY: LicensePolicy = {
  permissive: 'allowed',
  weak_copyleft: 'warn',
  strong_copyleft: 'blocked',
  network_copyleft: 'blocked',
  proprietary: 'warn',
  unknown: 'warn',
}

export interface ComponentLicenseResult {
  name: string
  ecosystem: string
  resolvedLicense: string | null
  category: LicenseCategory
  outcome: ComplianceOutcome
  source: 'static_db' | 'provided' | 'unknown'
}

export interface LicenseComplianceResult {
  components: ComponentLicenseResult[]
  blockedCount: number
  warnCount: number
  allowedCount: number
  unknownCount: number
  /** 0-100: penalises blocked (-20/ea) and warn (-5/ea), floor 0. */
  complianceScore: number
  /** Worst-case category seen in the set. */
  overallLevel: 'compliant' | 'caution' | 'non_compliant'
  /** Human-readable summary sentence. */
  summary: string
}

// ---------------------------------------------------------------------------
// License category map
// ---------------------------------------------------------------------------

/** SPDX identifier → category. Checked case-insensitively. */
const LICENSE_CATEGORY: Record<string, LicenseCategory> = {
  // permissive
  'mit': 'permissive',
  'isc': 'permissive',
  'bsd-2-clause': 'permissive',
  'bsd-3-clause': 'permissive',
  'apache-2.0': 'permissive',
  'apache 2.0': 'permissive',
  'apache2': 'permissive',
  'cc0-1.0': 'permissive',
  'unlicense': 'permissive',
  'wtfpl': 'permissive',
  'zlib': 'permissive',
  'python-2.0': 'permissive',
  'psf-2.0': 'permissive',
  '0bsd': 'permissive',
  'artistic-2.0': 'permissive',
  'bsl-1.0': 'permissive',
  // weak copyleft
  'lgpl-2.0': 'weak_copyleft',
  'lgpl-2.0-only': 'weak_copyleft',
  'lgpl-2.0-or-later': 'weak_copyleft',
  'lgpl-2.1': 'weak_copyleft',
  'lgpl-2.1-only': 'weak_copyleft',
  'lgpl-2.1-or-later': 'weak_copyleft',
  'lgpl-3.0': 'weak_copyleft',
  'lgpl-3.0-only': 'weak_copyleft',
  'lgpl-3.0-or-later': 'weak_copyleft',
  'mpl-2.0': 'weak_copyleft',
  'cddl-1.0': 'weak_copyleft',
  'eupl-1.1': 'weak_copyleft',
  'eupl-1.2': 'weak_copyleft',
  'epl-1.0': 'weak_copyleft',
  'epl-2.0': 'weak_copyleft',
  // strong copyleft
  'gpl-2.0': 'strong_copyleft',
  'gpl-2.0-only': 'strong_copyleft',
  'gpl-2.0-or-later': 'strong_copyleft',
  'gpl-3.0': 'strong_copyleft',
  'gpl-3.0-only': 'strong_copyleft',
  'gpl-3.0-or-later': 'strong_copyleft',
  // network copyleft (strictest — SaaS loophole closed)
  'agpl-3.0': 'network_copyleft',
  'agpl-3.0-only': 'network_copyleft',
  'agpl-3.0-or-later': 'network_copyleft',
  'sspl-1.0': 'network_copyleft',
  'osl-3.0': 'network_copyleft',
  'busl-1.1': 'network_copyleft', // BSL is not OSI but commercially restricted
  'commons-clause': 'network_copyleft',
  // proprietary
  'proprietary': 'proprietary',
  'commercial': 'proprietary',
  'see license': 'proprietary',
  'see license in license': 'proprietary',
}

// ---------------------------------------------------------------------------
// Static package-to-license lookup
// ---------------------------------------------------------------------------

type EcosystemMap = Record<string, string>

const STATIC_DB: Record<string, EcosystemMap> = {
  npm: {
    // permissive
    react: 'MIT', 'react-dom': 'MIT', 'react-router': 'MIT', 'react-router-dom': 'MIT',
    next: 'MIT', vue: 'MIT', svelte: 'MIT', angular: 'MIT',
    express: 'MIT', fastify: 'MIT', koa: 'MIT', hapi: 'MIT',
    lodash: 'MIT', 'lodash-es': 'MIT', underscore: 'MIT', ramda: 'MIT',
    axios: 'MIT', 'node-fetch': 'MIT', got: 'MIT', ky: 'MIT',
    typescript: 'Apache-2.0', '@types/node': 'MIT', tslib: '0BSD',
    webpack: 'MIT', vite: 'MIT', rollup: 'MIT', esbuild: 'MIT',
    prettier: 'MIT', eslint: 'MIT', biome: 'MIT',
    jest: 'MIT', vitest: 'MIT', mocha: 'MIT', jasmine: 'MIT',
    tailwindcss: 'MIT', postcss: 'MIT', sass: 'MIT', 'less': 'Apache-2.0',
    'moment': 'MIT', 'date-fns': 'MIT', dayjs: 'MIT',
    'jsonwebtoken': 'MIT', bcrypt: 'MIT', 'bcryptjs': 'MIT', argon2: 'MIT',
    dotenv: 'BSD-2-Clause', 'cross-env': 'MIT', chalk: 'MIT', ora: 'MIT',
    zod: 'MIT', yup: 'MIT', 'class-validator': 'MIT',
    prisma: 'Apache-2.0', drizzle: 'Apache-2.0', typeorm: 'MIT',
    'socket.io': 'MIT', ws: 'MIT',
    'class-transformer': 'MIT', inversify: 'MIT',
    commander: 'MIT', yargs: 'MIT', minimist: 'MIT',
    uuid: 'MIT', nanoid: 'MIT', shortid: 'MIT',
    debug: 'MIT', morgan: 'MIT', winston: 'MIT', pino: 'MIT',
    convex: 'Apache-2.0', '@tanstack/react-query': 'MIT', '@tanstack/router': 'MIT',
    // weak copyleft
    'node-sass': 'MIT', // wraps libsass which is MIT
    // network copyleft
    'mongoskin': 'AGPL-3.0', // historic reference
  },
  pypi: {
    // permissive
    django: 'BSD-3-Clause', flask: 'BSD-3-Clause', fastapi: 'MIT',
    starlette: 'BSD-3-Clause', tornado: 'Apache-2.0', aiohttp: 'Apache-2.0',
    requests: 'Apache-2.0', httpx: 'BSD-3-Clause', urllib3: 'MIT',
    numpy: 'BSD-3-Clause', pandas: 'BSD-3-Clause', scipy: 'BSD-3-Clause',
    matplotlib: 'PSF-2.0', pillow: 'MIT', 'Pillow': 'MIT',
    sqlalchemy: 'MIT', alembic: 'MIT', psycopg2: 'LGPL-3.0', psycopg: 'LGPL-3.0',
    pydantic: 'MIT', 'pydantic-settings': 'MIT',
    pytest: 'MIT', unittest2: 'BSD-3-Clause',
    celery: 'BSD-3-Clause', redis: 'MIT', 'redis-py': 'MIT',
    boto3: 'Apache-2.0', botocore: 'Apache-2.0', 's3transfer': 'Apache-2.0',
    google_cloud_storage: 'Apache-2.0', 'google-cloud-storage': 'Apache-2.0',
    openai: 'Apache-2.0', anthropic: 'MIT', transformers: 'Apache-2.0',
    torch: 'BSD-3-Clause', tensorflow: 'Apache-2.0', keras: 'Apache-2.0',
    scikit_learn: 'BSD-3-Clause', 'scikit-learn': 'BSD-3-Clause',
    click: 'BSD-3-Clause', typer: 'MIT', rich: 'MIT',
    cryptography: 'Apache-2.0', PyJWT: 'MIT', 'pyjwt': 'MIT', passlib: 'BSD-2-Clause',
    uvicorn: 'BSD-3-Clause', gunicorn: 'MIT', hypercorn: 'MIT',
    marshmallow: 'MIT', attrs: 'MIT', dataclasses_json: 'MIT',
    // weak copyleft
    psycopg2_binary: 'LGPL-3.0', 'psycopg2-binary': 'LGPL-3.0',
    // network copyleft
    'mysql-connector-python': 'GPL-2.0',
  },
  cargo: {
    // permissive
    serde: 'MIT OR Apache-2.0', 'serde_json': 'MIT OR Apache-2.0', 'serde_yaml': 'MIT OR Apache-2.0',
    tokio: 'MIT', async_std: 'Apache-2.0 OR MIT', actix_web: 'MIT OR Apache-2.0',
    axum: 'MIT', warp: 'MIT', hyper: 'MIT', reqwest: 'MIT OR Apache-2.0',
    clap: 'MIT OR Apache-2.0', structopt: 'MIT OR Apache-2.0',
    log: 'MIT OR Apache-2.0', tracing: 'MIT', env_logger: 'MIT OR Apache-2.0',
    anyhow: 'MIT OR Apache-2.0', thiserror: 'MIT OR Apache-2.0',
    uuid: 'MIT OR Apache-2.0', chrono: 'MIT OR Apache-2.0', time: 'MIT OR Apache-2.0',
    rand: 'MIT OR Apache-2.0', crypto: 'MIT OR Apache-2.0', sha2: 'MIT OR Apache-2.0',
    sqlx: 'MIT OR Apache-2.0', diesel: 'MIT OR Apache-2.0',
    'base64': 'MIT OR Apache-2.0', hex: 'MIT OR Apache-2.0',
    bytes: 'MIT', futures: 'MIT OR Apache-2.0',
    openssl: 'Apache-2.0', rustls: 'Apache-2.0 OR ISC OR MIT',
    // weak copyleft
    glib: 'LGPL-2.1', gtk: 'LGPL-2.1',
  },
  go: {
    // permissive — module paths as keys
    'github.com/gin-gonic/gin': 'MIT', 'github.com/labstack/echo': 'MIT',
    'github.com/gorilla/mux': 'BSD-3-Clause', 'github.com/gorilla/websocket': 'BSD-2-Clause',
    'github.com/go-chi/chi': 'MIT', 'github.com/spf13/cobra': 'Apache-2.0',
    'github.com/spf13/viper': 'MIT', 'github.com/urfave/cli': 'MIT',
    'github.com/sirupsen/logrus': 'MIT', 'go.uber.org/zap': 'MIT',
    'gorm.io/gorm': 'MIT', 'github.com/jackc/pgx': 'MIT',
    'github.com/redis/go-redis': 'BSD-2-Clause',
    'github.com/golang-jwt/jwt': 'MIT', 'github.com/dgrijalva/jwt-go': 'MIT',
    'golang.org/x/crypto': 'BSD-3-Clause', 'golang.org/x/net': 'BSD-3-Clause',
    'google.golang.org/grpc': 'Apache-2.0',
    'github.com/stretchr/testify': 'MIT',
    // weak copyleft
    'github.com/MariaDB/mariadb-connector-go': 'LGPL-2.1',
  },
}

// ---------------------------------------------------------------------------
// Core lookups
// ---------------------------------------------------------------------------

/** Normalize SPDX identifier for map lookup. */
function normalizeSpdx(license: string): string {
  return license.trim().toLowerCase().replace(/\s+/g, ' ')
}

/** Resolve license category from a SPDX string. */
export function classifyLicense(license: string): LicenseCategory {
  if (!license || license.trim() === '') return 'unknown'
  const key = normalizeSpdx(license)
  // Direct map lookup
  if (LICENSE_CATEGORY[key]) return LICENSE_CATEGORY[key]
  // Handle SPDX OR expressions (e.g. "MIT OR Apache-2.0"): take the most permissive
  if (key.includes(' or ')) {
    const parts = key.split(' or ').map((p) => p.trim())
    const cats = parts.map((p) => LICENSE_CATEGORY[p] ?? 'unknown')
    const order: LicenseCategory[] = [
      'permissive', 'weak_copyleft', 'strong_copyleft', 'network_copyleft', 'proprietary', 'unknown',
    ]
    for (const cat of order) {
      if (cats.includes(cat)) return cat
    }
  }
  // AND expressions: take the most restrictive
  if (key.includes(' and ')) {
    const parts = key.split(' and ').map((p) => p.trim())
    const cats = parts.map((p) => LICENSE_CATEGORY[p] ?? 'unknown')
    const order: LicenseCategory[] = [
      'network_copyleft', 'strong_copyleft', 'weak_copyleft', 'proprietary', 'permissive', 'unknown',
    ]
    for (const cat of order) {
      if (cats.includes(cat)) return cat
    }
  }
  // Substring heuristics for when the string isn't a clean SPDX token.
  // Order matters: most specific / restrictive checks first.
  if (/agpl|affero/i.test(license)) return 'network_copyleft'
  if (/sspl/i.test(license)) return 'network_copyleft'
  if (/lgpl|lesser general public/i.test(license)) return 'weak_copyleft'
  if (/gpl|general public license/i.test(license)) return 'strong_copyleft'
  if (/mpl|mozilla public/i.test(license)) return 'weak_copyleft'
  if (/mit\b/i.test(license)) return 'permissive'
  if (/apache/i.test(license)) return 'permissive'
  if (/bsd/i.test(license)) return 'permissive'
  if (/isc\b/i.test(license)) return 'permissive'
  if (/proprietary|commercial|all rights reserved/i.test(license)) return 'proprietary'
  return 'unknown'
}

/** Look up license from the static database using (normalized) name + ecosystem. */
export function lookupStaticLicense(name: string, ecosystem: string): string | null {
  const ecoMap = STATIC_DB[ecosystem.toLowerCase()] ?? {}
  return ecoMap[name] ?? ecoMap[name.toLowerCase()] ?? null
}

// ---------------------------------------------------------------------------
// Component assessment
// ---------------------------------------------------------------------------

export interface ComponentInput {
  name: string
  ecosystem: string
  /** License string from the manifest / SBOM, if available. */
  knownLicense?: string | null
}

/** Assess license compliance for a single component. */
export function assessComponentLicense(
  component: ComponentInput,
  policy: LicensePolicy = DEFAULT_COMMERCIAL_POLICY,
): ComponentLicenseResult {
  // Resolution order: (1) static DB, (2) passed-in knownLicense, (3) unknown
  const staticLicense = lookupStaticLicense(component.name, component.ecosystem)
  let resolvedLicense: string | null = null
  let source: ComponentLicenseResult['source'] = 'unknown'

  if (staticLicense) {
    resolvedLicense = staticLicense
    source = 'static_db'
  } else if (component.knownLicense && component.knownLicense.trim() !== '') {
    resolvedLicense = component.knownLicense.trim()
    source = 'provided'
  }

  const category: LicenseCategory = resolvedLicense
    ? classifyLicense(resolvedLicense)
    : 'unknown'

  const outcome: ComplianceOutcome = policy[category]

  return {
    name: component.name,
    ecosystem: component.ecosystem,
    resolvedLicense,
    category,
    outcome,
    source,
  }
}

// ---------------------------------------------------------------------------
// Full snapshot assessment
// ---------------------------------------------------------------------------

/** Compute compliance score: start 100, deduct 20 per blocked, 5 per warn, floor 0. */
function computeComplianceScore(blocked: number, warned: number): number {
  return Math.max(0, 100 - blocked * 20 - warned * 5)
}

function classifyLevel(
  blocked: number,
  warned: number,
): LicenseComplianceResult['overallLevel'] {
  if (blocked > 0) return 'non_compliant'
  if (warned > 0) return 'caution'
  return 'compliant'
}

function buildSummary(
  total: number,
  blocked: number,
  warned: number,
  score: number,
): string {
  if (total === 0) return 'No components to evaluate.'
  if (blocked === 0 && warned === 0) {
    return `All ${total} component(s) use permissive licenses — fully compliant (score ${score}).`
  }
  const parts: string[] = []
  if (blocked > 0) parts.push(`${blocked} blocked (copyleft violation)`)
  if (warned > 0) parts.push(`${warned} need review`)
  return `${parts.join(', ')} across ${total} component(s). Compliance score ${score}/100.`
}

/** Assess license compliance across all components in a snapshot. */
export function computeLicenseCompliance(
  components: ComponentInput[],
  policy: LicensePolicy = DEFAULT_COMMERCIAL_POLICY,
): LicenseComplianceResult {
  const results = components.map((c) => assessComponentLicense(c, policy))

  const blockedCount = results.filter((r) => r.outcome === 'blocked').length
  const warnCount = results.filter((r) => r.outcome === 'warn').length
  const allowedCount = results.filter((r) => r.outcome === 'allowed').length
  const unknownCount = results.filter((r) => r.category === 'unknown').length

  const complianceScore = computeComplianceScore(blockedCount, warnCount)
  const overallLevel = classifyLevel(blockedCount, warnCount)
  const summary = buildSummary(components.length, blockedCount, warnCount, complianceScore)

  return {
    components: results,
    blockedCount,
    warnCount,
    allowedCount,
    unknownCount,
    complianceScore,
    overallLevel,
    summary,
  }
}
