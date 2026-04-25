// WS-82 — Package & Artifact Registry Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to artifact registry and package repository security configuration files.
// This scanner focuses on the *artifact distribution layer* — configurations
// that govern how internal package registries authenticate clients, encrypt
// storage, and control access to binary artifacts.
//
// DISTINCT from:
//   WS-62  cloudSecurityDrift       — cloud-wide IAM/KMS and S3/GCS bucket
//                                     policies; WS-82 covers the registry
//                                     application configuration files
//   WS-66  certPkiDrift             — certificate and TLS key material;
//                                     WS-82 covers TLS settings inside
//                                     registry application configs
//   WS-70  identityAccessDrift      — server-side LDAP/Vault/PAM; WS-82
//                                     covers the registry-level auth settings
//                                     (local user stores, LDAP config refs,
//                                     RBAC built into Artifactory/Nexus)
//   WS-73  cicdPipelineSecurityDrift — CI/CD pipeline configs that reference
//                                     registries; WS-82 covers the registry
//                                     server configuration itself
//
// Covered rule groups (8 rules):
//
//   ARTIFACTORY_CONFIG_DRIFT     — JFrog Artifactory and JFrog Platform
//                                  security and access configuration
//   NEXUS_CONFIG_DRIFT           — Sonatype Nexus Repository Manager
//                                  security and storage configuration
//   HARBOR_REGISTRY_DRIFT        — Harbor OCI container registry and
//                                  component security configuration
//   DOCKER_REGISTRY_DRIFT        — Docker Distribution (registry v2) and
//                                  registry authentication configuration
//   NPM_REGISTRY_DRIFT           — Verdaccio, Sinopia, and private npm
//                                  registry security configuration
//   PYPI_REGISTRY_DRIFT          — Bandersnatch PyPI mirror, DevPI, and
//                                  private Python package registry configs
//   HELM_CHART_REPO_DRIFT        — ChartMuseum and private Helm chart
//                                  repository security configuration
//   GO_MODULE_PROXY_DRIFT        — Athens Go module proxy and goproxy
//                                  access configuration
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–81 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • harbor.yml / harbor.yaml are globally unambiguous (tool-named).
//   • verdaccio.yaml / verdaccio.yml are globally unambiguous (tool-named).
//   • bandersnatch.cfg / bandersnatch.ini are globally unambiguous (tool-named).
//   • chartmuseum.yaml / chartmuseum.yml are globally unambiguous (tool-named).
//   • athens.yaml / athens.toml are globally unambiguous (Go proxy tool name).
//   • nexus.properties is the Nexus startup config — globally unambiguous.
//   • artifactory.system.yaml is the Artifactory system config — unambiguous.
//   • config.yml is Docker Registry v2's config but is too generic to be
//     ungated — requires registry directory context via isDockerRegistryConfig
//     (user contribution).
//
// Exports:
//   isDockerRegistryConfig    — user contribution point (see JSDoc below)
//   ARTIFACT_REGISTRY_RULES   — readonly rule registry
//   scanArtifactRegistryDrift — main scanner, returns ArtifactRegistryDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ArtifactRegistryRuleId =
  | 'ARTIFACTORY_CONFIG_DRIFT'
  | 'NEXUS_CONFIG_DRIFT'
  | 'HARBOR_REGISTRY_DRIFT'
  | 'DOCKER_REGISTRY_DRIFT'
  | 'NPM_REGISTRY_DRIFT'
  | 'PYPI_REGISTRY_DRIFT'
  | 'HELM_CHART_REPO_DRIFT'
  | 'GO_MODULE_PROXY_DRIFT'

export type ArtifactRegistrySeverity = 'high' | 'medium' | 'low'
export type ArtifactRegistryRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type ArtifactRegistryDriftFinding = {
  ruleId: ArtifactRegistryRuleId
  severity: ArtifactRegistrySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type ArtifactRegistryDriftResult = {
  riskScore: number
  riskLevel: ArtifactRegistryRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: ArtifactRegistryDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/',
  'vendor/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.nuxt/',
  '__pycache__/',
  '.tox/',
  '.venv/',
  'venv/',
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const ARTIFACTORY_DIRS = ['artifactory/', 'jfrog/', '.artifactory/', 'artifactory-config/', 'artifactory-data/']
const NEXUS_DIRS       = ['nexus/', 'sonatype-work/', 'nexus-data/', 'nexus-config/', '.nexus/', 'nexus3/']
const HARBOR_DIRS      = ['harbor/', '.harbor/', 'harbor-config/', 'harbor-data/']
const REGISTRY_DIRS    = ['registry/', 'docker-registry/', '.registry/', 'container-registry/', 'distribution/']
const VERDACCIO_DIRS   = ['verdaccio/', '.verdaccio/', 'npm-registry/', 'sinopia/', 'private-npm/']
const DEVPI_DIRS       = ['devpi/', '.devpi/', 'pypi-registry/', 'pypi-mirror/', 'bandersnatch/', 'warehouse/']
const CHARTMUSEUM_DIRS = ['chartmuseum/', 'helm-repo/', 'chart-museum/', 'charts-repo/', 'helm-registry/']
const ATHENS_DIRS      = ['athens/', 'goproxy/', 'go-proxy/', '.athens/', 'go-module-proxy/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: ARTIFACTORY_CONFIG_DRIFT (high)
// JFrog Artifactory and JFrog Platform security configuration
// ---------------------------------------------------------------------------

const ARTIFACTORY_UNGATED = new Set([
  'artifactory.config.xml',      // Artifactory primary config — globally unambiguous
  'artifactory.system.yaml',     // Artifactory system config — globally unambiguous
  'artifactory.system.properties', // Legacy properties format
  'artifactory.lic',             // License file affects feature availability
])

function isArtifactoryConfig(pathLower: string, base: string): boolean {
  if (ARTIFACTORY_UNGATED.has(base)) return true

  // artifactory-* / jfrog-* prefix — filename names its own tool
  if (
    base.startsWith('artifactory-') ||
    base.startsWith('jfrog-')
  ) {
    if (
      base.endsWith('.yaml') || base.endsWith('.yml')        ||
      base.endsWith('.xml')  || base.endsWith('.properties') ||
      base.endsWith('.json') || base.endsWith('.conf')
    ) return true
  }

  if (!inAnyDir(pathLower, ARTIFACTORY_DIRS)) return false

  if (
    base === 'config.yaml'           ||
    base === 'config.yml'            ||
    base === 'access.yml'            ||  // JFrog Access (auth/RBAC)
    base === 'access.yaml'           ||
    base === 'binarystore.xml'       ||  // Binary storage config (S3/GCS/filesystem)
    base === 'db.properties'         ||  // Database connection config
    base === 'ha-node.properties'    ||  // HA cluster node config
    base === 'communication.key'     ||  // Node secret key
    base === 'master.key'            ||  // Master encryption key reference
    base === 'root.certs'            ||  // Trust chain
    base === '.env'                  ||
    base === 'docker-compose.yaml'   ||
    base === 'docker-compose.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.properties') || base.endsWith('.xml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: NEXUS_CONFIG_DRIFT (high)
// Sonatype Nexus Repository Manager security and storage configuration
// ---------------------------------------------------------------------------

const NEXUS_UNGATED = new Set([
  'nexus.properties',       // Nexus startup configuration — globally unambiguous
  'nexus-default.properties', // Default startup settings
])

function isNexusConfig(pathLower: string, base: string): boolean {
  if (NEXUS_UNGATED.has(base)) return true

  // nexus-* prefix — filename names its own tool
  if (base.startsWith('nexus-')) {
    if (
      base.endsWith('.properties') || base.endsWith('.yaml') ||
      base.endsWith('.yml')        || base.endsWith('.xml')   ||
      base.endsWith('.json')
    ) return true
  }

  if (!inAnyDir(pathLower, NEXUS_DIRS)) return false

  if (
    base === 'config.yaml'        ||
    base === 'config.yml'         ||
    base === 'nexus-store.properties' ||  // OrientDB/H2 storage config
    base === 'store.properties'   ||
    base === 'hazelcast.xml'      ||  // HA clustering config
    base === 'logback.xml'        ||  // Audit log config
    base === '.env'               ||
    base === 'docker-compose.yaml' ||
    base === 'docker-compose.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.properties') || base.endsWith('.xml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: HARBOR_REGISTRY_DRIFT (high)
// Harbor OCI container registry and component security configuration
// ---------------------------------------------------------------------------

const HARBOR_UNGATED = new Set([
  'harbor.yml',              // Harbor primary deployment config — globally unambiguous
  'harbor.yaml',             // YAML variant
  'harbor-v1.10.yml',        // Versioned variants (migration configs)
])

function isHarborRegistryConfig(pathLower: string, base: string): boolean {
  if (HARBOR_UNGATED.has(base)) return true

  // harbor-* prefix — filename names its own tool
  if (base.startsWith('harbor-')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, HARBOR_DIRS)) return false

  // Harbor component configs (microservice architecture)
  if (
    base === 'core.yaml'            ||  // Harbor Core auth/RBAC settings
    base === 'core.yml'             ||
    base === 'jobservice.yml'       ||  // Job service config
    base === 'jobservice.yaml'      ||
    base === 'database.yml'         ||  // PostgreSQL connection config
    base === 'database.yaml'        ||
    base === 'proxy.yaml'           ||  // Reverse proxy (nginx/envoy) config
    base === 'proxy.yml'            ||
    base === 'registryctl.yaml'     ||  // Registry controller config
    base === 'registryctl.yml'      ||
    base === 'trivy-adapter.yaml'   ||  // Trivy vulnerability scanner adapter
    base === 'config.yaml'          ||
    base === 'config.yml'           ||
    base === '.env'                 ||
    base === 'docker-compose.yaml'  ||
    base === 'docker-compose.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: DOCKER_REGISTRY_DRIFT (high) — user contribution
// Docker Distribution (registry v2) authentication and storage configuration
// ---------------------------------------------------------------------------

const DOCKER_REGISTRY_UNGATED = new Set([
  'docker-registry-config.yaml',  // Named registry config — globally unambiguous
  'docker-registry-config.yml',
  'registry-config.yaml',         // Registry-named config
  'registry-config.yml',
])

/**
 * WS-82 user contribution — determines whether a generic config file in a
 * registry directory is a Docker Distribution (registry v2) security
 * configuration rather than an unrelated application config.
 *
 * The challenge: Docker Distribution's canonical config file is named
 * `config.yml`, but this is one of the most common filenames in any codebase.
 * Without reading file content we cannot check for the `version: 0.1` registry
 * schema header, so we must rely on directory context and sibling file signals.
 *
 * Two disambiguation signals:
 *
 *   1. The file lives in a recognised registry directory segment
 *      (registry/, docker-registry/, container-registry/, distribution/) AND
 *      the basename is a registry-structural config name:
 *        - config.yml / config.yaml — Docker Registry v2 primary config
 *        - auth.yaml / auth.yml     — token auth service configuration
 *        - htpasswd                 — bcrypt user file for basic auth
 *        - nginx.conf               — nginx auth proxy for registry
 *
 *   2. The basename itself contains a registry-specific signal
 *      (registry-auth, registry-tls, registry-mirror in the name).
 *
 * Exclusions: paths in k8s/kubernetes/helm/terraform/ci dirs are excluded
 * since registry config references there are infrastructure declarations
 * rather than the registry application configuration itself.
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isDockerRegistryConfig(pathLower: string, base: string): boolean {
  // IaC / CI dirs — registry config references, not the registry config itself
  const INFRA_DIRS = [
    'terraform/', 'pulumi/', 'cdk/', 'k8s/', 'kubernetes/', 'helm/', 'charts/',
    '.github/', '.gitlab/', '.circleci/', '.buildkite/',
  ]
  if (INFRA_DIRS.some((d) => pathLower.includes(d))) return false

  // Registry-keyword in basename — clear signal regardless of directory
  if (
    base.includes('registry-auth') || base.includes('registry-tls') ||
    base.includes('registry-mirror') || base.includes('registry-config')
  ) {
    const CONFIG_EXTS = ['.yaml', '.yml', '.json', '.conf', '.toml']
    if (CONFIG_EXTS.some((ext) => base.endsWith(ext))) return true
  }

  // Must be in a recognised registry directory
  if (!inAnyDir(pathLower, REGISTRY_DIRS)) return false

  // Registry-structural file names inside registry directories
  if (
    base === 'config.yml'   ||  // Docker Registry v2 primary config
    base === 'config.yaml'  ||
    base === 'auth.yaml'    ||  // Token authentication service config
    base === 'auth.yml'     ||
    base === 'htpasswd'     ||  // Basic auth user file (bcrypt hashes)
    base === 'nginx.conf'   ||  // nginx auth proxy config
    base === '.env'         ||
    base === 'docker-compose.yaml' ||
    base === 'docker-compose.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: NPM_REGISTRY_DRIFT (medium)
// Verdaccio, Sinopia, and private npm registry security configuration
// ---------------------------------------------------------------------------

const VERDACCIO_UNGATED = new Set([
  'verdaccio.yaml',     // Verdaccio config — globally unambiguous tool name
  'verdaccio.yml',
  'sinopia.yaml',       // Sinopia (Verdaccio predecessor)
  'sinopia.yml',
])

function isNpmRegistryConfig(pathLower: string, base: string): boolean {
  if (VERDACCIO_UNGATED.has(base)) return true

  // verdaccio-* prefix
  if (base.startsWith('verdaccio-')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, VERDACCIO_DIRS)) return false

  if (
    base === 'config.yaml'         ||
    base === 'config.yml'          ||
    base === 'htpasswd'            ||  // Local user store for npm auth
    base === '.npmrc'              ||  // Registry URL + auth token
    base === '.env'                ||
    base === 'docker-compose.yaml' ||
    base === 'docker-compose.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: PYPI_REGISTRY_DRIFT (medium)
// Bandersnatch PyPI mirror, DevPI, and private Python package registry configs
// ---------------------------------------------------------------------------

const PYPI_REGISTRY_UNGATED = new Set([
  'bandersnatch.cfg',    // Bandersnatch PyPI mirror config — globally unambiguous
  'bandersnatch.ini',    // INI variant
  'devpi-server.cfg',    // DevPI server config — globally unambiguous tool name
  'devpi.ini',
  'warehouse.cfg',       // PyPI Warehouse (warehouse.pypa.io) config
])

function isPypiRegistryConfig(pathLower: string, base: string): boolean {
  if (PYPI_REGISTRY_UNGATED.has(base)) return true

  // bandersnatch-* / devpi-* prefix
  if (base.startsWith('bandersnatch-') || base.startsWith('devpi-')) {
    if (base.endsWith('.cfg') || base.endsWith('.ini') || base.endsWith('.yaml') || base.endsWith('.yml')) return true
  }

  if (!inAnyDir(pathLower, DEVPI_DIRS)) return false

  if (
    base === 'config.cfg'   ||
    base === 'config.ini'   ||
    base === 'server.cfg'   ||
    base === '.env'         ||
    base === 'config.yaml'  ||
    base === 'config.yml'
  ) return true

  if (base.endsWith('.cfg') || base.endsWith('.ini')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: HELM_CHART_REPO_DRIFT (medium)
// ChartMuseum and private Helm chart repository security configuration
// ---------------------------------------------------------------------------

const CHARTMUSEUM_UNGATED = new Set([
  'chartmuseum.yaml',    // ChartMuseum config — globally unambiguous tool name
  'chartmuseum.yml',
  'chartmuseum.json',
])

function isHelmChartRepoConfig(pathLower: string, base: string): boolean {
  if (CHARTMUSEUM_UNGATED.has(base)) return true

  // chartmuseum-* prefix
  if (base.startsWith('chartmuseum-')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, CHARTMUSEUM_DIRS)) return false

  if (
    base === 'config.yaml'         ||
    base === 'config.yml'          ||
    base === 'auth.yaml'           ||  // BasicAuth config
    base === 'auth.yml'            ||
    base === 'index.yaml'          ||  // Helm chart repository index (tracks all chart versions)
    base === 'values.yaml'         ||  // Helm deployment values for ChartMuseum itself
    base === '.env'                ||
    base === 'docker-compose.yaml' ||
    base === 'docker-compose.yml'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: GO_MODULE_PROXY_DRIFT (low)
// Athens Go module proxy and private goproxy access configuration
// ---------------------------------------------------------------------------

const ATHENS_UNGATED = new Set([
  'athens.yaml',        // Athens Go module proxy config — globally unambiguous
  'athens.yml',
  'athens.toml',
  'athens.json',
  '.athens.yaml',       // Dot-prefixed variant
])

function isGoModuleProxyConfig(pathLower: string, base: string): boolean {
  if (ATHENS_UNGATED.has(base)) return true

  // athens-* / goproxy-* prefix
  if (base.startsWith('athens-') || base.startsWith('goproxy-')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, ATHENS_DIRS)) return false

  if (
    base === 'config.yaml'   ||
    base === 'config.yml'    ||
    base === 'config.toml'   ||
    base === '.env'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const ARTIFACT_REGISTRY_RULES: ReadonlyArray<{
  id: ArtifactRegistryRuleId
  severity: ArtifactRegistrySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'ARTIFACTORY_CONFIG_DRIFT',
    severity: 'high',
    description: 'JFrog Artifactory or JFrog Platform security configuration changed.',
    recommendation:
      'Review Artifactory RBAC permission target changes, verify the master key and communication key have not been rotated without corresponding secret rotation in dependent services, audit binary store configuration for unintended public S3 bucket references, and confirm that JFrog Access token expiry and revocation settings are still in place.',
    match: (p, b) => isArtifactoryConfig(p, b),
  },
  {
    id: 'NEXUS_CONFIG_DRIFT',
    severity: 'high',
    description: 'Sonatype Nexus Repository Manager security or storage configuration changed.',
    recommendation:
      'Verify that nexus.properties admin password and session timeout settings have not been weakened, review any changes to blob store configuration for unintended public storage exposure, confirm that LDAP integration settings still enforce group-based access, and audit cleanup policy changes that could affect retention of security-relevant artifacts.',
    match: (p, b) => isNexusConfig(p, b),
  },
  {
    id: 'HARBOR_REGISTRY_DRIFT',
    severity: 'high',
    description: 'Harbor OCI container registry configuration changed.',
    recommendation:
      'Review Harbor RBAC policy changes and project-level public/private settings, verify that robot account token expiry has not been extended beyond policy, confirm Trivy adapter config still enforces vulnerability scanning at push, and audit any changes to the database connection config for credential exposure.',
    match: (p, b) => isHarborRegistryConfig(p, b),
  },
  {
    id: 'DOCKER_REGISTRY_DRIFT',
    severity: 'high',
    description: 'Docker Distribution registry v2 authentication or storage configuration changed.',
    recommendation:
      'Verify the registry auth type is set to token or htpasswd (not "silly"), audit storage backend configuration for unintended anonymous access, confirm TLS is configured and not using insecure registries, and review any changes to the token service or htpasswd user file for unauthorized account additions.',
    match: (p, b) => DOCKER_REGISTRY_UNGATED.has(b) || isDockerRegistryConfig(p, b),
  },
  {
    id: 'NPM_REGISTRY_DRIFT',
    severity: 'medium',
    description: 'Verdaccio or private npm registry security configuration changed.',
    recommendation:
      'Review Verdaccio auth plugin configuration and htpasswd changes for unauthorized account additions, confirm that package access rules enforce authentication for scoped packages, verify that uplinks to the public npm registry use TLS, and audit maxUsers limits to prevent unrestricted registration.',
    match: (p, b) => isNpmRegistryConfig(p, b),
  },
  {
    id: 'PYPI_REGISTRY_DRIFT',
    severity: 'medium',
    description: 'Bandersnatch PyPI mirror or DevPI private registry configuration changed.',
    recommendation:
      'Verify that bandersnatch allowlist/denylist changes do not expose internal-only packages to mirroring, review DevPI user and index permission changes, confirm that index authentication is enabled and not set to anonymous upload, and audit any changes to the mirror storage path for unexpected redirections.',
    match: (p, b) => isPypiRegistryConfig(p, b),
  },
  {
    id: 'HELM_CHART_REPO_DRIFT',
    severity: 'medium',
    description: 'ChartMuseum or private Helm chart repository configuration changed.',
    recommendation:
      'Review ChartMuseum basic auth configuration changes, confirm that the chart repository index is not publicly writable, verify TLS certificate configuration for the repository endpoint, and audit any changes to storage backend settings for unintended public bucket access.',
    match: (p, b) => isHelmChartRepoConfig(p, b),
  },
  {
    id: 'GO_MODULE_PROXY_DRIFT',
    severity: 'low',
    description: 'Athens Go module proxy or goproxy access configuration changed.',
    recommendation:
      'Verify that Athens is not configured with NoSumDB mode in production (bypasses checksum verification), review storage backend access configuration, confirm that GONOSUMCHECK and GONOSUMDB settings are not over-broad, and audit any changes to VCS credential configuration.',
    match: (p, b) => isGoModuleProxyConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<ArtifactRegistrySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: ArtifactRegistryDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): ArtifactRegistryRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

const MAX_PATHS_PER_SCAN = 500

export function scanArtifactRegistryDrift(changedFiles: string[]): ArtifactRegistryDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: ArtifactRegistryDriftFinding[] = []

  for (const rule of ARTIFACT_REGISTRY_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles.slice(0, MAX_PATHS_PER_SCAN)) {
      const p    = normalise(raw)
      const base = p.split('/').pop() ?? p

      if (isVendor(p)) continue
      if (!rule.match(p, base)) continue

      matchCount++
      if (!firstPath) firstPath = raw
    }

    if (matchCount > 0) {
      findings.push({
        ruleId:         rule.id,
        severity:       rule.severity,
        matchedPath:    firstPath,
        matchCount,
        description:    rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  // Sort: high → medium → low
  const ORDER: Record<ArtifactRegistrySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No artifact registry security configuration drift detected.'
      : `${findings.length} artifact registry rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`    : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`       : '',
        ].filter(Boolean).join(', ')}); risk score ${riskScore}/100.`

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
