// WS-103 — Dependency Manager Security Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to client-side package manager security configuration: npm/yarn/pnpm registry
// substitution (.npmrc), Python package index configuration (pip.conf/pip.ini),
// Maven repository/mirror configuration (settings.xml), Gradle wrapper
// distribution URL (gradle-wrapper.properties), Cargo registry sources
// (.cargo/config.toml), Ruby Bundler mirror configuration (.bundle/config),
// NuGet package feed configuration (NuGet.Config), and PHP Composer source/auth
// configuration (auth.json, config.json in .composer/).
//
// Distinct from:
//   WS-60  (app-level security config: TLS / CORS / CSP inside app code)
//   WS-73  (CI/CD pipeline security: GitHub Actions / Tekton / SLSA provenance)
//   WS-82  (artifact registry servers: Nexus / Artifactory / Harbor admin configs)
//   WS-83  (config management: Ansible / Chef / Puppet / SaltStack)
//
// Security relevance: these files are the primary vector for dependency confusion
// attacks, registry hijacking, and Gradle wrapper tampering.  An attacker that
// modifies .npmrc to point to a malicious registry or sets pip.conf
// extra-index-url can serve backdoored packages on every install.

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  'target/', '__pycache__/', '.venv/', 'venv/', '.tox/', 'site-packages/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: NPM_REGISTRY_DRIFT (high)
// ---------------------------------------------------------------------------
// npm / Yarn / pnpm client configuration holds registry URLs, auth tokens, and
// security settings (strict-ssl, ignore-scripts, audit).  Registry substitution
// is the core dependency-confusion attack primitive.

const NPM_UNGATED = new Set([
  '.npmrc', '.yarnrc', '.yarnrc.yml', '.yarnrc.yaml',
  '.pnpmfile.cjs', '.pnpmfile.js',
  'npm-config', 'npm.rc', 'npmrc',
  '.pnpmrc',
])

const NPM_DIRS = [
  'npm/', '.npm/', 'yarn/', '.yarn/', 'pnpm/', '.pnpm/',
  'npm-config/', 'yarn-config/', 'pnpm-config/',
]

function isNpmRegistryConfig(path: string, base: string): boolean {
  if (NPM_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('.npmrc-') ||
    base.startsWith('.yarnrc-') ||
    base.startsWith('npmrc-') ||
    base.startsWith('yarn-config-') ||
    base.startsWith('pnpm-config-')
  ) {
    return true
  }

  return NPM_DIRS.some((d) => low.includes(d)) &&
    /\.(rc|json|yaml|yml|cjs|js)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: PIP_INDEX_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------
// pip configuration controls index-url, extra-index-url, trusted-host, and
// no-index settings.  A malicious extra-index-url is the standard PyPI
// dependency-confusion attack path.

const PIP_UNGATED = new Set([
  'pip.conf', 'pip.ini', 'pip.cfg',
  '.pip.conf', '.pip.ini', '.pip.cfg',
  'pip.conf.local',
])

const PIP_DIRS = [
  '.pip/', 'pip/', 'pypi/', 'pip-config/', 'python/',
]

function isPipIndexConfig(path: string, base: string): boolean {
  if (PIP_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('pip-') ||
    base.startsWith('pip.conf')
  ) {
    return /\.(conf|ini|cfg)$/.test(base)
  }

  return PIP_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|ini|cfg)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: MAVEN_REPOSITORY_DRIFT (high)
// ---------------------------------------------------------------------------
// Maven settings.xml defines repositories, mirrors, and proxy settings.
// Mirror substitution is a well-documented Maven dependency confusion vector.
// settings-security.xml holds the encrypted master password — its modification
// can indicate key rotation or credential theft.

const MAVEN_UNGATED = new Set([
  'settings-security.xml',
])

const MAVEN_DIRS = [
  '.m2/', 'maven/', 'mvn/', 'maven-config/', 'mvn-config/',
  'maven-settings/',
]

function isMavenRepositoryConfig(path: string, base: string): boolean {
  if (MAVEN_UNGATED.has(base)) return true

  const low = path.toLowerCase()

  // settings.xml is heavily overloaded — require Maven directory context
  if (base === 'settings.xml' && MAVEN_DIRS.some((d) => low.includes(d))) {
    return true
  }

  if (
    base.startsWith('maven-settings-') ||
    base.startsWith('mvn-settings-') ||
    base.startsWith('maven-config-')
  ) {
    return /\.xml$/.test(base)
  }

  return MAVEN_DIRS.some((d) => low.includes(d)) &&
    /\.(xml|yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: GRADLE_WRAPPER_DRIFT (high)
// ---------------------------------------------------------------------------
// gradle-wrapper.properties embeds the distributionUrl used to download the
// Gradle binary.  Modifying this URL is the primary Gradle wrapper tampering
// attack: the victim downloads and executes a malicious Gradle distribution.
// init.gradle scripts run at every Gradle invocation — a common persistence
// mechanism for supply chain attackers.

const GRADLE_UNGATED = new Set([
  'gradle-wrapper.properties', 'gradle-wrapper.jar',
  'gradlew', 'gradlew.bat',
])

const GRADLE_DIRS = [
  'gradle/wrapper/', '.gradle/', 'gradle-home/', 'gradle-init/',
  'gradle/', 'wrapper/',
]

function isGradleWrapperConfig(path: string, base: string): boolean {
  if (GRADLE_UNGATED.has(base)) return true

  const low = path.toLowerCase()

  // init.gradle / init.d/*.gradle in well-known Gradle init dirs
  if (
    (base === 'init.gradle' || base === 'init.gradle.kts' || base.endsWith('.gradle')) &&
    GRADLE_DIRS.some((d) => low.includes(d))
  ) {
    return true
  }

  if (
    base.startsWith('gradle-wrapper-') ||
    base.startsWith('gradle-init-')
  ) {
    return /\.(properties|gradle|kts|jar|bat|sh)$/.test(base)
  }

  return GRADLE_DIRS.some((d) => low.includes(d)) &&
    /\.(properties|gradle|kts)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: CARGO_REGISTRY_DRIFT (medium)
// ---------------------------------------------------------------------------
// Cargo's .cargo/config.toml (or legacy .cargo/config) sets registry sources,
// replace-with mirrors, and network settings.  A tampered [source.crates-io]
// replace-with pointing to an attacker-controlled registry serves backdoored
// crates on every build.

const CARGO_DIRS = [
  '.cargo/', 'cargo/', 'cargo-config/', '.cargo/config',
]

function isCargoRegistryConfig(path: string, base: string): boolean {
  const low = path.toLowerCase()

  // config.toml / config in .cargo/ context
  if (
    (base === 'config.toml' || base === 'config') &&
    CARGO_DIRS.some((d) => low.includes(d))
  ) {
    return true
  }

  if (
    base.startsWith('cargo-config-') ||
    base.startsWith('cargo-registry-')
  ) {
    return /\.(toml|json|yaml|yml)$/.test(base)
  }

  return CARGO_DIRS.some((d) => low.includes(d)) &&
    /\.(toml|json|yaml|yml|conf)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: BUNDLER_SOURCE_DRIFT (medium)
// ---------------------------------------------------------------------------
// Bundler's .bundle/config controls mirror URLs, gem source hosts, and SSL
// verification.  BUNDLE_MIRROR__HTTPS__RUBYGEMS__ORG can redirect gem downloads
// to an attacker-controlled mirror.

const BUNDLER_DIRS = [
  '.bundle/', 'bundler/', 'bundle-config/', 'gems/',
]

function isBundlerSourceConfig(path: string, base: string): boolean {
  const low = path.toLowerCase()

  // config in .bundle/ context is the canonical Bundler config location
  if (base === 'config' && BUNDLER_DIRS.some((d) => low.includes(d))) {
    return true
  }

  if (
    base.startsWith('bundler-config-') ||
    base.startsWith('bundle-config-') ||
    base.startsWith('bundler-mirror-')
  ) {
    return true
  }

  return BUNDLER_DIRS.some((d) => low.includes(d)) &&
    /\.(rb|yaml|yml|conf|cfg|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: NUGET_FEED_DRIFT (medium)
// ---------------------------------------------------------------------------
// NuGet.Config defines package sources and credentials.  An attacker who adds
// a malicious source alongside the official feed exploits NuGet's
// package-resolution order, allowing shadowing of internal packages.

const NUGET_UNGATED = new Set([
  'NuGet.Config', 'NuGet.config', 'nuget.config', 'nuget.conf',
  'nuget.targets', 'NuGet.targets',
])

const NUGET_DIRS = [
  'nuget/', '.nuget/', 'NuGet/', 'nuget-config/', 'dotnet/',
]

function isNugetFeedConfig(path: string, base: string): boolean {
  if (NUGET_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('nuget-config-') ||
    base.startsWith('NuGet-config-') ||
    base.startsWith('nuget-feed-')
  ) {
    return /\.(config|conf|xml|json)$/.test(base)
  }

  return NUGET_DIRS.some((d) => low.includes(d)) &&
    /\.(config|conf|xml|json|props|targets)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: COMPOSER_SOURCE_DRIFT (low) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures PHP Composer's package source or
// authentication credentials.  auth.json in .composer/ stores OAuth tokens and
// HTTP Basic credentials for private repositories; config.json sets
// secure-http, discard-changes, and preferred-install settings.
//
// Trade-offs to consider:
//   - auth.json is common across many tools — require Composer directory context
//   - config.json is also generic — require .composer/ or composer/ dir context
//   - composer-auth.json / composer-config.json are unambiguous as prefixed names
//   - preferred-install: source allows running arbitrary build scripts, so changes
//     to this setting are security-relevant even when the source itself is trusted

const COMPOSER_DIRS = [
  '.composer/', 'composer/', 'composer-home/', 'php/', '.php/',
]

export function isComposerSourceConfig(path: string, base: string): boolean {
  const low = path.toLowerCase()

  // auth.json / config.json only in Composer directory context
  if (
    (base === 'auth.json' || base === 'config.json') &&
    COMPOSER_DIRS.some((d) => low.includes(d))
  ) {
    return true
  }

  // Prefixed variants are unambiguous
  if (
    base.startsWith('composer-auth') ||
    base.startsWith('composer-config') ||
    base.startsWith('composer-source')
  ) {
    return /\.(json|yaml|yml|conf)$/.test(base)
  }

  return COMPOSER_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|conf|cfg)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type DepMgrSecRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: DepMgrSecRule[] = [
  {
    id: 'NPM_REGISTRY_DRIFT',
    severity: 'high',
    description: 'npm / Yarn / pnpm registry configuration modified (.npmrc / .yarnrc.yml / .pnpmfile.cjs).',
    recommendation: 'Verify the registry URL has not been substituted with an untrusted mirror; audit auth token references, strict-ssl, and ignore-scripts settings; rotate any credentials referenced in modified config files.',
    match: isNpmRegistryConfig,
  },
  {
    id: 'PIP_INDEX_CONFIG_DRIFT',
    severity: 'high',
    description: 'Python pip package index configuration modified (pip.conf / pip.ini).',
    recommendation: 'Inspect index-url, extra-index-url, and trusted-host changes; remove any untrusted index URLs or trusted-host bypasses that disable SSL verification; ensure the primary index points to the official PyPI or the approved internal mirror.',
    match: isPipIndexConfig,
  },
  {
    id: 'MAVEN_REPOSITORY_DRIFT',
    severity: 'high',
    description: 'Maven repository or mirror configuration modified (settings.xml / settings-security.xml).',
    recommendation: 'Review mirror URL changes and repository definitions for unauthorised registry substitution; verify that the central mirror still points to the official Maven Central or the approved Nexus/Artifactory proxy; rotate the Maven master password if settings-security.xml was modified.',
    match: isMavenRepositoryConfig,
  },
  {
    id: 'GRADLE_WRAPPER_DRIFT',
    severity: 'high',
    description: 'Gradle wrapper or initialisation script modified (gradle-wrapper.properties / init.gradle).',
    recommendation: 'Validate that distributionUrl in gradle-wrapper.properties still points to the official Gradle distribution and matches the expected SHA-256 checksum; inspect any init.gradle changes for malicious plugin or repository additions that execute on every build.',
    match: isGradleWrapperConfig,
  },
  {
    id: 'CARGO_REGISTRY_DRIFT',
    severity: 'medium',
    description: 'Cargo / Rust registry source configuration modified (.cargo/config.toml).',
    recommendation: 'Check [source.crates-io] replace-with settings and any custom registry definitions for registry substitution; ensure no untrusted registry has been added as a replacement for crates.io.',
    match: isCargoRegistryConfig,
  },
  {
    id: 'BUNDLER_SOURCE_DRIFT',
    severity: 'medium',
    description: 'Ruby Bundler mirror or source configuration modified (.bundle/config).',
    recommendation: 'Audit BUNDLE_MIRROR__HTTPS__RUBYGEMS__ORG and BUNDLE_WITHOUT settings; remove any mirror URLs that redirect gem downloads to untrusted hosts; verify SSL_VERIFY_PEER has not been disabled.',
    match: isBundlerSourceConfig,
  },
  {
    id: 'NUGET_FEED_DRIFT',
    severity: 'medium',
    description: 'NuGet package feed or source configuration modified (NuGet.Config).',
    recommendation: 'Review packageSources entries for unauthorised source additions; check that the order places internal feeds before nuget.org to prevent package shadowing; audit credentials stored in the config for unexpectedly added sources.',
    match: isNugetFeedConfig,
  },
  {
    id: 'COMPOSER_SOURCE_DRIFT',
    severity: 'low',
    description: 'PHP Composer source or authentication configuration modified (.composer/auth.json / .composer/config.json).',
    recommendation: 'Verify that no new repository sources have been added; audit changes to preferred-install, secure-http, and any OAuth or HTTP Basic credentials stored in auth.json; rotate tokens if auth.json was unexpectedly modified.',
    match: isComposerSourceConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP: Record<Severity, number>     = { high: 45, medium: 25, low: 15 }

function computeRiskLevel(score: number): DepMgrSecDriftResult['riskLevel'] {
  if (score === 0)   return 'none'
  if (score < 15)    return 'low'
  if (score < 45)    return 'medium'
  if (score < 80)    return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type DepMgrSecDriftFinding = {
  ruleId: string
  severity: Severity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type DepMgrSecDriftResult = {
  riskScore: number
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none'
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: DepMgrSecDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// scanDepMgrSecurityDrift
// ---------------------------------------------------------------------------

export function scanDepMgrSecurityDrift(changedFiles: string[]): DepMgrSecDriftResult {
  const normalised = changedFiles
    .map(normalise)
    .filter((p) => !isVendorPath(p))

  const findings: DepMgrSecDriftFinding[] = []
  const perRuleScore: Record<string, number> = {}

  for (const rule of RULES) {
    const matched: string[] = []

    for (const p of normalised) {
      const base = p.split('/').pop() ?? p
      if (rule.match(p, base)) {
        matched.push(p)
      }
    }

    if (matched.length === 0) continue

    // Per-rule dedup: score counted once per rule regardless of match count
    const penalty = SEVERITY_PENALTY[rule.severity]
    const cap     = SEVERITY_CAP[rule.severity]
    const score   = Math.min(penalty, cap)
    perRuleScore[rule.id] = score

    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    matched[0],
      matchCount:     matched.length,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  const totalScore = Math.min(
    Object.values(perRuleScore).reduce((a, b) => a + b, 0),
    100,
  )

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const riskLevel = computeRiskLevel(totalScore)

  let summary: string
  if (findings.length === 0) {
    summary = 'No dependency manager security configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `Dependency manager security configuration drift detected: ${parts.join(', ')} severity finding${findings.length > 1 ? 's' : ''}. Risk score ${totalScore}/100 (${riskLevel}).`
  }

  return {
    riskScore:     totalScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
