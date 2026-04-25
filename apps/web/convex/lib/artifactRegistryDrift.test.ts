import { describe, expect, it } from 'vitest'
import {
  isDockerRegistryConfig,
  ARTIFACT_REGISTRY_RULES,
  scanArtifactRegistryDrift,
  type ArtifactRegistryDriftResult,
  type ArtifactRegistryRuleId,
} from './artifactRegistryDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]): ArtifactRegistryDriftResult {
  return scanArtifactRegistryDrift(files)
}

function triggeredRules(files: string[]): ArtifactRegistryRuleId[] {
  return scan(files).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Rule 1: ARTIFACTORY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('ARTIFACTORY_CONFIG_DRIFT', () => {
  it('matches artifactory.config.xml (ungated)', () => {
    expect(triggeredRules(['artifactory.config.xml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches artifactory.system.yaml (ungated)', () => {
    expect(triggeredRules(['artifactory.system.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches artifactory.system.properties (ungated)', () => {
    expect(triggeredRules(['artifactory.system.properties'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches artifactory.lic (ungated)', () => {
    expect(triggeredRules(['artifactory.lic'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches artifactory-access.yaml via prefix', () => {
    expect(triggeredRules(['artifactory-access.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches artifactory-security.yaml via prefix', () => {
    expect(triggeredRules(['artifactory-security.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches jfrog-platform.yaml via prefix', () => {
    expect(triggeredRules(['jfrog-platform.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches jfrog-config.json via prefix', () => {
    expect(triggeredRules(['jfrog-config.json'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches access.yml inside artifactory/ dir', () => {
    expect(triggeredRules(['artifactory/access.yml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches binarystore.xml inside jfrog/ dir', () => {
    expect(triggeredRules(['jfrog/binarystore.xml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches config.yaml inside .artifactory/ dir', () => {
    expect(triggeredRules(['.artifactory/config.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches master.key inside artifactory-config/ dir', () => {
    expect(triggeredRules(['artifactory-config/master.key'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('matches any yaml inside artifactory-data/ dir', () => {
    expect(triggeredRules(['artifactory-data/settings.yaml'])).toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('does NOT match config.yaml outside artifactory dirs', () => {
    expect(triggeredRules(['services/config.yaml'])).not.toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
  it('does NOT match vendor path', () => {
    expect(triggeredRules(['vendor/artifactory/artifactory.system.yaml'])).not.toContain('ARTIFACTORY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: NEXUS_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('NEXUS_CONFIG_DRIFT', () => {
  it('matches nexus.properties (ungated)', () => {
    expect(triggeredRules(['nexus.properties'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches nexus-default.properties (ungated)', () => {
    expect(triggeredRules(['nexus-default.properties'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches nexus-rbac.yaml via prefix', () => {
    expect(triggeredRules(['nexus-rbac.yaml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches nexus-storage.properties via prefix', () => {
    expect(triggeredRules(['nexus-storage.properties'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches nexus-ldap.xml via prefix', () => {
    expect(triggeredRules(['nexus-ldap.xml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches config.yaml inside nexus/ dir', () => {
    expect(triggeredRules(['nexus/config.yaml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches hazelcast.xml inside sonatype-work/ dir', () => {
    expect(triggeredRules(['sonatype-work/hazelcast.xml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches logback.xml inside nexus-data/ dir', () => {
    expect(triggeredRules(['nexus-data/logback.xml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches .env inside nexus-config/ dir', () => {
    expect(triggeredRules(['nexus-config/.env'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('matches any yaml inside nexus3/ dir', () => {
    expect(triggeredRules(['nexus3/security.yaml'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('does NOT match config.yaml outside nexus dirs', () => {
    expect(triggeredRules(['infra/config.yaml'])).not.toContain('NEXUS_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: HARBOR_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('HARBOR_REGISTRY_DRIFT', () => {
  it('matches harbor.yml (ungated)', () => {
    expect(triggeredRules(['harbor.yml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches harbor.yaml (ungated)', () => {
    expect(triggeredRules(['harbor.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches harbor-v1.10.yml (ungated versioned variant)', () => {
    expect(triggeredRules(['harbor-v1.10.yml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches harbor-prod.yaml via prefix', () => {
    expect(triggeredRules(['harbor-prod.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches harbor-notary.json via prefix', () => {
    expect(triggeredRules(['harbor-notary.json'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches core.yaml inside harbor/ dir', () => {
    expect(triggeredRules(['harbor/core.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches jobservice.yml inside .harbor/ dir', () => {
    expect(triggeredRules(['.harbor/jobservice.yml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches trivy-adapter.yaml inside harbor-config/ dir', () => {
    expect(triggeredRules(['harbor-config/trivy-adapter.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches database.yaml inside harbor-data/ dir', () => {
    expect(triggeredRules(['harbor-data/database.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('matches registryctl.yaml inside harbor/ dir', () => {
    expect(triggeredRules(['harbor/registryctl.yaml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('does NOT match config.yaml outside harbor dirs', () => {
    expect(triggeredRules(['app/config.yaml'])).not.toContain('HARBOR_REGISTRY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: DOCKER_REGISTRY_DRIFT + isDockerRegistryConfig
// ---------------------------------------------------------------------------

describe('DOCKER_REGISTRY_DRIFT', () => {
  it('matches docker-registry-config.yaml (ungated)', () => {
    expect(triggeredRules(['docker-registry-config.yaml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches docker-registry-config.yml (ungated)', () => {
    expect(triggeredRules(['docker-registry-config.yml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches registry-config.yaml (ungated)', () => {
    expect(triggeredRules(['registry-config.yaml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches registry-config.yml (ungated)', () => {
    expect(triggeredRules(['registry-config.yml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches registry-auth-config.yaml via basename keyword', () => {
    expect(triggeredRules(['registry-auth-config.yaml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches registry-tls-settings.yaml via basename keyword', () => {
    expect(triggeredRules(['registry-tls-settings.yaml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches registry-mirror.json via basename keyword', () => {
    expect(triggeredRules(['registry-mirror.json'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches config.yml inside registry/ dir', () => {
    expect(triggeredRules(['registry/config.yml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches auth.yaml inside docker-registry/ dir', () => {
    expect(triggeredRules(['docker-registry/auth.yaml'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches htpasswd inside container-registry/ dir', () => {
    expect(triggeredRules(['container-registry/htpasswd'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('matches nginx.conf inside distribution/ dir', () => {
    expect(triggeredRules(['distribution/nginx.conf'])).toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('does NOT match config.yml outside registry dirs', () => {
    expect(triggeredRules(['services/config.yml'])).not.toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('does NOT match config.yaml inside terraform/ dir', () => {
    expect(triggeredRules(['terraform/registry/config.yaml'])).not.toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('does NOT match auth.yaml inside k8s/ dir', () => {
    expect(triggeredRules(['k8s/registry/auth.yaml'])).not.toContain('DOCKER_REGISTRY_DRIFT')
  })
  it('does NOT match config.yaml inside helm/ dir', () => {
    expect(triggeredRules(['helm/registry/config.yaml'])).not.toContain('DOCKER_REGISTRY_DRIFT')
  })
})

describe('isDockerRegistryConfig', () => {
  it('returns true for registry-auth-config.yaml (basename keyword)', () => {
    expect(isDockerRegistryConfig('registry-auth-config.yaml', 'registry-auth-config.yaml')).toBe(true)
  })
  it('returns true for config.yml inside registry/ dir', () => {
    expect(isDockerRegistryConfig('registry/config.yml', 'config.yml')).toBe(true)
  })
  it('returns true for htpasswd inside docker-registry/ dir', () => {
    expect(isDockerRegistryConfig('docker-registry/htpasswd', 'htpasswd')).toBe(true)
  })
  it('returns true for auth.yml inside container-registry/ dir', () => {
    expect(isDockerRegistryConfig('container-registry/auth.yml', 'auth.yml')).toBe(true)
  })
  it('returns false for config.yml outside registry dirs', () => {
    expect(isDockerRegistryConfig('services/config.yml', 'config.yml')).toBe(false)
  })
  it('returns false when path includes terraform/', () => {
    expect(isDockerRegistryConfig('terraform/registry/config.yml', 'config.yml')).toBe(false)
  })
  it('returns false when path includes kubernetes/', () => {
    expect(isDockerRegistryConfig('kubernetes/registry/auth.yaml', 'auth.yaml')).toBe(false)
  })
  it('returns false when path includes .github/', () => {
    expect(isDockerRegistryConfig('.github/workflows/registry-config.yaml', 'registry-config.yaml')).toBe(false)
  })
  it('returns false for generic config.yaml outside all registry dirs', () => {
    expect(isDockerRegistryConfig('app/backend/config.yaml', 'config.yaml')).toBe(false)
  })
  it('returns false for registry-keyword basename with non-config extension', () => {
    expect(isDockerRegistryConfig('registry-auth.sh', 'registry-auth.sh')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: NPM_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('NPM_REGISTRY_DRIFT', () => {
  it('matches verdaccio.yaml (ungated)', () => {
    expect(triggeredRules(['verdaccio.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches verdaccio.yml (ungated)', () => {
    expect(triggeredRules(['verdaccio.yml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches sinopia.yaml (ungated)', () => {
    expect(triggeredRules(['sinopia.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches sinopia.yml (ungated)', () => {
    expect(triggeredRules(['sinopia.yml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches verdaccio-prod.yaml via prefix', () => {
    expect(triggeredRules(['verdaccio-prod.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches verdaccio-auth.json via prefix', () => {
    expect(triggeredRules(['verdaccio-auth.json'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches config.yaml inside verdaccio/ dir', () => {
    expect(triggeredRules(['verdaccio/config.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches htpasswd inside .verdaccio/ dir', () => {
    expect(triggeredRules(['.verdaccio/htpasswd'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches .npmrc inside npm-registry/ dir', () => {
    expect(triggeredRules(['npm-registry/.npmrc'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('matches any yaml inside private-npm/ dir', () => {
    expect(triggeredRules(['private-npm/settings.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('does NOT match config.yaml outside npm registry dirs', () => {
    expect(triggeredRules(['frontend/config.yaml'])).not.toContain('NPM_REGISTRY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: PYPI_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('PYPI_REGISTRY_DRIFT', () => {
  it('matches bandersnatch.cfg (ungated)', () => {
    expect(triggeredRules(['bandersnatch.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches bandersnatch.ini (ungated)', () => {
    expect(triggeredRules(['bandersnatch.ini'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches devpi-server.cfg (ungated)', () => {
    expect(triggeredRules(['devpi-server.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches devpi.ini (ungated)', () => {
    expect(triggeredRules(['devpi.ini'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches warehouse.cfg (ungated)', () => {
    expect(triggeredRules(['warehouse.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches bandersnatch-mirror.cfg via prefix', () => {
    expect(triggeredRules(['bandersnatch-mirror.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches devpi-auth.yaml via prefix', () => {
    expect(triggeredRules(['devpi-auth.yaml'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches config.cfg inside devpi/ dir', () => {
    expect(triggeredRules(['devpi/config.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches server.cfg inside .devpi/ dir', () => {
    expect(triggeredRules(['.devpi/server.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches config.yaml inside pypi-registry/ dir', () => {
    expect(triggeredRules(['pypi-registry/config.yaml'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches any cfg inside pypi-mirror/ dir', () => {
    expect(triggeredRules(['pypi-mirror/mirror.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('matches any cfg inside bandersnatch/ dir', () => {
    expect(triggeredRules(['bandersnatch/sync.cfg'])).toContain('PYPI_REGISTRY_DRIFT')
  })
  it('does NOT match config.cfg outside pypi dirs', () => {
    expect(triggeredRules(['python/config.cfg'])).not.toContain('PYPI_REGISTRY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: HELM_CHART_REPO_DRIFT
// ---------------------------------------------------------------------------

describe('HELM_CHART_REPO_DRIFT', () => {
  it('matches chartmuseum.yaml (ungated)', () => {
    expect(triggeredRules(['chartmuseum.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches chartmuseum.yml (ungated)', () => {
    expect(triggeredRules(['chartmuseum.yml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches chartmuseum.json (ungated)', () => {
    expect(triggeredRules(['chartmuseum.json'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches chartmuseum-prod.yaml via prefix', () => {
    expect(triggeredRules(['chartmuseum-prod.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches chartmuseum-auth.json via prefix', () => {
    expect(triggeredRules(['chartmuseum-auth.json'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches config.yaml inside chartmuseum/ dir', () => {
    expect(triggeredRules(['chartmuseum/config.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches auth.yaml inside helm-repo/ dir', () => {
    expect(triggeredRules(['helm-repo/auth.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches index.yaml inside chart-museum/ dir', () => {
    expect(triggeredRules(['chart-museum/index.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches values.yaml inside charts-repo/ dir', () => {
    expect(triggeredRules(['charts-repo/values.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('matches any yaml inside helm-registry/ dir', () => {
    expect(triggeredRules(['helm-registry/settings.yaml'])).toContain('HELM_CHART_REPO_DRIFT')
  })
  it('does NOT match index.yaml outside helm-repo dirs', () => {
    expect(triggeredRules(['docs/index.yaml'])).not.toContain('HELM_CHART_REPO_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: GO_MODULE_PROXY_DRIFT
// ---------------------------------------------------------------------------

describe('GO_MODULE_PROXY_DRIFT', () => {
  it('matches athens.yaml (ungated)', () => {
    expect(triggeredRules(['athens.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches athens.yml (ungated)', () => {
    expect(triggeredRules(['athens.yml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches athens.toml (ungated)', () => {
    expect(triggeredRules(['athens.toml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches athens.json (ungated)', () => {
    expect(triggeredRules(['athens.json'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches .athens.yaml (dot-prefixed ungated)', () => {
    expect(triggeredRules(['.athens.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches athens-prod.yaml via prefix', () => {
    expect(triggeredRules(['athens-prod.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches goproxy-config.yaml via prefix', () => {
    expect(triggeredRules(['goproxy-config.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches config.yaml inside athens/ dir', () => {
    expect(triggeredRules(['athens/config.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches config.toml inside goproxy/ dir', () => {
    expect(triggeredRules(['goproxy/config.toml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches config.yaml inside go-proxy/ dir', () => {
    expect(triggeredRules(['go-proxy/config.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches any yaml inside .athens/ dir', () => {
    expect(triggeredRules(['.athens/storage.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('matches config.toml inside go-module-proxy/ dir', () => {
    expect(triggeredRules(['go-module-proxy/config.toml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
  it('does NOT match config.yaml outside athens/go-proxy dirs', () => {
    expect(triggeredRules(['backend/config.yaml'])).not.toContain('GO_MODULE_PROXY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores node_modules paths', () => {
    expect(triggeredRules(['node_modules/harbor/harbor.yml'])).toHaveLength(0)
  })
  it('ignores vendor/ paths', () => {
    expect(triggeredRules(['vendor/nexus/nexus.properties'])).toHaveLength(0)
  })
  it('ignores dist/ paths', () => {
    expect(triggeredRules(['dist/artifactory/artifactory.system.yaml'])).toHaveLength(0)
  })
  it('ignores .venv paths', () => {
    expect(triggeredRules(['.venv/bandersnatch.cfg'])).toHaveLength(0)
  })
  it('ignores __pycache__ paths', () => {
    expect(triggeredRules(['__pycache__/verdaccio.yaml'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for harbor.yml', () => {
    expect(triggeredRules(['harbor\\harbor.yml'])).toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('normalises backslashes for nexus.properties in nexus dir', () => {
    expect(triggeredRules(['nexus\\nexus.properties'])).toContain('NEXUS_CONFIG_DRIFT')
  })
  it('normalises backslashes for verdaccio.yaml in verdaccio dir', () => {
    expect(triggeredRules(['verdaccio\\config.yaml'])).toContain('NPM_REGISTRY_DRIFT')
  })
  it('normalises backslashes for athens config', () => {
    expect(triggeredRules(['athens\\config.yaml'])).toContain('GO_MODULE_PROXY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matchCount
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces one finding for multiple nexus config files', () => {
    const result = scan(['nexus.properties', 'nexus-default.properties', 'nexus-rbac.yaml'])
    const nexusFindings = result.findings.filter((f) => f.ruleId === 'NEXUS_CONFIG_DRIFT')
    expect(nexusFindings).toHaveLength(1)
    expect(nexusFindings[0].matchCount).toBe(3)
  })
  it('produces separate findings for different rules', () => {
    const result = scan(['harbor.yml', 'verdaccio.yaml', 'athens.yaml'])
    expect(result.findings.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining(['HARBOR_REGISTRY_DRIFT', 'NPM_REGISTRY_DRIFT', 'GO_MODULE_PROXY_DRIFT']),
    )
  })
  it('records firstPath correctly', () => {
    const result = scan(['a/artifactory.system.yaml', 'b/artifactory-rbac.yaml'])
    const finding = result.findings.find((f) => f.ruleId === 'ARTIFACTORY_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('a/artifactory.system.yaml')
  })
  it('increments matchCount across all matched paths for a rule', () => {
    const result = scan([
      'registry/config.yml',
      'docker-registry/auth.yaml',
      'docker-registry/htpasswd',
    ])
    const dockerFinding = result.findings.find((f) => f.ruleId === 'DOCKER_REGISTRY_DRIFT')
    expect(dockerFinding?.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const result = scan([])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
  })
  it('returns score 15 and level low for 1 high finding', () => {
    const result = scan(['harbor.yml'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })
  it('returns score 8 and level low for 1 medium finding', () => {
    const result = scan(['verdaccio.yaml'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })
  it('returns score 4 and level low for 1 low finding', () => {
    const result = scan(['athens.yaml'])
    expect(result.riskScore).toBe(4)
    expect(result.riskLevel).toBe('low')
  })
  it('caps per-rule score at 45 when matchCount is high', () => {
    // Single high rule with 5 matches — 5×15=75 but per-rule cap is 45
    const files = [
      'harbor.yml',
      'harbor.yaml',
      'harbor-prod.yaml',
      'harbor-staging.yaml',
      'harbor-notary.json',
    ]
    const result = scan(files)
    // HARBOR cap: min(5×15, 45) = 45; score 45 → high
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('score for 4 separate high rules is 60', () => {
    const result = scan([
      'artifactory.system.yaml',  // ARTIFACTORY_CONFIG_DRIFT
      'nexus.properties',          // NEXUS_CONFIG_DRIFT
      'harbor.yml',                // HARBOR_REGISTRY_DRIFT
      'registry-config.yaml',      // DOCKER_REGISTRY_DRIFT
    ])
    expect(result.highCount).toBe(4)
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
  it('reaches critical at score >= 70', () => {
    // 4 high rules + 2 medium rules = 4×15 + 2×8 = 76
    const result = scan([
      'artifactory.system.yaml',
      'nexus.properties',
      'harbor.yml',
      'registry-config.yaml',
      'verdaccio.yaml',
      'chartmuseum.yaml',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })
  it('score is clamped to 100', () => {
    // All 8 rules — 4×15 + 3×8 + 1×4 = 88 (no individual caps hit)
    const result = scan([
      'artifactory.system.yaml',
      'nexus.properties',
      'harbor.yml',
      'registry-config.yaml',
      'verdaccio.yaml',
      'bandersnatch.cfg',
      'chartmuseum.yaml',
      'athens.yaml',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
  it('score 15 (1 high) → low', () => {
    expect(scan(['harbor.yml']).riskLevel).toBe('low')
  })
  it('score 34 (2 high + 1 low) → medium', () => {
    const result = scan(['harbor.yml', 'nexus.properties', 'athens.yaml'])
    // 2×15 + 1×4 = 34 → medium
    expect(result.riskScore).toBe(34)
    expect(result.riskLevel).toBe('medium')
  })
  it('score 45 (3 high) → high', () => {
    const result = scan(['artifactory.system.yaml', 'nexus.properties', 'harbor.yml'])
    // 3×15=45 — score < 45 is false, score < 70 is true → high
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('score 60 (4 high) → high', () => {
    const result = scan([
      'artifactory.system.yaml',
      'nexus.properties',
      'harbor.yml',
      'registry-config.yaml',
    ])
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
  it('score 76 (4 high + 2 medium) → critical', () => {
    const result = scan([
      'artifactory.system.yaml',
      'nexus.properties',
      'harbor.yml',
      'registry-config.yaml',
      'verdaccio.yaml',
      'chartmuseum.yaml',
    ])
    expect(result.riskScore).toBe(76)
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('sorts high before medium before low', () => {
    const result = scan(['athens.yaml', 'verdaccio.yaml', 'harbor.yml'])
    const severities = result.findings.map((f) => f.severity)
    const highIdx   = severities.indexOf('high')
    const mediumIdx = severities.indexOf('medium')
    const lowIdx    = severities.indexOf('low')
    if (highIdx !== -1 && mediumIdx !== -1) expect(highIdx).toBeLessThan(mediumIdx)
    if (mediumIdx !== -1 && lowIdx !== -1) expect(mediumIdx).toBeLessThan(lowIdx)
  })
  it('high rules appear before medium rules in findings array', () => {
    const result = scan([
      'verdaccio.yaml',       // medium
      'harbor.yml',            // high
      'athens.yaml',           // low
    ])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds.indexOf('HARBOR_REGISTRY_DRIFT')).toBeLessThan(ruleIds.indexOf('NPM_REGISTRY_DRIFT'))
    expect(ruleIds.indexOf('NPM_REGISTRY_DRIFT')).toBeLessThan(ruleIds.indexOf('GO_MODULE_PROXY_DRIFT'))
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns expected shape for empty input', () => {
    const result = scan([])
    expect(result).toMatchObject({
      riskScore: 0,
      riskLevel: 'none',
      totalFindings: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findings: [],
    })
    expect(typeof result.summary).toBe('string')
  })
  it('returns correct counts for mixed input', () => {
    const result = scan(['harbor.yml', 'verdaccio.yaml', 'athens.yaml'])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.totalFindings).toBe(3)
  })
  it('each finding has all required fields', () => {
    const result = scan(['nexus.properties'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
  it('summary describes no findings', () => {
    expect(scan([]).summary).toContain('No artifact registry')
  })
  it('summary includes finding count and score', () => {
    const result = scan(['harbor.yml'])
    expect(result.summary).toContain('1')
    expect(result.summary).toContain('15/100')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('full registry stack change triggers all 8 rules', () => {
    const result = scan([
      'artifactory.system.yaml',  // ARTIFACTORY_CONFIG_DRIFT
      'nexus.properties',          // NEXUS_CONFIG_DRIFT
      'harbor.yml',                // HARBOR_REGISTRY_DRIFT
      'registry-config.yaml',      // DOCKER_REGISTRY_DRIFT
      'verdaccio.yaml',            // NPM_REGISTRY_DRIFT
      'bandersnatch.cfg',          // PYPI_REGISTRY_DRIFT
      'chartmuseum.yaml',          // HELM_CHART_REPO_DRIFT
      'athens.yaml',               // GO_MODULE_PROXY_DRIFT
    ])
    expect(result.totalFindings).toBe(8)
  })
  it('chartmuseum.yaml triggers only HELM_CHART_REPO, not HARBOR', () => {
    const rules = triggeredRules(['chartmuseum.yaml'])
    expect(rules).toContain('HELM_CHART_REPO_DRIFT')
    expect(rules).not.toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('verdaccio.yaml triggers only NPM_REGISTRY, not PYPI_REGISTRY', () => {
    const rules = triggeredRules(['verdaccio.yaml'])
    expect(rules).toContain('NPM_REGISTRY_DRIFT')
    expect(rules).not.toContain('PYPI_REGISTRY_DRIFT')
  })
  it('config.yml in registry/ dir triggers DOCKER but not HARBOR', () => {
    const rules = triggeredRules(['registry/config.yml'])
    expect(rules).toContain('DOCKER_REGISTRY_DRIFT')
    expect(rules).not.toContain('HARBOR_REGISTRY_DRIFT')
  })
  it('harbor.yml inside vendor/ is excluded entirely', () => {
    const result = scan(['vendor/harbor/harbor.yml', 'harbor.yml'])
    const harborFindings = result.findings.filter((f) => f.ruleId === 'HARBOR_REGISTRY_DRIFT')
    expect(harborFindings).toHaveLength(1)
    expect(harborFindings[0].matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('ARTIFACT_REGISTRY_RULES registry', () => {
  it('has exactly 8 rules', () => {
    expect(ARTIFACT_REGISTRY_RULES).toHaveLength(8)
  })
  it('has 4 high severity rules', () => {
    expect(ARTIFACT_REGISTRY_RULES.filter((r) => r.severity === 'high')).toHaveLength(4)
  })
  it('has 3 medium severity rules', () => {
    expect(ARTIFACT_REGISTRY_RULES.filter((r) => r.severity === 'medium')).toHaveLength(3)
  })
  it('has 1 low severity rule', () => {
    expect(ARTIFACT_REGISTRY_RULES.filter((r) => r.severity === 'low')).toHaveLength(1)
  })
  it('all rule IDs are unique', () => {
    const ids = ARTIFACT_REGISTRY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
  it('all rules have non-empty description and recommendation', () => {
    for (const rule of ARTIFACT_REGISTRY_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
  it('first 4 rules are high severity', () => {
    const first4 = ARTIFACT_REGISTRY_RULES.slice(0, 4)
    expect(first4.every((r) => r.severity === 'high')).toBe(true)
  })
  it('rules 5-7 are medium severity', () => {
    const middle3 = ARTIFACT_REGISTRY_RULES.slice(4, 7)
    expect(middle3.every((r) => r.severity === 'medium')).toBe(true)
  })
  it('last rule is low severity', () => {
    expect(ARTIFACT_REGISTRY_RULES[7].severity).toBe('low')
  })
})
