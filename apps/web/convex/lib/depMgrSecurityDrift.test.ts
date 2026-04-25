/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  isComposerSourceConfig,
  scanDepMgrSecurityDrift,
} from './depMgrSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: NPM_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('NPM_REGISTRY_DRIFT', () => {
  it('detects .npmrc at repo root', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects .yarnrc', () => {
    const r = scanDepMgrSecurityDrift(['.yarnrc'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects .yarnrc.yml', () => {
    const r = scanDepMgrSecurityDrift(['.yarnrc.yml'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects .pnpmfile.cjs', () => {
    const r = scanDepMgrSecurityDrift(['.pnpmfile.cjs'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects .npmrc- prefixed variant', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc-production'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects config.json in yarn/ dir', () => {
    const r = scanDepMgrSecurityDrift(['yarn/config.json'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('does NOT match package.json', () => {
    const r = scanDepMgrSecurityDrift(['package.json'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(false)
  })

  it('does NOT match file in node_modules/', () => {
    const r = scanDepMgrSecurityDrift(['node_modules/foo/.npmrc'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc'])
    const f = r.findings.find((x) => x.ruleId === 'NPM_REGISTRY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: PIP_INDEX_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('PIP_INDEX_CONFIG_DRIFT', () => {
  it('detects pip.conf', () => {
    const r = scanDepMgrSecurityDrift(['pip.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(true)
  })

  it('detects pip.ini', () => {
    const r = scanDepMgrSecurityDrift(['pip.ini'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(true)
  })

  it('detects pip.cfg', () => {
    const r = scanDepMgrSecurityDrift(['pip.cfg'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(true)
  })

  it('detects .pip.conf', () => {
    const r = scanDepMgrSecurityDrift(['.pip.conf'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(true)
  })

  it('detects pip- prefixed conf in pip dir', () => {
    const r = scanDepMgrSecurityDrift(['.pip/pip-private.ini'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT match requirements.txt', () => {
    const r = scanDepMgrSecurityDrift(['requirements.txt'])
    expect(r.findings.some((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const r = scanDepMgrSecurityDrift(['pip.conf'])
    const f = r.findings.find((x) => x.ruleId === 'PIP_INDEX_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: MAVEN_REPOSITORY_DRIFT
// ---------------------------------------------------------------------------

describe('MAVEN_REPOSITORY_DRIFT', () => {
  it('detects settings-security.xml ungated', () => {
    const r = scanDepMgrSecurityDrift(['settings-security.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(true)
  })

  it('detects settings.xml in .m2/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.m2/settings.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(true)
  })

  it('detects settings.xml in maven/ dir', () => {
    const r = scanDepMgrSecurityDrift(['maven/settings.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(true)
  })

  it('does NOT detect settings.xml at root (too generic)', () => {
    const r = scanDepMgrSecurityDrift(['settings.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(false)
  })

  it('detects maven-settings- prefixed file', () => {
    const r = scanDepMgrSecurityDrift(['maven-settings-staging.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(true)
  })

  it('severity is high', () => {
    const r = scanDepMgrSecurityDrift(['settings-security.xml'])
    const f = r.findings.find((x) => x.ruleId === 'MAVEN_REPOSITORY_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: GRADLE_WRAPPER_DRIFT
// ---------------------------------------------------------------------------

describe('GRADLE_WRAPPER_DRIFT', () => {
  it('detects gradle-wrapper.properties', () => {
    const r = scanDepMgrSecurityDrift(['gradle/wrapper/gradle-wrapper.properties'])
    expect(r.findings.some((f) => f.ruleId === 'GRADLE_WRAPPER_DRIFT')).toBe(true)
  })

  it('detects gradle-wrapper.jar', () => {
    const r = scanDepMgrSecurityDrift(['gradle/wrapper/gradle-wrapper.jar'])
    expect(r.findings.some((f) => f.ruleId === 'GRADLE_WRAPPER_DRIFT')).toBe(true)
  })

  it('detects gradlew at root', () => {
    const r = scanDepMgrSecurityDrift(['gradlew'])
    expect(r.findings.some((f) => f.ruleId === 'GRADLE_WRAPPER_DRIFT')).toBe(true)
  })

  it('detects init.gradle in .gradle/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.gradle/init.gradle'])
    expect(r.findings.some((f) => f.ruleId === 'GRADLE_WRAPPER_DRIFT')).toBe(true)
  })

  it('does NOT match build.gradle in src/ (no gradle wrapper dir)', () => {
    const r = scanDepMgrSecurityDrift(['src/build.gradle'])
    expect(r.findings.some((f) => f.ruleId === 'GRADLE_WRAPPER_DRIFT')).toBe(false)
  })

  it('severity is high', () => {
    const r = scanDepMgrSecurityDrift(['gradle-wrapper.properties'])
    const f = r.findings.find((x) => x.ruleId === 'GRADLE_WRAPPER_DRIFT')!
    expect(f.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Rule 5: CARGO_REGISTRY_DRIFT
// ---------------------------------------------------------------------------

describe('CARGO_REGISTRY_DRIFT', () => {
  it('detects config.toml in .cargo/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.cargo/config.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CARGO_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects config (legacy format) in .cargo/', () => {
    const r = scanDepMgrSecurityDrift(['.cargo/config'])
    expect(r.findings.some((f) => f.ruleId === 'CARGO_REGISTRY_DRIFT')).toBe(true)
  })

  it('detects cargo-config- prefixed file', () => {
    const r = scanDepMgrSecurityDrift(['cargo-config-private.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CARGO_REGISTRY_DRIFT')).toBe(true)
  })

  it('does NOT match Cargo.toml at root (not in .cargo/ context)', () => {
    const r = scanDepMgrSecurityDrift(['Cargo.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CARGO_REGISTRY_DRIFT')).toBe(false)
  })

  it('severity is medium', () => {
    const r = scanDepMgrSecurityDrift(['.cargo/config.toml'])
    const f = r.findings.find((x) => x.ruleId === 'CARGO_REGISTRY_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: BUNDLER_SOURCE_DRIFT
// ---------------------------------------------------------------------------

describe('BUNDLER_SOURCE_DRIFT', () => {
  it('detects config in .bundle/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.bundle/config'])
    expect(r.findings.some((f) => f.ruleId === 'BUNDLER_SOURCE_DRIFT')).toBe(true)
  })

  it('detects bundler-config- prefixed file', () => {
    const r = scanDepMgrSecurityDrift(['bundler-config-prod.yml'])
    expect(r.findings.some((f) => f.ruleId === 'BUNDLER_SOURCE_DRIFT')).toBe(true)
  })

  it('detects .yml in .bundle/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.bundle/settings.yml'])
    expect(r.findings.some((f) => f.ruleId === 'BUNDLER_SOURCE_DRIFT')).toBe(true)
  })

  it('does NOT match Gemfile at root (no bundle dir context)', () => {
    const r = scanDepMgrSecurityDrift(['Gemfile'])
    expect(r.findings.some((f) => f.ruleId === 'BUNDLER_SOURCE_DRIFT')).toBe(false)
  })

  it('severity is medium', () => {
    const r = scanDepMgrSecurityDrift(['.bundle/config'])
    const f = r.findings.find((x) => x.ruleId === 'BUNDLER_SOURCE_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: NUGET_FEED_DRIFT
// ---------------------------------------------------------------------------

describe('NUGET_FEED_DRIFT', () => {
  it('detects NuGet.Config ungated', () => {
    const r = scanDepMgrSecurityDrift(['NuGet.Config'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(true)
  })

  it('detects NuGet.config (lowercase c)', () => {
    const r = scanDepMgrSecurityDrift(['NuGet.config'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(true)
  })

  it('detects nuget.config (all lowercase)', () => {
    const r = scanDepMgrSecurityDrift(['nuget.config'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(true)
  })

  it('detects nuget-config- prefixed file', () => {
    const r = scanDepMgrSecurityDrift(['nuget-config-enterprise.xml'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(true)
  })

  it('detects .config in nuget/ dir', () => {
    const r = scanDepMgrSecurityDrift(['nuget/enterprise.config'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(true)
  })

  it('does NOT match App.config (no nuget context)', () => {
    const r = scanDepMgrSecurityDrift(['App.config'])
    expect(r.findings.some((f) => f.ruleId === 'NUGET_FEED_DRIFT')).toBe(false)
  })

  it('severity is medium', () => {
    const r = scanDepMgrSecurityDrift(['NuGet.Config'])
    const f = r.findings.find((x) => x.ruleId === 'NUGET_FEED_DRIFT')!
    expect(f.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: COMPOSER_SOURCE_DRIFT (exported)
// ---------------------------------------------------------------------------

describe('COMPOSER_SOURCE_DRIFT — isComposerSourceConfig', () => {
  it('matches auth.json in .composer/ dir', () => {
    expect(isComposerSourceConfig('.composer/auth.json', 'auth.json')).toBe(true)
  })

  it('matches config.json in composer/ dir', () => {
    expect(isComposerSourceConfig('composer/config.json', 'config.json')).toBe(true)
  })

  it('matches composer-auth.json ungated prefix', () => {
    expect(isComposerSourceConfig('composer-auth.json', 'composer-auth.json')).toBe(true)
  })

  it('matches composer-config.json ungated prefix', () => {
    expect(isComposerSourceConfig('composer-config.json', 'composer-config.json')).toBe(true)
  })

  it('does NOT match auth.json at root (too generic)', () => {
    expect(isComposerSourceConfig('auth.json', 'auth.json')).toBe(false)
  })

  it('does NOT match config.json at root (too generic)', () => {
    expect(isComposerSourceConfig('config.json', 'config.json')).toBe(false)
  })

  it('does NOT match auth.json in src/ (no composer context)', () => {
    expect(isComposerSourceConfig('src/auth.json', 'auth.json')).toBe(false)
  })
})

describe('COMPOSER_SOURCE_DRIFT — scanDepMgrSecurityDrift', () => {
  it('detects auth.json in .composer/ dir', () => {
    const r = scanDepMgrSecurityDrift(['.composer/auth.json'])
    expect(r.findings.some((f) => f.ruleId === 'COMPOSER_SOURCE_DRIFT')).toBe(true)
  })

  it('severity is low', () => {
    const r = scanDepMgrSecurityDrift(['.composer/auth.json'])
    const f = r.findings.find((x) => x.ruleId === 'COMPOSER_SOURCE_DRIFT')!
    expect(f.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scanDepMgrSecurityDrift — scoring model', () => {
  it('empty file list returns riskScore 0 and riskLevel none', () => {
    const r = scanDepMgrSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('single high rule contributes 15 penalty → riskLevel medium (15 < 45)', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high rules → 45 penalty → riskLevel high (45 is not < 45)', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc', 'pip.conf', 'settings-security.xml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('all four high rules → 60 penalty → riskLevel high', () => {
    const r = scanDepMgrSecurityDrift([
      '.npmrc', 'pip.conf', 'settings-security.xml', 'gradle-wrapper.properties',
    ])
    expect(r.riskScore).toBe(60)
    expect(r.riskLevel).toBe('high')
  })

  it('single medium rule contributes 8 penalty → riskLevel low', () => {
    const r = scanDepMgrSecurityDrift(['.cargo/config.toml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('all 8 rules → score 88 → riskLevel critical', () => {
    const r = scanDepMgrSecurityDrift([
      '.npmrc', 'pip.conf', 'settings-security.xml', 'gradle-wrapper.properties',
      '.cargo/config.toml', '.bundle/config', 'NuGet.Config', '.composer/auth.json',
    ])
    // 4×15 + 3×8 + 1×4 = 60 + 24 + 4 = 88
    expect(r.riskScore).toBe(88)
    expect(r.riskLevel).toBe('critical')
  })

  it('score is capped at 100', () => {
    const files = [
      '.npmrc', 'pip.conf', 'settings-security.xml', 'gradle-wrapper.properties',
      '.cargo/config.toml', '.bundle/config', 'NuGet.Config', '.composer/auth.json',
      '.yarnrc', 'pip.ini', '.m2/settings.xml',
    ]
    const r = scanDepMgrSecurityDrift(files)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Per-rule dedup
// ---------------------------------------------------------------------------

describe('scanDepMgrSecurityDrift — per-rule dedup', () => {
  it('multiple npm config files count as one NPM_REGISTRY_DRIFT finding', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc', '.yarnrc', '.yarnrc.yml', '.pnpmfile.cjs'])
    const npmFindings = r.findings.filter((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')
    expect(npmFindings).toHaveLength(1)
  })

  it('matchCount reflects actual number of matched files for a rule', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc', '.yarnrc', '.yarnrc.yml'])
    const f = r.findings.find((x) => x.ruleId === 'NPM_REGISTRY_DRIFT')!
    expect(f.matchCount).toBe(3)
  })

  it('multiple pip config files count as one PIP_INDEX_CONFIG_DRIFT finding', () => {
    const r = scanDepMgrSecurityDrift(['pip.conf', 'pip.ini', 'pip.cfg'])
    const pipFindings = r.findings.filter((f) => f.ruleId === 'PIP_INDEX_CONFIG_DRIFT')
    expect(pipFindings).toHaveLength(1)
    // Still only 15 penalty (one HIGH rule)
    expect(r.riskScore).toBe(15)
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('scanDepMgrSecurityDrift — vendor exclusion', () => {
  it('ignores .npmrc nested inside node_modules/', () => {
    const r = scanDepMgrSecurityDrift(['node_modules/some-pkg/.npmrc'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores pip.conf inside vendor/', () => {
    const r = scanDepMgrSecurityDrift(['vendor/python/pip.conf'])
    expect(r.findings).toHaveLength(0)
  })

  it('ignores files inside .git/', () => {
    const r = scanDepMgrSecurityDrift(['.git/hooks/.npmrc'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

describe('scanDepMgrSecurityDrift — path normalisation', () => {
  it('handles Windows-style backslash paths', () => {
    const r = scanDepMgrSecurityDrift(['.cargo\\config.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CARGO_REGISTRY_DRIFT')).toBe(true)
  })

  it('handles ./ prefix', () => {
    const r = scanDepMgrSecurityDrift(['./.npmrc'])
    expect(r.findings.some((f) => f.ruleId === 'NPM_REGISTRY_DRIFT')).toBe(true)
  })

  it('handles deeply nested path', () => {
    const r = scanDepMgrSecurityDrift(['ci/config/.m2/settings.xml'])
    expect(r.findings.some((f) => f.ruleId === 'MAVEN_REPOSITORY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe('scanDepMgrSecurityDrift — summary', () => {
  it('returns clean summary when no findings', () => {
    const r = scanDepMgrSecurityDrift([])
    expect(r.summary).toBe('No dependency manager security configuration drift detected.')
  })

  it('summary includes riskLevel and score when findings exist', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc'])
    expect(r.summary).toContain('medium')
    expect(r.summary).toContain('15/100')
  })

  it('totalFindings matches findings array length', () => {
    const r = scanDepMgrSecurityDrift(['.npmrc', 'pip.conf'])
    expect(r.totalFindings).toBe(r.findings.length)
  })

  it('highCount / mediumCount / lowCount are accurate', () => {
    const r = scanDepMgrSecurityDrift([
      '.npmrc', 'pip.conf', '.cargo/config.toml', '.composer/auth.json',
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
  })
})
