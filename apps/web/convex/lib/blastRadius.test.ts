import { describe, expect, it } from 'vitest'
import { computeBlastRadius, type SbomComponentInput } from './blastRadius'

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const baseFinding = {
  affectedPackages: ['vulnerable-lib'],
  affectedFiles: ['requirements.txt'],
  severity: 'high' as const,
  exploitAvailable: false,
  source: 'breach_intel',
}

const baseComponent: SbomComponentInput = {
  name: 'vulnerable-lib',
  normalizedName: 'vulnerable-lib',
  version: '1.0.0',
  ecosystem: 'npm',
  layer: 'runtime',
  isDirect: true,
  hasKnownVulnerabilities: true,
  dependents: [],
}

// ---------------------------------------------------------------------------
// No-components case
// ---------------------------------------------------------------------------

describe('computeBlastRadius — no components', () => {
  it('returns zero exposure when the component list is empty', () => {
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [],
      repositoryName: 'my-repo',
    })
    expect(result.directExposureCount).toBe(0)
    expect(result.transitiveExposureCount).toBe(0)
    expect(result.attackPathDepth).toBe(0)
    expect(result.reachableServices).toHaveLength(0)
    expect(result.exposedDataLayers).toHaveLength(0)
  })

  it('still computes a non-zero score from severity alone when no components match', () => {
    const result = computeBlastRadius({
      finding: baseFinding, // severity = 'high' → weight 0.75
      components: [],
      repositoryName: 'my-repo',
    })
    // 0.75 × 40 = 30 (no direct, no exploit, no transitive bonus)
    expect(result.businessImpactScore).toBe(30)
    expect(result.riskTier).toBe('medium')
  })

  it('produces a "contained" summary when there are no matched components', () => {
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [],
      repositoryName: 'my-repo',
    })
    expect(result.summary).toContain('No matched components')
    expect(result.summary).toContain('my-repo')
  })
})

// ---------------------------------------------------------------------------
// Direct-dep-only case
// ---------------------------------------------------------------------------

describe('computeBlastRadius — direct dependency', () => {
  it('counts a direct dep correctly and sets attack depth to 1', () => {
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [baseComponent],
      repositoryName: 'my-repo',
    })
    expect(result.directExposureCount).toBe(1)
    expect(result.transitiveExposureCount).toBe(0)
    expect(result.attackPathDepth).toBe(1)
    expect(result.exposedDataLayers).toContain('runtime')
  })

  it('adds the repository to reachable services when there is a direct hit', () => {
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [baseComponent],
      repositoryName: 'my-repo',
    })
    expect(result.reachableServices).toContain('my-repo')
  })

  it('computes score correctly: high severity + 1 direct dep, no exploit', () => {
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [baseComponent],
      repositoryName: 'my-repo',
    })
    // 0.75×40=30 + min(1×20,30)=20 + 0 (no exploit) + 0 = 50
    expect(result.businessImpactScore).toBe(50)
    expect(result.riskTier).toBe('medium')
  })

  it('applies exploit bonus correctly', () => {
    const result = computeBlastRadius({
      finding: { ...baseFinding, exploitAvailable: true },
      components: [baseComponent],
      repositoryName: 'my-repo',
    })
    // 30 + 20 + 20 + 0 = 70
    expect(result.businessImpactScore).toBe(70)
    expect(result.riskTier).toBe('high')
  })

  it('caps direct exposure contribution at 30', () => {
    // 3 direct deps × 20 = 60, but capped at 30
    const components = [1, 2, 3].map((i) => ({
      ...baseComponent,
      name: `pkg-${i}`,
      normalizedName: `pkg-${i}`,
    }))
    const result = computeBlastRadius({
      finding: {
        ...baseFinding,
        affectedPackages: components.map((c) => c.name),
      },
      components,
      repositoryName: 'my-repo',
    })
    // 0.75×40=30 + min(3×20,30)=30 + 0 + 0 = 60
    expect(result.businessImpactScore).toBe(60)
    expect(result.riskTier).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Deep transitive chain case
// ---------------------------------------------------------------------------

describe('computeBlastRadius — transitive chain', () => {
  it('sets attack depth to 2 for a transitive dependency', () => {
    const transitiveComp: SbomComponentInput = {
      ...baseComponent,
      isDirect: false,
      layer: 'transitive',
    }
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [transitiveComp],
      repositoryName: 'my-repo',
    })
    expect(result.directExposureCount).toBe(0)
    expect(result.transitiveExposureCount).toBe(1)
    expect(result.attackPathDepth).toBe(2)
  })

  it('sets attack depth to 3 for a container-layer dependency', () => {
    const containerComp: SbomComponentInput = {
      ...baseComponent,
      isDirect: false,
      layer: 'container',
    }
    const result = computeBlastRadius({
      finding: baseFinding,
      components: [containerComp],
      repositoryName: 'my-repo',
    })
    expect(result.attackPathDepth).toBe(3)
    expect(result.exposedDataLayers).toContain('container')
  })

  it('applies the +10 transitive bonus when transitiveExposureCount > 5', () => {
    const transitiveComponents = Array.from({ length: 6 }, (_, i) => ({
      ...baseComponent,
      name: `dep-${i}`,
      normalizedName: `dep-${i}`,
      isDirect: false,
      layer: 'runtime',
    }))
    const result = computeBlastRadius({
      finding: {
        ...baseFinding,
        affectedPackages: transitiveComponents.map((c) => c.name),
      },
      components: transitiveComponents,
      repositoryName: 'my-repo',
    })
    expect(result.transitiveExposureCount).toBe(6)
    // 0.75×40=30 + 0 (no direct) + 0 (no exploit) + 10 (>5 transitive) = 40
    expect(result.businessImpactScore).toBe(40)
  })

  it('does NOT apply the transitive bonus when transitiveExposureCount is exactly 5', () => {
    const transitiveComponents = Array.from({ length: 5 }, (_, i) => ({
      ...baseComponent,
      name: `dep-${i}`,
      normalizedName: `dep-${i}`,
      isDirect: false,
    }))
    const result = computeBlastRadius({
      finding: {
        ...baseFinding,
        affectedPackages: transitiveComponents.map((c) => c.name),
      },
      components: transitiveComponents,
      repositoryName: 'my-repo',
    })
    // 30 + 0 + 0 + 0 = 30 (bonus only kicks in for >5, not >=5)
    expect(result.businessImpactScore).toBe(30)
  })
})

// ---------------------------------------------------------------------------
// Multi-service blast case
// ---------------------------------------------------------------------------

describe('computeBlastRadius — multi-service blast', () => {
  it('collects and deduplicates reachable services from all component dependents', () => {
    const components: SbomComponentInput[] = [
      {
        ...baseComponent,
        version: '1.0.0',
        isDirect: true,
        dependents: ['api-gateway', 'auth-service'],
      },
      {
        ...baseComponent,
        version: '1.1.0',
        isDirect: false,
        layer: 'transitive',
        dependents: ['payments-service', 'auth-service'], // auth-service is a duplicate
      },
    ]
    const result = computeBlastRadius({
      finding: baseFinding,
      components,
      repositoryName: 'my-repo',
    })
    expect(result.reachableServices).toContain('api-gateway')
    expect(result.reachableServices).toContain('auth-service')
    expect(result.reachableServices).toContain('payments-service')
    expect(result.reachableServices).toContain('my-repo')
    // auth-service must be deduplicated
    expect(
      result.reachableServices.filter((s) => s === 'auth-service'),
    ).toHaveLength(1)
  })

  it('collects unique layers across all affected components', () => {
    const components: SbomComponentInput[] = [
      { ...baseComponent, version: '1.0.0', layer: 'runtime', isDirect: true },
      {
        ...baseComponent,
        version: '1.1.0',
        layer: 'build',
        isDirect: false,
        dependents: [],
      },
    ]
    const result = computeBlastRadius({
      finding: baseFinding,
      components,
      repositoryName: 'my-repo',
    })
    expect(result.exposedDataLayers).toContain('runtime')
    expect(result.exposedDataLayers).toContain('build')
    expect(result.exposedDataLayers).toHaveLength(2)
  })

  it('matches affected packages case-insensitively', () => {
    const result = computeBlastRadius({
      finding: { ...baseFinding, affectedPackages: ['Vulnerable-Lib'] },
      components: [{ ...baseComponent, name: 'vulnerable-lib' }],
      repositoryName: 'my-repo',
    })
    expect(result.directExposureCount).toBe(1)
  })

  it('matches via normalizedName when name does not match', () => {
    const result = computeBlastRadius({
      finding: { ...baseFinding, affectedPackages: ['vuln-lib-normalized'] },
      components: [
        {
          ...baseComponent,
          name: 'vuln-lib@scope',
          normalizedName: 'vuln-lib-normalized',
        },
      ],
      repositoryName: 'my-repo',
    })
    expect(result.directExposureCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Risk tier boundary cases
// ---------------------------------------------------------------------------

describe('computeBlastRadius — risk tier boundaries', () => {
  it('assigns critical tier for score >= 75', () => {
    // critical severity (weight 1.0) + 2 direct deps + exploit = 40+30+20=90
    // affectedPackages must include the component names for them to match.
    const result = computeBlastRadius({
      finding: {
        ...baseFinding,
        severity: 'critical' as const,
        exploitAvailable: true,
        affectedPackages: ['p1', 'p2'],
      },
      components: [
        { ...baseComponent, name: 'p1', normalizedName: 'p1', isDirect: true },
        { ...baseComponent, name: 'p2', normalizedName: 'p2', isDirect: true },
      ],
      repositoryName: 'repo',
    })
    // 1.0×40=40 + min(2×20,30)=30 + 20 + 0 = 90
    expect(result.businessImpactScore).toBe(90)
    expect(result.riskTier).toBe('critical')
  })

  it('assigns low tier for informational severity with no other signals', () => {
    const result = computeBlastRadius({
      finding: {
        ...baseFinding,
        severity: 'informational' as const,
        exploitAvailable: false,
      },
      components: [],
      repositoryName: 'repo',
    })
    // 0×40=0 + 0 + 0 + 0 = 0
    expect(result.businessImpactScore).toBe(0)
    expect(result.riskTier).toBe('low')
  })

  it('caps businessImpactScore at 100', () => {
    // Theoretical max: critical(40) + directCap(30) + exploit(20) + transitive(10) = 100
    const components = Array.from({ length: 10 }, (_, i) => ({
      ...baseComponent,
      name: `p${i}`,
      normalizedName: `p${i}`,
      isDirect: true,
    }))
    const transitiveComponents = Array.from({ length: 6 }, (_, i) => ({
      ...baseComponent,
      name: `t${i}`,
      normalizedName: `t${i}`,
      isDirect: false,
    }))
    const result = computeBlastRadius({
      finding: {
        affectedPackages: [
          ...components.map((c) => c.name),
          ...transitiveComponents.map((c) => c.name),
        ],
        affectedFiles: [],
        severity: 'critical' as const,
        exploitAvailable: true,
        source: 'breach_intel',
      },
      components: [...components, ...transitiveComponents],
      repositoryName: 'repo',
    })
    expect(result.businessImpactScore).toBeLessThanOrEqual(100)
    expect(result.riskTier).toBe('critical')
  })
})
