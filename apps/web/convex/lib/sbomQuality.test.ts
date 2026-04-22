// WS-32 — SBOM Quality & Completeness Scoring: unit tests
/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  computeFreshnessScore,
  computeSbomQuality,
  countLayersPopulated,
  isExactVersion,
  type SbomComponentInput,
  type SbomSnapshotInput,
} from './sbomQuality'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 1000 * 60 * 60 * 24
const NOW = 1_000_000_000_000 // fixed reference for deterministic tests

function makeSnapshot(
  overrides: Partial<SbomSnapshotInput> = {},
): SbomSnapshotInput {
  return {
    capturedAt: NOW,
    directDependencyCount: 10,
    transitiveDependencyCount: 20,
    buildDependencyCount: 5,
    containerDependencyCount: 3,
    runtimeDependencyCount: 2,
    aiModelDependencyCount: 1,
    totalComponents: 41,
    sourceFiles: ['package-lock.json'],
    ...overrides,
  }
}

function makeComponent(
  overrides: Partial<SbomComponentInput> = {},
): SbomComponentInput {
  return {
    version: '1.2.3',
    license: 'MIT',
    isDirect: true,
    ecosystem: 'npm',
    layer: 'direct',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// isExactVersion
// ---------------------------------------------------------------------------

describe('isExactVersion', () => {
  it('accepts plain semver as exact', () => {
    expect(isExactVersion('1.2.3')).toBe(true)
  })

  it('accepts pre-release as exact', () => {
    expect(isExactVersion('0.9.0-alpha.1')).toBe(true)
  })

  it('accepts single integer version', () => {
    expect(isExactVersion('3')).toBe(true)
  })

  it('rejects caret range', () => {
    expect(isExactVersion('^1.0.0')).toBe(false)
  })

  it('rejects tilde range', () => {
    expect(isExactVersion('~2.1.0')).toBe(false)
  })

  it('rejects greater-than range', () => {
    expect(isExactVersion('>=1.0.0')).toBe(false)
  })

  it('rejects wildcard', () => {
    expect(isExactVersion('*')).toBe(false)
  })

  it('rejects empty string', () => {
    expect(isExactVersion('')).toBe(false)
  })

  it('rejects "latest"', () => {
    expect(isExactVersion('latest')).toBe(false)
  })

  it('rejects "any"', () => {
    expect(isExactVersion('any')).toBe(false)
  })

  it('rejects OR range', () => {
    expect(isExactVersion('1.2.3 || 2.0.0')).toBe(false)
  })

  it('rejects less-than range', () => {
    expect(isExactVersion('<2.0.0')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// computeFreshnessScore
// ---------------------------------------------------------------------------

describe('computeFreshnessScore', () => {
  it('returns 100 when captured right now', () => {
    expect(computeFreshnessScore(NOW, NOW)).toBe(100)
  })

  it('returns ~50 at 45 days', () => {
    const score = computeFreshnessScore(NOW - 45 * DAY_MS, NOW)
    expect(score).toBeGreaterThanOrEqual(48)
    expect(score).toBeLessThanOrEqual(52)
  })

  it('returns 0 at exactly 90 days', () => {
    expect(computeFreshnessScore(NOW - 90 * DAY_MS, NOW)).toBe(0)
  })

  it('floors at 0 beyond 90 days', () => {
    expect(computeFreshnessScore(NOW - 120 * DAY_MS, NOW)).toBe(0)
  })

  it('returns > 0 at 30 days old', () => {
    expect(computeFreshnessScore(NOW - 30 * DAY_MS, NOW)).toBeGreaterThan(60)
  })
})

// ---------------------------------------------------------------------------
// countLayersPopulated
// ---------------------------------------------------------------------------

describe('countLayersPopulated', () => {
  it('returns 6 when all layers have components', () => {
    expect(countLayersPopulated(makeSnapshot())).toBe(6)
  })

  it('returns 0 when all layers are empty', () => {
    const s = makeSnapshot({
      directDependencyCount: 0,
      transitiveDependencyCount: 0,
      buildDependencyCount: 0,
      containerDependencyCount: 0,
      runtimeDependencyCount: 0,
      aiModelDependencyCount: 0,
    })
    expect(countLayersPopulated(s)).toBe(0)
  })

  it('counts only non-zero layers', () => {
    const s = makeSnapshot({
      directDependencyCount: 5,
      transitiveDependencyCount: 10,
      buildDependencyCount: 0,
      containerDependencyCount: 0,
      runtimeDependencyCount: 0,
      aiModelDependencyCount: 0,
    })
    expect(countLayersPopulated(s)).toBe(2)
  })

  it('treats undefined runtime/ai as 0', () => {
    const s = makeSnapshot({
      runtimeDependencyCount: undefined,
      aiModelDependencyCount: undefined,
      directDependencyCount: 3,
      transitiveDependencyCount: 7,
      buildDependencyCount: 1,
      containerDependencyCount: 0,
    })
    expect(countLayersPopulated(s)).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// computeSbomQuality
// ---------------------------------------------------------------------------

describe('computeSbomQuality', () => {
  it('returns poor grade for empty component list', () => {
    const result = computeSbomQuality(makeSnapshot(), [], NOW)
    expect(result.grade).toBe('poor')
    expect(result.overallScore).toBeLessThan(40)
    expect(result.completenessScore).toBe(0)
    expect(result.versionPinningScore).toBe(0)
    expect(result.licenseResolutionScore).toBe(0)
    expect(result.summary).toMatch(/no components/i)
  })

  it('caps completeness at 100 for 20+ components', () => {
    const comps = Array.from({ length: 25 }, () => makeComponent())
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.completenessScore).toBe(100)
  })

  it('scales completeness linearly below 20 components', () => {
    const comps = Array.from({ length: 10 }, () => makeComponent())
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.completenessScore).toBe(50)
  })

  it('scores version pinning at 100 when all components are exact', () => {
    const comps = Array.from({ length: 5 }, () => makeComponent({ version: '1.0.0' }))
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.versionPinningScore).toBe(100)
    expect(result.versionPinningRate).toBe(1)
  })

  it('scores version pinning at 0 when all components have ranges', () => {
    const comps = Array.from({ length: 5 }, () => makeComponent({ version: '^1.0.0' }))
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.versionPinningScore).toBe(0)
    expect(result.exactVersionCount).toBe(0)
  })

  it('scores version pinning proportionally for mixed versions', () => {
    const comps = [
      makeComponent({ version: '1.0.0' }),
      makeComponent({ version: '1.0.0' }),
      makeComponent({ version: '^2.0.0' }),
      makeComponent({ version: '^3.0.0' }),
    ]
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.exactVersionCount).toBe(2)
    expect(result.versionPinningScore).toBe(50)
  })

  it('scores license resolution at 100 when all components have licenses', () => {
    const comps = Array.from({ length: 5 }, () => makeComponent({ license: 'MIT' }))
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.licenseResolutionScore).toBe(100)
    expect(result.licensedCount).toBe(5)
  })

  it('scores license resolution at 0 when no components have licenses', () => {
    const comps = Array.from({ length: 5 }, () => makeComponent({ license: undefined }))
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.licenseResolutionScore).toBe(0)
    expect(result.licensedCount).toBe(0)
  })

  it('treats null license as unknown', () => {
    const comps = [makeComponent({ license: null }), makeComponent({ license: 'MIT' })]
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.licensedCount).toBe(1)
    expect(result.licenseResolutionScore).toBe(50)
  })

  it('freshness score is 100 for just-captured snapshot', () => {
    const comps = [makeComponent()]
    const result = computeSbomQuality(makeSnapshot({ capturedAt: NOW }), comps, NOW)
    expect(result.freshnessScore).toBe(100)
    expect(result.daysSinceCapture).toBe(0)
  })

  it('freshness score is 0 for 90-day-old snapshot', () => {
    const comps = [makeComponent()]
    const result = computeSbomQuality(
      makeSnapshot({ capturedAt: NOW - 90 * DAY_MS }),
      comps,
      NOW,
    )
    expect(result.freshnessScore).toBe(0)
  })

  it('layer coverage is 100 when all 6 layers are populated', () => {
    const comps = [makeComponent()]
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.layerCoverageScore).toBe(100)
    expect(result.layersPopulated).toBe(6)
  })

  it('layer coverage is 0 when no layers have components', () => {
    const comps = [makeComponent()]
    const s = makeSnapshot({
      directDependencyCount: 0,
      transitiveDependencyCount: 0,
      buildDependencyCount: 0,
      containerDependencyCount: 0,
      runtimeDependencyCount: 0,
      aiModelDependencyCount: 0,
    })
    const result = computeSbomQuality(s, comps, NOW)
    expect(result.layerCoverageScore).toBe(0)
    expect(result.layersPopulated).toBe(0)
  })

  it('grade is excellent for high overall score', () => {
    // All perfect: many exact-version MIT-licensed components, fresh, all layers
    const comps = Array.from({ length: 20 }, () =>
      makeComponent({ version: '1.0.0', license: 'MIT' }),
    )
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.grade).toBe('excellent')
    expect(result.overallScore).toBeGreaterThanOrEqual(80)
  })

  it('grade is poor for empty SBOM', () => {
    const result = computeSbomQuality(makeSnapshot(), [], NOW)
    expect(result.grade).toBe('poor')
  })

  it('computes correct overall score from known inputs', () => {
    // completeness=50 (10 comps), versionPinning=100, licenseResolution=100,
    // freshness=100, layerCoverage=100
    // overallScore = round(50×0.25 + 100×0.25 + 100×0.2 + 100×0.15 + 100×0.15)
    //              = round(12.5 + 25 + 20 + 15 + 15) = round(87.5) = 88
    const comps = Array.from({ length: 10 }, () =>
      makeComponent({ version: '1.0.0', license: 'MIT' }),
    )
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.overallScore).toBe(88)
  })

  it('summary says all quality gates pass for excellent SBOM', () => {
    const comps = Array.from({ length: 20 }, () =>
      makeComponent({ version: '1.0.0', license: 'MIT' }),
    )
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.summary).toMatch(/all quality gates pass/i)
  })

  it('summary mentions unpinned versions when > 50% unpinned', () => {
    const comps = Array.from({ length: 4 }, () =>
      makeComponent({ version: '^1.0.0', license: 'MIT' }),
    )
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.summary).toMatch(/unpinned/i)
  })

  it('summary mentions unknown licenses when < 70% licensed', () => {
    const comps = [
      makeComponent({ license: undefined }),
      makeComponent({ license: undefined }),
      makeComponent({ license: 'MIT' }),
    ]
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.summary).toMatch(/unknown license/i)
  })

  it('summary mentions stale snapshot when > 30 days old', () => {
    const comps = [makeComponent()]
    const result = computeSbomQuality(
      makeSnapshot({ capturedAt: NOW - 45 * DAY_MS }),
      comps,
      NOW,
    )
    expect(result.summary).toMatch(/days? old/i)
  })

  it('returns correct totalComponents count', () => {
    const comps = Array.from({ length: 7 }, () => makeComponent())
    const result = computeSbomQuality(makeSnapshot(), comps, NOW)
    expect(result.totalComponents).toBe(7)
  })
})
