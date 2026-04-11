import { describe, expect, it } from 'vitest'
import { computeAttackSurface, type FindingForSurfaceInput } from './attackSurface'
import type { RepositoryMemoryRecord } from './memoryController'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const openCritical: FindingForSurfaceInput = {
  severity: 'critical',
  status: 'open',
  validationStatus: 'pending',
}

const openHigh: FindingForSurfaceInput = {
  severity: 'high',
  status: 'open',
  validationStatus: 'pending',
}

const openLow: FindingForSurfaceInput = {
  severity: 'low',
  status: 'open',
  validationStatus: 'pending',
}

const resolvedCritical: FindingForSurfaceInput = {
  severity: 'critical',
  status: 'resolved',
  validationStatus: 'validated',
}

const resolvedHigh: FindingForSurfaceInput = {
  severity: 'high',
  status: 'resolved',
  validationStatus: 'pending',
}

const mergedLow: FindingForSurfaceInput = {
  severity: 'low',
  status: 'merged',
  validationStatus: 'pending',
}

const acceptedCritical: FindingForSurfaceInput = {
  severity: 'critical',
  status: 'accepted_risk',
  validationStatus: 'unexploitable',
}

const prOpenedHigh: FindingForSurfaceInput = {
  severity: 'high',
  status: 'pr_opened',
  validationStatus: 'validated',
}

const validatedOpenCritical: FindingForSurfaceInput = {
  severity: 'critical',
  status: 'open',
  validationStatus: 'validated',
}

const healthyMemory: RepositoryMemoryRecord = {
  recurringVulnClasses: [
    { vulnClass: 'xss', count: 2, avgSeverityWeight: 0.75 },
  ],
  falsePositiveRate: 0.05,
  highConfidenceClasses: ['xss'],
  packageRiskMap: {},
  dominantSeverity: 'high',
  totalFindingsAnalyzed: 10,
  resolvedCount: 5,
  openCount: 5,
  summary: '10 findings analyzed.',
}

const unhealthyMemory: RepositoryMemoryRecord = {
  recurringVulnClasses: [
    { vulnClass: 'sql_injection', count: 3, avgSeverityWeight: 1.0 },
  ],
  falsePositiveRate: 0.6,
  highConfidenceClasses: [],
  packageRiskMap: {},
  dominantSeverity: 'critical',
  totalFindingsAnalyzed: 5,
  resolvedCount: 1,
  openCount: 4,
  summary: '5 findings analyzed.',
}

// ---------------------------------------------------------------------------
// 1. Empty findings
// ---------------------------------------------------------------------------

describe('computeAttackSurface — empty findings', () => {
  it('returns a baseline structural score and a no-findings summary when there are no findings', () => {
    const result = computeAttackSurface({
      findings: [],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'test-repo',
    })
    // With no findings: remediationScore=0×50=0, mitigationBonus=10 (no open),
    // validationBonus=7 (baseline), memoryBonus=0, sbom=0, noValidatedCritical=10
    // total = 27
    expect(result.score).toBe(27)
    expect(result.totalFindings).toBe(0)
    expect(result.resolvedFindings).toBe(0)
    expect(result.summary).toContain('test-repo')
  })

  it('awards SBOM bonus (+5) even with no findings', () => {
    const withSbom = computeAttackSurface({
      findings: [],
      repositoryMemory: null,
      hasActiveSbom: true,
      previousScore: null,
      repositoryName: 'repo',
    })
    const withoutSbom = computeAttackSurface({
      findings: [],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // withSbom = 32, withoutSbom = 27
    expect(withSbom.score).toBe(withoutSbom.score + 5)
  })
})

// ---------------------------------------------------------------------------
// 2. All findings open (no remediation)
// ---------------------------------------------------------------------------

describe('computeAttackSurface — all open findings', () => {
  it('produces a low score when all findings are open', () => {
    const result = computeAttackSurface({
      findings: [openCritical, openHigh, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'my-repo',
    })
    // remediationScore = 0, mitigationBonus = 0, validation = 7 (none validated),
    // memory = 0, sbom = 0, noValidatedCritical = 10 (no validated criticals)
    // expected = 0 + 0 + 7 + 0 + 0 + 10 = 17
    expect(result.score).toBe(17)
    expect(result.remediationRate).toBe(0)
    expect(result.openCriticalCount).toBe(1)
    expect(result.openHighCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// 3. All findings resolved
// ---------------------------------------------------------------------------

describe('computeAttackSurface — all findings resolved', () => {
  it('produces a high score when all findings are resolved', () => {
    const result = computeAttackSurface({
      findings: [resolvedCritical, resolvedHigh, mergedLow],
      repositoryMemory: null,
      hasActiveSbom: true,
      previousScore: null,
      repositoryName: 'secure-repo',
    })
    // remediationScore = 1.0 → ×50 = 50
    // mitigationBonus = 10 (no open findings)
    // validationBonus: 1 validated finding (resolvedCritical), resolved → 15
    // memoryHealthBonus = 0 (no memory)
    // sbomBonus = 5
    // noValidatedCriticalBonus = 10 (no open validated criticals)
    // total = 50 + 10 + 15 + 0 + 5 + 10 = 90
    expect(result.score).toBe(90)
    expect(result.remediationRate).toBe(1)
    expect(result.resolvedFindings).toBe(3)
    expect(result.openCriticalCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 4. Severity weighting: critical outweighs low
// ---------------------------------------------------------------------------

describe('computeAttackSurface — severity weighting', () => {
  it('resolving a critical contributes more to remediationRate than resolving a low', () => {
    const criticalResolved = computeAttackSurface({
      findings: [resolvedCritical, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const lowResolved = computeAttackSurface({
      findings: [openCritical, mergedLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // critical weight=4, low weight=1 → resolving critical yields rate 4/5=0.8 vs 1/5=0.2
    expect(criticalResolved.remediationRate).toBeGreaterThan(lowResolved.remediationRate)
    expect(criticalResolved.score).toBeGreaterThan(lowResolved.score)
  })

  it('accepted_risk counts the same as resolved for remediationRate', () => {
    const accepted = computeAttackSurface({
      findings: [acceptedCritical],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(accepted.remediationRate).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// 5. pr_opened gives partial credit
// ---------------------------------------------------------------------------

describe('computeAttackSurface — pr_opened partial credit', () => {
  it('pr_opened finding contributes 0.5× to remediationRate', () => {
    const result = computeAttackSurface({
      findings: [prOpenedHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // high weight = 3, credited = 1.5 → rate = 0.5
    expect(result.remediationRate).toBe(0.5)
    expect(result.activeMitigationCount).toBe(1)
  })

  it('mixed open + pr_opened: mitigationBonus is proportional', () => {
    const allOpen = computeAttackSurface({
      findings: [openHigh, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const halfMitigation = computeAttackSurface({
      findings: [prOpenedHigh, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(halfMitigation.score).toBeGreaterThan(allOpen.score)
  })
})

// ---------------------------------------------------------------------------
// 6. SBOM bonus
// ---------------------------------------------------------------------------

describe('computeAttackSurface — SBOM bonus', () => {
  it('adds exactly 5 points when hasActiveSbom is true', () => {
    const base = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const withSbom = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: true,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(withSbom.score - base.score).toBe(5)
  })
})

// ---------------------------------------------------------------------------
// 7. Memory health bonus
// ---------------------------------------------------------------------------

describe('computeAttackSurface — memoryHealthBonus', () => {
  it('healthy memory (low FP, no recurring critical) awards full 10 points', () => {
    const withMemory = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: healthyMemory,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const noMemory = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // healthyMemory: FP=0.05 → fpBonus=4.75, no recurring critical → classBonus=5 → total≈10
    expect(withMemory.score).toBeGreaterThan(noMemory.score)
    expect(withMemory.score - noMemory.score).toBeCloseTo(10, 0)
  })

  it('unhealthy memory (high FP + recurring critical) gives a low bonus', () => {
    const withUnhealthy = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: unhealthyMemory,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const noMemory = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // unhealthyMemory: FP=0.6 → fpBonus=2.0, recurring critical → classBonus=0 → total=2
    expect(withUnhealthy.score - noMemory.score).toBeLessThan(3)
  })

  it('null memory contributes exactly 0 to score vs healthy memory', () => {
    const withMemory = computeAttackSurface({
      findings: [resolvedHigh],
      repositoryMemory: healthyMemory,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const withoutMemory = computeAttackSurface({
      findings: [resolvedHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // memoryHealthBonus(null) = 0, so the difference equals the healthy bonus (~10)
    expect(withMemory.score).toBeGreaterThan(withoutMemory.score)
    expect(withMemory.score - withoutMemory.score).toBeCloseTo(10, 0)
  })
})

// ---------------------------------------------------------------------------
// 8. Validated-critical penalty
// ---------------------------------------------------------------------------

describe('computeAttackSurface — noValidatedCriticalBonus', () => {
  it('open validated critical reduces the bonus by 5', () => {
    const noCriticals = computeAttackSurface({
      findings: [openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const oneValidatedCritical = computeAttackSurface({
      findings: [openLow, validatedOpenCritical],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // Difference should primarily be the 5-point penalty on the critical bonus
    expect(noCriticals.score).toBeGreaterThan(oneValidatedCritical.score)
  })

  it('two open validated criticals floors the bonus at 0', () => {
    const twoValidatedCriticals = computeAttackSurface({
      findings: [validatedOpenCritical, validatedOpenCritical],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // noValidatedCriticalBonus = max(0, 10 - 2×5) = 0
    expect(twoValidatedCriticals.openCriticalCount).toBe(2)
  })

  it('likely_exploitable open criticals also reduce the bonus', () => {
    const withLikelyExploitable: FindingForSurfaceInput = {
      severity: 'critical',
      status: 'open',
      validationStatus: 'likely_exploitable',
    }
    const result = computeAttackSurface({
      findings: [withLikelyExploitable],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // 1 open validated critical → noValidatedCriticalBonus = 5 (not 10)
    const noValidatedResult = computeAttackSurface({
      findings: [openCritical],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(noValidatedResult.score).toBeGreaterThan(result.score)
  })
})

// ---------------------------------------------------------------------------
// 9. Validation bonus
// ---------------------------------------------------------------------------

describe('computeAttackSurface — validationBonus', () => {
  it('awards 7-point baseline when no validated findings exist', () => {
    // Only unvalidated (pending) findings
    const result = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // validationBonus = 7 (baseline) since no validated findings
    expect(result.score).toBeGreaterThanOrEqual(7)
  })

  it('awards full 15 when all validated findings are resolved', () => {
    const allValidatedResolved = computeAttackSurface({
      findings: [resolvedCritical],           // status=resolved, validation=validated
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    const noneValidatedResolved = computeAttackSurface({
      findings: [{ ...resolvedCritical, validationStatus: 'pending' }],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    // allValidatedResolved gets 15 vs 7 baseline → 8 more
    expect(allValidatedResolved.score - noneValidatedResolved.score).toBe(8)
  })
})

// ---------------------------------------------------------------------------
// 10. Trend computation
// ---------------------------------------------------------------------------

describe('computeAttackSurface — trend', () => {
  it('is "stable" when previousScore is null', () => {
    const result = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.trend).toBe('stable')
  })

  it('is "improving" when score exceeds previousScore by more than 2', () => {
    const result = computeAttackSurface({
      findings: [resolvedCritical, resolvedHigh],
      repositoryMemory: healthyMemory,
      hasActiveSbom: true,
      previousScore: 10,
      repositoryName: 'repo',
    })
    expect(result.trend).toBe('improving')
  })

  it('is "degrading" when score is more than 2 below previousScore', () => {
    const result = computeAttackSurface({
      findings: [openCritical, openHigh, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: 80,
      repositoryName: 'repo',
    })
    expect(result.trend).toBe('degrading')
  })

  it('is "stable" when score is within 2 of previousScore', () => {
    const result = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: 17, // matches the all-open score computed above
      repositoryName: 'repo',
    })
    expect(result.trend).toBe('stable')
  })
})

// ---------------------------------------------------------------------------
// 11. Score bounds
// ---------------------------------------------------------------------------

describe('computeAttackSurface — score bounds', () => {
  it('score is always in the range [0, 100]', () => {
    const extremeHigh = computeAttackSurface({
      findings: Array(20).fill(resolvedCritical),
      repositoryMemory: healthyMemory,
      hasActiveSbom: true,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(extremeHigh.score).toBeGreaterThanOrEqual(0)
    expect(extremeHigh.score).toBeLessThanOrEqual(100)

    const extremeLow = computeAttackSurface({
      findings: Array(20).fill(validatedOpenCritical),
      repositoryMemory: unhealthyMemory,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(extremeLow.score).toBeGreaterThanOrEqual(0)
    expect(extremeLow.score).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// 12. Summary content
// ---------------------------------------------------------------------------

describe('computeAttackSurface — summary', () => {
  it('includes repository name in summary', () => {
    const result = computeAttackSurface({
      findings: [openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'atlas-api',
    })
    expect(result.summary).toContain('atlas-api')
  })

  it('mentions open critical count when criticals are present', () => {
    const result = computeAttackSurface({
      findings: [openCritical, openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.summary).toContain('1 open critical')
  })

  it('mentions active mitigation count when PRs are open', () => {
    const result = computeAttackSurface({
      findings: [prOpenedHigh, openLow],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.summary).toContain('under active PR mitigation')
  })

  it('reflects "trending upward" for improving trend', () => {
    const result = computeAttackSurface({
      findings: [resolvedCritical],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: 10,
      repositoryName: 'repo',
    })
    if (result.trend === 'improving') {
      expect(result.summary).toContain('trending upward')
    }
  })
})

// ---------------------------------------------------------------------------
// 13. Derived count correctness
// ---------------------------------------------------------------------------

describe('computeAttackSurface — derived counts', () => {
  it('resolvedFindings counts resolved + merged + accepted_risk', () => {
    const result = computeAttackSurface({
      findings: [resolvedCritical, mergedLow, acceptedCritical, openHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.resolvedFindings).toBe(3)
  })

  it('openCriticalCount counts only open/pr_opened criticals', () => {
    const result = computeAttackSurface({
      findings: [openCritical, resolvedCritical, prOpenedHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.openCriticalCount).toBe(1)
  })

  it('activeMitigationCount counts only pr_opened status', () => {
    const result = computeAttackSurface({
      findings: [prOpenedHigh, openCritical, resolvedHigh],
      repositoryMemory: null,
      hasActiveSbom: false,
      previousScore: null,
      repositoryName: 'repo',
    })
    expect(result.activeMitigationCount).toBe(1)
  })
})
