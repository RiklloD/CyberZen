import { describe, expect, it } from 'vitest'
import {
  buildFrameworkCompliance,
  buildRepoSummary,
  complianceScoreFromFrameworks,
  computeCompositeScore,
  computeExecutiveReport,
  extractTopActions,
  scoreToGrade,
  scoreToRiskLevel,
  type RepoSnapshot,
} from './executiveReport'

// ── Fixtures ───────────────────────────────────────────────────────────────

const perfectSnap: RepoSnapshot = {
  repositoryId: 'repo-1',
  repositoryFullName: 'acme/api',
  healthScore: 95,
  healthGrade: 'A',
  healthTopRisks: [],
  driftPostureScore: 92,
  driftGrade: 'A',
  driftTopRisks: [],
  supplyChainScore: 91,
  supplyChainGrade: 'A',
  frameworks: [
    { framework: 'SOC 2', status: 'compliant', score: 95 },
    { framework: 'PCI-DSS', status: 'compliant', score: 90 },
  ],
}

const criticalSnap: RepoSnapshot = {
  repositoryId: 'repo-2',
  repositoryFullName: 'acme/legacy',
  healthScore: 22,
  healthGrade: 'F',
  healthTopRisks: ['Fix critical CVEs immediately', 'Rotate leaked secrets'],
  driftPostureScore: 18,
  driftGrade: 'F',
  driftTopRisks: ['Review AWS IAM policies', 'Enable MFA enforcement'],
  supplyChainScore: 30,
  supplyChainGrade: 'F',
  frameworks: [
    { framework: 'SOC 2', status: 'non_compliant', score: 20 },
    { framework: 'PCI-DSS', status: 'non_compliant', score: 15 },
  ],
}

const partialSnap: RepoSnapshot = {
  repositoryId: 'repo-3',
  repositoryFullName: 'acme/ui',
  healthScore: 70,
  healthGrade: 'C',
  healthTopRisks: ['Improve license compliance'],
  driftPostureScore: null,
  driftGrade: null,
  driftTopRisks: [],
  supplyChainScore: null,
  supplyChainGrade: null,
  frameworks: [],
}

const emptySnap: RepoSnapshot = {
  repositoryId: 'repo-4',
  repositoryFullName: 'acme/docs',
  healthScore: null,
  healthGrade: null,
  healthTopRisks: [],
  driftPostureScore: null,
  driftGrade: null,
  driftTopRisks: [],
  supplyChainScore: null,
  supplyChainGrade: null,
  frameworks: [],
}

// ── scoreToGrade ───────────────────────────────────────────────────────────

describe('scoreToGrade', () => {
  it('returns A for score ≥ 90', () => {
    expect(scoreToGrade(90)).toBe('A')
    expect(scoreToGrade(100)).toBe('A')
  })

  it('returns B for 75–89', () => {
    expect(scoreToGrade(75)).toBe('B')
    expect(scoreToGrade(89)).toBe('B')
  })

  it('returns C for 60–74', () => {
    expect(scoreToGrade(60)).toBe('C')
    expect(scoreToGrade(74)).toBe('C')
  })

  it('returns D for 40–59', () => {
    expect(scoreToGrade(40)).toBe('D')
    expect(scoreToGrade(59)).toBe('D')
  })

  it('returns F for score < 40', () => {
    expect(scoreToGrade(0)).toBe('F')
    expect(scoreToGrade(39)).toBe('F')
  })
})

// ── scoreToRiskLevel ───────────────────────────────────────────────────────

describe('scoreToRiskLevel', () => {
  it('safe for score ≥ 85', () => {
    expect(scoreToRiskLevel(85)).toBe('safe')
    expect(scoreToRiskLevel(100)).toBe('safe')
  })

  it('low for 70–84', () => {
    expect(scoreToRiskLevel(70)).toBe('low')
    expect(scoreToRiskLevel(84)).toBe('low')
  })

  it('medium for 55–69', () => {
    expect(scoreToRiskLevel(55)).toBe('medium')
    expect(scoreToRiskLevel(69)).toBe('medium')
  })

  it('high for 35–54', () => {
    expect(scoreToRiskLevel(35)).toBe('high')
    expect(scoreToRiskLevel(54)).toBe('high')
  })

  it('critical for score < 35', () => {
    expect(scoreToRiskLevel(0)).toBe('critical')
    expect(scoreToRiskLevel(34)).toBe('critical')
  })
})

// ── complianceScoreFromFrameworks ──────────────────────────────────────────

describe('complianceScoreFromFrameworks', () => {
  it('returns null for empty frameworks', () => {
    expect(complianceScoreFromFrameworks([])).toBeNull()
  })

  it('returns 100 for all-compliant', () => {
    expect(
      complianceScoreFromFrameworks([
        { framework: 'SOC 2', status: 'compliant', score: 100 },
        { framework: 'GDPR', status: 'compliant', score: 100 },
      ]),
    ).toBe(100)
  })

  it('returns 0 for all non_compliant', () => {
    expect(
      complianceScoreFromFrameworks([
        { framework: 'SOC 2', status: 'non_compliant', score: 0 },
        { framework: 'GDPR', status: 'non_compliant', score: 0 },
      ]),
    ).toBe(0)
  })

  it('returns 50 for all at_risk', () => {
    expect(
      complianceScoreFromFrameworks([
        { framework: 'SOC 2', status: 'at_risk', score: 60 },
        { framework: 'GDPR', status: 'at_risk', score: 70 },
      ]),
    ).toBe(50)
  })

  it('averages mixed statuses', () => {
    // compliant(100) + at_risk(50) + non_compliant(0) = 150 / 3 = 50
    expect(
      complianceScoreFromFrameworks([
        { framework: 'SOC 2', status: 'compliant', score: 95 },
        { framework: 'GDPR', status: 'at_risk', score: 60 },
        { framework: 'PCI-DSS', status: 'non_compliant', score: 10 },
      ]),
    ).toBe(50)
  })

  it('handles single framework', () => {
    expect(
      complianceScoreFromFrameworks([{ framework: 'HIPAA', status: 'at_risk', score: 70 }]),
    ).toBe(50)
  })
})

// ── computeCompositeScore ──────────────────────────────────────────────────

describe('computeCompositeScore', () => {
  it('returns null for empty snapshot', () => {
    expect(computeCompositeScore(emptySnap)).toBeNull()
  })

  it('returns a value near the input for a near-perfect repo', () => {
    const score = computeCompositeScore(perfectSnap)
    expect(score).not.toBeNull()
    expect(score!).toBeGreaterThan(85)
  })

  it('returns a low value for a critical repo', () => {
    const score = computeCompositeScore(criticalSnap)
    expect(score).not.toBeNull()
    expect(score!).toBeLessThan(40)
  })

  it('redistributes weight when drift is missing', () => {
    // health=70, drift=40 → with drift: (70*0.40 + 40*0.35) / 0.75 = 42/0.75 = 56
    // without drift: 70*0.40 / 0.40 = 70  (different from 56)
    const scoreWithDrift = computeCompositeScore({ ...partialSnap, driftPostureScore: 40 })
    const scoreWithoutDrift = computeCompositeScore(partialSnap)
    expect(scoreWithDrift).not.toBeNull()
    expect(scoreWithoutDrift).not.toBeNull()
    expect(scoreWithDrift).not.toBe(scoreWithoutDrift)
  })

  it('only health data → returns health score (weight 1.0)', () => {
    const score = computeCompositeScore(partialSnap)
    // Only health (70) contributes; totalWeight = 0.40 → 70*0.40/0.40 = 70
    expect(score).toBe(70)
  })

  it('all 100 inputs yield composite 100', () => {
    const snap: RepoSnapshot = {
      ...perfectSnap,
      healthScore: 100,
      driftPostureScore: 100,
      supplyChainScore: 100,
      frameworks: [{ framework: 'SOC 2', status: 'compliant', score: 100 }],
    }
    expect(computeCompositeScore(snap)).toBe(100)
  })

  it('all 0 inputs yield composite 0', () => {
    const snap: RepoSnapshot = {
      ...criticalSnap,
      healthScore: 0,
      driftPostureScore: 0,
      supplyChainScore: 0,
      frameworks: [{ framework: 'SOC 2', status: 'non_compliant', score: 0 }],
    }
    expect(computeCompositeScore(snap)).toBe(0)
  })
})

// ── buildRepoSummary ───────────────────────────────────────────────────────

describe('buildRepoSummary', () => {
  it('returns null for empty snapshot', () => {
    expect(buildRepoSummary(emptySnap)).toBeNull()
  })

  it('returns correct grade for perfect repo', () => {
    const s = buildRepoSummary(perfectSnap)
    expect(s).not.toBeNull()
    expect(s!.grade).toBe('A')
    expect(s!.riskLevel).toBe('safe')
  })

  it('returns F grade for critical repo', () => {
    const s = buildRepoSummary(criticalSnap)
    expect(s).not.toBeNull()
    expect(s!.grade).toBe('F')
    expect(s!.riskLevel).toBe('critical')
  })

  it('picks top risk from healthTopRisks first', () => {
    const s = buildRepoSummary(criticalSnap)
    expect(s!.topRisk).toBe('Fix critical CVEs immediately')
  })

  it('falls back to driftTopRisks when healthTopRisks empty', () => {
    const snap: RepoSnapshot = {
      ...criticalSnap,
      healthTopRisks: [],
      driftTopRisks: ['Audit IAM policies'],
    }
    const s = buildRepoSummary(snap)
    expect(s!.topRisk).toBe('Audit IAM policies')
  })

  it('uses fallback text when no risks', () => {
    const s = buildRepoSummary(perfectSnap)
    expect(s!.topRisk).toBe('No specific risk identified')
  })
})

// ── extractTopActions ──────────────────────────────────────────────────────

describe('extractTopActions', () => {
  it('returns empty array for empty snapshots', () => {
    expect(extractTopActions([])).toEqual([])
  })

  it('deduplicates identical actions (case-insensitive)', () => {
    const snaps: RepoSnapshot[] = [
      { ...criticalSnap, healthTopRisks: ['Fix CVEs'], driftTopRisks: ['fix cves'] },
    ]
    const actions = extractTopActions(snaps)
    expect(actions).toHaveLength(1)
    expect(actions[0]).toBe('Fix CVEs')
  })

  it('collects from both health and drift risks', () => {
    const snaps: RepoSnapshot[] = [
      {
        ...criticalSnap,
        healthTopRisks: ['Action A'],
        driftTopRisks: ['Action B'],
      },
    ]
    const actions = extractTopActions(snaps)
    expect(actions).toContain('Action A')
    expect(actions).toContain('Action B')
  })

  it('limits to 5 by default', () => {
    const snaps: RepoSnapshot[] = [
      {
        ...criticalSnap,
        healthTopRisks: ['A', 'B', 'C', 'D', 'E', 'F'],
        driftTopRisks: [],
      },
    ]
    expect(extractTopActions(snaps)).toHaveLength(5)
  })

  it('respects custom limit', () => {
    const snaps: RepoSnapshot[] = [
      { ...criticalSnap, healthTopRisks: ['A', 'B', 'C'], driftTopRisks: [] },
    ]
    expect(extractTopActions(snaps, 2)).toHaveLength(2)
  })
})

// ── buildFrameworkCompliance ───────────────────────────────────────────────

describe('buildFrameworkCompliance', () => {
  it('returns empty for snapshots with no frameworks', () => {
    expect(buildFrameworkCompliance([emptySnap, partialSnap])).toEqual([])
  })

  it('computes 100% rate when all repos compliant', () => {
    const result = buildFrameworkCompliance([perfectSnap, perfectSnap])
    const soc2 = result.find((r) => r.framework === 'SOC 2')
    expect(soc2).toBeDefined()
    expect(soc2!.complianceRate).toBe(100)
    expect(soc2!.totalRepos).toBe(2)
    expect(soc2!.compliantRepos).toBe(2)
  })

  it('computes 0% rate when all repos non_compliant', () => {
    const result = buildFrameworkCompliance([criticalSnap, criticalSnap])
    const soc2 = result.find((r) => r.framework === 'SOC 2')
    expect(soc2!.complianceRate).toBe(0)
    expect(soc2!.nonCompliantRepos).toBe(2)
  })

  it('sorts worst framework first (lowest compliance rate)', () => {
    const snap1: RepoSnapshot = {
      ...perfectSnap,
      frameworks: [
        { framework: 'SOC 2', status: 'compliant', score: 95 },
        { framework: 'GDPR', status: 'non_compliant', score: 10 },
      ],
    }
    const result = buildFrameworkCompliance([snap1])
    expect(result[0].framework).toBe('GDPR')
  })

  it('counts at_risk repos separately', () => {
    const snap: RepoSnapshot = {
      ...perfectSnap,
      frameworks: [{ framework: 'HIPAA', status: 'at_risk', score: 60 }],
    }
    const result = buildFrameworkCompliance([snap])
    expect(result[0].atRiskRepos).toBe(1)
    expect(result[0].compliantRepos).toBe(0)
    expect(result[0].nonCompliantRepos).toBe(0)
  })
})

// ── computeExecutiveReport ─────────────────────────────────────────────────

describe('computeExecutiveReport', () => {
  it('handles empty repository list', () => {
    const report = computeExecutiveReport('acme', [])
    expect(report.totalRepositories).toBe(0)
    expect(report.scoredRepositories).toBe(0)
    expect(report.overallScore).toBe(0)
    expect(report.overallGrade).toBe('F')
    expect(report.riskLevel).toBe('critical')
    expect(report.worstRepos).toHaveLength(0)
    expect(report.bestRepos).toHaveLength(0)
    expect(report.topActions).toHaveLength(0)
  })

  it('includes tenantSlug and generatedAt', () => {
    const before = Date.now()
    const report = computeExecutiveReport('acme', [perfectSnap])
    const after = Date.now()
    expect(report.tenantSlug).toBe('acme')
    expect(report.generatedAt).toBeGreaterThanOrEqual(before)
    expect(report.generatedAt).toBeLessThanOrEqual(after)
  })

  it('counts total and scored repos correctly', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, emptySnap])
    expect(report.totalRepositories).toBe(2)
    expect(report.scoredRepositories).toBe(1)  // emptySnap has no scores
  })

  it('returns safe/A for all-perfect repos', () => {
    const report = computeExecutiveReport('acme', [perfectSnap])
    expect(report.overallGrade).toBe('A')
    expect(report.riskLevel).toBe('safe')
    expect(report.overallScore).toBeGreaterThan(85)
  })

  it('returns critical/F for all-critical repos', () => {
    const report = computeExecutiveReport('acme', [criticalSnap])
    expect(report.overallGrade).toBe('F')
    expect(report.riskLevel).toBe('critical')
    expect(report.overallScore).toBeLessThan(35)
  })

  it('averages composite scores across repos', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, criticalSnap])
    const perfScore = computeCompositeScore(perfectSnap)!
    const critScore = computeCompositeScore(criticalSnap)!
    const expected = Math.round((perfScore + critScore) / 2)
    expect(report.overallScore).toBe(expected)
  })

  it('lists worstRepos in ascending score order', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, criticalSnap, partialSnap])
    const scores = report.worstRepos.map((r) => r.compositeScore)
    expect(scores).toEqual([...scores].sort((a, b) => a - b))
  })

  it('lists bestRepos in descending score order', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, criticalSnap, partialSnap])
    const scores = report.bestRepos.map((r) => r.compositeScore)
    expect(scores).toEqual([...scores].sort((a, b) => b - a))
  })

  it('caps worstRepos at 5', () => {
    const snaps = Array.from({ length: 10 }, (_, i) => ({
      ...criticalSnap,
      repositoryId: `repo-${i}`,
      repositoryFullName: `acme/repo-${i}`,
      healthScore: i * 5,
    }))
    const report = computeExecutiveReport('acme', snaps)
    expect(report.worstRepos.length).toBeLessThanOrEqual(5)
  })

  it('caps bestRepos at 5', () => {
    const snaps = Array.from({ length: 10 }, (_, i) => ({
      ...perfectSnap,
      repositoryId: `repo-${i}`,
      repositoryFullName: `acme/repo-${i}`,
      healthScore: 50 + i * 4,
    }))
    const report = computeExecutiveReport('acme', snaps)
    expect(report.bestRepos.length).toBeLessThanOrEqual(5)
  })

  it('populates domain averages', () => {
    const report = computeExecutiveReport('acme', [perfectSnap])
    expect(report.domainAverages.healthAvg).toBe(95)
    expect(report.domainAverages.driftPostureAvg).toBe(92)
    expect(report.domainAverages.supplyChainAvg).toBe(91)
    expect(report.domainAverages.complianceAvg).not.toBeNull()
  })

  it('returns null domain averages when no data', () => {
    const report = computeExecutiveReport('acme', [emptySnap])
    expect(report.domainAverages.healthAvg).toBeNull()
    expect(report.domainAverages.driftPostureAvg).toBeNull()
    expect(report.domainAverages.supplyChainAvg).toBeNull()
    expect(report.domainAverages.complianceAvg).toBeNull()
  })

  it('topActions comes from worst repos', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, criticalSnap])
    // criticalSnap is the worst, its top risks should surface as top actions
    expect(report.topActions.length).toBeGreaterThan(0)
    const allCritRisks = [...criticalSnap.healthTopRisks, ...criticalSnap.driftTopRisks]
    expect(report.topActions[0]).toBe(allCritRisks[0])
  })

  it('includes framework compliance roll-up', () => {
    const report = computeExecutiveReport('acme', [perfectSnap, criticalSnap])
    const soc2 = report.frameworkCompliance.find((f) => f.framework === 'SOC 2')
    expect(soc2).toBeDefined()
    expect(soc2!.totalRepos).toBe(2)
  })

  it('sets tenantSlug correctly', () => {
    const report = computeExecutiveReport('my-tenant', [])
    expect(report.tenantSlug).toBe('my-tenant')
  })
})
