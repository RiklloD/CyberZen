import { describe, it, expect } from 'vitest'
import {
  computeUpdateRecommendations,
  parseSemver,
  classifyEffort,
  isMajorBump,
  type CveFinding,
  type EolFinding,
  type AbandonmentFinding,
  type DependencyUpdateInput,
} from './dependencyUpdateRecommendation'

// ---------------------------------------------------------------------------
// parseSemver
// ---------------------------------------------------------------------------

describe('parseSemver', () => {
  it('parses standard semver', () => {
    expect(parseSemver('1.2.3')).toEqual([1, 2, 3])
  })

  it('strips v-prefix', () => {
    expect(parseSemver('v2.0.1')).toEqual([2, 0, 1])
  })

  it('handles two-segment versions', () => {
    expect(parseSemver('3.7')).toEqual([3, 7, 0])
  })

  it('handles single-segment versions', () => {
    expect(parseSemver('14')).toEqual([14, 0, 0])
  })

  it('strips pre-release suffix', () => {
    expect(parseSemver('1.2.3-beta.1')).toEqual([1, 2, 3])
  })

  it('strips build metadata', () => {
    expect(parseSemver('1.2.3+build.42')).toEqual([1, 2, 3])
  })

  it('strips Maven .RELEASE suffix', () => {
    expect(parseSemver('2.5.0.RELEASE')).toEqual([2, 5, 0])
  })

  it('strips Maven .SNAPSHOT suffix', () => {
    expect(parseSemver('3.0.0.SNAPSHOT')).toEqual([3, 0, 0])
  })

  it('returns null for non-numeric', () => {
    expect(parseSemver('latest')).toBeNull()
  })

  it('returns null for empty string', () => {
    expect(parseSemver('')).toBeNull()
  })

  it('returns null for too many segments', () => {
    expect(parseSemver('1.2.3.4.5')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// classifyEffort
// ---------------------------------------------------------------------------

describe('classifyEffort', () => {
  it('patch-level bump', () => {
    expect(classifyEffort('1.2.3', '1.2.5')).toBe('patch')
  })

  it('minor-level bump', () => {
    expect(classifyEffort('1.2.3', '1.4.0')).toBe('minor')
  })

  it('major-level bump', () => {
    expect(classifyEffort('1.2.3', '2.0.0')).toBe('major')
  })

  it('same version returns patch', () => {
    expect(classifyEffort('1.2.3', '1.2.3')).toBe('patch')
  })

  it('unparseable versions default to major', () => {
    expect(classifyEffort('latest', '2.0.0')).toBe('major')
    expect(classifyEffort('1.2.3', 'latest')).toBe('major')
  })

  it('v-prefixed versions work', () => {
    expect(classifyEffort('v1.0.0', 'v1.1.0')).toBe('minor')
  })
})

// ---------------------------------------------------------------------------
// isMajorBump
// ---------------------------------------------------------------------------

describe('isMajorBump', () => {
  it('returns true for major version change', () => {
    expect(isMajorBump('1.2.3', '2.0.0')).toBe(true)
  })

  it('returns false for minor version change', () => {
    expect(isMajorBump('1.2.3', '1.4.0')).toBe(false)
  })

  it('returns false for patch version change', () => {
    expect(isMajorBump('1.2.3', '1.2.5')).toBe(false)
  })

  it('returns true for unparseable versions (assumes breaking)', () => {
    expect(isMajorBump('latest', '2.0.0')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Empty / no-findings input
// ---------------------------------------------------------------------------

describe('empty input', () => {
  const result = computeUpdateRecommendations({})

  it('returns zero recommendations', () => {
    expect(result.totalRecommendations).toBe(0)
    expect(result.recommendations).toHaveLength(0)
  })

  it('all counts are zero', () => {
    expect(result.criticalCount).toBe(0)
    expect(result.highCount).toBe(0)
    expect(result.mediumCount).toBe(0)
    expect(result.lowCount).toBe(0)
    expect(result.patchCount).toBe(0)
    expect(result.breakingCount).toBe(0)
  })

  it('summary says no updates needed', () => {
    expect(result.summary).toContain('No dependency updates')
  })
})

// ---------------------------------------------------------------------------
// CVE-only findings
// ---------------------------------------------------------------------------

describe('CVE findings', () => {
  const cveFinding: CveFinding = {
    packageName: 'lodash',
    ecosystem: 'npm',
    version: '4.17.20',
    cveId: 'CVE-2021-23337',
    cvss: 7.2,
    minimumSafeVersion: '4.17.21',
    riskLevel: 'high',
  }

  it('generates a patch recommendation for a minor fix', () => {
    const result = computeUpdateRecommendations({ cveFindings: [cveFinding] })
    expect(result.totalRecommendations).toBe(1)
    const rec = result.recommendations[0]
    expect(rec.packageName).toBe('lodash')
    expect(rec.currentVersion).toBe('4.17.20')
    expect(rec.recommendedVersion).toBe('4.17.21')
    expect(rec.effort).toBe('patch')
    expect(rec.breakingChangeRisk).toBe(false)
    expect(rec.reasons).toContain('cve_fix')
    expect(rec.cveIds).toContain('CVE-2021-23337')
  })

  it('urgency matches CVE riskLevel', () => {
    const result = computeUpdateRecommendations({ cveFindings: [cveFinding] })
    expect(result.recommendations[0].urgency).toBe('high')
  })

  it('critical CVE produces critical urgency', () => {
    const criticalCve: CveFinding = {
      ...cveFinding,
      cveId: 'CVE-2021-44228',
      cvss: 10.0,
      minimumSafeVersion: '2.17.0',
      riskLevel: 'critical',
      packageName: 'log4j-core',
      ecosystem: 'maven',
      version: '2.14.1',
    }
    const result = computeUpdateRecommendations({ cveFindings: [criticalCve] })
    expect(result.criticalCount).toBe(1)
    expect(result.recommendations[0].urgency).toBe('critical')
  })

  it('major version CVE fix is classified as major effort', () => {
    const majorCve: CveFinding = {
      packageName: 'express',
      ecosystem: 'npm',
      version: '3.21.2',
      cveId: 'CVE-2024-99999',
      cvss: 8.0,
      minimumSafeVersion: '4.18.2',
      riskLevel: 'high',
    }
    const result = computeUpdateRecommendations({ cveFindings: [majorCve] })
    const rec = result.recommendations[0]
    expect(rec.effort).toBe('major')
    expect(rec.breakingChangeRisk).toBe(true)
  })

  it('multiple CVEs for same package deduplicate', () => {
    const cve1: CveFinding = {
      packageName: 'lodash',
      ecosystem: 'npm',
      version: '4.17.11',
      cveId: 'CVE-2019-10744',
      cvss: 9.1,
      minimumSafeVersion: '4.17.12',
      riskLevel: 'critical',
    }
    const cve2: CveFinding = {
      packageName: 'lodash',
      ecosystem: 'npm',
      version: '4.17.11',
      cveId: 'CVE-2021-23337',
      cvss: 7.2,
      minimumSafeVersion: '4.17.21',
      riskLevel: 'high',
    }
    const result = computeUpdateRecommendations({ cveFindings: [cve1, cve2] })
    expect(result.totalRecommendations).toBe(1)
    const rec = result.recommendations[0]
    // Should recommend the highest safe version
    expect(rec.recommendedVersion).toBe('4.17.21')
    // Should have the highest urgency
    expect(rec.urgency).toBe('critical')
    // Should list both CVE IDs
    expect(rec.cveIds).toHaveLength(2)
    expect(rec.cveIds).toContain('CVE-2019-10744')
    expect(rec.cveIds).toContain('CVE-2021-23337')
  })

  it('detail includes CVE ID and CVSS', () => {
    const result = computeUpdateRecommendations({ cveFindings: [cveFinding] })
    expect(result.recommendations[0].details[0]).toContain('CVE-2021-23337')
    expect(result.recommendations[0].details[0]).toContain('7.2')
  })
})

// ---------------------------------------------------------------------------
// EOL findings
// ---------------------------------------------------------------------------

describe('EOL findings', () => {
  it('end_of_life generates high urgency', () => {
    const eol: EolFinding = {
      packageName: 'node',
      ecosystem: 'npm',
      version: '14.21.3',
      eolStatus: 'end_of_life',
      replacedBy: '18.19.0',
    }
    const result = computeUpdateRecommendations({ eolFindings: [eol] })
    expect(result.totalRecommendations).toBe(1)
    const rec = result.recommendations[0]
    expect(rec.urgency).toBe('high')
    expect(rec.reasons).toContain('eol_upgrade')
    expect(rec.recommendedVersion).toBe('18.19.0')
  })

  it('near_eol generates medium urgency', () => {
    const eol: EolFinding = {
      packageName: 'python',
      ecosystem: 'pypi',
      version: '3.8.18',
      eolStatus: 'near_eol',
      replacedBy: '3.12.0',
    }
    const result = computeUpdateRecommendations({ eolFindings: [eol] })
    const rec = result.recommendations[0]
    expect(rec.urgency).toBe('medium')
    expect(rec.reasons).toContain('near_eol_upgrade')
  })

  it('null replacedBy still generates recommendation', () => {
    const eol: EolFinding = {
      packageName: 'someruntime',
      ecosystem: 'npm',
      version: '1.0.0',
      eolStatus: 'end_of_life',
      replacedBy: null,
    }
    const result = computeUpdateRecommendations({ eolFindings: [eol] })
    expect(result.totalRecommendations).toBe(1)
    expect(result.recommendations[0].details[0]).toContain('latest supported release')
  })

  it('replacement package detected when replacedBy is a package name', () => {
    const eol: EolFinding = {
      packageName: 'request',
      ecosystem: 'npm',
      version: '2.88.2',
      eolStatus: 'end_of_life',
      replacedBy: 'got',
    }
    const result = computeUpdateRecommendations({ eolFindings: [eol] })
    const rec = result.recommendations[0]
    expect(rec.effort).toBe('replacement')
    expect(rec.replacementPackage).toBe('got')
    expect(rec.breakingChangeRisk).toBe(true)
  })

  it('version-style replacedBy stays as same package upgrade', () => {
    const eol: EolFinding = {
      packageName: 'node',
      ecosystem: 'npm',
      version: '14.21.3',
      eolStatus: 'end_of_life',
      replacedBy: '18.19.0',
    }
    const result = computeUpdateRecommendations({ eolFindings: [eol] })
    const rec = result.recommendations[0]
    expect(rec.replacementPackage).toBeNull()
    expect(rec.effort).toBe('major') // 14 → 18 is major
  })
})

// ---------------------------------------------------------------------------
// Abandonment findings
// ---------------------------------------------------------------------------

describe('abandonment findings', () => {
  it('supply_chain_compromised generates critical urgency', () => {
    const ab: AbandonmentFinding = {
      packageName: 'event-stream',
      ecosystem: 'npm',
      version: '3.3.6',
      reason: 'supply_chain_compromised',
      riskLevel: 'critical',
      replacedBy: null,
    }
    const result = computeUpdateRecommendations({ abandonmentFindings: [ab] })
    expect(result.recommendations[0].urgency).toBe('critical')
    expect(result.recommendations[0].reasons).toContain('abandonment_replacement')
  })

  it('deprecated package with replacement', () => {
    const ab: AbandonmentFinding = {
      packageName: 'tslint',
      ecosystem: 'npm',
      version: '6.1.3',
      reason: 'officially_deprecated',
      riskLevel: 'medium',
      replacedBy: 'eslint',
    }
    const result = computeUpdateRecommendations({ abandonmentFindings: [ab] })
    const rec = result.recommendations[0]
    expect(rec.replacementPackage).toBe('eslint')
    expect(rec.effort).toBe('replacement')
    expect(rec.breakingChangeRisk).toBe(true)
  })

  it('archived package without replacement', () => {
    const ab: AbandonmentFinding = {
      packageName: 'left-pad',
      ecosystem: 'npm',
      version: '1.3.0',
      reason: 'archived',
      riskLevel: 'low',
      replacedBy: null,
    }
    const result = computeUpdateRecommendations({ abandonmentFindings: [ab] })
    const rec = result.recommendations[0]
    expect(rec.details[0]).toContain('archived/unmaintained')
    expect(rec.details[0]).toContain('actively maintained alternative')
    expect(rec.replacementPackage).toBeNull()
  })

  it('superseded package label is correct', () => {
    const ab: AbandonmentFinding = {
      packageName: 'node-uuid',
      ecosystem: 'npm',
      version: '1.4.8',
      reason: 'superseded',
      riskLevel: 'low',
      replacedBy: 'uuid',
    }
    const result = computeUpdateRecommendations({ abandonmentFindings: [ab] })
    expect(result.recommendations[0].details[0]).toContain('superseded')
    expect(result.recommendations[0].details[0]).toContain('uuid')
  })
})

// ---------------------------------------------------------------------------
// Cross-scanner deduplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('same package from CVE + EOL produces one recommendation', () => {
    const cve: CveFinding = {
      packageName: 'django',
      ecosystem: 'pypi',
      version: '2.2.28',
      cveId: 'CVE-2023-36053',
      cvss: 7.5,
      minimumSafeVersion: '3.2.20',
      riskLevel: 'high',
    }
    const eol: EolFinding = {
      packageName: 'django',
      ecosystem: 'pypi',
      version: '2.2.28',
      eolStatus: 'end_of_life',
      replacedBy: '4.2.0',
    }
    const result = computeUpdateRecommendations({ cveFindings: [cve], eolFindings: [eol] })
    expect(result.totalRecommendations).toBe(1)
    const rec = result.recommendations[0]
    // Should recommend the higher version (4.2.0 > 3.2.20)
    expect(rec.recommendedVersion).toBe('4.2.0')
    expect(rec.reasons).toContain('cve_fix')
    expect(rec.reasons).toContain('eol_upgrade')
    expect(rec.urgency).toBe('high') // both are high
  })

  it('same package from CVE + abandonment takes highest urgency', () => {
    const cve: CveFinding = {
      packageName: 'event-stream',
      ecosystem: 'npm',
      version: '3.3.6',
      cveId: 'CVE-2018-100001',
      cvss: 9.8,
      minimumSafeVersion: '4.0.0',
      riskLevel: 'critical',
    }
    const ab: AbandonmentFinding = {
      packageName: 'event-stream',
      ecosystem: 'npm',
      version: '3.3.6',
      reason: 'supply_chain_compromised',
      riskLevel: 'critical',
      replacedBy: null,
    }
    const result = computeUpdateRecommendations({
      cveFindings: [cve],
      abandonmentFindings: [ab],
    })
    expect(result.totalRecommendations).toBe(1)
    const rec = result.recommendations[0]
    expect(rec.urgency).toBe('critical')
    expect(rec.reasons).toContain('cve_fix')
    expect(rec.reasons).toContain('abandonment_replacement')
  })

  it('deduplication is case-insensitive on ecosystem and name', () => {
    const cve: CveFinding = {
      packageName: 'Lodash',
      ecosystem: 'NPM',
      version: '4.17.20',
      cveId: 'CVE-2021-23337',
      cvss: 7.2,
      minimumSafeVersion: '4.17.21',
      riskLevel: 'high',
    }
    const eol: EolFinding = {
      packageName: 'lodash',
      ecosystem: 'npm',
      version: '4.17.20',
      eolStatus: 'near_eol',
      replacedBy: null,
    }
    const result = computeUpdateRecommendations({ cveFindings: [cve], eolFindings: [eol] })
    expect(result.totalRecommendations).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

describe('sorting', () => {
  it('critical recommendations come before high', () => {
    const findings: CveFinding[] = [
      {
        packageName: 'low-risk',
        ecosystem: 'npm',
        version: '1.0.0',
        cveId: 'CVE-A',
        cvss: 4.0,
        minimumSafeVersion: '1.0.1',
        riskLevel: 'medium',
      },
      {
        packageName: 'high-risk',
        ecosystem: 'npm',
        version: '2.0.0',
        cveId: 'CVE-B',
        cvss: 10.0,
        minimumSafeVersion: '2.0.1',
        riskLevel: 'critical',
      },
    ]
    const result = computeUpdateRecommendations({ cveFindings: findings })
    expect(result.recommendations[0].packageName).toBe('high-risk')
    expect(result.recommendations[1].packageName).toBe('low-risk')
  })

  it('at same urgency, patch effort comes before major', () => {
    const findings: CveFinding[] = [
      {
        packageName: 'major-update',
        ecosystem: 'npm',
        version: '1.0.0',
        cveId: 'CVE-A',
        cvss: 7.5,
        minimumSafeVersion: '2.0.0',
        riskLevel: 'high',
      },
      {
        packageName: 'patch-update',
        ecosystem: 'npm',
        version: '1.0.0',
        cveId: 'CVE-B',
        cvss: 7.5,
        minimumSafeVersion: '1.0.1',
        riskLevel: 'high',
      },
    ]
    const result = computeUpdateRecommendations({ cveFindings: findings })
    expect(result.recommendations[0].packageName).toBe('patch-update')
    expect(result.recommendations[1].packageName).toBe('major-update')
  })

  it('at same urgency and effort, alphabetical by name', () => {
    const findings: CveFinding[] = [
      {
        packageName: 'zebra',
        ecosystem: 'npm',
        version: '1.0.0',
        cveId: 'CVE-A',
        cvss: 7.0,
        minimumSafeVersion: '1.0.1',
        riskLevel: 'high',
      },
      {
        packageName: 'alpha',
        ecosystem: 'npm',
        version: '1.0.0',
        cveId: 'CVE-B',
        cvss: 7.0,
        minimumSafeVersion: '1.0.1',
        riskLevel: 'high',
      },
    ]
    const result = computeUpdateRecommendations({ cveFindings: findings })
    expect(result.recommendations[0].packageName).toBe('alpha')
    expect(result.recommendations[1].packageName).toBe('zebra')
  })
})

// ---------------------------------------------------------------------------
// Aggregate counts
// ---------------------------------------------------------------------------

describe('aggregate counts', () => {
  const input: DependencyUpdateInput = {
    cveFindings: [
      { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 10.0, minimumSafeVersion: '1.0.1', riskLevel: 'critical' },
      { packageName: 'b', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-2', cvss: 8.0, minimumSafeVersion: '1.0.1', riskLevel: 'high' },
      { packageName: 'c', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-3', cvss: 5.0, minimumSafeVersion: '1.0.1', riskLevel: 'medium' },
      { packageName: 'd', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-4', cvss: 2.0, minimumSafeVersion: '1.0.1', riskLevel: 'low' },
    ],
  }
  const result = computeUpdateRecommendations(input)

  it('counts critical correctly', () => {
    expect(result.criticalCount).toBe(1)
  })

  it('counts high correctly', () => {
    expect(result.highCount).toBe(1)
  })

  it('counts medium correctly', () => {
    expect(result.mediumCount).toBe(1)
  })

  it('counts low correctly', () => {
    expect(result.lowCount).toBe(1)
  })

  it('totalRecommendations is correct', () => {
    expect(result.totalRecommendations).toBe(4)
  })

  it('patchCount counts patch-level updates', () => {
    expect(result.patchCount).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('mentions total count', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 10.0, minimumSafeVersion: '1.0.1', riskLevel: 'critical' },
      ],
    })
    expect(result.summary).toContain('1 dependency update')
  })

  it('mentions critical count when present', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 10.0, minimumSafeVersion: '1.0.1', riskLevel: 'critical' },
      ],
    })
    expect(result.summary).toContain('1 critical')
  })

  it('mentions breaking changes when present', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 8.0, minimumSafeVersion: '2.0.0', riskLevel: 'high' },
      ],
    })
    expect(result.summary).toContain('breaking change')
  })

  it('pluralizes correctly for single update', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 7.0, minimumSafeVersion: '1.0.1', riskLevel: 'high' },
      ],
    })
    expect(result.summary).toMatch(/1 dependency update recommended/)
    expect(result.summary).not.toContain('updates recommended')
  })

  it('pluralizes correctly for multiple updates', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'a', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 7.0, minimumSafeVersion: '1.0.1', riskLevel: 'high' },
        { packageName: 'b', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-2', cvss: 7.0, minimumSafeVersion: '1.0.1', riskLevel: 'high' },
      ],
    })
    expect(result.summary).toContain('updates recommended')
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('edge cases', () => {
  it('empty arrays produce no recommendations', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [],
      eolFindings: [],
      abandonmentFindings: [],
    })
    expect(result.totalRecommendations).toBe(0)
  })

  it('all null/undefined inputs treated as empty', () => {
    const result = computeUpdateRecommendations({
      cveFindings: undefined,
      eolFindings: undefined,
      abandonmentFindings: undefined,
    })
    expect(result.totalRecommendations).toBe(0)
  })

  it('preserves ecosystem in output', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'flask', ecosystem: 'pypi', version: '1.0.0', cveId: 'CVE-1', cvss: 7.0, minimumSafeVersion: '1.1.0', riskLevel: 'high' },
      ],
    })
    expect(result.recommendations[0].ecosystem).toBe('pypi')
  })

  it('handles unparseable target version gracefully', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'weird', ecosystem: 'npm', version: 'latest', cveId: 'CVE-1', cvss: 7.0, minimumSafeVersion: '1.0.0', riskLevel: 'high' },
      ],
    })
    // Should still produce a recommendation with major effort (safe default)
    expect(result.totalRecommendations).toBe(1)
    expect(result.recommendations[0].effort).toBe('major')
  })

  it('breakingCount counts major + replacement', () => {
    const input: DependencyUpdateInput = {
      cveFindings: [
        { packageName: 'major-pkg', ecosystem: 'npm', version: '1.0.0', cveId: 'CVE-1', cvss: 8.0, minimumSafeVersion: '2.0.0', riskLevel: 'high' },
      ],
      abandonmentFindings: [
        { packageName: 'old-pkg', ecosystem: 'npm', version: '1.0.0', reason: 'officially_deprecated', riskLevel: 'medium', replacedBy: 'new-pkg' },
      ],
    }
    const result = computeUpdateRecommendations(input)
    expect(result.breakingCount).toBe(2) // one major, one replacement
  })

  it('replacement package is null when not a different package', () => {
    const result = computeUpdateRecommendations({
      cveFindings: [
        { packageName: 'lodash', ecosystem: 'npm', version: '4.17.20', cveId: 'CVE-1', cvss: 7.0, minimumSafeVersion: '4.17.21', riskLevel: 'high' },
      ],
    })
    expect(result.recommendations[0].replacementPackage).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Mixed scenario: realistic repository
// ---------------------------------------------------------------------------

describe('realistic mixed scenario', () => {
  const input: DependencyUpdateInput = {
    cveFindings: [
      // Log4Shell
      { packageName: 'log4j-core', ecosystem: 'maven', version: '2.14.1', cveId: 'CVE-2021-44228', cvss: 10.0, minimumSafeVersion: '2.17.0', riskLevel: 'critical' },
      // lodash prototype pollution
      { packageName: 'lodash', ecosystem: 'npm', version: '4.17.11', cveId: 'CVE-2019-10744', cvss: 9.1, minimumSafeVersion: '4.17.12', riskLevel: 'critical' },
      { packageName: 'lodash', ecosystem: 'npm', version: '4.17.11', cveId: 'CVE-2021-23337', cvss: 7.2, minimumSafeVersion: '4.17.21', riskLevel: 'high' },
    ],
    eolFindings: [
      // Node 14 is EOL
      { packageName: 'node', ecosystem: 'npm', version: '14.21.3', eolStatus: 'end_of_life', replacedBy: '20.11.0' },
    ],
    abandonmentFindings: [
      // request is deprecated
      { packageName: 'request', ecosystem: 'npm', version: '2.88.2', reason: 'archived', riskLevel: 'high', replacedBy: 'got' },
    ],
  }

  const result = computeUpdateRecommendations(input)

  it('produces 4 recommendations (lodash deduplicated)', () => {
    expect(result.totalRecommendations).toBe(4)
  })

  it('log4j is first (critical, patch)', () => {
    // log4j: critical urgency, minor effort (2.14→2.17)
    // lodash: critical urgency, patch effort (4.17.11→4.17.21)
    // Both critical — lodash patch < log4j minor
    expect(result.recommendations[0].packageName).toBe('lodash')
    expect(result.recommendations[1].packageName).toBe('log4j-core')
  })

  it('lodash is deduplicated with highest safe version', () => {
    const lodash = result.recommendations.find((r) => r.packageName === 'lodash')!
    expect(lodash.recommendedVersion).toBe('4.17.21')
    expect(lodash.cveIds).toHaveLength(2)
    expect(lodash.urgency).toBe('critical')
  })

  it('request is a replacement recommendation', () => {
    const request = result.recommendations.find((r) => r.packageName === 'request')!
    expect(request.effort).toBe('replacement')
    expect(request.replacementPackage).toBe('got')
  })

  it('node is a major upgrade', () => {
    const node = result.recommendations.find((r) => r.packageName === 'node')!
    expect(node.effort).toBe('major')
    expect(node.breakingChangeRisk).toBe(true)
    expect(node.recommendedVersion).toBe('20.11.0')
  })

  it('summary is informative', () => {
    expect(result.summary).toContain('4 dependency updates')
    expect(result.summary).toContain('critical')
  })
})
