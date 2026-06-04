import { describe, expect, it } from 'vitest'
import {
  assessRepositoryImpact,
  computeCrossRepoImpact,
  matchesPackage,
  normalizeForCrossRepo,
  type ComponentSnapshot,
  type RepositorySnapshot,
} from './crossRepoImpact'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeComponent(
  overrides: Partial<ComponentSnapshot> & { name: string },
): ComponentSnapshot {
  return {
    normalizedName: normalizeForCrossRepo(overrides.name),
    ecosystem: 'npm',
    version: '1.0.0',
    isDirect: true,
    ...overrides,
  }
}

function makeSnapshot(
  repositoryId: string,
  repositoryName: string,
  components: ComponentSnapshot[],
): RepositorySnapshot {
  return { repositoryId, repositoryName, components }
}

// ─── normalizeForCrossRepo ────────────────────────────────────────────────────

describe('normalizeForCrossRepo', () => {
  it('lowercases names', () => {
    expect(normalizeForCrossRepo('Express')).toBe('express')
  })

  it('strips @scope/ npm prefix', () => {
    expect(normalizeForCrossRepo('@types/node')).toBe('node')
    expect(normalizeForCrossRepo('@babel/core')).toBe('core')
  })

  it('normalises underscores to dashes', () => {
    expect(normalizeForCrossRepo('my_package')).toBe('my-package')
  })

  it('normalises dots to dashes', () => {
    expect(normalizeForCrossRepo('my.package')).toBe('my-package')
  })

  it('collapses consecutive separators and trims leading/trailing dashes', () => {
    expect(normalizeForCrossRepo('--foo__bar..')).toBe('foo-bar')
  })
})

// ─── matchesPackage ────────────────────────────────────────────────────────────

describe('matchesPackage', () => {
  it('matches identical names and ecosystems', () => {
    const comp = makeComponent({ name: 'lodash', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', 'npm')).toBe(true)
  })

  it('matches case-insensitively', () => {
    const comp = makeComponent({ name: 'Lodash', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', 'npm')).toBe(true)
  })

  it('matches when ecosystem is unknown (skips ecosystem check)', () => {
    const comp = makeComponent({ name: 'lodash', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', 'unknown')).toBe(true)
  })

  it('matches when ecosystem is empty string', () => {
    const comp = makeComponent({ name: 'lodash', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', '')).toBe(true)
  })

  it('rejects mismatched ecosystem', () => {
    const comp = makeComponent({ name: 'lodash', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', 'pypi')).toBe(false)
  })

  it('rejects mismatched name', () => {
    const comp = makeComponent({ name: 'underscore', ecosystem: 'npm' })
    expect(matchesPackage(comp, 'lodash', 'npm')).toBe(false)
  })

  it('uses component.normalizedName when available instead of re-normalizing', () => {
    // Simulate a component whose normalizedName was pre-computed differently from name
    const comp: ComponentSnapshot = {
      name: 'MY-PKG',
      normalizedName: 'my-pkg',
      ecosystem: 'npm',
      version: '1.0.0',
      isDirect: true,
    }
    expect(matchesPackage(comp, 'MY-PKG', 'npm')).toBe(true)
  })
})

// ─── assessRepositoryImpact ───────────────────────────────────────────────────

describe('assessRepositoryImpact', () => {
  it('returns affected=false for an empty snapshot', () => {
    const snapshot = makeSnapshot('r1', 'repo-a', [])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.affected).toBe(false)
    expect(result.totalMatchCount).toBe(0)
    expect(result.directMatchCount).toBe(0)
    expect(result.transitiveMatchCount).toBe(0)
  })

  it('returns affected=true when the package is found', () => {
    const snapshot = makeSnapshot('r1', 'repo-a', [
      makeComponent({ name: 'lodash', ecosystem: 'npm' }),
    ])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.affected).toBe(true)
    expect(result.totalMatchCount).toBe(1)
    expect(result.directMatchCount).toBe(1)
  })

  it('correctly splits direct vs. transitive counts', () => {
    const snapshot = makeSnapshot('r1', 'repo-a', [
      makeComponent({ name: 'lodash', isDirect: true }),
      makeComponent({ name: 'lodash', isDirect: false, version: '4.17.0' }),
    ])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.directMatchCount).toBe(1)
    expect(result.transitiveMatchCount).toBe(1)
  })

  it('deduplicates matched versions', () => {
    const snapshot = makeSnapshot('r1', 'repo-a', [
      makeComponent({ name: 'lodash', version: '4.17.21' }),
      makeComponent({ name: 'lodash', version: '4.17.21', isDirect: false }),
    ])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.matchedVersions).toEqual(['4.17.21'])
  })

  it('does not count non-matching packages', () => {
    const snapshot = makeSnapshot('r1', 'repo-a', [
      makeComponent({ name: 'underscore' }),
      makeComponent({ name: 'moment' }),
    ])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.affected).toBe(false)
  })

  it('preserves repositoryId and repositoryName in the result', () => {
    const snapshot = makeSnapshot('id-abc', 'my-repo', [])
    const result = assessRepositoryImpact(snapshot, 'lodash', 'npm')
    expect(result.repositoryId).toBe('id-abc')
    expect(result.repositoryName).toBe('my-repo')
  })
})

// ─── computeCrossRepoImpact ───────────────────────────────────────────────────

describe('computeCrossRepoImpact', () => {
  const base = {
    packageName: 'lodash',
    ecosystem: 'npm',
    severity: 'high',
    findingTitle: 'lodash prototype pollution',
  }

  it('returns zero counts when no other repos exist', () => {
    const result = computeCrossRepoImpact({ ...base, repositorySnapshots: [] })
    expect(result.totalRepositories).toBe(0)
    expect(result.affectedRepositoryCount).toBe(0)
    expect(result.affectedRepositories).toHaveLength(0)
  })

  it('returns zero affected when no repos contain the package', () => {
    const snapshots = [
      makeSnapshot('r1', 'repo-a', [makeComponent({ name: 'express' })]),
      makeSnapshot('r2', 'repo-b', [makeComponent({ name: 'moment' })]),
    ]
    const result = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(result.totalRepositories).toBe(2)
    expect(result.affectedRepositoryCount).toBe(0)
  })

  it('returns only affected repos in affectedRepositories', () => {
    const snapshots = [
      makeSnapshot('r1', 'repo-a', [makeComponent({ name: 'lodash' })]),
      makeSnapshot('r2', 'repo-b', [makeComponent({ name: 'express' })]),
    ]
    const result = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(result.affectedRepositoryCount).toBe(1)
    expect(result.affectedRepositories[0].repositoryName).toBe('repo-a')
  })

  it('counts all affected repos correctly', () => {
    const snapshots = [
      makeSnapshot('r1', 'repo-a', [makeComponent({ name: 'lodash' })]),
      makeSnapshot('r2', 'repo-b', [makeComponent({ name: 'lodash' })]),
      makeSnapshot('r3', 'repo-c', [makeComponent({ name: 'moment' })]),
    ]
    const result = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(result.totalRepositories).toBe(3)
    expect(result.affectedRepositoryCount).toBe(2)
  })

  it('summary mentions "no lateral exposure" when no repos affected', () => {
    const snapshots = [makeSnapshot('r1', 'repo-a', [])]
    const { summary } = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(summary).toContain('no lateral exposure')
  })

  it('summary mentions the affected repo name when exactly one affected', () => {
    const snapshots = [
      makeSnapshot('r1', 'repo-alpha', [makeComponent({ name: 'lodash' })]),
    ]
    const { summary } = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(summary).toContain('repo-alpha')
    expect(summary).toContain('1 of 1')
  })

  it('summary mentions repo count when multiple repos affected', () => {
    const snapshots = [
      makeSnapshot('r1', 'repo-a', [makeComponent({ name: 'lodash' })]),
      makeSnapshot('r2', 'repo-b', [makeComponent({ name: 'lodash' })]),
      makeSnapshot('r3', 'repo-c', [makeComponent({ name: 'lodash' })]),
    ]
    const { summary } = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(summary).toContain('3 of 3')
  })

  it('summary uses "and N others" when more than 3 repos affected', () => {
    const snapshots = Array.from({ length: 5 }, (_, i) =>
      makeSnapshot(`r${i}`, `repo-${i}`, [makeComponent({ name: 'lodash' })]),
    )
    const { summary } = computeCrossRepoImpact({
      ...base,
      repositorySnapshots: snapshots,
    })
    expect(summary).toContain('and 3 others')
  })
})
