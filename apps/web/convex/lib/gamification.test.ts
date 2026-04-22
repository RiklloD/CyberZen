import { describe, expect, it } from 'vitest'
import {
  computeEngineerLeaderboard,
  computeGamification,
  computeRepositoryLeaderboard,
  selectWindowSnapshots,
  type PrProposalInput,
  type RepositorySnapshotInput,
} from './gamification'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000 // fixed reference timestamp
const DAY = 24 * 60 * 60 * 1000
const WINDOW_START = NOW - 14 * DAY
const WINDOW_END = NOW

function makeSnap(
  overrides: Partial<RepositorySnapshotInput> & {
    repositoryId?: string
    repositoryName?: string
    score?: number
    trend?: 'improving' | 'stable' | 'degrading'
    computedAt?: number
  } = {},
): RepositorySnapshotInput {
  return {
    repositoryId: 'repo-a',
    repositoryName: 'acme/api',
    score: 60,
    trend: 'stable',
    computedAt: NOW - 7 * DAY, // mid-window by default
    ...overrides,
  }
}

function makePr(
  overrides: Partial<PrProposalInput> & {
    repositoryId?: string
    status?: string
    mergedAt?: number | null
    mergedBy?: string | null
    createdAt?: number
  } = {},
): PrProposalInput {
  return {
    repositoryId: 'repo-a',
    status: 'merged',
    mergedAt: NOW - 5 * DAY,
    mergedBy: 'alice',
    createdAt: NOW - 10 * DAY,
    ...overrides,
  }
}

// ─── selectWindowSnapshots ────────────────────────────────────────────────────

describe('selectWindowSnapshots', () => {
  it('returns null current and null previous when array is empty', () => {
    const { current, previous } = selectWindowSnapshots([], WINDOW_START, WINDOW_END)
    expect(current).toBeNull()
    expect(previous).toBeNull()
  })

  it('picks the latest snapshot inside the window as current', () => {
    const snaps = [
      makeSnap({ score: 50, computedAt: NOW - 10 * DAY }),
      makeSnap({ score: 70, computedAt: NOW - 3 * DAY }), // latest in window
    ]
    const { current } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(current?.score).toBe(70)
  })

  it('picks the latest snapshot before window as previous', () => {
    const snaps = [
      makeSnap({ score: 40, computedAt: NOW - 20 * DAY }), // before window
      makeSnap({ score: 45, computedAt: NOW - 16 * DAY }), // latest before window
      makeSnap({ score: 60, computedAt: NOW - 7 * DAY }),  // in window
    ]
    const { previous } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(previous?.score).toBe(45)
  })

  it('returns null previous when no snapshot exists before window start', () => {
    const snaps = [makeSnap({ computedAt: NOW - 7 * DAY })]
    const { previous } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(previous).toBeNull()
  })

  it('returns null current when all snapshots are outside window', () => {
    const snaps = [
      makeSnap({ computedAt: NOW - 20 * DAY }),
      makeSnap({ computedAt: NOW + DAY }),   // future
    ]
    const { current } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(current).toBeNull()
  })

  it('snapshot at exact windowStart boundary is included in window', () => {
    const snaps = [makeSnap({ computedAt: WINDOW_START })]
    const { current } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(current).not.toBeNull()
  })

  it('snapshot at exact windowEnd boundary is included in window', () => {
    const snaps = [makeSnap({ computedAt: WINDOW_END })]
    const { current } = selectWindowSnapshots(snaps, WINDOW_START, WINDOW_END)
    expect(current).not.toBeNull()
  })
})

// ─── computeRepositoryLeaderboard ────────────────────────────────────────────

describe('computeRepositoryLeaderboard', () => {
  it('returns empty array when no snapshots', () => {
    const result = computeRepositoryLeaderboard([], [], WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('excludes repositories with no in-window snapshot', () => {
    const snaps = [makeSnap({ computedAt: NOW - 30 * DAY })] // before window
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('includes repository with in-window snapshot', () => {
    const snaps = [makeSnap({ score: 65, computedAt: NOW - 7 * DAY })]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(1)
    expect(result[0].currentScore).toBe(65)
  })

  it('scoreDelta is 0 when no previous snapshot exists', () => {
    const snaps = [makeSnap({ score: 70, computedAt: NOW - 7 * DAY })]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].scoreDelta).toBe(0)
    expect(result[0].previousScore).toBeNull()
  })

  it('computes positive scoreDelta when score improved', () => {
    const snaps = [
      makeSnap({ score: 50, computedAt: NOW - 20 * DAY }), // previous
      makeSnap({ score: 75, computedAt: NOW - 7 * DAY }),  // current
    ]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].scoreDelta).toBe(25)
    expect(result[0].previousScore).toBe(50)
  })

  it('computes negative scoreDelta when score degraded', () => {
    const snaps = [
      makeSnap({ score: 80, computedAt: NOW - 20 * DAY }),
      makeSnap({ score: 60, computedAt: NOW - 7 * DAY }),
    ]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].scoreDelta).toBe(-20)
  })

  it('ranks multiple repositories by scoreDelta descending', () => {
    const snaps = [
      makeSnap({ repositoryId: 'repo-a', repositoryName: 'api', score: 40, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'repo-a', repositoryName: 'api', score: 80, computedAt: NOW - 7 * DAY }),  // +40
      makeSnap({ repositoryId: 'repo-b', repositoryName: 'web', score: 60, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'repo-b', repositoryName: 'web', score: 70, computedAt: NOW - 7 * DAY }),  // +10
    ]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].repositoryId).toBe('repo-a')
    expect(result[0].rank).toBe(1)
    expect(result[1].repositoryId).toBe('repo-b')
    expect(result[1].rank).toBe(2)
  })

  it('breaks tie by currentScore descending', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', score: 50, computedAt: NOW - 7 * DAY }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', score: 80, computedAt: NOW - 7 * DAY }),
    ]
    // Both have scoreDelta=0; r2 has higher currentScore → ranks first
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].repositoryId).toBe('r2')
  })

  it('assigns gold/silver/bronze badges to top 3', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', score: 20, computedAt: NOW - 25 * DAY }),
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', score: 80, computedAt: NOW - 7 * DAY }), // +60
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', score: 30, computedAt: NOW - 25 * DAY }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', score: 70, computedAt: NOW - 7 * DAY }), // +40
      makeSnap({ repositoryId: 'r3', repositoryName: 'r3', score: 40, computedAt: NOW - 25 * DAY }),
      makeSnap({ repositoryId: 'r3', repositoryName: 'r3', score: 60, computedAt: NOW - 7 * DAY }), // +20
      makeSnap({ repositoryId: 'r4', repositoryName: 'r4', score: 50, computedAt: NOW - 25 * DAY }),
      makeSnap({ repositoryId: 'r4', repositoryName: 'r4', score: 55, computedAt: NOW - 7 * DAY }), // +5
    ]
    const result = computeRepositoryLeaderboard(snaps, [], WINDOW_START, WINDOW_END)
    expect(result[0].badge).toBe('gold')
    expect(result[1].badge).toBe('silver')
    expect(result[2].badge).toBe('bronze')
    expect(result[3].badge).toBeNull()
  })

  it('counts merged PRs within window for each repository', () => {
    const snaps = [makeSnap({ score: 70, computedAt: NOW - 7 * DAY })]
    const prs = [
      makePr({ repositoryId: 'repo-a', mergedAt: NOW - 5 * DAY }),
      makePr({ repositoryId: 'repo-a', mergedAt: NOW - 3 * DAY }),
      makePr({ repositoryId: 'repo-a', mergedAt: NOW - 30 * DAY }), // outside window
    ]
    const result = computeRepositoryLeaderboard(snaps, prs, WINDOW_START, WINDOW_END)
    expect(result[0].mergedPrCount).toBe(2)
  })

  it('does not count open PRs toward mergedPrCount', () => {
    const snaps = [makeSnap({ score: 70, computedAt: NOW - 7 * DAY })]
    const prs = [
      makePr({ status: 'open' }),
      makePr({ status: 'draft' }),
    ]
    const result = computeRepositoryLeaderboard(snaps, prs, WINDOW_START, WINDOW_END)
    expect(result[0].mergedPrCount).toBe(0)
  })
})

// ─── computeEngineerLeaderboard ───────────────────────────────────────────────

describe('computeEngineerLeaderboard', () => {
  it('returns empty when no PRs', () => {
    const result = computeEngineerLeaderboard([], [], WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('excludes PRs without mergedBy', () => {
    const prs = [makePr({ mergedBy: null }), makePr({ mergedBy: undefined })]
    const result = computeEngineerLeaderboard([], prs, WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('excludes PRs outside the window', () => {
    const prs = [makePr({ mergedAt: NOW - 30 * DAY, mergedBy: 'alice' })]
    const result = computeEngineerLeaderboard([], prs, WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('excludes non-merged PRs', () => {
    const prs = [makePr({ status: 'open', mergedBy: 'alice' })]
    const result = computeEngineerLeaderboard([], prs, WINDOW_START, WINDOW_END)
    expect(result).toHaveLength(0)
  })

  it('ranks engineers by mergedPrCount descending', () => {
    const prs = [
      makePr({ mergedBy: 'alice', repositoryId: 'r1', mergedAt: NOW - 5 * DAY }),
      makePr({ mergedBy: 'alice', repositoryId: 'r1', mergedAt: NOW - 4 * DAY }),
      makePr({ mergedBy: 'bob',   repositoryId: 'r1', mergedAt: NOW - 3 * DAY }),
    ]
    const result = computeEngineerLeaderboard([], prs, WINDOW_START, WINDOW_END)
    expect(result[0].engineerLogin).toBe('alice')
    expect(result[0].mergedPrCount).toBe(2)
    expect(result[0].rank).toBe(1)
    expect(result[1].engineerLogin).toBe('bob')
    expect(result[1].rank).toBe(2)
  })

  it('breaks ties alphabetically by login', () => {
    const prs = [
      makePr({ mergedBy: 'zara' }),
      makePr({ mergedBy: 'alice' }),
    ]
    const result = computeEngineerLeaderboard([], prs, WINDOW_START, WINDOW_END)
    expect(result[0].engineerLogin).toBe('alice')
  })

  it('accumulates distinct repository names from snapshots', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'acme/api' }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'acme/web' }),
    ]
    const prs = [
      makePr({ mergedBy: 'alice', repositoryId: 'r1' }),
      makePr({ mergedBy: 'alice', repositoryId: 'r2' }),
      makePr({ mergedBy: 'alice', repositoryId: 'r1' }), // duplicate repoId
    ]
    const result = computeEngineerLeaderboard(snaps, prs, WINDOW_START, WINDOW_END)
    expect(result[0].repositoriesContributed).toEqual(['acme/api', 'acme/web'])
    expect(result[0].mergedPrCount).toBe(3)
  })
})

// ─── computeGamification ──────────────────────────────────────────────────────

describe('computeGamification', () => {
  it('returns empty leaderboards and placeholder summary when no data', () => {
    const result = computeGamification([], [], 14, NOW)
    expect(result.repositoryLeaderboard).toHaveLength(0)
    expect(result.engineerLeaderboard).toHaveLength(0)
    expect(result.mostImprovedRepository).toBeNull()
    expect(result.summary).toContain('No attack surface data')
  })

  it('sets windowDays and computedAt correctly', () => {
    const result = computeGamification([], [], 7, NOW)
    expect(result.windowDays).toBe(7)
    expect(result.computedAt).toBe(NOW)
  })

  it('aggregates totalScoreDelta across repositories', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', score: 50, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', score: 70, computedAt: NOW - 7 * DAY }),  // +20
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', score: 60, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', score: 75, computedAt: NOW - 7 * DAY }),  // +15
    ]
    const result = computeGamification(snaps, [], 14, NOW)
    expect(result.totalScoreDelta).toBe(35)
  })

  it('sets mostImprovedRepository to the rank-1 repository name', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'best-repo', score: 40, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'r1', repositoryName: 'best-repo', score: 90, computedAt: NOW - 7 * DAY }), // +50
      makeSnap({ repositoryId: 'r2', repositoryName: 'other-repo', score: 50, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'other-repo', score: 60, computedAt: NOW - 7 * DAY }), // +10
    ]
    const result = computeGamification(snaps, [], 14, NOW)
    expect(result.mostImprovedRepository).toBe('best-repo')
  })

  it('counts totalPrsMerged across all repositories', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'r1', computedAt: NOW - 7 * DAY }),
      makeSnap({ repositoryId: 'r2', repositoryName: 'r2', computedAt: NOW - 7 * DAY }),
    ]
    const prs = [
      makePr({ repositoryId: 'r1', mergedAt: NOW - 5 * DAY }),
      makePr({ repositoryId: 'r1', mergedAt: NOW - 4 * DAY }),
      makePr({ repositoryId: 'r2', mergedAt: NOW - 3 * DAY }),
    ]
    const result = computeGamification(snaps, prs, 14, NOW)
    expect(result.totalPrsMerged).toBe(3)
  })

  it('summary mentions top performer when scoreDelta is positive', () => {
    const snaps = [
      makeSnap({ repositoryId: 'r1', repositoryName: 'star-repo', score: 50, computedAt: NOW - 20 * DAY }),
      makeSnap({ repositoryId: 'r1', repositoryName: 'star-repo', score: 80, computedAt: NOW - 7 * DAY }),
    ]
    const result = computeGamification(snaps, [], 14, NOW)
    expect(result.summary).toContain('star-repo')
    expect(result.summary).toContain('+30.0 pts')
  })

  it('summary mentions security PRs when any were merged', () => {
    const snaps = [makeSnap({ computedAt: NOW - 7 * DAY })]
    const prs = [makePr(), makePr()]
    const result = computeGamification(snaps, prs, 14, NOW)
    expect(result.summary).toContain('2 security PRs merged')
  })

  it('summary uses singular "PR" when exactly one was merged', () => {
    const snaps = [makeSnap({ computedAt: NOW - 7 * DAY })]
    const prs = [makePr()]
    const result = computeGamification(snaps, prs, 14, NOW)
    expect(result.summary).toContain('1 security PR merged')
  })

  it('uses 30-day window when windowDays=30', () => {
    // snapshot at NOW - 25 days should be in a 30-day window but not a 14-day window
    const snaps = [makeSnap({ score: 70, computedAt: NOW - 25 * DAY })]
    const r14 = computeGamification(snaps, [], 14, NOW)
    const r30 = computeGamification(snaps, [], 30, NOW)
    expect(r14.repositoryLeaderboard).toHaveLength(0)
    expect(r30.repositoryLeaderboard).toHaveLength(1)
  })
})
