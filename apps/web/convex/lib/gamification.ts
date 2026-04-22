// WS-28 — Gamification Layer (spec §3.7.4): sprint leaderboards for attack
// surface reduction.
//
// No DB access. All computation is pure so the library is fully unit-testable
// without spinning up a Convex environment.
//
// The layer surfaces three ranked views:
//   1. Repository leaderboard  — ranked by attack surface score delta over the sprint
//   2. Engineer leaderboard    — ranked by security fix PRs merged (requires mergedBy)
//   3. GamificationResult      — full report combining both + summary text
//
// Window logic:
//   windowStart = now − windowDays × 86_400_000 ms
//   windowEnd   = now
//   current     = latest snapshot with computedAt ∈ [windowStart, windowEnd]
//   previous    = latest snapshot with computedAt < windowStart  (baseline)
//   scoreDelta  = current.score − previous.score  (positive = improved)

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type AttackSurfaceTrend = 'improving' | 'stable' | 'degrading'

export type RepositorySnapshotInput = {
  /** Convex document ID (string) */
  repositoryId: string
  repositoryName: string
  /** 0–100 composite reduction score. */
  score: number
  trend: AttackSurfaceTrend
  /** Unix ms */
  computedAt: number
}

export type PrProposalInput = {
  repositoryId: string
  /** 'merged' | 'open' | 'draft' | 'closed' | 'failed' */
  status: string
  /** Unix ms; undefined / null when not merged. */
  mergedAt?: number | null
  /** GitHub login of the engineer who merged; undefined / null when unknown. */
  mergedBy?: string | null
  createdAt: number
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type RepoBadge = 'gold' | 'silver' | 'bronze' | null

export type RepositoryLeaderboardEntry = {
  repositoryId: string
  repositoryName: string
  /** Latest score within the window (0–100). */
  currentScore: number
  /** Score at start-of-window baseline; null if no prior snapshot exists. */
  previousScore: number | null
  /** currentScore − previousScore.  Positive = attack surface reduced. */
  scoreDelta: number
  trend: AttackSurfaceTrend
  /** Count of Sentinel-generated fix PRs merged within the window. */
  mergedPrCount: number
  /** 1-indexed rank (1 = most improved). */
  rank: number
  badge: RepoBadge
}

export type EngineerLeaderboardEntry = {
  engineerLogin: string
  mergedPrCount: number
  /** Distinct repository names this engineer contributed fixes to. */
  repositoriesContributed: string[]
  rank: number
}

export type GamificationResult = {
  windowDays: number
  repositoryLeaderboard: RepositoryLeaderboardEntry[]
  engineerLeaderboard: EngineerLeaderboardEntry[]
  /** Name of the top-ranked repository; null when no data. */
  mostImprovedRepository: string | null
  /** Sum of scoreDelta across all ranked repositories. */
  totalScoreDelta: number
  /** Count of security fix PRs merged tenant-wide during the window. */
  totalPrsMerged: number
  /** Human-readable summary sentence. */
  summary: string
  computedAt: number
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const BADGE_MAP: Record<number, RepoBadge> = {
  1: 'gold',
  2: 'silver',
  3: 'bronze',
}

// ---------------------------------------------------------------------------
// selectWindowSnapshots
// ---------------------------------------------------------------------------

/**
 * From a set of snapshots for a single repository, return:
 *   current  — latest snapshot with computedAt ∈ [windowStart, windowEnd]
 *   previous — latest snapshot with computedAt < windowStart  (baseline)
 *
 * Both may be null if no snapshot exists in the given range.
 */
export function selectWindowSnapshots(
  snapshots: RepositorySnapshotInput[],
  windowStart: number,
  windowEnd: number,
): { current: RepositorySnapshotInput | null; previous: RepositorySnapshotInput | null } {
  const sorted = [...snapshots].sort((a, b) => b.computedAt - a.computedAt)
  const current =
    sorted.find((s) => s.computedAt >= windowStart && s.computedAt <= windowEnd) ?? null
  const previous = sorted.find((s) => s.computedAt < windowStart) ?? null
  return { current, previous }
}

// ---------------------------------------------------------------------------
// computeRepositoryLeaderboard
// ---------------------------------------------------------------------------

/**
 * Rank repositories by attack surface score improvement over
 * [windowStart, windowEnd].
 *
 * Repositories with no snapshot inside the window are excluded.
 *
 * Sort key: scoreDelta DESC; ties broken by currentScore DESC then name ASC.
 */
export function computeRepositoryLeaderboard(
  snapshots: RepositorySnapshotInput[],
  prProposals: PrProposalInput[],
  windowStart: number,
  windowEnd: number,
): RepositoryLeaderboardEntry[] {
  // ── Group snapshots by repositoryId ───────────────────────────────────────
  const byRepo = new Map<string, RepositorySnapshotInput[]>()
  for (const snap of snapshots) {
    const list = byRepo.get(snap.repositoryId) ?? []
    list.push(snap)
    byRepo.set(snap.repositoryId, list)
  }

  // ── Count merged PRs per repo within the window ──────────────────────────
  const mergedByRepo = new Map<string, number>()
  for (const pr of prProposals) {
    if (
      pr.status === 'merged' &&
      pr.mergedAt != null &&
      pr.mergedAt >= windowStart &&
      pr.mergedAt <= windowEnd
    ) {
      mergedByRepo.set(pr.repositoryId, (mergedByRepo.get(pr.repositoryId) ?? 0) + 1)
    }
  }

  // ── Build entries ─────────────────────────────────────────────────────────
  const entries: RepositoryLeaderboardEntry[] = []
  for (const [repoId, repoSnaps] of byRepo) {
    const { current, previous } = selectWindowSnapshots(repoSnaps, windowStart, windowEnd)
    if (!current) continue // no data in window → exclude

    const scoreDelta = previous != null ? current.score - previous.score : 0

    entries.push({
      repositoryId: repoId,
      repositoryName: current.repositoryName,
      currentScore: current.score,
      previousScore: previous?.score ?? null,
      scoreDelta,
      trend: current.trend,
      mergedPrCount: mergedByRepo.get(repoId) ?? 0,
      rank: 0, // filled below
      badge: null, // filled below
    })
  }

  // ── Sort and assign rank / badge ──────────────────────────────────────────
  entries.sort((a, b) => {
    if (b.scoreDelta !== a.scoreDelta) return b.scoreDelta - a.scoreDelta
    if (b.currentScore !== a.currentScore) return b.currentScore - a.currentScore
    return a.repositoryName.localeCompare(b.repositoryName)
  })
  entries.forEach((e, i) => {
    e.rank = i + 1
    e.badge = BADGE_MAP[i + 1] ?? null
  })

  return entries
}

// ---------------------------------------------------------------------------
// computeEngineerLeaderboard
// ---------------------------------------------------------------------------

/**
 * Rank engineers by security fix PRs merged during [windowStart, windowEnd].
 *
 * Only PRs that have a non-empty `mergedBy` login are counted.
 * Sort key: mergedPrCount DESC; ties broken by login ASC.
 */
export function computeEngineerLeaderboard(
  snapshots: RepositorySnapshotInput[],
  prProposals: PrProposalInput[],
  windowStart: number,
  windowEnd: number,
): EngineerLeaderboardEntry[] {
  // Build a repositoryId → repositoryName lookup from snapshots
  const repoNameById = new Map<string, string>()
  for (const snap of snapshots) {
    if (!repoNameById.has(snap.repositoryId)) {
      repoNameById.set(snap.repositoryId, snap.repositoryName)
    }
  }

  // Aggregate by login
  const byLogin = new Map<string, { count: number; repos: Set<string> }>()
  for (const pr of prProposals) {
    if (
      pr.status === 'merged' &&
      pr.mergedAt != null &&
      pr.mergedAt >= windowStart &&
      pr.mergedAt <= windowEnd &&
      pr.mergedBy
    ) {
      const agg = byLogin.get(pr.mergedBy) ?? { count: 0, repos: new Set<string>() }
      agg.count++
      agg.repos.add(repoNameById.get(pr.repositoryId) ?? pr.repositoryId)
      byLogin.set(pr.mergedBy, agg)
    }
  }

  const entries: EngineerLeaderboardEntry[] = []
  for (const [login, agg] of byLogin) {
    entries.push({
      engineerLogin: login,
      mergedPrCount: agg.count,
      repositoriesContributed: [...agg.repos].sort(),
      rank: 0,
    })
  }

  entries.sort((a, b) => {
    if (b.mergedPrCount !== a.mergedPrCount) return b.mergedPrCount - a.mergedPrCount
    return a.engineerLogin.localeCompare(b.engineerLogin)
  })
  entries.forEach((e, i) => {
    e.rank = i + 1
  })

  return entries
}

// ---------------------------------------------------------------------------
// computeGamification
// ---------------------------------------------------------------------------

/**
 * Full gamification report for a tenant over a lookback window.
 *
 * @param snapshots    All attackSurfaceSnapshots for the tenant's repositories.
 * @param prProposals  All prProposals for the tenant.
 * @param windowDays   Sprint window length in days (default 14 = bi-weekly sprint).
 * @param now          Reference timestamp in ms (defaults to Date.now()).
 */
export function computeGamification(
  snapshots: RepositorySnapshotInput[],
  prProposals: PrProposalInput[],
  windowDays = 14,
  now = Date.now(),
): GamificationResult {
  const windowEnd = now
  const windowStart = now - windowDays * 24 * 60 * 60 * 1000

  const repositoryLeaderboard = computeRepositoryLeaderboard(
    snapshots,
    prProposals,
    windowStart,
    windowEnd,
  )
  const engineerLeaderboard = computeEngineerLeaderboard(
    snapshots,
    prProposals,
    windowStart,
    windowEnd,
  )

  const totalScoreDelta = repositoryLeaderboard.reduce((acc, e) => acc + e.scoreDelta, 0)
  const totalPrsMerged = repositoryLeaderboard.reduce((acc, e) => acc + e.mergedPrCount, 0)
  const topRepo = repositoryLeaderboard.find((e) => e.rank === 1) ?? null
  const improvingCount = repositoryLeaderboard.filter((e) => e.scoreDelta > 0).length

  // Compose summary
  const parts: string[] = []
  if (repositoryLeaderboard.length === 0) {
    parts.push(`No attack surface data available for the last ${windowDays} days.`)
  } else {
    parts.push(
      `${repositoryLeaderboard.length} ${repositoryLeaderboard.length === 1 ? 'repository' : 'repositories'} tracked over ${windowDays} days.`,
    )
    if (topRepo && topRepo.scoreDelta > 0) {
      parts.push(
        `🥇 Top performer: ${topRepo.repositoryName} (+${topRepo.scoreDelta.toFixed(1)} pts).`,
      )
    }
    if (improvingCount > 0) {
      parts.push(`${improvingCount} of ${repositoryLeaderboard.length} repos improving.`)
    }
    if (totalPrsMerged > 0) {
      parts.push(`${totalPrsMerged} security PR${totalPrsMerged === 1 ? '' : 's'} merged.`)
    }
  }

  return {
    windowDays,
    repositoryLeaderboard,
    engineerLeaderboard,
    mostImprovedRepository: topRepo?.repositoryName ?? null,
    totalScoreDelta,
    totalPrsMerged,
    summary: parts.join(' '),
    computedAt: now,
  }
}
