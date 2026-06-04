/**
 * Tenant Security Executive Report — pure computation library (WS-97)
 *
 * Synthesises per-repository signals from four existing scoring systems
 * (WS-49 health, WS-96 drift posture, WS-44 supply chain, WS-46 compliance)
 * into a single tenant-level executive summary with composite scores,
 * risk tiers, worst/best-repo rankings, and deduped top-action items.
 *
 * No new schema table — entirely a computed view assembled at query time.
 */

// ── Domain weights ─────────────────────────────────────────────────────────

export const EXEC_WEIGHTS = {
  health: 0.40,
  driftPosture: 0.35,
  supplyChain: 0.15,
  compliance: 0.10,
} as const

// ── Types ──────────────────────────────────────────────────────────────────

export type ExecRiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical'
export type ExecGrade = 'A' | 'B' | 'C' | 'D' | 'F'
export type FrameworkStatus = 'compliant' | 'at_risk' | 'non_compliant'

export interface RepoFrameworkData {
  framework: string
  status: FrameworkStatus
  score: number  // 0–100 per-framework score from WS-46
}

export interface RepoSnapshot {
  repositoryId: string
  repositoryFullName: string
  /** 0–100 overall score from WS-49 health score, or null if not yet computed. */
  healthScore: number | null
  healthGrade: string | null
  healthTopRisks: string[]
  /** 0–100 overall score from WS-96 drift posture, or null if not yet computed. */
  driftPostureScore: number | null
  driftGrade: string | null
  driftTopRisks: string[]
  /** 0–100 score from WS-44 supply chain posture (supplyChainScore), or null. */
  supplyChainScore: number | null
  supplyChainGrade: string | null
  /** Per-framework compliance data from WS-46. */
  frameworks: RepoFrameworkData[]
}

export interface ExecRepoSummary {
  repositoryFullName: string
  compositeScore: number
  grade: ExecGrade
  riskLevel: ExecRiskLevel
  topRisk: string
}

export interface ExecFrameworkStatus {
  framework: string
  totalRepos: number
  compliantRepos: number
  atRiskRepos: number
  nonCompliantRepos: number
  /** Percentage of repos that are compliant (0–100). */
  complianceRate: number
}

export interface TenantExecutiveReport {
  tenantSlug: string
  generatedAt: number
  totalRepositories: number
  /** Repos for which at least one scoring system has data. */
  scoredRepositories: number
  overallScore: number
  overallGrade: ExecGrade
  riskLevel: ExecRiskLevel
  domainAverages: {
    healthAvg: number | null
    driftPostureAvg: number | null
    supplyChainAvg: number | null
    complianceAvg: number | null
  }
  /** Bottom 5 repos by composite score. */
  worstRepos: ExecRepoSummary[]
  /** Top 5 repos by composite score. */
  bestRepos: ExecRepoSummary[]
  /** Deduped, prioritised top-5 action items derived from worst repos. */
  topActions: string[]
  /** Per-framework compliance roll-up across all repos. */
  frameworkCompliance: ExecFrameworkStatus[]
}

// ── Score helpers ──────────────────────────────────────────────────────────

/**
 * Convert a 0–100 composite score to an A–F grade using the same thresholds
 * as WS-49 and WS-96.
 */
export function scoreToGrade(score: number): ExecGrade {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

/**
 * Map a 0–100 composite score to an executive risk tier.
 */
export function scoreToRiskLevel(score: number): ExecRiskLevel {
  if (score >= 85) return 'safe'
  if (score >= 70) return 'low'
  if (score >= 55) return 'medium'
  if (score >= 35) return 'high'
  return 'critical'
}

/**
 * Derive a 0–100 compliance score from a repo's framework array.
 * Maps: compliant→100, at_risk→50, non_compliant→0; averages across frameworks.
 * Returns null if no frameworks are provided.
 */
export function complianceScoreFromFrameworks(frameworks: RepoFrameworkData[]): number | null {
  if (frameworks.length === 0) return null
  const STATUS_SCORE: Record<FrameworkStatus, number> = {
    compliant: 100,
    at_risk: 50,
    non_compliant: 0,
  }
  const total = frameworks.reduce((sum, f) => sum + STATUS_SCORE[f.status], 0)
  return Math.round(total / frameworks.length)
}

/**
 * Compute a 0–100 composite score for a single repository.
 * Dimensions with no data are excluded — the weight is redistributed
 * proportionally among present dimensions.
 * Returns null when no dimension has data.
 */
export function computeCompositeScore(snap: RepoSnapshot): number | null {
  const complianceScore = complianceScoreFromFrameworks(snap.frameworks)

  const dims: Array<{ score: number | null; weight: number }> = [
    { score: snap.healthScore, weight: EXEC_WEIGHTS.health },
    { score: snap.driftPostureScore, weight: EXEC_WEIGHTS.driftPosture },
    { score: snap.supplyChainScore, weight: EXEC_WEIGHTS.supplyChain },
    { score: complianceScore, weight: EXEC_WEIGHTS.compliance },
  ]

  let weightedSum = 0
  let totalWeight = 0
  for (const { score, weight } of dims) {
    if (score != null) {
      weightedSum += score * weight
      totalWeight += weight
    }
  }
  if (totalWeight === 0) return null
  return Math.round(weightedSum / totalWeight)
}

// ── Aggregation helpers ────────────────────────────────────────────────────

function avg(values: number[]): number | null {
  if (values.length === 0) return null
  return Math.round(values.reduce((s, v) => s + v, 0) / values.length)
}

/**
 * Build the ExecRepoSummary for a single repository.
 * Returns null if there is no composite score (zero data).
 */
export function buildRepoSummary(snap: RepoSnapshot): ExecRepoSummary | null {
  const composite = computeCompositeScore(snap)
  if (composite == null) return null

  // Pick the most urgent risk description available
  const allRisks = [...snap.healthTopRisks, ...snap.driftTopRisks]
  const topRisk = allRisks[0] ?? 'No specific risk identified'

  return {
    repositoryFullName: snap.repositoryFullName,
    compositeScore: composite,
    grade: scoreToGrade(composite),
    riskLevel: scoreToRiskLevel(composite),
    topRisk,
  }
}

/**
 * Collect and deduplicate top-action strings from the N worst-scoring repos.
 * Returns at most `limit` unique action strings.
 */
export function extractTopActions(
  snapshots: RepoSnapshot[],
  limit: number = 5,
): string[] {
  const seen = new Set<string>()
  const actions: string[] = []

  for (const snap of snapshots) {
    const allRisks = [...snap.healthTopRisks, ...snap.driftTopRisks]
    for (const risk of allRisks) {
      const key = risk.toLowerCase().trim()
      if (!seen.has(key)) {
        seen.add(key)
        actions.push(risk)
        if (actions.length >= limit) return actions
      }
    }
  }
  return actions
}

/**
 * Roll up per-framework compliance across all repositories.
 */
export function buildFrameworkCompliance(snapshots: RepoSnapshot[]): ExecFrameworkStatus[] {
  const byFramework = new Map<
    string,
    { total: number; compliant: number; atRisk: number; nonCompliant: number }
  >()

  for (const snap of snapshots) {
    for (const fw of snap.frameworks) {
      const entry = byFramework.get(fw.framework) ?? {
        total: 0,
        compliant: 0,
        atRisk: 0,
        nonCompliant: 0,
      }
      entry.total++
      if (fw.status === 'compliant') entry.compliant++
      else if (fw.status === 'at_risk') entry.atRisk++
      else entry.nonCompliant++
      byFramework.set(fw.framework, entry)
    }
  }

  return Array.from(byFramework.entries())
    .map(([framework, e]) => ({
      framework,
      totalRepos: e.total,
      compliantRepos: e.compliant,
      atRiskRepos: e.atRisk,
      nonCompliantRepos: e.nonCompliant,
      complianceRate: Math.round((e.compliant / e.total) * 100),
    }))
    .sort((a, b) => a.complianceRate - b.complianceRate)  // worst framework first
}

// ── Main entry ─────────────────────────────────────────────────────────────

export function computeExecutiveReport(
  tenantSlug: string,
  snapshots: RepoSnapshot[],
): TenantExecutiveReport {
  const now = Date.now()

  const summaries = snapshots
    .map((s) => ({ snap: s, summary: buildRepoSummary(s) }))
    .filter((x): x is { snap: RepoSnapshot; summary: ExecRepoSummary } => x.summary != null)

  const scoredRepositories = summaries.length

  // Per-domain averages
  const healthScores = snapshots.map((s) => s.healthScore).filter((v): v is number => v != null)
  const driftScores = snapshots.map((s) => s.driftPostureScore).filter((v): v is number => v != null)
  const supplyChainScores = snapshots.map((s) => s.supplyChainScore).filter((v): v is number => v != null)
  const complianceScores = snapshots
    .map((s) => complianceScoreFromFrameworks(s.frameworks))
    .filter((v): v is number => v != null)

  // Overall composite = average of per-repo composites
  const compositeScores = summaries.map((x) => x.summary.compositeScore)
  const overallScore = avg(compositeScores) ?? 0

  // Sort by composite score ascending (worst first)
  const sorted = summaries.sort((a, b) => a.summary.compositeScore - b.summary.compositeScore)
  const worstSnapshots = sorted.slice(0, 5).map((x) => x.snap)
  const topActions = extractTopActions(worstSnapshots)

  return {
    tenantSlug,
    generatedAt: now,
    totalRepositories: snapshots.length,
    scoredRepositories,
    overallScore,
    overallGrade: scoreToGrade(overallScore),
    riskLevel: scoreToRiskLevel(overallScore),
    domainAverages: {
      healthAvg: avg(healthScores),
      driftPostureAvg: avg(driftScores),
      supplyChainAvg: avg(supplyChainScores),
      complianceAvg: avg(complianceScores),
    },
    worstRepos: sorted.slice(0, 5).map((x) => x.summary),
    bestRepos: sorted
      .slice(-5)
      .reverse()
      .map((x) => x.summary),
    topActions,
    frameworkCompliance: buildFrameworkCompliance(snapshots),
  }
}
