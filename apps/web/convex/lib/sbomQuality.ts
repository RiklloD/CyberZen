// WS-32 — SBOM Quality & Completeness Scoring: pure computation library.
//
// Exports:
//   isExactVersion      — true when a version string is a precise pin (no ranges)
//   computeFreshnessScore — linear decay: 100 at day 0, 0 at day 90
//   countLayersPopulated — how many of the 6 SBOM layers have components
//   computeSbomQuality  — overall 0–100 quality score with sub-scores and grade

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SbomSnapshotInput = {
  capturedAt: number
  directDependencyCount: number
  transitiveDependencyCount: number
  buildDependencyCount: number
  containerDependencyCount: number
  runtimeDependencyCount?: number
  aiModelDependencyCount?: number
  totalComponents: number
  sourceFiles: string[]
}

export type SbomComponentInput = {
  version: string
  license?: string | null | undefined
  isDirect: boolean
  ecosystem: string
  layer: string
}

export type SbomQualityGrade = 'excellent' | 'good' | 'fair' | 'poor'

export type SbomQualityResult = {
  overallScore: number
  grade: SbomQualityGrade

  // Sub-scores (each 0–100)
  completenessScore: number
  versionPinningScore: number
  licenseResolutionScore: number
  freshnessScore: number
  layerCoverageScore: number

  // Raw stats
  totalComponents: number
  exactVersionCount: number
  versionPinningRate: number
  licensedCount: number
  licenseResolutionRate: number
  daysSinceCapture: number
  layersPopulated: number

  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Any of these characters in a version string indicates a range specifier. */
const VERSION_RANGE_RE = /[\^~*><=|]/

/**
 * Day boundary after which a snapshot is considered fully stale (score = 0).
 */
const FRESHNESS_STALE_DAYS = 90

/**
 * Completeness score per component: 5 pts each, capped at 100.
 * Reaches 100 at 20 components — representative of a non-trivial project.
 */
const COMPLETENESS_PTS_PER_COMPONENT = 5

// ---------------------------------------------------------------------------
// isExactVersion
// ---------------------------------------------------------------------------

/**
 * Returns true if the version string represents an exact pinned version —
 * i.e. it contains no range specifiers (`^`, `~`, `>`, `<`, `=`, `*`, `|`).
 *
 * Empty strings, `any`, and `latest` are treated as unpinned.
 *
 * Examples
 *   "1.2.3"          → true
 *   "0.9.0-alpha.1"  → true
 *   "^1.0.0"         → false
 *   ">=2.1"          → false
 *   "*"              → false
 *   ""               → false
 *   "latest"         → false
 */
export function isExactVersion(version: string): boolean {
  if (!version || version.trim() === '' || version === 'any' || version === 'latest') return false
  return !VERSION_RANGE_RE.test(version)
}

// ---------------------------------------------------------------------------
// computeFreshnessScore
// ---------------------------------------------------------------------------

/**
 * Linear decay: 100 at day 0, 0 at day 90+.
 *
 * @param capturedAt  Unix ms timestamp of when the snapshot was taken
 * @param now         Current Unix ms timestamp (injectable for testing)
 */
export function computeFreshnessScore(capturedAt: number, now: number): number {
  const daysSinceCapture = Math.floor((now - capturedAt) / (1000 * 60 * 60 * 24))
  return Math.max(0, Math.round(100 - daysSinceCapture * (100 / FRESHNESS_STALE_DAYS)))
}

// ---------------------------------------------------------------------------
// countLayersPopulated
// ---------------------------------------------------------------------------

/**
 * Returns how many of the 6 SBOM layers have at least one component.
 * Layers: direct, transitive, build, container, runtime, AI model.
 */
export function countLayersPopulated(snapshot: SbomSnapshotInput): number {
  const counts = [
    snapshot.directDependencyCount,
    snapshot.transitiveDependencyCount,
    snapshot.buildDependencyCount,
    snapshot.containerDependencyCount,
    snapshot.runtimeDependencyCount ?? 0,
    snapshot.aiModelDependencyCount ?? 0,
  ]
  return counts.filter((n) => n > 0).length
}

// ---------------------------------------------------------------------------
// computeSbomQuality
// ---------------------------------------------------------------------------

/**
 * Computes a holistic SBOM quality score for a single snapshot.
 *
 * Sub-score weights:
 *   completeness       25 %  — penalises empty or near-empty SBOMs
 *   versionPinning     25 %  — rewards fully pinned dependency trees
 *   licenseResolution  20 %  — rewards known licenses (integrates with WS-31)
 *   freshness          15 %  — penalises stale snapshots (>90 days → 0)
 *   layerCoverage      15 %  — rewards populating all 6 SBOM layers
 *
 * Grade thresholds: excellent ≥ 80, good ≥ 60, fair ≥ 40, poor < 40.
 *
 * @param snapshot    SBOM snapshot metadata
 * @param components  All components in the snapshot
 * @param now         Current Unix ms timestamp (defaults to Date.now())
 */
export function computeSbomQuality(
  snapshot: SbomSnapshotInput,
  components: SbomComponentInput[],
  now = Date.now(),
): SbomQualityResult {
  const total = components.length

  // ── Completeness ──────────────────────────────────────────────────────────
  const completenessScore =
    total === 0 ? 0 : Math.min(100, total * COMPLETENESS_PTS_PER_COMPONENT)

  // ── Version pinning ───────────────────────────────────────────────────────
  const exactVersionCount = components.filter((c) => isExactVersion(c.version)).length
  // 0 components → 0 (no data means no credit; avoids misleading 100% on empty SBOMs)
  const versionPinningRate = total === 0 ? 0 : exactVersionCount / total
  const versionPinningScore = Math.round(versionPinningRate * 100)

  // ── License resolution ────────────────────────────────────────────────────
  const licensedCount = components.filter(
    (c) => c.license != null && c.license.trim() !== '',
  ).length
  const licenseResolutionRate = total === 0 ? 0 : licensedCount / total
  const licenseResolutionScore = Math.round(licenseResolutionRate * 100)

  // ── Freshness ─────────────────────────────────────────────────────────────
  const daysSinceCapture = Math.floor((now - snapshot.capturedAt) / (1000 * 60 * 60 * 24))
  const freshnessScore = computeFreshnessScore(snapshot.capturedAt, now)

  // ── Layer coverage ────────────────────────────────────────────────────────
  const layersPopulated = countLayersPopulated(snapshot)
  const layerCoverageScore = Math.round((layersPopulated / 6) * 100)

  // ── Overall weighted score ────────────────────────────────────────────────
  const overallScore = Math.round(
    completenessScore * 0.25 +
      versionPinningScore * 0.25 +
      licenseResolutionScore * 0.2 +
      freshnessScore * 0.15 +
      layerCoverageScore * 0.15,
  )

  // ── Grade ─────────────────────────────────────────────────────────────────
  const grade: SbomQualityGrade =
    overallScore >= 80
      ? 'excellent'
      : overallScore >= 60
        ? 'good'
        : overallScore >= 40
          ? 'fair'
          : 'poor'

  // ── Summary ───────────────────────────────────────────────────────────────
  const issues: string[] = []

  if (versionPinningScore < 50) {
    const unpinned = total - exactVersionCount
    issues.push(`${unpinned} unpinned version${unpinned === 1 ? '' : 's'}`)
  }
  if (licenseResolutionScore < 70) {
    const unlicensed = total - licensedCount
    issues.push(`${unlicensed} component${unlicensed === 1 ? '' : 's'} with unknown license`)
  }
  if (daysSinceCapture > 30) {
    issues.push(`snapshot is ${daysSinceCapture} day${daysSinceCapture === 1 ? '' : 's'} old`)
  }
  if (layersPopulated < 3) {
    issues.push(`only ${layersPopulated} of 6 SBOM layer${layersPopulated === 1 ? '' : 's'} populated`)
  }

  const summary =
    total === 0
      ? 'No components in this SBOM snapshot.'
      : issues.length === 0
        ? `SBOM quality is ${grade} (${overallScore}/100). All quality gates pass.`
        : `SBOM quality is ${grade} (${overallScore}/100). Issues: ${issues.join('; ')}.`

  return {
    overallScore,
    grade,
    completenessScore,
    versionPinningScore,
    licenseResolutionScore,
    freshnessScore,
    layerCoverageScore,
    totalComponents: total,
    exactVersionCount,
    versionPinningRate,
    licensedCount,
    licenseResolutionRate,
    daysSinceCapture,
    layersPopulated,
    summary,
  }
}
