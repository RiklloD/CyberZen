/**
 * WS-50 — Dependency Update Recommendation Engine: pure computation library.
 *
 * Reads findings from WS-43 (CVE), WS-38 (EOL), and WS-39 (abandonment)
 * scanners and produces a deduplicated, prioritised list of concrete
 * dependency update recommendations.
 *
 * Each recommendation answers "what should I upgrade, to what version, why,
 * and how hard will it be?" — the actionable step after vulnerability detection.
 *
 * Key design decisions:
 *   - Deduplication by ecosystem:name key — same package across multiple
 *     scanners gets ONE recommendation with combined reasons.
 *   - Effort classification via semver segment comparison: patch (safe),
 *     minor (low risk), major (breaking potential), replacement (different pkg).
 *   - Urgency inherits the highest severity from contributing findings.
 *   - Recommendations sorted by urgency (critical-first), then effort (easiest-first).
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UpdateUrgency = 'critical' | 'high' | 'medium' | 'low'

export type UpdateEffort =
  | 'patch'        // patch-level bump (e.g. 1.2.3 → 1.2.5) — lowest risk
  | 'minor'        // minor-level bump (e.g. 1.2.3 → 1.4.0) — low risk
  | 'major'        // major-level bump (e.g. 1.2.3 → 2.0.0) — breaking changes possible
  | 'replacement'  // different package entirely (e.g. request → got)

export type UpdateReason =
  | 'cve_fix'                // CVE vulnerability with a known safe version
  | 'eol_upgrade'            // End-of-life runtime/framework
  | 'near_eol_upgrade'       // Approaching EOL within 90 days
  | 'abandonment_replacement' // Abandoned/compromised package

export type UpdateRecommendation = {
  /** Package ecosystem (npm, pypi, maven, etc.) */
  ecosystem: string
  /** Package name */
  packageName: string
  /** Current installed version */
  currentVersion: string
  /** Recommended target version or package */
  recommendedVersion: string
  /** Combined urgency (highest from all contributing findings) */
  urgency: UpdateUrgency
  /** Estimated effort to apply this update */
  effort: UpdateEffort
  /** Whether the update crosses a major version boundary */
  breakingChangeRisk: boolean
  /** All reasons this update is recommended (may have multiple) */
  reasons: UpdateReason[]
  /** Human-readable descriptions for each reason */
  details: string[]
  /** CVE IDs if the recommendation is driven by vulnerabilities */
  cveIds: string[]
  /** Replacement package name if different from current */
  replacementPackage: string | null
}

export type UpdateRecommendationResult = {
  recommendations: UpdateRecommendation[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalRecommendations: number
  /** Number of recommendations that are simple patches */
  patchCount: number
  /** Number of recommendations that require major upgrades or replacements */
  breakingCount: number
  summary: string
}

// ---------------------------------------------------------------------------
// Scanner finding input types (subset of what each scanner persists)
// ---------------------------------------------------------------------------

export type CveFinding = {
  packageName: string
  ecosystem: string
  version: string
  cveId: string
  cvss: number
  minimumSafeVersion: string
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
}

export type EolFinding = {
  packageName: string
  ecosystem: string
  version: string
  eolStatus: 'end_of_life' | 'near_eol'
  replacedBy: string | null
}

export type AbandonmentFinding = {
  packageName: string
  ecosystem: string
  version: string
  reason: 'supply_chain_compromised' | 'officially_deprecated' | 'archived' | 'superseded' | 'unmaintained'
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  replacedBy: string | null
}

export type DependencyUpdateInput = {
  cveFindings?: CveFinding[]
  eolFindings?: EolFinding[]
  abandonmentFindings?: AbandonmentFinding[]
}

// ---------------------------------------------------------------------------
// Semver utilities
// ---------------------------------------------------------------------------

/**
 * Parse a version string into [major, minor, patch] tuple.
 * Handles v-prefixes, pre-release suffixes, etc.
 * Returns null if the version is not parseable as semver.
 */
export function parseSemver(version: string): [number, number, number] | null {
  const cleaned = version
    .replace(/^v/i, '')
    .replace(/[-+].*$/, '') // strip pre-release / build metadata
    .replace(/\.RELEASE$|\.SNAPSHOT$/i, '') // Maven suffixes
    .trim()

  const parts = cleaned.split('.')
  if (parts.length < 1 || parts.length > 3) return null

  const nums = parts.map((p) => parseInt(p, 10))
  if (nums.some((n) => isNaN(n) || n < 0)) return null

  return [nums[0] ?? 0, nums[1] ?? 0, nums[2] ?? 0]
}

/**
 * Classify the effort of upgrading from `current` to `target`.
 * If either version is not parseable, returns 'major' as a safe default.
 */
export function classifyEffort(
  currentVersion: string,
  targetVersion: string,
): UpdateEffort {
  const curr = parseSemver(currentVersion)
  const tgt = parseSemver(targetVersion)

  if (!curr || !tgt) return 'major' // unparseable → assume risky

  if (tgt[0] > curr[0]) return 'major'
  if (tgt[1] > curr[1]) return 'minor'
  return 'patch'
}

/**
 * Determine if a version jump crosses a major boundary.
 */
export function isMajorBump(currentVersion: string, targetVersion: string): boolean {
  const curr = parseSemver(currentVersion)
  const tgt = parseSemver(targetVersion)
  if (!curr || !tgt) return true // assume breaking if we can't parse
  return tgt[0] > curr[0]
}

// ---------------------------------------------------------------------------
// Urgency ranking
// ---------------------------------------------------------------------------

const URGENCY_RANK: Record<UpdateUrgency, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const EFFORT_RANK: Record<UpdateEffort, number> = {
  patch: 1,
  minor: 2,
  major: 3,
  replacement: 4,
}

function higherUrgency(a: UpdateUrgency, b: UpdateUrgency): UpdateUrgency {
  return URGENCY_RANK[a] >= URGENCY_RANK[b] ? a : b
}

// ---------------------------------------------------------------------------
// Internal accumulator for deduplication
// ---------------------------------------------------------------------------

type RecommendationBuilder = {
  ecosystem: string
  packageName: string
  currentVersion: string
  recommendedVersion: string
  urgency: UpdateUrgency
  effort: UpdateEffort
  breakingChangeRisk: boolean
  reasons: Set<UpdateReason>
  details: string[]
  cveIds: string[]
  replacementPackage: string | null
}

function packageKey(ecosystem: string, name: string): string {
  return `${ecosystem.toLowerCase()}::${name.toLowerCase()}`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute dependency update recommendations from CVE, EOL, and abandonment
 * scanner findings.
 */
export function computeUpdateRecommendations(
  input: DependencyUpdateInput,
): UpdateRecommendationResult {
  const builders = new Map<string, RecommendationBuilder>()

  function getOrCreate(ecosystem: string, packageName: string, currentVersion: string): RecommendationBuilder {
    const key = packageKey(ecosystem, packageName)
    let builder = builders.get(key)
    if (!builder) {
      builder = {
        ecosystem,
        packageName,
        currentVersion,
        recommendedVersion: currentVersion,
        urgency: 'low',
        effort: 'patch',
        breakingChangeRisk: false,
        reasons: new Set(),
        details: [],
        cveIds: [],
        replacementPackage: null,
      }
      builders.set(key, builder)
    }
    return builder
  }

  // ── Process CVE findings ─────────────────────────────────────────────
  for (const cve of input.cveFindings ?? []) {
    const b = getOrCreate(cve.ecosystem, cve.packageName, cve.version)
    b.urgency = higherUrgency(b.urgency, cve.riskLevel)
    b.reasons.add('cve_fix')
    b.cveIds.push(cve.cveId)
    b.details.push(
      `${cve.cveId} (CVSS ${cve.cvss.toFixed(1)}): upgrade to ≥${cve.minimumSafeVersion}`,
    )

    // If the CVE's safe version is higher than what we already recommend, use it
    const safeSemver = parseSemver(cve.minimumSafeVersion)
    const recSemver = parseSemver(b.recommendedVersion)
    if (safeSemver && recSemver) {
      if (
        safeSemver[0] > recSemver[0] ||
        (safeSemver[0] === recSemver[0] && safeSemver[1] > recSemver[1]) ||
        (safeSemver[0] === recSemver[0] && safeSemver[1] === recSemver[1] && safeSemver[2] > recSemver[2])
      ) {
        b.recommendedVersion = cve.minimumSafeVersion
      }
    } else if (b.recommendedVersion === b.currentVersion) {
      // Can't parse, but at least set the target
      b.recommendedVersion = cve.minimumSafeVersion
    }
  }

  // ── Process EOL findings ─────────────────────────────────────────────
  for (const eol of input.eolFindings ?? []) {
    const b = getOrCreate(eol.ecosystem, eol.packageName, eol.version)
    const reason: UpdateReason = eol.eolStatus === 'end_of_life' ? 'eol_upgrade' : 'near_eol_upgrade'
    b.reasons.add(reason)

    const eolUrgency: UpdateUrgency = eol.eolStatus === 'end_of_life' ? 'high' : 'medium'
    b.urgency = higherUrgency(b.urgency, eolUrgency)

    if (eol.replacedBy) {
      // Check if replacedBy is a version of the same package or a different package
      if (isReplacementPackage(eol.replacedBy, eol.packageName)) {
        b.replacementPackage = eol.replacedBy
        b.recommendedVersion = eol.replacedBy
        b.effort = 'replacement'
        b.breakingChangeRisk = true
      } else {
        // It's a version string for the same package
        const recSemver = parseSemver(b.recommendedVersion)
        const repSemver = parseSemver(eol.replacedBy)
        if (repSemver && recSemver) {
          if (
            repSemver[0] > recSemver[0] ||
            (repSemver[0] === recSemver[0] && repSemver[1] > recSemver[1]) ||
            (repSemver[0] === recSemver[0] && repSemver[1] === recSemver[1] && repSemver[2] > recSemver[2])
          ) {
            b.recommendedVersion = eol.replacedBy
          }
        } else if (b.recommendedVersion === b.currentVersion) {
          b.recommendedVersion = eol.replacedBy
        }
      }

      const verb = eol.eolStatus === 'end_of_life' ? 'is end-of-life' : 'is nearing end-of-life'
      b.details.push(`${eol.packageName} ${eol.version} ${verb}; upgrade to ${eol.replacedBy}`)
    } else {
      const verb = eol.eolStatus === 'end_of_life' ? 'is end-of-life' : 'is nearing end-of-life'
      b.details.push(`${eol.packageName} ${eol.version} ${verb}; check for latest supported release`)
    }
  }

  // ── Process abandonment findings ─────────────────────────────────────
  for (const ab of input.abandonmentFindings ?? []) {
    const b = getOrCreate(ab.ecosystem, ab.packageName, ab.version)
    b.reasons.add('abandonment_replacement')
    b.urgency = higherUrgency(b.urgency, ab.riskLevel)

    if (ab.replacedBy) {
      if (isReplacementPackage(ab.replacedBy, ab.packageName)) {
        b.replacementPackage = ab.replacedBy
        b.recommendedVersion = ab.replacedBy
        b.effort = 'replacement'
        b.breakingChangeRisk = true
      } else if (b.recommendedVersion === b.currentVersion) {
        b.recommendedVersion = ab.replacedBy
      }

      const reasonLabel = ABANDONMENT_LABEL[ab.reason] ?? ab.reason
      b.details.push(`${ab.packageName} is ${reasonLabel}; migrate to ${ab.replacedBy}`)
    } else {
      const reasonLabel = ABANDONMENT_LABEL[ab.reason] ?? ab.reason
      b.details.push(`${ab.packageName} is ${reasonLabel}; find an actively maintained alternative`)
    }
  }

  // ── Finalize effort + breaking risk ──────────────────────────────────
  for (const b of builders.values()) {
    // If not already marked as replacement, compute effort from version comparison
    if (b.effort !== 'replacement' && b.recommendedVersion !== b.currentVersion) {
      b.effort = classifyEffort(b.currentVersion, b.recommendedVersion)
      b.breakingChangeRisk = isMajorBump(b.currentVersion, b.recommendedVersion)
    }
  }

  // ── Convert to sorted output ─────────────────────────────────────────
  const recommendations: UpdateRecommendation[] = [...builders.values()]
    .map((b) => ({
      ecosystem: b.ecosystem,
      packageName: b.packageName,
      currentVersion: b.currentVersion,
      recommendedVersion: b.recommendedVersion,
      urgency: b.urgency,
      effort: b.effort,
      breakingChangeRisk: b.breakingChangeRisk,
      reasons: [...b.reasons],
      details: b.details,
      cveIds: b.cveIds,
      replacementPackage: b.replacementPackage,
    }))
    .sort((a, b) => {
      // Primary: urgency desc
      const urgDiff = URGENCY_RANK[b.urgency] - URGENCY_RANK[a.urgency]
      if (urgDiff !== 0) return urgDiff
      // Secondary: effort asc (easiest first)
      const effDiff = EFFORT_RANK[a.effort] - EFFORT_RANK[b.effort]
      if (effDiff !== 0) return effDiff
      // Tertiary: alphabetical
      return a.packageName.localeCompare(b.packageName)
    })

  // ── Aggregate counts ─────────────────────────────────────────────────
  const criticalCount = recommendations.filter((r) => r.urgency === 'critical').length
  const highCount = recommendations.filter((r) => r.urgency === 'high').length
  const mediumCount = recommendations.filter((r) => r.urgency === 'medium').length
  const lowCount = recommendations.filter((r) => r.urgency === 'low').length
  const patchCount = recommendations.filter((r) => r.effort === 'patch').length
  const breakingCount = recommendations.filter(
    (r) => r.effort === 'major' || r.effort === 'replacement',
  ).length

  const summary = buildSummary({
    totalRecommendations: recommendations.length,
    criticalCount,
    highCount,
    patchCount,
    breakingCount,
  })

  return {
    recommendations,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalRecommendations: recommendations.length,
    patchCount,
    breakingCount,
    summary,
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ABANDONMENT_LABEL: Record<string, string> = {
  supply_chain_compromised: 'supply-chain-compromised',
  officially_deprecated: 'officially deprecated',
  archived: 'archived/unmaintained',
  superseded: 'superseded',
  unmaintained: 'unmaintained',
}

/**
 * Heuristic to detect if `replacedBy` is a different package name vs a version.
 * A replacement package typically contains letters and doesn't look like a semver.
 */
function isReplacementPackage(replacedBy: string, currentName: string): boolean {
  // If it's the same name, it's not a replacement
  if (replacedBy.toLowerCase() === currentName.toLowerCase()) return false
  // If it looks like a semver (digits and dots only), it's a version
  if (/^\d+(\.\d+)*$/.test(replacedBy.replace(/^v/i, ''))) return false
  // If it contains @ (scoped package) or letters without dots, it's likely a package name
  if (/[a-zA-Z]/.test(replacedBy) && !replacedBy.match(/^\d/)) return true
  return false
}

function buildSummary(counts: {
  totalRecommendations: number
  criticalCount: number
  highCount: number
  patchCount: number
  breakingCount: number
}): string {
  if (counts.totalRecommendations === 0) {
    return 'No dependency updates recommended. All dependencies are up to date.'
  }

  const parts: string[] = [
    `${counts.totalRecommendations} dependency update${counts.totalRecommendations > 1 ? 's' : ''} recommended.`,
  ]

  if (counts.criticalCount > 0) {
    parts.push(`${counts.criticalCount} critical.`)
  }
  if (counts.highCount > 0) {
    parts.push(`${counts.highCount} high-priority.`)
  }
  if (counts.patchCount > 0) {
    parts.push(`${counts.patchCount} are simple patch-level fixes.`)
  }
  if (counts.breakingCount > 0) {
    parts.push(
      `${counts.breakingCount} may involve breaking changes or package replacements.`,
    )
  }

  return parts.join(' ')
}
