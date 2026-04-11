// WS-14 Phase 2 — Memory and Learning Loop (spec 3.13): pure aggregation library.
//
// No DB access. Aggregates a flat list of finding records into a
// RepositoryMemoryRecord that the Red/Blue simulator and dashboard can consume.
//
// Design: keep this function deterministic given the same input set so that
// refreshes are always idempotent and tests are fully reproducible.

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type FindingMemoryInput = {
  vulnClass: string
  severity: string
  source: string
  /** 'open' | 'pr_opened' | 'merged' | 'resolved' | 'accepted_risk' */
  status: string
  /** 'pending' | 'validated' | 'likely_exploitable' | 'unexploitable' | 'dismissed' */
  validationStatus: string
  affectedPackages: string[]
  confidence: number
  businessImpactScore: number
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type VulnClassSummary = {
  vulnClass: string
  count: number
  /** Mean severity weight (critical=1.0, high=0.75, medium=0.5, low=0.25, info=0) */
  avgSeverityWeight: number
}

export type RepositoryMemoryRecord = {
  /** Vulnerability classes ranked by recurrence, highest first. */
  recurringVulnClasses: VulnClassSummary[]
  /** Fraction of findings classified as unexploitable (0–1). */
  falsePositiveRate: number
  /** Vuln classes where mean confidence > 0.8 across all findings. */
  highConfidenceClasses: string[]
  /**
   * Package name (lowercased) → mean businessImpactScore across all findings
   * that reference it. Only ASCII-safe keys are stored (Convex record constraint).
   */
  packageRiskMap: Record<string, number>
  /** Most frequently occurring severity across all findings. */
  dominantSeverity: 'critical' | 'high' | 'medium' | 'low'
  totalFindingsAnalyzed: number
  resolvedCount: number
  openCount: number
  summary: string
}

// ---------------------------------------------------------------------------
// Zero-value export (consumed by redBlueIntel and attackSurfaceIntel)
// ---------------------------------------------------------------------------

export const EMPTY_MEMORY_RECORD: RepositoryMemoryRecord = {
  recurringVulnClasses: [],
  falsePositiveRate: 0,
  highConfidenceClasses: [],
  packageRiskMap: {},
  dominantSeverity: 'low',
  totalFindingsAnalyzed: 0,
  resolvedCount: 0,
  openCount: 0,
  summary: 'No findings recorded yet.',
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
  informational: 0,
}

function severityWeight(severity: string): number {
  return SEVERITY_WEIGHT[severity] ?? 0.25
}

const VALID_DOMINANT_SEVERITIES = new Set(['critical', 'high', 'medium', 'low'])

/**
 * Normalize a package name into an ASCII-safe Convex record key.
 * Strips leading '@', replaces '/', spaces, and '.' with '_',
 * then filters non-ASCII characters.
 */
function normalizePackageKey(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/^@/, '')          // drop leading @ from scoped npm packages
    .replace(/[/\s.]/g, '_')    // replace path separators and whitespace with _
    .replace(/[^a-z0-9_-]/g, '') // drop anything still non-ASCII-safe
}

// ---------------------------------------------------------------------------
// Core aggregation
// ---------------------------------------------------------------------------

/**
 * Aggregate a list of findings into a RepositoryMemoryRecord.
 * Pure function — no async, no DB calls, O(n) where n = findings.length.
 */
export function aggregateFindingMemory(input: {
  findings: FindingMemoryInput[]
}): RepositoryMemoryRecord {
  const { findings } = input
  const totalFindingsAnalyzed = findings.length

  if (totalFindingsAnalyzed === 0) {
    return {
      recurringVulnClasses: [],
      falsePositiveRate: 0,
      highConfidenceClasses: [],
      packageRiskMap: {},
      dominantSeverity: 'low',
      totalFindingsAnalyzed: 0,
      resolvedCount: 0,
      openCount: 0,
      summary: 'No findings recorded yet.',
    }
  }

  // ── Recurring vuln classes ────────────────────────────────────────────────
  const vulnClassMap = new Map<string, { count: number; totalWeight: number }>()
  for (const f of findings) {
    const entry = vulnClassMap.get(f.vulnClass) ?? { count: 0, totalWeight: 0 }
    entry.count++
    entry.totalWeight += severityWeight(f.severity)
    vulnClassMap.set(f.vulnClass, entry)
  }
  const recurringVulnClasses: VulnClassSummary[] = [...vulnClassMap.entries()]
    .map(([vulnClass, { count, totalWeight }]) => ({
      vulnClass,
      count,
      avgSeverityWeight: totalWeight / count,
    }))
    .sort((a, b) => b.count - a.count)

  // ── False positive rate ───────────────────────────────────────────────────
  const unexploitableCount = findings.filter(
    (f) => f.validationStatus === 'unexploitable',
  ).length
  const falsePositiveRate = unexploitableCount / totalFindingsAnalyzed

  // ── High-confidence classes ───────────────────────────────────────────────
  const classConfidenceMap = new Map<string, { total: number; count: number }>()
  for (const f of findings) {
    const entry = classConfidenceMap.get(f.vulnClass) ?? { total: 0, count: 0 }
    entry.total += f.confidence
    entry.count++
    classConfidenceMap.set(f.vulnClass, entry)
  }
  const highConfidenceClasses = [...classConfidenceMap.entries()]
    .filter(([, { total, count }]) => total / count > 0.8)
    .map(([vulnClass]) => vulnClass)

  // ── Package risk map ──────────────────────────────────────────────────────
  const packageScoreMap = new Map<string, { total: number; count: number }>()
  for (const f of findings) {
    for (const pkg of f.affectedPackages) {
      const key = normalizePackageKey(pkg)
      if (!key || key.startsWith('_') || key.startsWith('$')) continue
      const entry = packageScoreMap.get(key) ?? { total: 0, count: 0 }
      entry.total += f.businessImpactScore
      entry.count++
      packageScoreMap.set(key, entry)
    }
  }
  const packageRiskMap: Record<string, number> = {}
  for (const [pkg, { total, count }] of packageScoreMap.entries()) {
    packageRiskMap[pkg] = Math.round(total / count)
  }

  // ── Dominant severity ─────────────────────────────────────────────────────
  const severityCount = new Map<string, number>()
  for (const f of findings) {
    severityCount.set(f.severity, (severityCount.get(f.severity) ?? 0) + 1)
  }
  const rawDominant =
    [...severityCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'low'
  const dominantSeverity = (
    VALID_DOMINANT_SEVERITIES.has(rawDominant) ? rawDominant : 'low'
  ) as 'critical' | 'high' | 'medium' | 'low'

  // ── Status counts ─────────────────────────────────────────────────────────
  const resolvedCount = findings.filter(
    (f) => f.status === 'resolved' || f.status === 'merged',
  ).length
  const openCount = findings.filter(
    (f) => f.status === 'open' || f.status === 'pr_opened',
  ).length

  // ── Summary ───────────────────────────────────────────────────────────────
  const topClass = recurringVulnClasses[0]
  const summary = topClass
    ? `${totalFindingsAnalyzed} findings analyzed; ${topClass.vulnClass.replaceAll('_', ' ')} is the most recurring class (${topClass.count} occurrence${topClass.count === 1 ? '' : 's'}). False positive rate: ${(falsePositiveRate * 100).toFixed(0)}%.`
    : `${totalFindingsAnalyzed} finding${totalFindingsAnalyzed === 1 ? '' : 's'} analyzed with no dominant vulnerability class identified.`

  return {
    recurringVulnClasses,
    falsePositiveRate,
    highConfidenceClasses,
    packageRiskMap,
    dominantSeverity,
    totalFindingsAnalyzed,
    resolvedCount,
    openCount,
    summary,
  }
}
