// WS-29 — Production Traffic Anomaly Detection (spec §10 Phase 4):
// "Real-time production traffic analysis — anomaly detection in production
// without code access."
//
// No DB access. All detection is pure so the library is fully unit-testable
// without a Convex environment.
//
// The detector receives a batch of HTTP traffic events (from an access log,
// API gateway, or Kubernetes ingress), runs six detection passes, combines
// their signals into a 0–100 anomaly score, and emits finding candidates that
// can flow into the normal findings pipeline.
//
// Detection passes:
//   1. detectErrorSpike         — sudden rise in 4xx/5xx response rate
//   2. detectPathEnumeration    — high-cardinality numeric-ID path access (IDOR)
//   3. detectSuspiciousUserAgent — known attack-tool fingerprints
//   4. detectLatencyOutliers    — high p95/p50 ratio on specific paths (blind SQLi)
//   5. detectInjectionAttempts  — SQL/XSS/template injection patterns in paths
//   6. detectRequestFlood       — volume spike that dwarfs the baseline
//
// Scoring model:
//   anomalyScore = min(100, Σ(pattern.confidence × PATTERN_WEIGHT[pattern.type]))
//
// Level thresholds:
//   normal    < 20  — within expected parameters
//   suspicious  20–49 — warrants investigation
//   anomalous   50–74 — active threat likely
//   critical    ≥ 75  — immediate action recommended

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type TrafficEvent = {
  /** Unix ms timestamp of the request. */
  timestamp: number
  /** HTTP method: GET, POST, PUT, DELETE, … */
  method: string
  /** URL path WITHOUT query string, e.g. "/api/users/42". */
  path: string
  /** HTTP response status code. */
  statusCode: number
  /** Server-measured response time in milliseconds. */
  latencyMs: number
  /** Optional User-Agent header value. */
  userAgent?: string
  /** Optional request body size in bytes. */
  requestSizeBytes?: number
}

/** Optional baseline computed from prior windows for rate comparison. */
export type TrafficBaseline = {
  avgRequestsPerWindow: number
  avgErrorRate: number        // fraction 0–1
  avgLatencyMs: number
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

export type AnomalyPatternType =
  | 'error_spike'
  | 'path_enumeration'
  | 'suspicious_user_agent'
  | 'latency_outlier'
  | 'injection_attempt'
  | 'request_flood'

export type TrafficAnomalyPattern = {
  type: AnomalyPatternType
  /** 0–1 confidence that this is a true positive. */
  confidence: number
  /** Human-readable description of what triggered this pattern. */
  details: string
  /** Vulnerability class this maps to. */
  relatedVulnClass: string
  /** Paths implicated in this detection. */
  affectedPaths: string[]
}

export type TrafficFindingCandidate = {
  vulnClass: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  description: string
}

export type TrafficAnomalyResult = {
  /** 0–100 composite anomaly score. Higher = more suspicious. */
  anomalyScore: number
  level: 'normal' | 'suspicious' | 'anomalous' | 'critical'
  /** Detected patterns sorted by confidence descending. */
  patterns: TrafficAnomalyPattern[]
  findingCandidates: TrafficFindingCandidate[]
  /** Window stats for dashboard display. */
  stats: {
    totalRequests: number
    errorRate: number
    avgLatencyMs: number
    uniquePaths: number
  }
  summary: string
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Score contribution weight per pattern type. */
const PATTERN_WEIGHT: Record<AnomalyPatternType, number> = {
  injection_attempt: 40,
  suspicious_user_agent: 35,
  error_spike: 25,
  path_enumeration: 20,
  latency_outlier: 20,
  request_flood: 15,
}

/** Regex: numeric segment at end of a path component — likely resource ID. */
const NUMERIC_ID_RE = /\/\d{1,12}(?:\/|$)/

/** Known attack-tool User-Agent substrings (lower-case). */
const ATTACK_TOOL_SIGS: { sig: string; tool: string; vulnClass: string }[] = [
  { sig: 'sqlmap', tool: 'sqlmap', vulnClass: 'sql_injection' },
  { sig: 'nikto', tool: 'Nikto', vulnClass: 'web_scanning' },
  { sig: 'nmap scripting', tool: 'Nmap NSE', vulnClass: 'web_scanning' },
  { sig: 'masscan', tool: 'masscan', vulnClass: 'web_scanning' },
  { sig: 'nuclei', tool: 'Nuclei', vulnClass: 'web_scanning' },
  { sig: 'burpsuite', tool: 'Burp Suite', vulnClass: 'web_scanning' },
  { sig: 'dirbuster', tool: 'DirBuster', vulnClass: 'path_traversal' },
  { sig: 'gobuster', tool: 'Gobuster', vulnClass: 'path_traversal' },
  { sig: 'ffuf', tool: 'ffuf', vulnClass: 'path_traversal' },
  { sig: 'wfuzz', tool: 'wfuzz', vulnClass: 'path_traversal' },
  { sig: 'hydra', tool: 'Hydra', vulnClass: 'authentication_bypass' },
  { sig: 'zgrab', tool: 'ZGrab', vulnClass: 'web_scanning' },
  { sig: 'python-requests/2.', tool: 'python-requests', vulnClass: 'web_scanning' },
  { sig: 'go-http-client/1.', tool: 'Go HTTP', vulnClass: 'web_scanning' },
]

/** Injection pattern signatures in URL paths. */
const INJECTION_PATTERNS: { pattern: RegExp; vulnClass: string; label: string }[] = [
  { pattern: /['"][\s]*(?:or|and|union|select|insert|drop|delete|update)[\s'"]/i, vulnClass: 'sql_injection', label: 'SQL keyword injection' },
  { pattern: /union[\s]+(?:all[\s]+)?select/i, vulnClass: 'sql_injection', label: 'UNION SELECT' },
  { pattern: /(?:--|#|\/\*)\s*$/,              vulnClass: 'sql_injection', label: 'SQL comment terminator' },
  { pattern: /\.\.\/|\.\.%2f|%2e%2e\//i,      vulnClass: 'path_traversal', label: 'path traversal' },
  { pattern: /%00|\\x00/i,                     vulnClass: 'path_traversal', label: 'null byte injection' },
  { pattern: /<script|javascript:|onerror=/i,  vulnClass: 'cross_site_scripting', label: 'XSS payload' },
  { pattern: /\{\{.*\}\}|\$\{.*\}|#\{.*\}/,   vulnClass: 'template_injection', label: 'template injection' },
  { pattern: /(?:\/etc\/passwd|\/etc\/shadow|\/proc\/self)/i, vulnClass: 'path_traversal', label: 'LFI target path' },
  { pattern: /(?:cmd|exec|system|passthru|eval)\s*\(/i, vulnClass: 'command_injection', label: 'command injection keyword' },
]

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0
  const idx = Math.ceil((p / 100) * sorted.length) - 1
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))]
}

function classifyLevel(score: number): TrafficAnomalyResult['level'] {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'anomalous'
  if (score >= 20) return 'suspicious'
  return 'normal'
}

function candidateSeverity(
  vulnClass: string,
  confidence: number,
): TrafficFindingCandidate['severity'] {
  if (vulnClass === 'sql_injection' || vulnClass === 'command_injection') {
    return confidence >= 0.6 ? 'critical' : 'high'
  }
  if (vulnClass === 'authentication_bypass' || vulnClass === 'cross_site_scripting') {
    return 'high'
  }
  if (confidence >= 0.7) return 'high'
  return 'medium'
}

// ---------------------------------------------------------------------------
// Detection pass 1: Error spike
// ---------------------------------------------------------------------------

export function detectErrorSpike(
  events: TrafficEvent[],
  baseline?: TrafficBaseline,
): TrafficAnomalyPattern | null {
  if (events.length === 0) return null

  const errors = events.filter((e) => e.statusCode >= 400)
  const errorRate = errors.length / events.length

  // Determine confidence
  let confidence = 0
  let details = ''

  const baselineRate = baseline?.avgErrorRate ?? 0.05 // default 5% baseline

  if (errorRate >= 0.5) {
    confidence = 0.9
    details = `${(errorRate * 100).toFixed(0)}% error rate (${errors.length}/${events.length} requests)`
  } else if (errorRate >= 0.3 || errorRate >= baselineRate * 4) {
    confidence = 0.6
    details = `Elevated error rate ${(errorRate * 100).toFixed(0)}% (baseline ~${(baselineRate * 100).toFixed(0)}%)`
  } else {
    return null
  }

  // Top affected paths
  const pathCounts = new Map<string, number>()
  for (const e of errors) {
    pathCounts.set(e.path, (pathCounts.get(e.path) ?? 0) + 1)
  }
  const topPaths = [...pathCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([p]) => p)

  return {
    type: 'error_spike',
    confidence,
    details,
    relatedVulnClass: 'access_control',
    affectedPaths: topPaths,
  }
}

// ---------------------------------------------------------------------------
// Detection pass 2: Path enumeration (IDOR)
// ---------------------------------------------------------------------------

export function detectPathEnumeration(events: TrafficEvent[]): TrafficAnomalyPattern | null {
  if (events.length === 0) return null

  // Collapse numeric IDs to a template: /api/users/42 → /api/users/{id}
  const templateCounts = new Map<string, Set<string>>()
  for (const e of events) {
    if (!NUMERIC_ID_RE.test(e.path)) continue
    const template = e.path.replace(/\/\d{1,12}(?=\/|$)/g, '/{id}')
    const ids = templateCounts.get(template) ?? new Set()
    ids.add(e.path)
    templateCounts.set(template, ids)
  }

  // Find templates with > 20 unique IDs
  const suspicious = [...templateCounts.entries()].filter(([, ids]) => ids.size > 20)
  if (suspicious.length === 0) return null

  const top = suspicious.sort((a, b) => b[1].size - a[1].size)[0]
  const uniqueIds = top[1].size
  const confidence = uniqueIds >= 100 ? 0.85 : uniqueIds >= 50 ? 0.7 : 0.5

  return {
    type: 'path_enumeration',
    confidence,
    details: `${uniqueIds} unique resource IDs accessed on pattern "${top[0]}"`,
    relatedVulnClass: 'insecure_direct_object_reference',
    affectedPaths: [top[0]],
  }
}

// ---------------------------------------------------------------------------
// Detection pass 3: Suspicious user agents
// ---------------------------------------------------------------------------

export function detectSuspiciousUserAgent(
  events: TrafficEvent[],
): TrafficAnomalyPattern | null {
  const hits: { tool: string; vulnClass: string; count: number }[] = []

  const toolCounts = new Map<string, { vulnClass: string; count: number }>()
  for (const e of events) {
    if (!e.userAgent) continue
    const ua = e.userAgent.toLowerCase()
    for (const sig of ATTACK_TOOL_SIGS) {
      if (ua.includes(sig.sig)) {
        const prev = toolCounts.get(sig.tool) ?? { vulnClass: sig.vulnClass, count: 0 }
        toolCounts.set(sig.tool, { vulnClass: sig.vulnClass, count: prev.count + 1 })
        break // one match per event
      }
    }
  }

  if (toolCounts.size === 0) return null

  for (const [tool, { vulnClass, count }] of toolCounts) {
    hits.push({ tool, vulnClass, count })
  }
  hits.sort((a, b) => b.count - a.count)

  const primaryVulnClass = hits[0].vulnClass
  const confidence = hits[0].count >= 10 ? 0.95 : hits[0].count >= 3 ? 0.85 : 0.7
  const toolList = hits.map((h) => `${h.tool} (${h.count} req)`).join(', ')

  return {
    type: 'suspicious_user_agent',
    confidence,
    details: `Attack tool signature detected: ${toolList}`,
    relatedVulnClass: primaryVulnClass,
    affectedPaths: [],
  }
}

// ---------------------------------------------------------------------------
// Detection pass 4: Latency outliers (possible blind injection)
// ---------------------------------------------------------------------------

export function detectLatencyOutliers(events: TrafficEvent[]): TrafficAnomalyPattern | null {
  if (events.length < 10) return null

  // Group by path, compute per-path p95/p50 ratio
  const byPath = new Map<string, number[]>()
  for (const e of events) {
    const list = byPath.get(e.path) ?? []
    list.push(e.latencyMs)
    byPath.set(e.path, list)
  }

  const outlierPaths: string[] = []
  let maxRatio = 0

  for (const [path, latencies] of byPath) {
    if (latencies.length < 3) continue
    const sorted = [...latencies].sort((a, b) => a - b)
    const p50 = percentile(sorted, 50)
    const p95 = percentile(sorted, 95)
    if (p50 === 0) continue
    const ratio = p95 / p50
    if (ratio >= 10) {
      outlierPaths.push(path)
      maxRatio = Math.max(maxRatio, ratio)
    }
  }

  if (outlierPaths.length === 0) return null

  const confidence = maxRatio >= 50 ? 0.7 : 0.5

  return {
    type: 'latency_outlier',
    confidence,
    details: `p95/p50 latency ratio ≥${maxRatio.toFixed(0)}× on ${outlierPaths.length} path(s) — possible blind injection`,
    relatedVulnClass: 'sql_injection',
    affectedPaths: outlierPaths.slice(0, 5),
  }
}

// ---------------------------------------------------------------------------
// Detection pass 5: Injection attempts in paths
// ---------------------------------------------------------------------------

export function detectInjectionAttempts(events: TrafficEvent[]): TrafficAnomalyPattern | null {
  interface Hit {
    vulnClass: string
    label: string
    paths: Set<string>
    /** Total number of requests that matched (may repeat the same path). */
    count: number
  }
  const hits = new Map<string, Hit>()

  for (const e of events) {
    const target = decodeURIComponent(e.path).toLowerCase()
    for (const { pattern, vulnClass, label } of INJECTION_PATTERNS) {
      if (pattern.test(target)) {
        const prev = hits.get(vulnClass) ?? {
          vulnClass,
          label,
          paths: new Set<string>(),
          count: 0,
        }
        prev.paths.add(e.path)
        prev.count++
        hits.set(vulnClass, prev)
        break
      }
    }
  }

  if (hits.size === 0) return null

  // Find the highest-severity hit by priority
  const priority = [
    'command_injection',
    'sql_injection',
    'path_traversal',
    'template_injection',
    'cross_site_scripting',
  ]
  let primary: Hit | null = null
  for (const cls of priority) {
    if (hits.has(cls)) {
      primary = hits.get(cls)!
      break
    }
  }
  if (!primary) primary = [...hits.values()][0]

  // Confidence scales with total request count across all detected classes
  const totalRequests = [...hits.values()].reduce((s, h) => s + h.count, 0)
  const confidence = totalRequests >= 10 ? 0.85 : totalRequests >= 3 ? 0.7 : 0.55

  const vulnClasses = [...hits.keys()].join(', ')

  return {
    type: 'injection_attempt',
    confidence,
    details: `Injection patterns detected across ${hits.size} class(es): ${vulnClasses} — ${totalRequests} request(s) affected`,
    relatedVulnClass: primary.vulnClass,
    affectedPaths: [...primary.paths].slice(0, 5),
  }
}

// ---------------------------------------------------------------------------
// Detection pass 6: Request flood
// ---------------------------------------------------------------------------

export function detectRequestFlood(
  events: TrafficEvent[],
  baseline?: TrafficBaseline,
): TrafficAnomalyPattern | null {
  if (events.length === 0) return null

  const baselineAvg = baseline?.avgRequestsPerWindow ?? 200
  const ratio = events.length / baselineAvg

  if (ratio < 5) return null

  const confidence = ratio >= 20 ? 0.8 : ratio >= 10 ? 0.65 : 0.5
  const uniquePaths = new Set(events.map((e) => e.path)).size
  const detail = uniquePaths > events.length * 0.8
    ? `${events.length} requests with ${uniquePaths} unique paths — scanning/crawling pattern`
    : `${events.length} requests (${ratio.toFixed(0)}× normal volume) — possible flood/DDoS`

  return {
    type: 'request_flood',
    confidence,
    details: detail,
    relatedVulnClass: uniquePaths > events.length * 0.8 ? 'path_traversal' : 'denial_of_service',
    affectedPaths: [],
  }
}

// ---------------------------------------------------------------------------
// computeTrafficAnomaly — main entry point
// ---------------------------------------------------------------------------

/**
 * Run all six detection passes over a batch of traffic events and return a
 * combined anomaly assessment.
 *
 * @param events   Batch of HTTP traffic events from an access log or gateway.
 * @param baseline Optional baseline for rate comparison.  Pass null / omit
 *                 for first-run detection (conservative thresholds apply).
 */
export function computeTrafficAnomaly(
  events: TrafficEvent[],
  baseline?: TrafficBaseline,
): TrafficAnomalyResult {
  // ── Window stats ──────────────────────────────────────────────────────────
  const totalRequests = events.length
  const errorCount = events.filter((e) => e.statusCode >= 400).length
  const errorRate = totalRequests > 0 ? errorCount / totalRequests : 0
  const avgLatencyMs =
    totalRequests > 0 ? events.reduce((s, e) => s + e.latencyMs, 0) / totalRequests : 0
  const uniquePaths = new Set(events.map((e) => e.path)).size

  // ── Run detection passes ──────────────────────────────────────────────────
  const rawPatterns = [
    detectErrorSpike(events, baseline),
    detectPathEnumeration(events),
    detectSuspiciousUserAgent(events),
    detectLatencyOutliers(events),
    detectInjectionAttempts(events),
    detectRequestFlood(events, baseline),
  ].filter((p): p is TrafficAnomalyPattern => p !== null)

  // Sort by confidence descending
  const patterns = rawPatterns.sort((a, b) => b.confidence - a.confidence)

  // ── Compute score ─────────────────────────────────────────────────────────
  const anomalyScore = Math.min(
    100,
    patterns.reduce((acc, p) => acc + p.confidence * PATTERN_WEIGHT[p.type], 0),
  )

  const level = classifyLevel(anomalyScore)

  // ── Build finding candidates ──────────────────────────────────────────────
  const seen = new Set<string>()
  const findingCandidates: TrafficFindingCandidate[] = []
  for (const pattern of patterns) {
    if (seen.has(pattern.relatedVulnClass)) continue
    seen.add(pattern.relatedVulnClass)
    findingCandidates.push({
      vulnClass: pattern.relatedVulnClass,
      severity: candidateSeverity(pattern.relatedVulnClass, pattern.confidence),
      confidence: pattern.confidence,
      description: `${pattern.relatedVulnClass.replace(/_/g, ' ')} activity detected via traffic analysis: ${pattern.details}`,
    })
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  let summary = `${totalRequests} requests analysed.`
  if (patterns.length === 0) {
    summary += ' Traffic within normal parameters.'
  } else {
    const topPattern = patterns[0]
    summary += ` ${level.toUpperCase()}: ${topPattern.details}`
    if (patterns.length > 1) {
      summary += ` (+${patterns.length - 1} additional signal${patterns.length === 2 ? '' : 's'}).`
    }
  }

  return {
    anomalyScore: Math.round(anomalyScore),
    level,
    patterns,
    findingCandidates,
    stats: {
      totalRequests,
      errorRate,
      avgLatencyMs: Math.round(avgLatencyMs),
      uniquePaths,
    },
    summary,
  }
}
