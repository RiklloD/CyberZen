import { describe, expect, it } from 'vitest'
import {
  computeTrafficAnomaly,
  detectErrorSpike,
  detectInjectionAttempts,
  detectLatencyOutliers,
  detectPathEnumeration,
  detectRequestFlood,
  detectSuspiciousUserAgent,
  type TrafficEvent,
} from './trafficAnomaly'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const TS = 1_700_000_000_000

function makeEvent(overrides: Partial<TrafficEvent> = {}): TrafficEvent {
  return {
    timestamp: TS,
    method: 'GET',
    path: '/api/health',
    statusCode: 200,
    latencyMs: 50,
    ...overrides,
  }
}

function makeEvents(count: number, overrides: Partial<TrafficEvent> = {}): TrafficEvent[] {
  return Array.from({ length: count }, () => makeEvent(overrides))
}

// ─── detectErrorSpike ─────────────────────────────────────────────────────────

describe('detectErrorSpike', () => {
  it('returns null for empty events', () => {
    expect(detectErrorSpike([])).toBeNull()
  })

  it('returns null when error rate is below threshold', () => {
    const events = [
      ...makeEvents(90, { statusCode: 200 }),
      ...makeEvents(5, { statusCode: 404 }),
    ]
    expect(detectErrorSpike(events)).toBeNull()
  })

  it('detects moderate error spike at 30%+ error rate', () => {
    const events = [
      ...makeEvents(70, { statusCode: 200 }),
      ...makeEvents(30, { statusCode: 500 }),
    ]
    const result = detectErrorSpike(events)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('error_spike')
    expect(result!.confidence).toBeGreaterThanOrEqual(0.6)
  })

  it('assigns high confidence at 50%+ error rate', () => {
    const events = [
      ...makeEvents(50, { statusCode: 200 }),
      ...makeEvents(50, { statusCode: 500 }),
    ]
    const result = detectErrorSpike(events)
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9)
  })

  it('detects spike relative to baseline even at lower absolute rate', () => {
    // 20% error rate when baseline is 2% should trigger
    const events = [
      ...makeEvents(80, { statusCode: 200 }),
      ...makeEvents(20, { statusCode: 404 }),
    ]
    const result = detectErrorSpike(events, { avgErrorRate: 0.02, avgRequestsPerWindow: 100, avgLatencyMs: 50 })
    expect(result).not.toBeNull()
  })

  it('maps to access_control vuln class', () => {
    const events = [
      ...makeEvents(50, { statusCode: 200 }),
      ...makeEvents(50, { statusCode: 403 }),
    ]
    expect(detectErrorSpike(events)!.relatedVulnClass).toBe('access_control')
  })
})

// ─── detectPathEnumeration ────────────────────────────────────────────────────

describe('detectPathEnumeration', () => {
  it('returns null for empty events', () => {
    expect(detectPathEnumeration([])).toBeNull()
  })

  it('returns null when fewer than 20 unique numeric IDs', () => {
    const events = Array.from({ length: 10 }, (_, i) =>
      makeEvent({ path: `/api/users/${i + 1}` }),
    )
    expect(detectPathEnumeration(events)).toBeNull()
  })

  it('detects enumeration with > 20 unique resource IDs', () => {
    const events = Array.from({ length: 50 }, (_, i) =>
      makeEvent({ path: `/api/users/${i + 1}` }),
    )
    const result = detectPathEnumeration(events)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('path_enumeration')
    expect(result!.relatedVulnClass).toBe('insecure_direct_object_reference')
  })

  it('assigns higher confidence for 100+ unique IDs', () => {
    const events = Array.from({ length: 120 }, (_, i) =>
      makeEvent({ path: `/api/orders/${i + 1}` }),
    )
    const result = detectPathEnumeration(events)
    expect(result!.confidence).toBeGreaterThanOrEqual(0.85)
  })

  it('ignores non-numeric path segments', () => {
    const events = makeEvents(50, { path: '/api/users/profile' })
    expect(detectPathEnumeration(events)).toBeNull()
  })
})

// ─── detectSuspiciousUserAgent ────────────────────────────────────────────────

describe('detectSuspiciousUserAgent', () => {
  it('returns null for empty events', () => {
    expect(detectSuspiciousUserAgent([])).toBeNull()
  })

  it('returns null when no attack tool signatures match', () => {
    const events = makeEvents(10, { userAgent: 'Mozilla/5.0 (compatible; Chrome)' })
    expect(detectSuspiciousUserAgent(events)).toBeNull()
  })

  it('detects sqlmap user agent', () => {
    const events = makeEvents(5, { userAgent: 'sqlmap/1.7.9#stable (https://sqlmap.org)' })
    const result = detectSuspiciousUserAgent(events)
    expect(result).not.toBeNull()
    expect(result!.relatedVulnClass).toBe('sql_injection')
    expect(result!.confidence).toBeGreaterThanOrEqual(0.85)
  })

  it('detects nikto user agent', () => {
    const events = makeEvents(3, { userAgent: 'Nikto/2.1.6' })
    expect(detectSuspiciousUserAgent(events)!.type).toBe('suspicious_user_agent')
  })

  it('detects nuclei scanner', () => {
    const events = makeEvents(10, { userAgent: 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)' })
    const result = detectSuspiciousUserAgent(events)
    expect(result!.confidence).toBeGreaterThanOrEqual(0.85)
  })

  it('assigns maximum confidence for 10+ requests from attack tool', () => {
    const events = makeEvents(15, { userAgent: 'sqlmap/1.7.9' })
    expect(detectSuspiciousUserAgent(events)!.confidence).toBeGreaterThanOrEqual(0.95)
  })
})

// ─── detectLatencyOutliers ────────────────────────────────────────────────────

describe('detectLatencyOutliers', () => {
  it('returns null for fewer than 10 events', () => {
    const events = makeEvents(5, { latencyMs: 100 })
    expect(detectLatencyOutliers(events)).toBeNull()
  })

  it('returns null when p95/p50 ratio is normal', () => {
    // All requests ~50ms ± small variance
    const events = Array.from({ length: 20 }, (_, i) =>
      makeEvent({ path: '/api/data', latencyMs: 50 + (i % 3) * 10 }),
    )
    expect(detectLatencyOutliers(events)).toBeNull()
  })

  it('detects latency outlier when p95 >> p50', () => {
    // Most requests fast (20ms), some very slow (5000ms)
    const events = [
      ...Array.from({ length: 18 }, () => makeEvent({ path: '/api/search', latencyMs: 20 })),
      ...Array.from({ length: 2 }, () => makeEvent({ path: '/api/search', latencyMs: 5000 })),
    ]
    const result = detectLatencyOutliers(events)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('latency_outlier')
    expect(result!.relatedVulnClass).toBe('sql_injection')
  })
})

// ─── detectInjectionAttempts ──────────────────────────────────────────────────

describe('detectInjectionAttempts', () => {
  it('returns null for clean traffic', () => {
    const events = makeEvents(10, { path: '/api/users/1' })
    expect(detectInjectionAttempts(events)).toBeNull()
  })

  it('detects SQL UNION SELECT in path', () => {
    const events = [makeEvent({ path: "/api/users?id=1 UNION SELECT * FROM users--" })]
    const result = detectInjectionAttempts(events)
    expect(result).not.toBeNull()
    expect(result!.relatedVulnClass).toBe('sql_injection')
  })

  it('detects path traversal sequences', () => {
    const events = [makeEvent({ path: '/api/files/../../../etc/passwd' })]
    const result = detectInjectionAttempts(events)
    expect(result).not.toBeNull()
    expect(['path_traversal', 'sql_injection']).toContain(result!.relatedVulnClass)
  })

  it('detects XSS payload in path', () => {
    const events = [makeEvent({ path: '/search?q=<script>alert(1)</script>' })]
    const result = detectInjectionAttempts(events)
    expect(result).not.toBeNull()
    expect(result!.relatedVulnClass).toBe('cross_site_scripting')
  })

  it('detects template injection pattern', () => {
    const events = [makeEvent({ path: '/api/render?template={{7*7}}' })]
    const result = detectInjectionAttempts(events)
    expect(result).not.toBeNull()
    expect(result!.relatedVulnClass).toBe('template_injection')
  })

  it('assigns higher confidence for many injection requests', () => {
    const events = Array.from({ length: 15 }, () =>
      makeEvent({ path: "/api/users?id=' OR 1=1 --" }),
    )
    expect(detectInjectionAttempts(events)!.confidence).toBeGreaterThanOrEqual(0.85)
  })
})

// ─── detectRequestFlood ───────────────────────────────────────────────────────

describe('detectRequestFlood', () => {
  it('returns null for empty events', () => {
    expect(detectRequestFlood([])).toBeNull()
  })

  it('returns null when volume is within 5× baseline', () => {
    const events = makeEvents(500) // 500 vs default 200 baseline (2.5×)
    expect(detectRequestFlood(events)).toBeNull()
  })

  it('detects flood when volume exceeds 5× baseline', () => {
    const events = makeEvents(2000) // 10× baseline of 200
    const result = detectRequestFlood(events)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('request_flood')
  })

  it('classifies high-unique-path flood as scanning', () => {
    // Many unique paths = scanning/crawling
    const events = Array.from({ length: 2000 }, (_, i) =>
      makeEvent({ path: `/page/${i}` }),
    )
    const result = detectRequestFlood(events)
    expect(result).not.toBeNull()
    expect(result!.relatedVulnClass).toBe('path_traversal')
  })

  it('assigns higher confidence for 20× volume spike', () => {
    const events = makeEvents(5000) // 25× baseline of 200
    expect(detectRequestFlood(events)!.confidence).toBeGreaterThanOrEqual(0.8)
  })
})

// ─── computeTrafficAnomaly ────────────────────────────────────────────────────

describe('computeTrafficAnomaly', () => {
  it('returns normal level for clean traffic', () => {
    const events = makeEvents(100, { statusCode: 200, latencyMs: 50 })
    const result = computeTrafficAnomaly(events)
    expect(result.level).toBe('normal')
    expect(result.anomalyScore).toBeLessThan(20)
    expect(result.patterns).toHaveLength(0)
    expect(result.findingCandidates).toHaveLength(0)
  })

  it('returns critical level for sqlmap attack with errors', () => {
    // sqlmap generates many 500s alongside injection paths — triggers
    // suspicious_user_agent + injection_attempt + error_spike simultaneously
    const events = makeEvents(20, {
      userAgent: 'sqlmap/1.7.9',
      path: "/api/users?id=1 UNION SELECT username,password FROM users--",
      statusCode: 500,
    })
    const result = computeTrafficAnomaly(events)
    expect(result.level).toBe('critical')
    expect(result.anomalyScore).toBeGreaterThanOrEqual(75)
  })

  it('populates stats correctly', () => {
    const events = [
      ...makeEvents(80, { statusCode: 200, latencyMs: 50 }),
      ...makeEvents(20, { statusCode: 500, latencyMs: 200 }),
    ]
    const result = computeTrafficAnomaly(events)
    expect(result.stats.totalRequests).toBe(100)
    expect(result.stats.errorRate).toBe(0.2)
    expect(result.stats.avgLatencyMs).toBe(80) // (80×50 + 20×200)/100 = 8000/100 = 80
  })

  it('deduplicates vuln classes in findingCandidates', () => {
    // Both injection_attempt and suspicious_user_agent for sql_injection
    const events = makeEvents(10, {
      userAgent: 'sqlmap/1.7.9',
      path: "/api/data?q=' OR 1=1--",
    })
    const result = computeTrafficAnomaly(events)
    const classes = result.findingCandidates.map((c) => c.vulnClass)
    const unique = new Set(classes)
    expect(classes.length).toBe(unique.size)
  })

  it('summary mentions anomaly level for suspicious traffic', () => {
    const events = makeEvents(10, { userAgent: 'sqlmap/1.7.9' })
    const result = computeTrafficAnomaly(events)
    expect(result.summary).toContain(result.level.toUpperCase())
  })

  it('summary says "within normal parameters" for clean traffic', () => {
    const result = computeTrafficAnomaly(makeEvents(50))
    expect(result.summary).toContain('normal parameters')
  })

  it('anomalyScore is capped at 100', () => {
    // Trigger multiple high-confidence patterns simultaneously
    const events = makeEvents(5000, {
      userAgent: 'sqlmap/1.7.9',
      path: "/api/users?id=1 UNION SELECT * FROM users--",
      statusCode: 500,
      latencyMs: 5000,
    })
    const result = computeTrafficAnomaly(events)
    expect(result.anomalyScore).toBeLessThanOrEqual(100)
  })

  it('patterns sorted by confidence descending', () => {
    const events = [
      ...makeEvents(50, { userAgent: 'sqlmap/1.7.9' }),
      ...makeEvents(50, { statusCode: 500 }),
    ]
    const result = computeTrafficAnomaly(events)
    for (let i = 1; i < result.patterns.length; i++) {
      expect(result.patterns[i - 1].confidence).toBeGreaterThanOrEqual(result.patterns[i].confidence)
    }
  })

  it('injection finding candidate severity is critical for sql_injection with high confidence', () => {
    const events = makeEvents(15, { path: "/api/users?id=' UNION SELECT username,password FROM users--", userAgent: 'sqlmap/1.7.9' })
    const result = computeTrafficAnomaly(events)
    const sqliCandidate = result.findingCandidates.find((c) => c.vulnClass === 'sql_injection')
    expect(sqliCandidate?.severity).toBe('critical')
  })
})
