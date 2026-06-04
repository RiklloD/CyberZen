/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { computeHoneypotPlan } from './honeypotInjector'
import type { HoneypotInput, HoneypotKind } from './honeypotInjector'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const EMPTY: HoneypotInput = {
  reachableServices: [],
  exposedDataLayers: [],
  attackPathDepth: 0,
  openCriticalCount: 0,
}

function proposalsOfKind(result: ReturnType<typeof computeHoneypotPlan>, kind: HoneypotKind) {
  return result.proposals.filter((p) => p.kind === kind)
}

// ─── Basic structure ──────────────────────────────────────────────────────────

describe('computeHoneypotPlan — basic structure', () => {
  it('always generates endpoint proposals even with no services', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.endpointCount).toBe(4)
  })

  it('always generates exactly 3 file proposals', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.fileCount).toBe(3)
  })

  it('generates no database field proposals when no data layers exist', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.databaseFieldCount).toBe(0)
  })

  it('generates no token proposals when attackPathDepth < 2', () => {
    const result = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 1 })
    expect(result.tokenCount).toBe(0)
  })

  it('totalProposals matches the sum of kind counts', () => {
    const result = computeHoneypotPlan(EMPTY)
    const sum =
      result.endpointCount +
      result.fileCount +
      result.databaseFieldCount +
      result.tokenCount
    expect(result.totalProposals).toBe(sum)
    expect(result.totalProposals).toBe(result.proposals.length)
  })
})

// ─── Data layer gating ────────────────────────────────────────────────────────

describe('computeHoneypotPlan — database field proposals', () => {
  it('generates 2 DB field proposals when data layers are present', () => {
    const result = computeHoneypotPlan({ ...EMPTY, exposedDataLayers: ['users', 'payments'] })
    expect(result.databaseFieldCount).toBe(2)
  })

  it('generates DB field proposals with a single data layer', () => {
    const result = computeHoneypotPlan({ ...EMPTY, exposedDataLayers: ['secrets'] })
    expect(result.databaseFieldCount).toBe(2)
  })

  it('sets targetContext for DB field proposals to the matched data layer', () => {
    const result = computeHoneypotPlan({ ...EMPTY, exposedDataLayers: ['payment', 'api'] })
    const dbProps = proposalsOfKind(result, 'database_field')
    for (const p of dbProps) {
      expect(p.targetContext).toBeDefined()
    }
  })

  it('rationale references the data layer name', () => {
    const result = computeHoneypotPlan({ ...EMPTY, exposedDataLayers: ['users'] })
    const dbProp = proposalsOfKind(result, 'database_field')[0]
    expect(dbProp.rationale).toContain('users')
  })
})

// ─── Token gating by depth ────────────────────────────────────────────────────

describe('computeHoneypotPlan — token proposals', () => {
  it('generates 2 token proposals when attackPathDepth >= 2', () => {
    const result = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 2 })
    expect(result.tokenCount).toBe(2)
  })

  it('generates 2 token proposals when attackPathDepth is 5', () => {
    const result = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 5 })
    expect(result.tokenCount).toBe(2)
  })

  it('token proposals are absent at depth 0', () => {
    expect(computeHoneypotPlan({ ...EMPTY, attackPathDepth: 0 }).tokenCount).toBe(0)
  })

  it('token proposals are absent at depth 1', () => {
    expect(computeHoneypotPlan({ ...EMPTY, attackPathDepth: 1 }).tokenCount).toBe(0)
  })
})

// ─── Depth bonus scoring ──────────────────────────────────────────────────────

describe('computeHoneypotPlan — depth bonus', () => {
  it('higher depth increases attractiveness scores', () => {
    const shallow = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 0 })
    const deep = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 3 })
    expect(deep.topAttractiveness).toBeGreaterThanOrEqual(shallow.topAttractiveness)
  })

  it('depth bonus caps at 15 points (depth 3+ gives same bonus as depth 10)', () => {
    const depth3 = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 3 })
    const depth10 = computeHoneypotPlan({ ...EMPTY, attackPathDepth: 10 })
    expect(depth10.topAttractiveness).toBe(depth3.topAttractiveness)
  })

  it('scores are capped at 100 even for max depth + high-affinity templates', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth', 'admin'],
      exposedDataLayers: ['users', 'payments', 'secrets'],
      attackPathDepth: 10,
      openCriticalCount: 5,
    })
    for (const p of result.proposals) {
      expect(p.attractivenessScore).toBeLessThanOrEqual(100)
      expect(p.attractivenessScore).toBeGreaterThanOrEqual(0)
    }
  })
})

// ─── Affinity scoring (service matching) ─────────────────────────────────────

describe('computeHoneypotPlan — service affinity', () => {
  it('auth service raises score of auth-related endpoint templates', () => {
    const withAuth = computeHoneypotPlan({ ...EMPTY, reachableServices: ['auth-service'] })
    const withoutAuth = computeHoneypotPlan(EMPTY)
    // The /api/v1/auth/bypass template has the highest affinity for "auth"
    const authBypassWith = withAuth.proposals.find((p) => p.path.includes('auth/bypass'))
    const authBypassWithout = withoutAuth.proposals.find((p) => p.path.includes('auth/bypass'))
    if (authBypassWith && authBypassWithout) {
      expect(authBypassWith.attractivenessScore).toBeGreaterThan(authBypassWithout.attractivenessScore)
    }
  })

  it('payment service raises score of billing-related endpoints', () => {
    const withPayment = computeHoneypotPlan({ ...EMPTY, reachableServices: ['payment-processor'] })
    const billingProp = withPayment.proposals.find((p) => p.path.includes('payment-methods'))
    expect(billingProp).toBeDefined()
    expect(billingProp!.targetContext).toContain('payment')
  })

  it('endpoint targetContext references the matched service name', () => {
    const result = computeHoneypotPlan({ ...EMPTY, reachableServices: ['admin-panel', 'billing-api'] })
    const withCtx = result.proposals.filter(
      (p) => p.kind === 'endpoint' && p.targetContext !== undefined,
    )
    expect(withCtx.length).toBeGreaterThan(0)
    for (const p of withCtx) {
      expect(p.rationale).toContain(p.targetContext!)
    }
  })
})

// ─── Ordering ─────────────────────────────────────────────────────────────────

describe('computeHoneypotPlan — proposal ordering', () => {
  it('proposals are sorted by attractivenessScore descending', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth', 'admin', 'billing'],
      exposedDataLayers: ['users', 'payments'],
      attackPathDepth: 2,
      openCriticalCount: 3,
    })
    for (let i = 1; i < result.proposals.length; i++) {
      expect(result.proposals[i - 1].attractivenessScore).toBeGreaterThanOrEqual(
        result.proposals[i].attractivenessScore,
      )
    }
  })

  it('topAttractiveness equals the first proposal score', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth'],
      exposedDataLayers: ['users'],
      attackPathDepth: 2,
      openCriticalCount: 1,
    })
    expect(result.topAttractiveness).toBe(result.proposals[0].attractivenessScore)
  })
})

// ─── Summary string ───────────────────────────────────────────────────────────

describe('computeHoneypotPlan — summary', () => {
  it('summary mentions total proposal count', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.summary).toContain(String(result.totalProposals))
  })

  it('summary mentions peak attractiveness score', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.summary).toContain(String(result.topAttractiveness))
  })

  it('summary mentions all four honeypot kinds', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth'],
      exposedDataLayers: ['users'],
      attackPathDepth: 2,
      openCriticalCount: 0,
    })
    expect(result.summary).toContain('endpoint')
    expect(result.summary).toContain('file')
    expect(result.summary).toContain('DB field')
    expect(result.summary).toContain('token')
  })
})

// ─── Full plan counts ─────────────────────────────────────────────────────────

describe('computeHoneypotPlan — full plan', () => {
  it('full plan (all signals present) produces 4+2+3+2=11 proposals', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth', 'admin', 'payments'],
      exposedDataLayers: ['users', 'secrets'],
      attackPathDepth: 3,
      openCriticalCount: 2,
    })
    expect(result.totalProposals).toBe(11)
    expect(result.endpointCount).toBe(4)
    expect(result.fileCount).toBe(3)
    expect(result.databaseFieldCount).toBe(2)
    expect(result.tokenCount).toBe(2)
  })

  it('minimal plan (no services, no layers, depth 0) produces 4+3=7 proposals', () => {
    const result = computeHoneypotPlan(EMPTY)
    expect(result.totalProposals).toBe(7)
    expect(result.endpointCount).toBe(4)
    expect(result.fileCount).toBe(3)
    expect(result.databaseFieldCount).toBe(0)
    expect(result.tokenCount).toBe(0)
  })
})

// ─── Proposal field invariants ────────────────────────────────────────────────

describe('computeHoneypotPlan — proposal field invariants', () => {
  it('every proposal has a non-empty path', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth'],
      exposedDataLayers: ['users'],
      attackPathDepth: 3,
      openCriticalCount: 1,
    })
    for (const p of result.proposals) {
      expect(p.path.length).toBeGreaterThan(0)
    }
  })

  it('every proposal has a non-empty rationale', () => {
    const result = computeHoneypotPlan({
      reachableServices: ['auth'],
      exposedDataLayers: ['users'],
      attackPathDepth: 3,
      openCriticalCount: 1,
    })
    for (const p of result.proposals) {
      expect(p.rationale.length).toBeGreaterThan(0)
    }
  })

  it('file proposals have undefined targetContext', () => {
    const result = computeHoneypotPlan(EMPTY)
    const files = proposalsOfKind(result, 'file')
    for (const f of files) {
      expect(f.targetContext).toBeUndefined()
    }
  })

  it('all proposal kinds are one of the four valid values', () => {
    const validKinds = new Set<HoneypotKind>(['endpoint', 'database_field', 'file', 'token'])
    const result = computeHoneypotPlan({
      reachableServices: ['auth'],
      exposedDataLayers: ['users'],
      attackPathDepth: 2,
      openCriticalCount: 0,
    })
    for (const p of result.proposals) {
      expect(validKinds.has(p.kind)).toBe(true)
    }
  })
})
