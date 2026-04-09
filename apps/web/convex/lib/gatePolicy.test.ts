/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import {
  assessGateFinding,
  computeWorkflowGatePosture,
  DEFAULT_GATE_POLICY,
  type GatePolicyFinding,
} from './gatePolicy'

const baseArgs = {
  policy: DEFAULT_GATE_POLICY,
  repositoryName: 'payments-api',
  branch: 'main',
}

function makeFinding(overrides: Partial<GatePolicyFinding> = {}): GatePolicyFinding {
  return {
    id: 'finding-1',
    title: 'JWT auth bypass',
    severity: 'high',
    validationStatus: 'validated',
    status: 'open',
    source: 'semantic_fingerprint',
    confidence: 0.92,
    ...overrides,
  }
}

describe('assessGateFinding', () => {
  test('blocks a validated critical finding and requires explicit approval', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'critical', validationStatus: 'validated' }),
    })
    expect(result.decision).toBe('blocked')
    expect(result.blockingReason).toContain('severity=critical')
    expect(result.recommendedAction).toContain('explicit named approval')
  })

  test('blocks a validated high finding without explicit-approval requirement', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'high', validationStatus: 'validated' }),
    })
    expect(result.decision).toBe('blocked')
    expect(result.recommendedAction).not.toContain('explicit named approval')
  })

  test('blocks a likely_exploitable high finding', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'high', validationStatus: 'likely_exploitable' }),
    })
    expect(result.decision).toBe('blocked')
  })

  test('approves a pending medium finding (validation threshold not met)', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'medium', validationStatus: 'pending' }),
    })
    expect(result.decision).toBe('approved')
  })

  test('approves a validated low finding (severity threshold not met)', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'low', validationStatus: 'validated' }),
    })
    expect(result.decision).toBe('approved')
  })

  test('approves an unexploitable high finding', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'high', validationStatus: 'unexploitable' }),
    })
    expect(result.decision).toBe('approved')
  })

  test('approves a resolved finding regardless of severity and validation', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'critical', validationStatus: 'validated', status: 'resolved' }),
    })
    expect(result.decision).toBe('approved')
  })

  test('approves an accepted_risk finding regardless of validation', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({
        severity: 'critical',
        validationStatus: 'validated',
        status: 'accepted_risk',
      }),
    })
    expect(result.decision).toBe('approved')
  })

  test('approves a merged finding regardless of severity', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'high', validationStatus: 'validated', status: 'merged' }),
    })
    expect(result.decision).toBe('approved')
  })

  test('includes repository name and branch in justification for blocked findings', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'high', validationStatus: 'validated' }),
    })
    expect(result.justification).toContain('payments-api')
    expect(result.justification).toContain('main')
  })

  test('includes repository name and branch in justification for approved findings', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ severity: 'low', validationStatus: 'validated' }),
    })
    expect(result.justification).toContain('payments-api')
    expect(result.justification).toContain('main')
  })

  test('preserves findingId in assessment', () => {
    const result = assessGateFinding({
      ...baseArgs,
      finding: makeFinding({ id: 'specific-finding-id' }),
    })
    expect(result.findingId).toBe('specific-finding-id')
  })
})

describe('computeWorkflowGatePosture', () => {
  test('blocked when any single finding is blocked', () => {
    const assessments = [
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ severity: 'critical', validationStatus: 'validated' }),
      }),
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ id: 'f2', severity: 'medium', validationStatus: 'pending' }),
      }),
    ]
    const posture = computeWorkflowGatePosture(assessments, 'payments-api')
    expect(posture.overallDecision).toBe('blocked')
    expect(posture.blockCount).toBe(1)
    expect(posture.totalEvaluated).toBe(2)
    expect(posture.summary).toContain('blocked by 1')
  })

  test('blocked when all findings are blocked', () => {
    const assessments = [
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ severity: 'critical', validationStatus: 'validated' }),
      }),
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ id: 'f2', severity: 'high', validationStatus: 'likely_exploitable' }),
      }),
    ]
    const posture = computeWorkflowGatePosture(assessments, 'payments-api')
    expect(posture.overallDecision).toBe('blocked')
    expect(posture.blockCount).toBe(2)
  })

  test('approved when all findings pass the threshold', () => {
    const assessments = [
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ severity: 'medium', validationStatus: 'pending' }),
      }),
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ id: 'f2', severity: 'low', validationStatus: 'validated' }),
      }),
    ]
    const posture = computeWorkflowGatePosture(assessments, 'payments-api')
    expect(posture.overallDecision).toBe('approved')
    expect(posture.blockCount).toBe(0)
    expect(posture.totalEvaluated).toBe(2)
  })

  test('approved vacuously when there are no findings', () => {
    const posture = computeWorkflowGatePosture([], 'payments-api')
    expect(posture.overallDecision).toBe('approved')
    expect(posture.blockCount).toBe(0)
    expect(posture.totalEvaluated).toBe(0)
    expect(posture.summary).toContain('no gate-relevant findings')
  })

  test('summary mentions repository name', () => {
    const assessments = [
      assessGateFinding({
        ...baseArgs,
        finding: makeFinding({ severity: 'high', validationStatus: 'validated' }),
      }),
    ]
    const posture = computeWorkflowGatePosture(assessments, 'payments-api')
    expect(posture.summary).toContain('payments-api')
  })
})
