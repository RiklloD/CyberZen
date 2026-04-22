import { describe, it, expect } from 'vitest'
import {
  buildCreateAlertBody,
  buildCloseAlertBody,
  buildOpsgenieAlias,
  sentinelSeverityToOpsgenieP,
} from './opsgeniePayload'

// ---------------------------------------------------------------------------
// sentinelSeverityToOpsgenieP
// ---------------------------------------------------------------------------

describe('sentinelSeverityToOpsgenieP', () => {
  it('maps critical to P1', () => {
    expect(sentinelSeverityToOpsgenieP('critical')).toBe('P1')
  })
  it('maps high to P2', () => {
    expect(sentinelSeverityToOpsgenieP('high')).toBe('P2')
  })
  it('maps medium to P3', () => {
    expect(sentinelSeverityToOpsgenieP('medium')).toBe('P3')
  })
  it('maps low to P4', () => {
    expect(sentinelSeverityToOpsgenieP('low')).toBe('P4')
  })
  it('maps unknown/undefined to P3', () => {
    expect(sentinelSeverityToOpsgenieP(undefined)).toBe('P3')
    expect(sentinelSeverityToOpsgenieP('')).toBe('P3')
  })
})

// ---------------------------------------------------------------------------
// buildOpsgenieAlias
// ---------------------------------------------------------------------------

describe('buildOpsgenieAlias', () => {
  it('produces a deterministic alias', () => {
    const alias1 = buildOpsgenieAlias({
      kind: 'critical_finding',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
    })
    const alias2 = buildOpsgenieAlias({
      kind: 'critical_finding',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
    })
    expect(alias1).toBe(alias2)
  })

  it('includes findingId when provided', () => {
    const alias = buildOpsgenieAlias({
      kind: 'critical_finding',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
      findingId: 'find-123',
    })
    expect(alias).toContain('find-123')
  })

  it('differs by kind', () => {
    const a1 = buildOpsgenieAlias({ kind: 'critical_finding', tenantSlug: 'x', repositoryFullName: 'x/y' })
    const a2 = buildOpsgenieAlias({ kind: 'gate_blocked', tenantSlug: 'x', repositoryFullName: 'x/y' })
    expect(a1).not.toBe(a2)
  })

  it('replaces slash in repo name', () => {
    const alias = buildOpsgenieAlias({ kind: 'honeypot_triggered', tenantSlug: 'x', repositoryFullName: 'org/repo' })
    expect(alias).not.toContain('/')
  })
})

// ---------------------------------------------------------------------------
// buildCreateAlertBody
// ---------------------------------------------------------------------------

describe('buildCreateAlertBody', () => {
  const base = {
    kind: 'critical_finding' as const,
    tenantSlug: 'acme',
    repositoryFullName: 'acme/payments-api',
    severity: 'critical',
    title: 'SQL Injection in /api/transfer',
    vulnClass: 'sql_injection',
    findingId: 'find-456',
  }

  it('sets priority P1 for critical', () => {
    const body = buildCreateAlertBody(base)
    expect(body.priority).toBe('P1')
  })

  it('message is at most 130 chars', () => {
    const body = buildCreateAlertBody(base)
    expect((body.message ?? '').length).toBeLessThanOrEqual(130)
  })

  it('includes alias', () => {
    const body = buildCreateAlertBody(base)
    expect(body.alias).toBeTruthy()
    expect(body.alias).toContain('find-456')
  })

  it('includes responders when teamId is provided', () => {
    const body = buildCreateAlertBody({ ...base, teamId: 'team-abc' })
    expect(body.responders).toHaveLength(1)
    expect(body.responders?.[0]).toEqual({ type: 'team', id: 'team-abc' })
  })

  it('omits responders when teamId is absent', () => {
    const body = buildCreateAlertBody(base)
    expect(body.responders).toHaveLength(0)
  })

  it('includes tags with sentinel prefix', () => {
    const body = buildCreateAlertBody(base)
    expect(body.tags).toContain('sentinel')
  })

  it('includes vuln_class in details', () => {
    const body = buildCreateAlertBody(base)
    expect(body.details?.vuln_class).toBe('sql_injection')
  })

  it('honeypot_triggered is always P1 regardless of severity', () => {
    const body = buildCreateAlertBody({
      kind: 'honeypot_triggered',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
      severity: 'low',  // should still produce P1
    })
    expect(body.priority).toBe('P1')
  })

  it('gate_blocked message mentions CI gate', () => {
    const body = buildCreateAlertBody({
      kind: 'gate_blocked',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
      severity: 'high',
    })
    expect(body.message).toContain('Gate Blocked')
  })

  it('source is always Sentinel Security Agent', () => {
    const body = buildCreateAlertBody(base)
    expect(body.source).toBe('Sentinel Security Agent')
  })

  it('entity is the repository full name', () => {
    const body = buildCreateAlertBody(base)
    expect(body.entity).toBe('acme/payments-api')
  })

  it('description includes summary when provided', () => {
    const body = buildCreateAlertBody({ ...base, summary: 'Attacker can extract session tokens' })
    expect(body.description).toContain('Attacker can extract session tokens')
  })
})

// ---------------------------------------------------------------------------
// buildCloseAlertBody
// ---------------------------------------------------------------------------

describe('buildCloseAlertBody', () => {
  it('includes default note when none provided', () => {
    const body = buildCloseAlertBody()
    expect(body.note).toBeTruthy()
  })

  it('includes custom note when provided', () => {
    const body = buildCloseAlertBody('Custom resolution note')
    expect(body.note).toBe('Custom resolution note')
  })

  it('source is always Sentinel Security Agent', () => {
    const body = buildCloseAlertBody()
    expect(body.source).toBe('Sentinel Security Agent')
  })
})
