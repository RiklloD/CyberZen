import { describe, it, expect } from 'vitest'
import {
  buildTeamsPayload,
  meetsMinSeverity,
  severityLabel,
  severityToColor,
  type TeamsAlertPayload,
} from './teamsCards'

// ---------------------------------------------------------------------------
// severityLabel
// ---------------------------------------------------------------------------

describe('severityLabel', () => {
  it('returns CRITICAL for critical', () => {
    expect(severityLabel('critical')).toContain('CRITICAL')
  })
  it('returns HIGH for high', () => {
    expect(severityLabel('high')).toContain('HIGH')
  })
  it('returns MEDIUM for medium', () => {
    expect(severityLabel('medium')).toContain('MEDIUM')
  })
  it('returns LOW for low', () => {
    expect(severityLabel('low')).toContain('LOW')
  })
  it('returns UNKNOWN for undefined', () => {
    expect(severityLabel(undefined)).toContain('UNKNOWN')
  })
})

// ---------------------------------------------------------------------------
// severityToColor
// ---------------------------------------------------------------------------

describe('severityToColor', () => {
  it('maps critical to Attention', () => {
    expect(severityToColor('critical')).toBe('Attention')
  })
  it('maps high to Warning', () => {
    expect(severityToColor('high')).toBe('Warning')
  })
  it('maps medium to Accent', () => {
    expect(severityToColor('medium')).toBe('Accent')
  })
  it('maps low to Good', () => {
    expect(severityToColor('low')).toBe('Good')
  })
  it('maps unknown to Default', () => {
    expect(severityToColor('unknown')).toBe('Default')
    expect(severityToColor(undefined)).toBe('Default')
  })
})

// ---------------------------------------------------------------------------
// meetsMinSeverity
// ---------------------------------------------------------------------------

describe('meetsMinSeverity', () => {
  it('critical meets critical threshold', () => {
    expect(meetsMinSeverity('critical', 'critical')).toBe(true)
  })
  it('critical meets high threshold', () => {
    expect(meetsMinSeverity('critical', 'high')).toBe(true)
  })
  it('high meets high threshold', () => {
    expect(meetsMinSeverity('high', 'high')).toBe(true)
  })
  it('medium does NOT meet high threshold', () => {
    expect(meetsMinSeverity('medium', 'high')).toBe(false)
  })
  it('low does NOT meet medium threshold', () => {
    expect(meetsMinSeverity('low', 'medium')).toBe(false)
  })
  it('informational does NOT meet low threshold', () => {
    expect(meetsMinSeverity('informational', 'low')).toBe(false)
  })
  it('undefined severity falls back to low and does NOT meet high threshold', () => {
    expect(meetsMinSeverity(undefined, 'high')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// buildTeamsPayload — shape validation helpers
// ---------------------------------------------------------------------------

function getCard(payload: ReturnType<typeof buildTeamsPayload>) {
  expect(payload.type).toBe('message')
  expect(payload.attachments).toHaveLength(1)
  const att = payload.attachments[0]
  expect(att.contentType).toBe('application/vnd.microsoft.card.adaptive')
  expect(att.contentUrl).toBeNull()
  const card = att.content
  expect(card.type).toBe('AdaptiveCard')
  expect(card.version).toBe('1.4')
  expect(card.$schema).toBe('http://adaptivecards.io/schemas/adaptive-card.json')
  return card
}

function basePayload(overrides: Partial<TeamsAlertPayload> = {}): TeamsAlertPayload {
  return {
    kind: 'finding_validated',
    tenantSlug: 'acme',
    repositoryFullName: 'acme/api',
    severity: 'high',
    title: 'SQL Injection in /api/upload',
    ...overrides,
  }
}

describe('buildTeamsPayload — finding_validated', () => {
  it('produces valid message envelope', () => {
    getCard(buildTeamsPayload(basePayload()))
  })

  it('includes severity label in first TextBlock text', () => {
    const card = getCard(buildTeamsPayload(basePayload({ severity: 'critical' })))
    const firstBlock = card.body[0] as { type: string; text: string }
    expect(firstBlock.text).toContain('CRITICAL')
  })

  it('includes repository and vuln class in facts', () => {
    const card = getCard(buildTeamsPayload(basePayload({ vulnClass: 'sql_injection' })))
    const factSet = card.body.find((b) => b.type === 'FactSet') as {
      type: string
      facts: Array<{ title: string; value: string }>
    }
    expect(factSet.facts.some((f) => f.title === 'Repository')).toBe(true)
    expect(factSet.facts.some((f) => f.value === 'sql_injection')).toBe(true)
  })

  it('adds PR action when prUrl is provided', () => {
    const card = getCard(buildTeamsPayload(basePayload({ prUrl: 'https://github.com/pr/1' })))
    expect(card.actions).toBeDefined()
    const openUrl = card.actions?.find((a) => a.type === 'Action.OpenUrl')
    expect(openUrl?.url).toBe('https://github.com/pr/1')
  })

  it('omits actions when prUrl is absent', () => {
    const card = getCard(buildTeamsPayload(basePayload()))
    expect(card.actions).toBeUndefined()
  })

  it('truncates summary to 300 chars', () => {
    const long = 'x'.repeat(500)
    const card = getCard(buildTeamsPayload(basePayload({ summary: long })))
    const textBlocks = card.body.filter(
      (b) => b.type === 'TextBlock',
    ) as Array<{ type: string; text: string }>
    const summaryBlock = textBlocks.find((b) => b.text === long.slice(0, 300))
    expect(summaryBlock).toBeDefined()
  })

  it('includes blast radius container when blastRadiusSummary is set', () => {
    const card = getCard(buildTeamsPayload(basePayload({ blastRadiusSummary: 'auth-service, payments' })))
    const containers = card.body.filter((b) => b.type === 'Container')
    expect(containers.length).toBeGreaterThan(0)
  })

  it('sets msteams.width to Full', () => {
    const card = getCard(buildTeamsPayload(basePayload()))
    expect(card.msteams?.width).toBe('Full')
  })
})

describe('buildTeamsPayload — gate_blocked', () => {
  it('includes gate blocked text', () => {
    const card = getCard(buildTeamsPayload(basePayload({ kind: 'gate_blocked' })))
    const first = card.body[0] as { type: string; text: string }
    expect(first.text).toContain('CI Gate Blocked')
  })

  it('uses Attention color', () => {
    const card = getCard(buildTeamsPayload(basePayload({ kind: 'gate_blocked' })))
    const first = card.body[0] as { type: string; color: string }
    expect(first.color).toBe('Attention')
  })
})

describe('buildTeamsPayload — honeypot_triggered', () => {
  it('includes HONEYPOT text', () => {
    const card = getCard(buildTeamsPayload(basePayload({ kind: 'honeypot_triggered' })))
    const first = card.body[0] as { type: string; text: string }
    expect(first.text).toContain('HONEYPOT')
  })

  it('includes extra context when provided', () => {
    const card = getCard(buildTeamsPayload(basePayload({
      kind: 'honeypot_triggered',
      extraContext: 'Attacker IP: 1.2.3.4',
    })))
    const containers = card.body.filter((b) => b.type === 'Container')
    expect(containers.length).toBeGreaterThan(0)
  })
})
