/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import { generateDetectionRules, mergeRuleSets } from './blueAgent'
import type { RedAgentRoundInput } from './blueAgent'

function redWin(chains: string[]): RedAgentRoundInput {
  return {
    exploitChains: chains,
    redStrategySummary: 'Targeted SQL injection in auth path',
    attackSurfaceCoverage: 70,
    blueDetectionScore: 30,
    roundOutcome: 'red_wins',
    repositoryName: 'payments-api',
  }
}

function bluWin(chains: string[]): RedAgentRoundInput {
  return {
    exploitChains: chains,
    redStrategySummary: 'Broad recon sweep',
    attackSurfaceCoverage: 50,
    blueDetectionScore: 90,
    roundOutcome: 'blue_wins',
    repositoryName: 'payments-api',
  }
}

// ── Core rule generation ──────────────────────────────────────────────────────

describe('generateDetectionRules', () => {
  test('produces empty rule set when no red wins', () => {
    const rounds = [bluWin(['xss/search_param'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.totalRules).toBe(0)
    expect(result.nginx).toHaveLength(0)
    expect(result.splunk).toHaveLength(0)
  })

  test('generates rules only from red_wins rounds', () => {
    const rounds = [
      redWin(['sql_injection/payments-db']),
      bluWin(['xss/search_param']),
    ]
    const result = generateDetectionRules(rounds, 'payments-api')
    // Should have SQL injection rules, not XSS
    const classes = new Set(result.nginx.map((r) => r.tags).flat().filter((t) => t !== 'sentinel-auto' && t !== 'waf' && t !== 'nginx'))
    expect(classes.has('sql_injection')).toBe(true)
    expect(classes.has('xss')).toBe(false)
  })

  test('deduplicates rules across rounds with same vuln class', () => {
    const rounds = [
      redWin(['sql_injection/user-db']),
      redWin(['sql_injection/payments-db']),  // same class — should dedupe
    ]
    const result = generateDetectionRules(rounds, 'repo')
    const sqlSplunk = result.splunk.filter((r) => r.tags.includes('sql_injection'))
    expect(sqlSplunk.length).toBe(1)
  })

  test('generates all 5 output formats for sql injection', () => {
    const rounds = [redWin(['sqli_union_null/id'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.nginx.length).toBeGreaterThan(0)
    expect(result.modsecurity.length).toBeGreaterThan(0)
    expect(result.splunk.length).toBeGreaterThan(0)
    expect(result.elastic.length).toBeGreaterThan(0)
    expect(result.sentinel.length).toBeGreaterThan(0)
    expect(result.logRegex.length).toBeGreaterThan(0)
  })

  test('nginx rules contain deny/return 403', () => {
    const rounds = [redWin(['sql_injection/auth'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.nginx) {
      expect(rule.content).toMatch(/return 403|deny/i)
    }
  })

  test('modsecurity rules contain SecRule and id', () => {
    const rounds = [redWin(['sql_injection/auth'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.modsecurity) {
      expect(rule.content).toContain('SecRule')
      expect(rule.content).toMatch(/id:\d+/)
    }
  })

  test('splunk rules contain index= and stats', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.splunk) {
      expect(rule.content).toContain('index=')
      expect(rule.content).toContain('stats count')
    }
  })

  test('elastic rules contain event.dataset', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.elastic) {
      expect(rule.content).toContain('event.dataset')
    }
  })

  test('sentinel rules contain AzureDiagnostics', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.sentinel) {
      expect(rule.content).toContain('AzureDiagnostics')
    }
  })

  test('log regex rules contain PATTERN:', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    for (const rule of result.logRegex) {
      expect(rule.content).toContain('PATTERN:')
    }
  })

  test('all rules have correct format field', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    result.nginx.forEach((r) => expect(r.format).toBe('nginx_deny'))
    result.modsecurity.forEach((r) => expect(r.format).toBe('modsecurity'))
    result.splunk.forEach((r) => expect(r.format).toBe('splunk_spl'))
    result.elastic.forEach((r) => expect(r.format).toBe('elastic_kql'))
    result.sentinel.forEach((r) => expect(r.format).toBe('sentinel_kql'))
    result.logRegex.forEach((r) => expect(r.format).toBe('log_regex'))
  })

  test('rules are tagged sentinel-auto', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    const allRules = [
      ...result.nginx, ...result.modsecurity, ...result.splunk,
      ...result.elastic, ...result.sentinel, ...result.logRegex,
    ]
    for (const rule of allRules) {
      expect(rule.tags).toContain('sentinel-auto')
    }
  })

  test('xss chains generate rules', () => {
    const rounds = [redWin(['xss_basic_script/search'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.nginx.some((r) => r.tags.includes('xss'))).toBe(true)
  })

  test('path traversal chains generate rules', () => {
    const rounds = [redWin(['path_traversal_etc_passwd'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.totalRules).toBeGreaterThan(0)
    const classes = [...result.logRegex].flatMap((r) => r.tags)
    expect(classes.includes('path_traversal')).toBe(true)
  })

  test('command injection chains generate rules', () => {
    const rounds = [redWin(['cmdi_semicolon_cmd'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.totalRules).toBeGreaterThan(0)
  })

  test('ssrf chains generate rules', () => {
    const rounds = [redWin(['ssrf_169_metadata'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.totalRules).toBeGreaterThan(0)
  })

  test('multiple distinct vuln classes each generate rules', () => {
    const rounds = [
      redWin(['sql_injection/users', 'xss/search', 'ssrf_blind/webhook']),
    ]
    const result = generateDetectionRules(rounds, 'repo')
    const splunkClasses = result.splunk.map((r) => r.tags.find((t) => !['sentinel-auto', 'splunk', 'siem'].includes(t)))
    expect(splunkClasses.length).toBeGreaterThanOrEqual(3)
  })

  test('totalRules equals sum of all format arrays', () => {
    const rounds = [redWin(['sql_injection/db', 'xss/search'])]
    const result = generateDetectionRules(rounds, 'repo')
    const counted = result.nginx.length + result.modsecurity.length +
      result.splunk.length + result.elastic.length +
      result.sentinel.length + result.logRegex.length
    expect(result.totalRules).toBe(counted)
  })

  test('summary mentions vuln class count', () => {
    const rounds = [redWin(['sql_injection/db'])]
    const result = generateDetectionRules(rounds, 'repo')
    expect(result.summary).toContain('sql injection')
  })
})

// ── mergeRuleSets ─────────────────────────────────────────────────────────────

describe('mergeRuleSets', () => {
  test('merges two rule sets without duplicates', () => {
    const a = generateDetectionRules([redWin(['sql_injection/db'])], 'repo')
    const b = generateDetectionRules([redWin(['xss/search'])], 'repo')
    const merged = mergeRuleSets(a, b)
    expect(merged.totalRules).toBe(a.totalRules + b.totalRules)
  })

  test('deduplicates identical rule IDs', () => {
    const a = generateDetectionRules([redWin(['sql_injection/db'])], 'repo')
    const b = generateDetectionRules([redWin(['sql_injection/auth'])], 'repo')  // same class = same IDs
    const merged = mergeRuleSets(a, b)
    // Should not double up
    expect(merged.splunk.length).toBe(a.splunk.length)
  })

  test('merged totalRules matches actual arrays', () => {
    const a = generateDetectionRules([redWin(['sql_injection/db'])], 'repo')
    const b = generateDetectionRules([redWin(['xss/search'])], 'repo')
    const merged = mergeRuleSets(a, b)
    const actual = merged.nginx.length + merged.modsecurity.length +
      merged.splunk.length + merged.elastic.length +
      merged.sentinel.length + merged.logRegex.length
    expect(merged.totalRules).toBe(actual)
  })
})
