/// <reference types="vite/client" />
/**
 * Tests for the SIEM export pure library.
 *
 * Covers: Splunk HEC body construction, Elastic _bulk body construction,
 * edge cases (empty arrays, special characters in repo names), and URL validation.
 */

import { describe, expect, test } from 'vitest'
import {
  buildElasticBulkBody,
  buildSplunkHecBody,
  isValidSiemUrl,
} from './siemExport'

// ── buildSplunkHecBody ────────────────────────────────────────────────────────

describe('buildSplunkHecBody', () => {
  const rules = [
    'url_query="*union*select*" OR uri_path="*sleep(*"',
    'url_query="*<script*" OR request_body="*onerror=*"',
  ]

  test('produces one JSON line per rule', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    expect(lines).toHaveLength(2)
  })

  test('each line is valid JSON', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    for (const line of body.split('\n').filter(Boolean)) {
      expect(() => JSON.parse(line)).not.toThrow()
    }
  })

  test('event contains correct rule_content', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.event.rule_content).toBe(rules[0])
  })

  test('event rule_index increments', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    expect(JSON.parse(lines[0]).event.rule_index).toBe(0)
    expect(JSON.parse(lines[1]).event.rule_index).toBe(1)
  })

  test('event format is splunk_spl', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.event.format).toBe('splunk_spl')
  })

  test('sourcetype is sentinel:detection_rule', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.sourcetype).toBe('sentinel:detection_rule')
  })

  test('uses default index when not provided', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.index).toBe('sentinel_detection_rules')
  })

  test('uses custom index when provided', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000, 'my_index')
    const first = JSON.parse(body.split('\n')[0])
    expect(first.index).toBe('my_index')
  })

  test('host field equals repository name', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.host).toBe('acme/api')
  })

  test('sentinel_source is blue_agent', () => {
    const body = buildSplunkHecBody(rules, 'acme/api', 1700000000000)
    const first = JSON.parse(body.split('\n')[0])
    expect(first.event.sentinel_source).toBe('blue_agent')
  })

  test('returns empty string for empty rules array', () => {
    expect(buildSplunkHecBody([], 'acme/api', 1700000000000)).toBe('')
  })

  test('handles a single rule', () => {
    const body = buildSplunkHecBody(['url_query="*sqli*"'], 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    expect(lines).toHaveLength(1)
  })
})

// ── buildElasticBulkBody ──────────────────────────────────────────────────────

describe('buildElasticBulkBody', () => {
  const rules = [
    'url.query: (*union*select* OR *%27*)',
    'url.query: (*<script* OR *javascript:*)',
  ]

  test('produces 2 lines per rule (action + document)', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    // trailing newline means last split element is empty — filter it
    const lines = body.split('\n').filter(Boolean)
    expect(lines).toHaveLength(rules.length * 2)
  })

  test('body ends with a trailing newline (Elastic requirement)', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    expect(body.endsWith('\n')).toBe(true)
  })

  test('action lines contain _index field', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    const actionLine = JSON.parse(lines[0])
    expect(actionLine.index._index).toBeDefined()
  })

  test('uses default index name', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    const actionLine = JSON.parse(lines[0])
    expect(actionLine.index._index).toBe('sentinel-detection-rules')
  })

  test('uses custom index name when provided', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000, 'custom-idx')
    const actionLine = JSON.parse(body.split('\n')[0])
    expect(actionLine.index._index).toBe('custom-idx')
  })

  test('document lines contain rule_content', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    const doc = JSON.parse(lines[1]) // second line is the first document
    expect(doc.rule_content).toBe(rules[0])
  })

  test('document format is elastic_kql', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    const doc = JSON.parse(lines[1])
    expect(doc.format).toBe('elastic_kql')
  })

  test('document rule_index increments', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const lines = body.split('\n').filter(Boolean)
    expect(JSON.parse(lines[1]).rule_index).toBe(0) // first doc
    expect(JSON.parse(lines[3]).rule_index).toBe(1) // second doc
  })

  test('doc _id is deterministic from repo + timestamp + index', () => {
    const body1 = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const body2 = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const id1 = JSON.parse(body1.split('\n')[0]).index._id
    const id2 = JSON.parse(body2.split('\n')[0]).index._id
    expect(id1).toBe(id2)
  })

  test('doc _id replaces slashes with underscores', () => {
    const body = buildElasticBulkBody(rules, 'acme/api', 1700000000000)
    const id = JSON.parse(body.split('\n')[0]).index._id
    expect(id).not.toContain('/')
  })

  test('returns empty string for empty rules array', () => {
    expect(buildElasticBulkBody([], 'acme/api', 1700000000000)).toBe('')
  })
})

// ── isValidSiemUrl ────────────────────────────────────────────────────────────

describe('isValidSiemUrl', () => {
  test('accepts https URL', () => {
    expect(isValidSiemUrl('https://splunk.internal:8088')).toBe(true)
  })

  test('accepts http URL', () => {
    expect(isValidSiemUrl('http://localhost:9200')).toBe(true)
  })

  test('rejects empty string', () => {
    expect(isValidSiemUrl('')).toBe(false)
  })

  test('rejects non-http protocol', () => {
    expect(isValidSiemUrl('ftp://splunk.example.com')).toBe(false)
  })

  test('rejects bare hostname', () => {
    expect(isValidSiemUrl('splunk.internal:8088')).toBe(false)
  })

  test('rejects relative path', () => {
    expect(isValidSiemUrl('/api/endpoint')).toBe(false)
  })
})
