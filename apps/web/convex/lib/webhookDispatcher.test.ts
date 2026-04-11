/// <reference types="vite/client" />
import { describe, expect, it, vi } from 'vitest'
import {
  ALL_WEBHOOK_EVENT_TYPES,
  buildSignedPayload,
  isSubscribed,
  postWebhookPayload,
  validateEndpointUrl,
  validateSubscribedEvents,
  type AttackSurfaceIncreasedData,
  type FindingValidatedData,
  type GateBlockedData,
  type WebhookEnvelope,
} from './webhookDispatcher'

// ---------------------------------------------------------------------------
// buildSignedPayload
// ---------------------------------------------------------------------------

describe('buildSignedPayload', () => {
  const baseEnvelope: WebhookEnvelope = {
    event: 'finding.validated',
    tenantSlug: 'acme',
    repositoryFullName: 'acme/api',
    timestamp: 1700000000000,
    deliveryId: 'del-001',
    data: {
      findingId: 'find-1',
      title: 'Log4Shell',
      severity: 'critical',
      vulnClass: 'rce',
      validationStatus: 'validated',
      validationConfidence: 0.95,
    } satisfies FindingValidatedData,
  }

  it('returns a body string containing the serialized envelope', async () => {
    const { body } = await buildSignedPayload(baseEnvelope, 'secret')
    const parsed = JSON.parse(body)
    expect(parsed.event).toBe('finding.validated')
    expect(parsed.tenantSlug).toBe('acme')
    expect(parsed.deliveryId).toBe('del-001')
    expect(parsed.data.severity).toBe('critical')
  })

  it('signature starts with "sha256="', async () => {
    const { signature } = await buildSignedPayload(baseEnvelope, 'secret')
    expect(signature).toMatch(/^sha256=[0-9a-f]{64}$/)
  })

  it('same inputs produce same signature', async () => {
    const { signature: s1 } = await buildSignedPayload(baseEnvelope, 'mysecret')
    const { signature: s2 } = await buildSignedPayload(baseEnvelope, 'mysecret')
    expect(s1).toBe(s2)
  })

  it('different secrets produce different signatures', async () => {
    const { signature: s1 } = await buildSignedPayload(baseEnvelope, 'secret-a')
    const { signature: s2 } = await buildSignedPayload(baseEnvelope, 'secret-b')
    expect(s1).not.toBe(s2)
  })

  it('different envelopes produce different signatures', async () => {
    const env2 = { ...baseEnvelope, deliveryId: 'del-999' }
    const { signature: s1 } = await buildSignedPayload(baseEnvelope, 'secret')
    const { signature: s2 } = await buildSignedPayload(env2, 'secret')
    expect(s1).not.toBe(s2)
  })

  it('handles all event types without throwing', async () => {
    for (const event of ALL_WEBHOOK_EVENT_TYPES) {
      const env = { ...baseEnvelope, event } as WebhookEnvelope
      await expect(buildSignedPayload(env, 'key')).resolves.toBeDefined()
    }
  })
})

// ---------------------------------------------------------------------------
// isSubscribed
// ---------------------------------------------------------------------------

describe('isSubscribed', () => {
  it('returns true for empty list (wildcard subscription)', () => {
    expect(isSubscribed([], 'finding.validated')).toBe(true)
    expect(isSubscribed([], 'gate.blocked')).toBe(true)
  })

  it('returns true when event is in the list', () => {
    expect(isSubscribed(['finding.validated', 'gate.blocked'], 'gate.blocked')).toBe(true)
  })

  it('returns false when event is not in the list', () => {
    expect(isSubscribed(['finding.validated'], 'gate.blocked')).toBe(false)
  })

  it('handles single-item list correctly', () => {
    expect(isSubscribed(['sbom.drift_detected'], 'sbom.drift_detected')).toBe(true)
    expect(isSubscribed(['sbom.drift_detected'], 'finding.resolved')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// validateEndpointUrl
// ---------------------------------------------------------------------------

describe('validateEndpointUrl', () => {
  it('accepts https URLs', () => {
    const r = validateEndpointUrl('https://example.com/webhook')
    expect(r.valid).toBe(true)
  })

  it('accepts http URLs (for local dev)', () => {
    const r = validateEndpointUrl('http://localhost:3000/webhook')
    expect(r.valid).toBe(true)
  })

  it('rejects non-URL strings', () => {
    const r = validateEndpointUrl('not-a-url')
    expect(r.valid).toBe(false)
    if (!r.valid) expect(r.reason).toBeTruthy()
  })

  it('rejects unsupported protocol', () => {
    const r = validateEndpointUrl('ftp://example.com/webhook')
    expect(r.valid).toBe(false)
    if (!r.valid) expect(r.reason).toContain('http')
  })

  it('rejects empty string', () => {
    const r = validateEndpointUrl('')
    expect(r.valid).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// validateSubscribedEvents
// ---------------------------------------------------------------------------

describe('validateSubscribedEvents', () => {
  it('accepts empty list (wildcard)', () => {
    expect(validateSubscribedEvents([]).valid).toBe(true)
  })

  it('accepts all valid event types', () => {
    expect(validateSubscribedEvents([...ALL_WEBHOOK_EVENT_TYPES]).valid).toBe(true)
  })

  it('accepts a subset of valid events', () => {
    expect(validateSubscribedEvents(['finding.validated', 'gate.blocked']).valid).toBe(true)
  })

  it('rejects unknown event type', () => {
    const r = validateSubscribedEvents(['finding.validated', 'foo.bar'])
    expect(r.valid).toBe(false)
    if (!r.valid) expect(r.reason).toContain('foo.bar')
  })

  it('lists valid types in the error message', () => {
    const r = validateSubscribedEvents(['unknown.event'])
    expect(r.valid).toBe(false)
    if (!r.valid) expect(r.reason).toContain('finding.validated')
  })
})

// ---------------------------------------------------------------------------
// postWebhookPayload
// ---------------------------------------------------------------------------

describe('postWebhookPayload', () => {
  const signed = { body: '{"test":1}', signature: 'sha256=abc123' }

  it('returns success=true for 200 response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 200 })
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-1', 'https://example.com/hook', signed, 'del-1')
    expect(result.success).toBe(true)
    expect(result.statusCode).toBe(200)
    expect(result.endpointId).toBe('ep-1')
    expect(result.errorMessage).toBeNull()

    vi.unstubAllGlobals()
  })

  it('returns success=true for 201 response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 201 })
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-2', 'https://example.com/hook', signed, 'del-2')
    expect(result.success).toBe(true)
    expect(result.statusCode).toBe(201)

    vi.unstubAllGlobals()
  })

  it('returns success=false for 400 response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 400 })
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-3', 'https://example.com/hook', signed, 'del-3')
    expect(result.success).toBe(false)
    expect(result.statusCode).toBe(400)

    vi.unstubAllGlobals()
  })

  it('returns success=false for 500 response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 500 })
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-4', 'https://example.com/hook', signed, 'del-4')
    expect(result.success).toBe(false)
    expect(result.statusCode).toBe(500)

    vi.unstubAllGlobals()
  })

  it('handles network error gracefully', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-5', 'https://example.com/hook', signed, 'del-5')
    expect(result.success).toBe(false)
    expect(result.statusCode).toBeNull()
    expect(result.errorMessage).toContain('ECONNREFUSED')

    vi.unstubAllGlobals()
  })

  it('sends correct headers', async () => {
    let capturedInit: RequestInit | undefined
    const mockFetch = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      capturedInit = init
      return Promise.resolve({ status: 200 })
    })
    vi.stubGlobal('fetch', mockFetch)

    await postWebhookPayload('ep-6', 'https://example.com/hook', signed, 'del-6')

    const headers = capturedInit?.headers as Record<string, string>
    expect(headers['X-Sentinel-Signature-256']).toBe('sha256=abc123')
    expect(headers['X-Sentinel-Delivery']).toBe('del-6')
    expect(headers['Content-Type']).toBe('application/json')

    vi.unstubAllGlobals()
  })

  it('sends the signed body as request body', async () => {
    let capturedBody: string | undefined
    const mockFetch = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      capturedBody = init.body as string
      return Promise.resolve({ status: 200 })
    })
    vi.stubGlobal('fetch', mockFetch)

    await postWebhookPayload('ep-7', 'https://example.com/hook', signed, 'del-7')
    expect(capturedBody).toBe('{"test":1}')

    vi.unstubAllGlobals()
  })

  it('includes durationMs in result', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ status: 200 })
    vi.stubGlobal('fetch', mockFetch)

    const result = await postWebhookPayload('ep-8', 'https://example.com/hook', signed, 'del-8')
    expect(typeof result.durationMs).toBe('number')
    expect(result.durationMs).toBeGreaterThanOrEqual(0)

    vi.unstubAllGlobals()
  })
})

// ---------------------------------------------------------------------------
// Envelope shape for each event type
// ---------------------------------------------------------------------------

describe('WebhookEnvelope shapes', () => {
  it('gate.blocked envelope serialises correctly', async () => {
    const env: WebhookEnvelope = {
      event: 'gate.blocked',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/api',
      timestamp: 1700000000000,
      deliveryId: 'del-gate-1',
      data: {
        commitSha: 'abc123',
        branch: 'main',
        blockedReasons: ['critical CVE in lodash'],
        decisionPolicy: 'strict',
      } satisfies GateBlockedData,
    }
    const { body } = await buildSignedPayload(env, 'secret')
    const parsed = JSON.parse(body)
    expect(parsed.event).toBe('gate.blocked')
    expect(parsed.data.blockedReasons).toHaveLength(1)
  })

  it('attack_surface.increased envelope serialises correctly', async () => {
    const env: WebhookEnvelope = {
      event: 'attack_surface.increased',
      tenantSlug: 'acme',
      repositoryFullName: 'acme/web',
      timestamp: 1700000000000,
      deliveryId: 'del-as-1',
      data: {
        previousScore: 72,
        newScore: 55,
        delta: -17,
        trend: 'degrading',
      } satisfies AttackSurfaceIncreasedData,
    }
    const { body } = await buildSignedPayload(env, 'secret')
    const parsed = JSON.parse(body)
    expect(parsed.data.delta).toBe(-17)
    expect(parsed.data.trend).toBe('degrading')
  })
})
