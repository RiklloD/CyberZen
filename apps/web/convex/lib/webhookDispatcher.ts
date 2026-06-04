// Outbound webhook event dispatcher — pure library (spec §7.2)
//
// Builds typed webhook payloads for all 10 outbound event types and handles
// HMAC-SHA256 signing plus HTTP delivery.  No Convex runtime dependency —
// safe to unit-test under @edge-runtime/vm.

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

export type WebhookEventType =
  | 'finding.validated'
  | 'finding.pr_opened'
  | 'finding.resolved'
  | 'finding.severity_escalated'
  | 'trust_score.degraded'
  | 'trust_score.compromised'
  | 'honeypot.triggered'
  | 'gate.blocked'
  | 'gate.override'
  | 'regulatory.gap_detected'
  | 'sbom.drift_detected'
  | 'attack_surface.increased'

export const ALL_WEBHOOK_EVENT_TYPES: WebhookEventType[] = [
  'finding.validated',
  'finding.pr_opened',
  'finding.resolved',
  'finding.severity_escalated',
  'trust_score.degraded',
  'trust_score.compromised',
  'honeypot.triggered',
  'gate.blocked',
  'gate.override',
  'regulatory.gap_detected',
  'sbom.drift_detected',
  'attack_surface.increased',
]

// ---------------------------------------------------------------------------
// Per-event data shapes
// ---------------------------------------------------------------------------

export type FindingValidatedData = {
  findingId: string
  title: string
  severity: string
  vulnClass: string
  validationStatus: string
  validationConfidence: number
}

export type FindingPrOpenedData = {
  findingId: string
  title: string
  severity: string
  prUrl: string | null
  prTitle: string
  proposedBranch: string
}

export type FindingResolvedData = {
  findingId: string
  title: string
  severity: string
  resolvedAt: number
}

export type FindingSeverityEscalatedData = {
  findingId: string
  title: string
  previousSeverity: string
  newSeverity: string
  /** Escalation trigger identifiers that fired. */
  triggers: string[]
  /** Human-readable rationale for the escalation. */
  rationale: string[]
}

export type TrustScoreDegradedData = {
  packageName: string
  ecosystem: string
  previousScore: number
  newScore: number
  delta: number
}

export type TrustScoreCompromisedData = {
  packageName: string
  ecosystem: string
  /** Current trust score — always below the compromised threshold. */
  score: number
  /** The absolute threshold that was breached (e.g. 30). */
  threshold: number
}

export type HoneypotTriggeredData = {
  honeypotPath: string
  kind: string
  repositoryFullName: string
  triggeredAt: number
}

export type GateBlockedData = {
  commitSha: string
  branch: string
  blockedReasons: string[]
  decisionPolicy: string
}

export type GateOverrideData = {
  commitSha: string
  branch: string
  overriddenBy: string
  decisionPolicy: string
}

export type RegulatoryGapDetectedData = {
  frameworks: string[]
  driftLevel: string
  criticalGapCount: number
  openGapCount: number
}

export type SbomDriftDetectedData = {
  previousComponentCount: number
  newComponentCount: number
  riskDelta: number
  branch: string
  commitSha: string
}

export type AttackSurfaceIncreasedData = {
  previousScore: number
  newScore: number
  delta: number
  trend: string
}

// Discriminated union used by the dispatcher.
export type WebhookEventPayload =
  | { event: 'finding.validated'; data: FindingValidatedData }
  | { event: 'finding.pr_opened'; data: FindingPrOpenedData }
  | { event: 'finding.resolved'; data: FindingResolvedData }
  | { event: 'finding.severity_escalated'; data: FindingSeverityEscalatedData }
  | { event: 'trust_score.degraded'; data: TrustScoreDegradedData }
  | { event: 'trust_score.compromised'; data: TrustScoreCompromisedData }
  | { event: 'honeypot.triggered'; data: HoneypotTriggeredData }
  | { event: 'gate.blocked'; data: GateBlockedData }
  | { event: 'gate.override'; data: GateOverrideData }
  | { event: 'regulatory.gap_detected'; data: RegulatoryGapDetectedData }
  | { event: 'sbom.drift_detected'; data: SbomDriftDetectedData }
  | { event: 'attack_surface.increased'; data: AttackSurfaceIncreasedData }

// ---------------------------------------------------------------------------
// Envelope — the full JSON body sent to customer endpoints
// ---------------------------------------------------------------------------

export type WebhookEnvelope = WebhookEventPayload & {
  tenantSlug: string
  repositoryFullName: string
  timestamp: number
  deliveryId: string
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

export type SignedWebhookPayload = {
  /** JSON-serialized envelope body. */
  body: string
  /** "sha256=<hex>" HMAC-SHA256 signature of `body`. */
  signature: string
}

/**
 * Serialise the envelope and compute its HMAC-SHA256 signature using the
 * Web Crypto API (available in both V8/Convex and edge runtimes).
 */
export async function buildSignedPayload(
  envelope: WebhookEnvelope,
  secret: string,
): Promise<SignedWebhookPayload> {
  const body = JSON.stringify(envelope)
  const signature = await computeHmacSha256(body, secret)
  return { body, signature }
}

async function computeHmacSha256(payload: string, secret: string): Promise<string> {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sigBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(payload))
  const hexParts = [...new Uint8Array(sigBuffer)].map((b) =>
    b.toString(16).padStart(2, '0'),
  )
  return `sha256=${hexParts.join('')}`
}

// ---------------------------------------------------------------------------
// Event filtering
// ---------------------------------------------------------------------------

/**
 * Returns true if the given endpoint should receive this event type.
 * An empty `subscribedEvents` list means "subscribe to everything".
 */
export function isSubscribed(
  subscribedEvents: string[],
  eventType: WebhookEventType,
): boolean {
  return subscribedEvents.length === 0 || subscribedEvents.includes(eventType)
}

// ---------------------------------------------------------------------------
// HTTP delivery
// ---------------------------------------------------------------------------

export type WebhookDeliveryResult = {
  endpointId: string
  url: string
  statusCode: number | null
  success: boolean
  errorMessage: string | null
  durationMs: number
}

/**
 * POST a signed webhook payload to a single endpoint URL.
 * Never throws — failure details are returned in the result object.
 */
export async function postWebhookPayload(
  endpointId: string,
  url: string,
  signed: SignedWebhookPayload,
  deliveryId: string,
): Promise<WebhookDeliveryResult> {
  const startMs = Date.now()
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Signature-256': signed.signature,
        'X-Sentinel-Delivery': deliveryId,
      },
      body: signed.body,
    })
    const durationMs = Date.now() - startMs
    return {
      endpointId,
      url,
      statusCode: res.status,
      success: res.status >= 200 && res.status < 300,
      errorMessage: null,
      durationMs,
    }
  } catch (err) {
    const durationMs = Date.now() - startMs
    return {
      endpointId,
      url,
      statusCode: null,
      success: false,
      errorMessage: err instanceof Error ? err.message : String(err),
      durationMs,
    }
  }
}

// ---------------------------------------------------------------------------
// Validation helpers (used by HTTP endpoint registration)
// ---------------------------------------------------------------------------

export type EndpointValidationResult =
  | { valid: true }
  | { valid: false; reason: string }

// Returns true if the hostname is a private, loopback, or link-local address
// that must not be reachable as a webhook target (SSRF prevention).
export function isPrivateHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '') // strip IPv6 brackets

  if (h === 'localhost' || h === '0.0.0.0' || h === '::' || h === '::1') return true

  // IPv6 private ranges: fc00::/7 (ULA), fe80::/10 (link-local)
  if (/^f[cd]/i.test(h) || /^fe[89ab]/i.test(h)) return true

  // IPv4 private/reserved ranges
  const octets = h.split('.')
  if (octets.length === 4) {
    const [a, b] = octets.map(Number)
    if (octets.every((o) => /^\d+$/.test(o) && Number(o) >= 0 && Number(o) <= 255)) {
      if (a === 0) return true                              // 0.0.0.0/8
      if (a === 10) return true                             // 10.0.0.0/8
      if (a === 127) return true                            // 127.0.0.0/8 loopback
      if (a === 169 && b === 254) return true               // 169.254.0.0/16 link-local
      if (a === 172 && b >= 16 && b <= 31) return true      // 172.16.0.0/12
      if (a === 192 && b === 168) return true               // 192.168.0.0/16
    }
  }

  return false
}

export function validateEndpointUrl(url: string): EndpointValidationResult {
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { valid: false, reason: 'URL must use http or https.' }
    }
    if (isPrivateHostname(parsed.hostname)) {
      return {
        valid: false,
        reason: 'Webhook URLs must not target private, loopback, or link-local addresses.',
      }
    }
    return { valid: true }
  } catch {
    return { valid: false, reason: 'Invalid URL format.' }
  }
}

export function validateSubscribedEvents(events: string[]): EndpointValidationResult {
  const validSet = new Set<string>(ALL_WEBHOOK_EVENT_TYPES)
  for (const e of events) {
    if (!validSet.has(e)) {
      return {
        valid: false,
        reason: `Unknown event type: "${e}". Valid types: ${ALL_WEBHOOK_EVENT_TYPES.join(', ')}.`,
      }
    }
  }
  return { valid: true }
}
