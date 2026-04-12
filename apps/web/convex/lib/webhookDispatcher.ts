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

export function validateEndpointUrl(url: string): EndpointValidationResult {
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { valid: false, reason: 'URL must use http or https.' }
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
