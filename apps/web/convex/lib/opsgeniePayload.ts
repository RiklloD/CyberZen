// Opsgenie Alerts API v2 payload builder — pure, no Convex dependencies.
//
// The Opsgenie API distinguishes alert creation (POST /v2/alerts) from
// closure (POST /v2/alerts/{alias}/close).  This library builds the
// typed request bodies for both operations.
//
// Documentation:
//   https://docs.opsgenie.com/docs/alert-api#create-alert
//   https://docs.opsgenie.com/docs/alert-api#close-alert

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Opsgenie P1–P5 priority levels. */
export type OpsgeniePriority = 'P1' | 'P2' | 'P3' | 'P4' | 'P5'

/** Opsgenie responder — either a team or a user. */
export type OpsgenieResponder =
  | { type: 'team'; id: string }
  | { type: 'user'; id: string }
  | { type: 'escalation'; id: string }
  | { type: 'schedule'; id: string }

/** Body sent to POST /v2/alerts */
export interface OpsgenieCreateAlertBody {
  message: string          // max 130 chars, required
  alias?: string           // dedup key, max 512 chars
  description?: string     // max 15000 chars
  responders?: OpsgenieResponder[]
  priority?: OpsgeniePriority
  tags?: string[]
  details?: Record<string, string>
  source?: string          // free-form source label
  entity?: string          // related entity (repo name)
  note?: string            // additional human note
}

/** Body sent to POST /v2/alerts/{alias}/close */
export interface OpsgenieCloseAlertBody {
  user?: string
  source?: string
  note?: string
}

/** Opsgenie alert kinds recognised by the integration. */
export type OpsgenieAlertKind =
  | 'critical_finding'
  | 'gate_blocked'
  | 'honeypot_triggered'

export interface OpsgenieAlertInput {
  kind: OpsgenieAlertKind
  tenantSlug: string
  repositoryFullName: string
  severity?: string
  title?: string
  summary?: string
  vulnClass?: string
  findingId?: string
  teamId?: string     // optional: OPSGENIE_TEAM_ID env value
}

// ---------------------------------------------------------------------------
// Priority mapping
// ---------------------------------------------------------------------------

/** Maps a Sentinel severity to an Opsgenie P1–P5 priority. */
export function sentinelSeverityToOpsgenieP(severity: string | undefined): OpsgeniePriority {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'P1'
    case 'high':     return 'P2'
    case 'medium':   return 'P3'
    case 'low':      return 'P4'
    default:         return 'P3'
  }
}

// ---------------------------------------------------------------------------
// Alias (dedup key) generator
// ---------------------------------------------------------------------------

/** Builds a deterministic dedup key for an alert so retries are idempotent. */
export function buildOpsgenieAlias(input: {
  kind: OpsgenieAlertKind
  tenantSlug: string
  repositoryFullName: string
  findingId?: string
}): string {
  const base = `sentinel-${input.kind}-${input.tenantSlug}-${input.repositoryFullName.replace('/', '-')}`
  return input.findingId ? `${base}-${input.findingId}` : base
}

// ---------------------------------------------------------------------------
// Create-alert body builder
// ---------------------------------------------------------------------------

/**
 * Builds the request body for POST /v2/alerts.
 * Pure function — safe to call in unit tests.
 */
export function buildCreateAlertBody(input: OpsgenieAlertInput): OpsgenieCreateAlertBody {
  const alias = buildOpsgenieAlias({
    kind: input.kind,
    tenantSlug: input.tenantSlug,
    repositoryFullName: input.repositoryFullName,
    findingId: input.findingId,
  })

  const priority = input.kind === 'honeypot_triggered'
    ? 'P1'   // honeypots are always P1 regardless of severity field
    : sentinelSeverityToOpsgenieP(input.severity)

  const message = buildMessage(input).slice(0, 130)
  const description = buildDescription(input)

  const responders: OpsgenieResponder[] = input.teamId
    ? [{ type: 'team', id: input.teamId }]
    : []

  const tags: string[] = [
    'sentinel',
    input.kind.replace(/_/g, '-'),
    `severity:${input.severity ?? 'unknown'}`,
  ]

  const details: Record<string, string> = {
    repository: input.repositoryFullName,
    tenant: input.tenantSlug,
    kind: input.kind,
  }
  if (input.vulnClass) details.vuln_class = input.vulnClass
  if (input.findingId) details.finding_id = input.findingId

  return {
    message,
    alias,
    description,
    responders,
    priority,
    tags,
    details,
    source: 'Sentinel Security Agent',
    entity: input.repositoryFullName,
  }
}

function buildMessage(input: OpsgenieAlertInput): string {
  switch (input.kind) {
    case 'critical_finding':
      return `[Sentinel] ${(input.severity ?? 'unknown').toUpperCase()} Finding: ${input.title ?? 'Confirmed exploit in ' + input.repositoryFullName}`
    case 'gate_blocked':
      return `[Sentinel] CI Gate Blocked: ${input.repositoryFullName}`
    case 'honeypot_triggered':
      return `[Sentinel] 🍯 HONEYPOT TRIGGERED — Possible Active Breach in ${input.repositoryFullName}`
    default:
      return `[Sentinel] Security Alert — ${input.repositoryFullName}`
  }
}

function buildDescription(input: OpsgenieAlertInput): string {
  const lines: string[] = []

  if (input.kind === 'honeypot_triggered') {
    lines.push('A canary asset was accessed. This is a HIGH-CONFIDENCE breach indicator.')
    lines.push('Investigate immediately.')
  } else if (input.kind === 'gate_blocked') {
    lines.push(`CI gate blocked due to a confirmed ${input.severity ?? 'unknown'} severity finding.`)
    if (input.title) lines.push(`Finding: ${input.title}`)
  } else {
    if (input.title) lines.push(`Finding: ${input.title}`)
  }

  if (input.summary) lines.push('', input.summary.slice(0, 500))
  if (input.vulnClass) lines.push(`Vulnerability class: ${input.vulnClass}`)

  lines.push('', `Repository: ${input.repositoryFullName}`)
  lines.push(`Tenant: ${input.tenantSlug}`)

  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Close-alert body builder
// ---------------------------------------------------------------------------

export function buildCloseAlertBody(note?: string): OpsgenieCloseAlertBody {
  return {
    source: 'Sentinel Security Agent',
    note: note ?? 'Finding resolved — post-fix validation passed.',
  }
}
