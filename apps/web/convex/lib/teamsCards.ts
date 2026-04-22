// Microsoft Teams Adaptive Card builder — pure, no Convex dependencies.
//
// Teams incoming webhooks accept an "Office 365 Connector" payload OR the newer
// "Workflow" Power Automate format.  We use the Adaptive Card format which
// works with both the legacy O365 Connector endpoint and the newer Workflows
// approach:
//
//   POST <TEAMS_WEBHOOK_URL>
//   Content-Type: application/json
//
//   {
//     "type": "message",
//     "attachments": [{
//       "contentType": "application/vnd.microsoft.card.adaptive",
//       "contentUrl": null,
//       "content": { <AdaptiveCard> }
//     }]
//   }
//
// Adaptive Card spec: https://adaptivecards.io/
// Teams card samples:  https://docs.microsoft.com/en-us/adaptive-cards/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TeamsAlertKind =
  | 'finding_validated'
  | 'gate_blocked'
  | 'honeypot_triggered'
  | 'posture_digest'

export interface TeamsAlertPayload {
  kind: TeamsAlertKind
  tenantSlug: string
  repositoryFullName: string
  severity?: string
  title?: string
  summary?: string
  vulnClass?: string
  blastRadiusSummary?: string
  prUrl?: string
  findingId?: string
  extraContext?: string
}

// ── Adaptive Card primitive elements ──────────────────────────────────────────

type AdaptiveTextBlock = {
  type: 'TextBlock'
  text: string
  size?: 'Small' | 'Default' | 'Medium' | 'Large' | 'ExtraLarge'
  weight?: 'Lighter' | 'Default' | 'Bolder'
  color?: 'Default' | 'Dark' | 'Light' | 'Accent' | 'Good' | 'Warning' | 'Attention'
  wrap?: boolean
  spacing?: 'None' | 'Small' | 'Default' | 'Medium' | 'Large' | 'ExtraLarge' | 'Padding'
  isSubtle?: boolean
}

type AdaptiveFactSet = {
  type: 'FactSet'
  facts: Array<{ title: string; value: string }>
}

type AdaptiveContainer = {
  type: 'Container'
  style?: 'default' | 'emphasis' | 'good' | 'attention' | 'warning' | 'accent'
  items: AdaptiveElement[]
}

type AdaptiveColumnSet = {
  type: 'ColumnSet'
  columns: Array<{
    type: 'Column'
    width: 'auto' | 'stretch' | string
    items: AdaptiveElement[]
  }>
}

type AdaptiveElement =
  | AdaptiveTextBlock
  | AdaptiveFactSet
  | AdaptiveContainer
  | AdaptiveColumnSet

type AdaptiveAction = {
  type: 'Action.OpenUrl'
  title: string
  url: string
  style?: 'default' | 'positive' | 'destructive'
}

export interface AdaptiveCardContent {
  $schema: 'http://adaptivecards.io/schemas/adaptive-card.json'
  type: 'AdaptiveCard'
  version: '1.4'
  body: AdaptiveElement[]
  actions?: AdaptiveAction[]
  msteams?: { width: 'Full' | 'Auto' }
}

export interface TeamsWebhookPayload {
  type: 'message'
  attachments: Array<{
    contentType: 'application/vnd.microsoft.card.adaptive'
    contentUrl: null
    content: AdaptiveCardContent
  }>
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

/** Maps Sentinel severity to an Adaptive Card `color` value. */
export function severityToColor(
  severity: string | undefined,
): AdaptiveTextBlock['color'] {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'Attention'
    case 'high':     return 'Warning'
    case 'medium':   return 'Accent'
    case 'low':      return 'Good'
    default:         return 'Default'
  }
}

/** Returns a short emoji + text label for severity. */
export function severityLabel(severity: string | undefined): string {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return '🔴 CRITICAL'
    case 'high':     return '🟠 HIGH'
    case 'medium':   return '🟡 MEDIUM'
    case 'low':      return '🔵 LOW'
    default:         return '⚪ UNKNOWN'
  }
}

// ---------------------------------------------------------------------------
// Card builders
// ---------------------------------------------------------------------------

function buildFindingValidatedCard(p: TeamsAlertPayload): AdaptiveCardContent {
  const body: AdaptiveElement[] = [
    {
      type: 'TextBlock',
      text: `🔍 [SENTINEL] ${severityLabel(p.severity)} Finding Confirmed`,
      size: 'Large',
      weight: 'Bolder',
      color: severityToColor(p.severity),
      wrap: true,
    },
    {
      type: 'TextBlock',
      text: p.title ?? 'Untitled finding',
      size: 'Medium',
      weight: 'Bolder',
      wrap: true,
    },
    {
      type: 'FactSet',
      facts: [
        { title: 'Repository', value: p.repositoryFullName },
        { title: 'Vulnerability Class', value: p.vulnClass ?? 'Unknown' },
        { title: 'Severity', value: severityLabel(p.severity) },
        { title: 'Tenant', value: p.tenantSlug },
      ],
    },
  ]

  if (p.summary) {
    body.push({
      type: 'TextBlock',
      text: p.summary.slice(0, 300),
      wrap: true,
      spacing: 'Medium',
    })
  }

  if (p.blastRadiusSummary) {
    body.push({
      type: 'Container',
      style: 'emphasis',
      items: [
        {
          type: 'TextBlock',
          text: `💥 Blast Radius: ${p.blastRadiusSummary.slice(0, 200)}`,
          wrap: true,
          isSubtle: true,
        },
      ],
    })
  }

  body.push({
    type: 'TextBlock',
    text: `Sentinel Security Agent · ${new Date().toUTCString()}`,
    isSubtle: true,
    size: 'Small',
    spacing: 'Medium',
  })

  const actions: AdaptiveAction[] = []
  if (p.prUrl) {
    actions.push({
      type: 'Action.OpenUrl',
      title: 'Review Fix PR',
      url: p.prUrl,
      style: 'positive',
    })
  }

  return {
    $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
    type: 'AdaptiveCard',
    version: '1.4',
    body,
    ...(actions.length > 0 ? { actions } : {}),
    msteams: { width: 'Full' },
  }
}

function buildGateBlockedCard(p: TeamsAlertPayload): AdaptiveCardContent {
  const body: AdaptiveElement[] = [
    {
      type: 'TextBlock',
      text: '🚫 [SENTINEL] CI Gate Blocked',
      size: 'Large',
      weight: 'Bolder',
      color: 'Attention',
      wrap: true,
    },
    {
      type: 'TextBlock',
      text: `A deployment was blocked due to a confirmed ${severityLabel(p.severity)} finding.`,
      wrap: true,
    },
    {
      type: 'FactSet',
      facts: [
        { title: 'Repository', value: p.repositoryFullName },
        { title: 'Finding', value: p.title ?? 'Unknown' },
        { title: 'Severity', value: severityLabel(p.severity) },
        { title: 'Tenant', value: p.tenantSlug },
      ],
    },
  ]

  if (p.summary) {
    body.push({
      type: 'TextBlock',
      text: p.summary.slice(0, 300),
      wrap: true,
      spacing: 'Medium',
    })
  }

  body.push({
    type: 'TextBlock',
    text: `Sentinel Security Agent · ${new Date().toUTCString()}`,
    isSubtle: true,
    size: 'Small',
    spacing: 'Medium',
  })

  return {
    $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
    type: 'AdaptiveCard',
    version: '1.4',
    body,
    msteams: { width: 'Full' },
  }
}

function buildHoneypotTriggeredCard(p: TeamsAlertPayload): AdaptiveCardContent {
  const body: AdaptiveElement[] = [
    {
      type: 'TextBlock',
      text: '🍯 [SENTINEL] HONEYPOT TRIGGERED — Possible Active Breach',
      size: 'Large',
      weight: 'Bolder',
      color: 'Attention',
      wrap: true,
    },
    {
      type: 'TextBlock',
      text: `A canary asset in \`${p.repositoryFullName}\` was accessed. This is a high-confidence breach indicator. Investigate immediately.`,
      wrap: true,
      color: 'Attention',
    },
  ]

  if (p.extraContext) {
    body.push({
      type: 'Container',
      style: 'attention',
      items: [
        {
          type: 'TextBlock',
          text: p.extraContext.slice(0, 300),
          wrap: true,
        },
      ],
    })
  }

  body.push({
    type: 'TextBlock',
    text: `⚠️ Investigate immediately · ${new Date().toUTCString()}`,
    isSubtle: true,
    size: 'Small',
    spacing: 'Medium',
  })

  return {
    $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
    type: 'AdaptiveCard',
    version: '1.4',
    body,
    msteams: { width: 'Full' },
  }
}

// ---------------------------------------------------------------------------
// Public: build Teams webhook payload
// ---------------------------------------------------------------------------

/**
 * Builds a complete Teams webhook JSON payload for any alert kind.
 * Pure function — safe to call in tests without side effects.
 */
export function buildTeamsPayload(p: TeamsAlertPayload): TeamsWebhookPayload {
  let content: AdaptiveCardContent
  switch (p.kind) {
    case 'finding_validated':
      content = buildFindingValidatedCard(p)
      break
    case 'gate_blocked':
      content = buildGateBlockedCard(p)
      break
    case 'honeypot_triggered':
      content = buildHoneypotTriggeredCard(p)
      break
    default:
      content = buildFindingValidatedCard(p)
  }

  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        contentUrl: null,
        content,
      },
    ],
  }
}

// ---------------------------------------------------------------------------
// Severity filter helper (shared with teams.ts action)
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']

/**
 * Returns true when `severity` meets or exceeds `minSeverity`.
 * e.g. meetsMinSeverity('critical', 'high') → true
 *      meetsMinSeverity('low', 'high')      → false
 */
export function meetsMinSeverity(
  severity: string | undefined,
  minSeverity: string,
): boolean {
  const sev = (severity ?? 'low').toLowerCase()
  const min = minSeverity.toLowerCase()
  const sevIdx = SEVERITY_ORDER.indexOf(sev)
  const minIdx = SEVERITY_ORDER.indexOf(min)
  if (sevIdx === -1 || minIdx === -1) return false
  return sevIdx <= minIdx
}
