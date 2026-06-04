/**
 * PostHog Event Taxonomy — Analytics wrapper for CyberZen
 *
 * Provides a typed `track()` function that wraps `posthog.capture()`.
 * All instrumented events are declared here as a typed map so the
 * compiler catches typos and keeps the taxonomy consistent.
 *
 * Usage:
 *   import { track } from '@/lib/analytics'
 *   track('finding.triaged', { severity: 'critical', action: 'false_positive' })
 */

type EventName =
  | 'finding.triaged'
  | 'finding.accepted_risk'
  | 'gate.overridden'
  | 'pr.generated'
  | 'scan.triggered'
  | 'repo.connected'
  | 'member.invited'
  | 'export.run'

interface EventProperties {
  'finding.triaged': {
    severity: string
    action: string
    findingId?: string
    repositoryName?: string
  }
  'finding.accepted_risk': {
    findingId?: string
    severity?: string
    justification?: string
    expiryDays?: number
  }
  'gate.overridden': {
    gateDecisionId?: string
    repositoryName?: string
    findingTitle?: string
    actorType?: string
  }
  'pr.generated': {
    proposalId?: string
    repositoryName?: string
    findingTitle?: string
    fixType?: string
  }
  'scan.triggered': {
    scannerSlug: string
    repositoryName?: string
    triggerType: 'manual' | 'scheduled' | 'webhook'
  }
  'repo.connected': {
    provider: string
    repositoryName?: string
    repositoryCount?: number
  }
  'member.invited': {
    role?: string
    hasRoleId?: boolean
  }
  'export.run': {
    format: 'csv' | 'pdf'
    scope: string
    recordCount?: number
  }
}

/**
 * Capture an analytics event via PostHog (if available).
 * Gracefully no-ops when PostHog is not initialised (e.g. local dev,
 * missing NEXT_PUBLIC_POSTHOG_KEY).
 */
export function track<E extends EventName>(
  name: E,
  props: EventProperties[E],
): void {
  try {
    // Dynamic import guard — PostHog may not be present in all builds
    const ph = (globalThis as any)?.posthog
    if (ph && typeof ph.capture === 'function') {
      ph.capture(name, props as Record<string, unknown>)
    }
  } catch {
    // Silently swallow — analytics must never break the app
  }

  if (import.meta.env?.DEV) {
    console.debug(`[analytics] ${name}`, props)
  }
}

/**
 * Event names as a const array — useful for building type-safe pickers
 * or for documentation generation.
 */
export const ANALYTICS_EVENTS: readonly EventName[] = [
  'finding.triaged',
  'finding.accepted_risk',
  'gate.overridden',
  'pr.generated',
  'scan.triggered',
  'repo.connected',
  'member.invited',
  'export.run',
] as const
