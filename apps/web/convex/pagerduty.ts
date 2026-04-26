/**
 * PagerDuty Integration — Events API v2
 *
 * Pages on-call engineers for critical security events that require
 * immediate human response. Only fires for the highest-severity events:
 *   - Critical or high confirmed findings (EXPLOITED outcome)
 *   - Honeypot triggers (near-certain active breach)
 *   - Trust score compromised on a direct dependency
 *
 * Configuration:
 *   npx convex env set PAGERDUTY_INTEGRATION_KEY <routing-key>
 *   npx convex env set PAGERDUTY_SEVERITY_THRESHOLD "critical"  (critical|high, default critical)
 *
 * PagerDuty setup:
 *   Service → Integrations → Events API v2 → copy Routing Key
 *   → paste as PAGERDUTY_INTEGRATION_KEY in Convex env
 */

import { v } from "convex/values";
import { internalAction } from "./_generated/server";
import { internal } from "./_generated/api";

// ── PagerDuty Events API v2 types ─────────────────────────────────────────────

type PdSeverity = "critical" | "error" | "warning" | "info";

type PdPayload = {
  summary: string;       // max 1024 chars
  source: string;        // service/tool that generated the event
  severity: PdSeverity;
  timestamp?: string;    // ISO 8601
  component?: string;    // e.g. "auth-service"
  group?: string;        // e.g. "repository / tenant"
  class?: string;        // e.g. "SQL Injection"
  custom_details?: Record<string, unknown>;
};

type PdEventPayload = {
  routing_key: string;
  event_action: "trigger" | "acknowledge" | "resolve";
  dedup_key?: string;  // For de-duplication across retries
  payload: PdPayload;
  links?: Array<{ href: string; text: string }>;
};

// ── Severity mapping ──────────────────────────────────────────────────────────

function sentinelSeverityToPd(severity: string | undefined): PdSeverity {
  switch ((severity ?? "").toLowerCase()) {
    case "critical": return "critical";
    case "high":     return "error";
    case "medium":   return "warning";
    default:         return "info";
  }
}

// ── Core action ───────────────────────────────────────────────────────────────

export const sendPagerDutyAlert = internalAction({
  args: {
    eventAction: v.union(v.literal("trigger"), v.literal("acknowledge"), v.literal("resolve")),
    dedupKey: v.optional(v.string()),
    summary: v.string(),
    severity: v.optional(v.string()),
    source: v.string(),
    component: v.optional(v.string()),
    group: v.optional(v.string()),
    vulnClass: v.optional(v.string()),
    repositoryFullName: v.string(),
    tenantSlug: v.string(),
    findingId: v.optional(v.string()),
    prUrl: v.optional(v.string()),
    extraDetails: v.optional(v.any()),
  },
  handler: async (_ctx, args) => {
    const routingKey = process.env.PAGERDUTY_INTEGRATION_KEY;
    if (!routingKey) {
      console.log("[pagerduty] PAGERDUTY_INTEGRATION_KEY not set — skipping");
      return { sent: false, reason: "no_routing_key" };
    }

    const minSeverity = (process.env.PAGERDUTY_SEVERITY_THRESHOLD ?? "critical").toLowerCase();

    // Only page if severity meets threshold
    if (args.eventAction === "trigger") {
      const severityOrder = ["critical", "high", "medium", "low", "informational"];
      const argSev = (args.severity ?? "low").toLowerCase();
      const argIdx = severityOrder.indexOf(argSev);
      const minIdx = severityOrder.indexOf(minSeverity);
      if (argIdx > minIdx) {
        return { sent: false, reason: "below_threshold" };
      }
    }

    const pdPayload: PdEventPayload = {
      routing_key: routingKey,
      event_action: args.eventAction,
      dedup_key: args.dedupKey,
      payload: {
        summary: args.summary.slice(0, 1024),
        source: "Sentinel Security Agent",
        severity: sentinelSeverityToPd(args.severity),
        timestamp: new Date().toISOString(),
        component: args.component ?? args.repositoryFullName,
        group: `${args.tenantSlug} / ${args.repositoryFullName}`,
        class: args.vulnClass,
        custom_details: {
          repository: args.repositoryFullName,
          tenant: args.tenantSlug,
          finding_id: args.findingId,
          pr_url: args.prUrl,
          source_system: args.source,
          ...(args.extraDetails as Record<string, unknown> | undefined ?? {}),
        },
      },
      links: [
        ...(args.prUrl ? [{ href: args.prUrl, text: "View Fix PR" }] : []),
        {
          href: `https://sentinelsec.io/dashboard/${args.tenantSlug}`,
          text: "View in Sentinel Dashboard",
        },
      ],
    };

    const resp = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Routing-Key": routingKey,
      },
      body: JSON.stringify(pdPayload),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error(`[pagerduty] alert failed: ${resp.status} — ${body.slice(0, 200)}`);
      return { sent: false, reason: `http_${resp.status}` };
    }

    const data = await resp.json() as { status?: string; dedup_key?: string };
    console.log(`[pagerduty] alert sent: ${data.status} dedup_key=${data.dedup_key}`);
    return { sent: true, dedupKey: data.dedup_key };
  },
});

// ── Convenience wrappers called from other modules ────────────────────────────

export const pageOnConfirmedExploit = internalAction({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    findingId: v.string(),
    findingTitle: v.string(),
    severity: v.string(),
    vulnClass: v.string(),
    blastRadiusSummary: v.string(),
    prUrl: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.runAction(internal.pagerduty.sendPagerDutyAlert, {
      eventAction: "trigger",
      dedupKey: `sentinel-finding-${args.findingId}`,
      summary: `[${args.severity.toUpperCase()}] Confirmed exploit: ${args.findingTitle} in ${args.repositoryFullName}`,
      severity: args.severity,
      source: "Sentinel Exploit Validation Engine",
      component: args.repositoryFullName,
      vulnClass: args.vulnClass,
      repositoryFullName: args.repositoryFullName,
      tenantSlug: args.tenantSlug,
      findingId: args.findingId,
      prUrl: args.prUrl,
      extraDetails: { blast_radius: args.blastRadiusSummary },
    });
  },
});

export const pageOnHoneypotTrigger = internalAction({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    honeypotPath: v.string(),
    honeypotKind: v.string(),
    sourceIdentifier: v.optional(v.string()),
  },
  handler: async (_ctx, args) => {
    // Honeypots always page — they're near-certain breach indicators
    const routingKey = process.env.PAGERDUTY_INTEGRATION_KEY;
    if (!routingKey) return;

    const payload: PdEventPayload = {
      routing_key: routingKey,
      event_action: "trigger",
      dedup_key: `sentinel-honeypot-${args.repositoryFullName}-${args.honeypotPath}`,
      payload: {
        summary: `🍯 HONEYPOT TRIGGERED — Possible active breach in ${args.repositoryFullName}`,
        source: "Sentinel Honeypot Monitor",
        severity: "critical",
        timestamp: new Date().toISOString(),
        component: args.honeypotPath,
        group: `${args.tenantSlug} / ${args.repositoryFullName}`,
        class: "honeypot_trigger",
        custom_details: {
          honeypot_path: args.honeypotPath,
          honeypot_kind: args.honeypotKind,
          source_identifier: args.sourceIdentifier,
          repository: args.repositoryFullName,
          tenant: args.tenantSlug,
          action_required: "Investigate immediately — canary asset accessed",
        },
      },
    };

    await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  },
});

export const resolveIncident = internalAction({
  args: {
    dedupKey: v.string(),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    resolution: v.string(),
  },
  handler: async (_ctx, args) => {
    const routingKey = process.env.PAGERDUTY_INTEGRATION_KEY;
    if (!routingKey) return;

    await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "resolve",
        dedup_key: args.dedupKey,
        payload: {
          summary: args.resolution,
          source: "Sentinel Security Agent",
          severity: "info" as PdSeverity,
          custom_details: {
            repository: args.repositoryFullName,
            tenant: args.tenantSlug,
          },
        },
      } satisfies PdEventPayload),
    });
  },
});

