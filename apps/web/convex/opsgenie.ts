/**
 * Sentinel Opsgenie Integration — Alerts API v2
 *
 * Pages on-call engineers for the same high-signal events as PagerDuty:
 *   - Critical/high confirmed findings (EXPLOITED outcome)
 *   - Gate blocked events
 *   - Honeypot triggers (near-certain active breach)
 *
 * Configuration:
 *   npx convex env set OPSGENIE_API_KEY <your-api-key>
 *   npx convex env set OPSGENIE_TEAM_ID <your-team-id>        (optional)
 *   npx convex env set OPSGENIE_SEVERITY_THRESHOLD "critical"  (critical|high, default critical)
 *
 * Opsgenie setup:
 *   Settings → API key management → Add new API key (read/write for Alerts)
 *   (for EU use https://api.eu.opsgenie.com/v2 instead of the US endpoint)
 *
 * Alert dedup:
 *   Every alert carries a deterministic `alias` so re-triggers are idempotent.
 */

import { v } from "convex/values";
import { internalAction } from "./_generated/server";
import {
  buildCreateAlertBody,
  buildCloseAlertBody,
  buildOpsgenieAlias,
  type OpsgenieAlertKind,
} from "./lib/opsgeniePayload";

// Opsgenie base URL — can be overridden for EU regions
const OPSGENIE_BASE = "https://api.opsgenie.com";

// ── Core create / close helpers ───────────────────────────────────────────────

async function createOpsgenieAlert(
  apiKey: string,
  body: ReturnType<typeof buildCreateAlertBody>,
): Promise<{ ok: boolean; status: number; requestId?: string }> {
  const resp = await fetch(`${OPSGENIE_BASE}/v2/alerts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `GenieKey ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  const text = await resp.text().catch(() => "");
  if (!resp.ok) {
    console.error(`[opsgenie] create alert failed: ${resp.status} — ${text}`);
  }

  let requestId: string | undefined;
  try {
    const json = JSON.parse(text) as { requestId?: string };
    requestId = json.requestId;
  } catch {
    // ignore parse errors
  }

  return { ok: resp.ok, status: resp.status, requestId };
}

async function closeOpsgenieAlert(
  apiKey: string,
  alias: string,
  note?: string,
): Promise<{ ok: boolean; status: number }> {
  const body = buildCloseAlertBody(note);
  const resp = await fetch(
    `${OPSGENIE_BASE}/v2/alerts/${encodeURIComponent(alias)}/close`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `GenieKey ${apiKey}`,
      },
      body: JSON.stringify(body),
    },
  );

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error(`[opsgenie] close alert failed: ${resp.status} — ${text}`);
  }

  return { ok: resp.ok, status: resp.status };
}

// ── Severity threshold helper (mirrors PagerDuty impl) ────────────────────────

function meetsOpsgenieThreshold(
  severity: string | undefined,
  threshold: string,
): boolean {
  const order = ["critical", "high", "medium", "low", "informational"];
  const sevIdx = order.indexOf((severity ?? "").toLowerCase());
  const thrIdx = order.indexOf(threshold.toLowerCase());
  if (sevIdx === -1 || thrIdx === -1) return false;
  return sevIdx <= thrIdx;
}

// ── Public internalActions ────────────────────────────────────────────────────

/**
 * Create an Opsgenie alert for a Sentinel event.
 * Ignores findings below OPSGENIE_SEVERITY_THRESHOLD (default: critical).
 * Honeypot triggers bypass the threshold and always page.
 */
export const sendOpsgenieAlert = internalAction({
  args: {
    kind: v.union(
      v.literal("critical_finding"),
      v.literal("gate_blocked"),
      v.literal("honeypot_triggered"),
    ),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    severity: v.optional(v.string()),
    title: v.optional(v.string()),
    summary: v.optional(v.string()),
    vulnClass: v.optional(v.string()),
    findingId: v.optional(v.string()),
  },
  handler: async (_ctx, args) => {
    const apiKey = process.env.OPSGENIE_API_KEY;
    if (!apiKey) {
      console.log("[opsgenie] OPSGENIE_API_KEY not set — skipping alert");
      return { sent: false, reason: "no_api_key" };
    }

    const threshold = process.env.OPSGENIE_SEVERITY_THRESHOLD ?? "critical";

    // Severity gating — honeypots always fire
    if (
      args.kind !== "honeypot_triggered" &&
      !meetsOpsgenieThreshold(args.severity, threshold)
    ) {
      return { sent: false, reason: "below_threshold" };
    }

    const body = buildCreateAlertBody({
      kind: args.kind as OpsgenieAlertKind,
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      severity: args.severity,
      title: args.title,
      summary: args.summary,
      vulnClass: args.vulnClass,
      findingId: args.findingId,
      teamId: process.env.OPSGENIE_TEAM_ID,
    });

    const result = await createOpsgenieAlert(apiKey, body);
    return {
      sent: result.ok,
      status: result.status,
      requestId: result.requestId,
      alias: body.alias,
    };
  },
});

/**
 * Page the on-call team for a confirmed critical finding.
 * Convenience wrapper — calls the core alert HTTP helper directly.
 */
export const pageOnConfirmedExploit = internalAction({
  args: {
    findingId: v.string(),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    severity: v.string(),
    title: v.string(),
    summary: v.optional(v.string()),
    vulnClass: v.optional(v.string()),
  },
  handler: async (_ctx, args): Promise<{ sent: boolean; reason?: string; status?: number; alias?: string }> => {
    const apiKey = process.env.OPSGENIE_API_KEY;
    if (!apiKey) return { sent: false, reason: "no_api_key" };

    const threshold = process.env.OPSGENIE_SEVERITY_THRESHOLD ?? "critical";
    if (!meetsOpsgenieThreshold(args.severity, threshold)) {
      return { sent: false, reason: "below_threshold" };
    }

    const body = buildCreateAlertBody({
      kind: "critical_finding",
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      severity: args.severity,
      title: args.title,
      summary: args.summary,
      vulnClass: args.vulnClass,
      findingId: args.findingId,
      teamId: process.env.OPSGENIE_TEAM_ID,
    });
    const result = await createOpsgenieAlert(apiKey, body);
    return { sent: result.ok, status: result.status, alias: body.alias };
  },
});

/**
 * Page for a honeypot trigger.  Always P1 regardless of configuration.
 */
export const pageOnHoneypotTrigger = internalAction({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    honeyType: v.optional(v.string()),
    detail: v.optional(v.string()),
  },
  handler: async (_ctx, args): Promise<{ sent: boolean; reason?: string; status?: number; alias?: string }> => {
    const apiKey = process.env.OPSGENIE_API_KEY;
    if (!apiKey) return { sent: false, reason: "no_api_key" };

    const body = buildCreateAlertBody({
      kind: "honeypot_triggered",
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      severity: "critical",
      summary: args.detail,
      teamId: process.env.OPSGENIE_TEAM_ID,
    });
    const result = await createOpsgenieAlert(apiKey, body);
    return { sent: result.ok, status: result.status, alias: body.alias };
  },
});

/**
 * Close an Opsgenie alert by its deterministic alias.
 * Called after post-fix validation confirms a finding is resolved.
 */
export const resolveOpsgenieAlert = internalAction({
  args: {
    kind: v.union(
      v.literal("critical_finding"),
      v.literal("gate_blocked"),
      v.literal("honeypot_triggered"),
    ),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    findingId: v.optional(v.string()),
    note: v.optional(v.string()),
  },
  handler: async (_ctx, args) => {
    const apiKey = process.env.OPSGENIE_API_KEY;
    if (!apiKey) return { closed: false, reason: "no_api_key" };

    const alias = buildOpsgenieAlias({
      kind: args.kind as OpsgenieAlertKind,
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      findingId: args.findingId,
    });

    const result = await closeOpsgenieAlert(apiKey, alias, args.note);
    return { closed: result.ok, status: result.status, alias };
  },
});

