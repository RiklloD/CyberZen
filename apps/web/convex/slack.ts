"use node";
/**
 * Sentinel Slack Integration
 *
 * Sends rich Block Kit alert cards to a Slack webhook for:
 *   - Critical / high validated findings
 *   - Gate blocked events
 *   - Honeypot triggers (immediate breach indicator)
 *   - Weekly security posture digest (scheduled)
 *
 * Configuration:
 *   npx convex env set SLACK_WEBHOOK_URL https://hooks.slack.com/services/...
 *   npx convex env set SLACK_ALERT_CHANNEL "#security-alerts"  (optional label only)
 *   npx convex env set SLACK_MIN_SEVERITY "high"               (critical|high|medium, default high)
 */

import { v } from "convex/values";
import { internalAction, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Types ─────────────────────────────────────────────────────────────────────

type SlackBlock =
  | { type: "section"; text: { type: "mrkdwn"; text: string } }
  | { type: "section"; fields: Array<{ type: "mrkdwn"; text: string }> }
  | { type: "divider" }
  | { type: "context"; elements: Array<{ type: "mrkdwn"; text: string }> }
  | { type: "actions"; elements: Array<{ type: "button"; text: { type: "plain_text"; text: string }; url: string; style?: string }> };

export type SlackAlertKind =
  | "finding_validated"
  | "gate_blocked"
  | "honeypot_triggered"
  | "posture_digest";

interface SlackAlertPayload {
  kind: SlackAlertKind;
  tenantSlug: string;
  repositoryFullName: string;
  severity?: string;
  title?: string;
  summary?: string;
  vulnClass?: string;
  blastRadiusSummary?: string;
  prUrl?: string;
  findingId?: string;
  extraContext?: string;
}

// ── Severity emoji ────────────────────────────────────────────────────────────

function severityEmoji(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case "critical": return "🔴";
    case "high":     return "🟠";
    case "medium":   return "🟡";
    case "low":      return "🔵";
    default:         return "⚪";
  }
}

function severityLabel(severity: string | undefined): string {
  return (severity ?? "unknown").toUpperCase();
}

// ── Block Kit builders ────────────────────────────────────────────────────────

function buildFindingValidatedBlocks(p: SlackAlertPayload): SlackBlock[] {
  const emoji = severityEmoji(p.severity);
  const blocks: SlackBlock[] = [
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${emoji} *[SENTINEL] ${severityLabel(p.severity)} Finding Confirmed*\n*${p.title ?? "Untitled finding"}*`,
      },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Repository*\n\`${p.repositoryFullName}\`` },
        { type: "mrkdwn", text: `*Class*\n\`${p.vulnClass ?? "unknown"}\`` },
        { type: "mrkdwn", text: `*Severity*\n${emoji} ${severityLabel(p.severity)}` },
        { type: "mrkdwn", text: `*Tenant*\n${p.tenantSlug}` },
      ],
    },
  ];

  if (p.summary) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Summary*\n${p.summary.slice(0, 300)}` },
    });
  }

  if (p.blastRadiusSummary) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Blast Radius*\n${p.blastRadiusSummary.slice(0, 200)}` },
    });
  }

  const actions: Array<{ type: "button"; text: { type: "plain_text"; text: string }; url: string; style?: string }> = [];

  if (p.prUrl) {
    actions.push({
      type: "button",
      text: { type: "plain_text", text: "Review Fix PR" },
      url: p.prUrl,
      style: "primary",
    });
  }

  if (actions.length > 0) {
    blocks.push({ type: "actions", elements: actions });
  }

  blocks.push({
    type: "context",
    elements: [{ type: "mrkdwn", text: `Sentinel Security Agent · ${new Date().toUTCString()}` }],
  });

  return blocks;
}

function buildGateBlockedBlocks(p: SlackAlertPayload): SlackBlock[] {
  return [
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `🚫 *[SENTINEL] CI Gate Blocked*\nA deployment was blocked due to a confirmed ${severityLabel(p.severity)} finding.`,
      },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Repository*\n\`${p.repositoryFullName}\`` },
        { type: "mrkdwn", text: `*Finding*\n${p.title ?? "Unknown"}` },
        { type: "mrkdwn", text: `*Severity*\n${severityEmoji(p.severity)} ${severityLabel(p.severity)}` },
      ],
    },
    ...(p.summary ? [{
      type: "section" as const,
      text: { type: "mrkdwn" as const, text: p.summary.slice(0, 300) },
    }] : []),
    {
      type: "context",
      elements: [{ type: "mrkdwn", text: `Sentinel Security Agent · ${new Date().toUTCString()}` }],
    },
  ];
}

function buildHoneypotTriggeredBlocks(p: SlackAlertPayload): SlackBlock[] {
  return [
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `🍯 *[SENTINEL] HONEYPOT TRIGGERED — Possible Active Breach*\nA canary asset in \`${p.repositoryFullName}\` was accessed. This is a high-confidence breach indicator.`,
      },
    },
    ...(p.extraContext ? [{
      type: "section" as const,
      text: { type: "mrkdwn" as const, text: `*Details*\n${p.extraContext.slice(0, 300)}` },
    }] : []),
    {
      type: "context",
      elements: [{ type: "mrkdwn", text: `⚠️ Investigate immediately · ${new Date().toUTCString()}` }],
    },
  ];
}

function buildBlocks(p: SlackAlertPayload): SlackBlock[] {
  switch (p.kind) {
    case "finding_validated":   return buildFindingValidatedBlocks(p);
    case "gate_blocked":        return buildGateBlockedBlocks(p);
    case "honeypot_triggered":  return buildHoneypotTriggeredBlocks(p);
    default:                    return buildFindingValidatedBlocks(p);
  }
}

// ── Severity filter ───────────────────────────────────────────────────────────

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

function meetsMinSeverity(severity: string | undefined, minSeverity: string): boolean {
  const sev = (severity ?? "low").toLowerCase();
  const min = minSeverity.toLowerCase();
  const sevIdx = SEVERITY_ORDER.indexOf(sev);
  const minIdx = SEVERITY_ORDER.indexOf(min);
  if (sevIdx === -1 || minIdx === -1) return false;
  return sevIdx <= minIdx; // lower index = higher severity
}

// ── Core dispatch ─────────────────────────────────────────────────────────────

export const sendSlackAlert = internalAction({
  args: {
    kind: v.union(
      v.literal("finding_validated"),
      v.literal("gate_blocked"),
      v.literal("honeypot_triggered"),
      v.literal("posture_digest"),
    ),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    severity: v.optional(v.string()),
    title: v.optional(v.string()),
    summary: v.optional(v.string()),
    vulnClass: v.optional(v.string()),
    blastRadiusSummary: v.optional(v.string()),
    prUrl: v.optional(v.string()),
    findingId: v.optional(v.string()),
    extraContext: v.optional(v.string()),
  },
  handler: async (_ctx, args) => {
    const webhookUrl = process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) {
      console.log("[slack] SLACK_WEBHOOK_URL not set — skipping notification");
      return { sent: false, reason: "no_webhook_url" };
    }

    const minSeverity = process.env.SLACK_MIN_SEVERITY ?? "high";

    // Only alert on findings that meet the severity threshold
    if (
      args.kind === "finding_validated" &&
      !meetsMinSeverity(args.severity, minSeverity)
    ) {
      return { sent: false, reason: "below_min_severity" };
    }

    // Honeypots always alert regardless of severity
    const payload = {
      blocks: buildBlocks(args as SlackAlertPayload),
      // Fallback text for notifications / screen readers
      text: `[Sentinel] ${args.kind.replace(/_/g, " ")} — ${args.repositoryFullName}`,
    };

    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error(`[slack] webhook failed: ${resp.status} — ${body}`);
      return { sent: false, reason: `http_${resp.status}` };
    }

    // Record delivery for audit
    await _ctx.runMutation(internal.slack.recordSlackDelivery, {
      kind: args.kind,
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
      severity: args.severity,
      success: true,
    });

    return { sent: true };
  },
});

// ── Delivery audit ────────────────────────────────────────────────────────────

export const recordSlackDelivery = internalMutation({
  args: {
    kind: v.string(),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    severity: v.optional(v.string()),
    success: v.boolean(),
  },
  handler: async (_ctx, args) => {
    console.log(
      `[slack] delivery recorded: kind=${args.kind} repo=${args.repositoryFullName} severity=${args.severity ?? "?"} success=${args.success}`,
    );
  },
});

// ── Weekly posture digest ─────────────────────────────────────────────────────

export const sendWeeklyPostureDigest = internalAction({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const webhookUrl = process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) return;

    const repos: Array<{ fullName: string; openFindings: number; lastScanned: string }> =
      await ctx.runQuery(internal.slack.listRepoSummariesBySlug, { tenantSlug });
    if (!repos.length) return;

    const lines = repos
      .slice(0, 10)
      .map(
        (r: { fullName: string; openFindings: number; lastScanned: string }) =>
          `• \`${r.fullName}\` — ${r.openFindings} open findings, last scanned ${r.lastScanned}`,
      );

    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `📊 *Sentinel Weekly Security Digest — ${tenantSlug}*\n\n${lines.join("\n")}\n\n_${repos.length} repositories tracked_`,
      }),
    });
  },
});

export const getRepoDigestSummary = internalAction({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }): Promise<Array<{ fullName: string; openFindings: number; lastScanned: string }>> => {
    return await ctx.runQuery(internal.slack.listRepoSummariesBySlug, { tenantSlug });
  },
});

import { internalQuery } from "./_generated/server";

// ── SLA breach alert ──────────────────────────────────────────────────────────

// Sends a focused Slack message when a finding exceeds its SLA deadline.
// Separate from the main sendSlackAlert path to keep SLA severity logic clean
// (SLA breaches always alert regardless of SLACK_MIN_SEVERITY).
export const sendSlaBreachNotification = internalAction({
  args: {
    findingTitle: v.string(),
    severity: v.string(),
    repositoryFullName: v.string(),
    hoursOverdue: v.number(),
  },
  handler: async (_ctx, { findingTitle, severity, repositoryFullName, hoursOverdue }) => {
    const webhookUrl = process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) return;

    const emoji =
      severity === "critical" ? "🔴" : severity === "high" ? "🟠" : "🟡";
    const overdueText =
      hoursOverdue === 0
        ? "just breached"
        : hoursOverdue === 1
          ? "1 hour overdue"
          : `${hoursOverdue} hours overdue`;

    const blocks: SlackBlock[] = [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `${emoji} *SLA Breach — ${repositoryFullName}*`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Finding*\n${findingTitle}` },
          { type: "mrkdwn", text: `*Severity*\n${severity.toUpperCase()}` },
          { type: "mrkdwn", text: `*Status*\n${overdueText}` },
          { type: "mrkdwn", text: `*Repository*\n\`${repositoryFullName}\`` },
        ],
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: "Sentinel SLA Enforcement · resolve or accept risk to clear this breach",
          },
        ],
      },
    ];

    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        blocks,
        text: `[Sentinel] SLA breached — ${findingTitle} in ${repositoryFullName} (${overdueText})`,
      }),
    });
  },
});

// ── Risk acceptance expiry alert ──────────────────────────────────────────────

// Notifies the Slack channel when a time-bounded risk acceptance expires and
// the finding is automatically re-opened for remediation.
export const sendAcceptanceExpiryNotification = internalAction({
  args: {
    findingId: v.string(),
    justification: v.string(),
    approver: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (_ctx, { justification, approver, repositoryFullName }) => {
    const webhookUrl = process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) return;

    const blocks: SlackBlock[] = [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `⏰ *Risk Acceptance Expired — ${repositoryFullName}*`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Repository*\n\`${repositoryFullName}\`` },
          { type: "mrkdwn", text: `*Original Approver*\n${approver}` },
          {
            type: "mrkdwn",
            text: `*Justification*\n${justification.slice(0, 120)}${justification.length > 120 ? "…" : ""}`,
          },
          { type: "mrkdwn", text: `*Status*\nFinding re-opened` },
        ],
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: "Sentinel Risk Governance · review the re-opened finding and remediate or renew the acceptance",
          },
        ],
      },
    ];

    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        blocks,
        text: `[Sentinel] Risk acceptance expired — finding re-opened in ${repositoryFullName}`,
      }),
    });
  },
});

export const listRepoSummariesBySlug = internalQuery({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) return [];

    const repos = await ctx.db
      .query("repositories")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .take(20);

    const results: Array<{ fullName: string; openFindings: number; lastScanned: string }> = [];
    for (const repo of repos) {
      const openFindings = await ctx.db
        .query("findings")
        .withIndex("by_repository_and_status", (q) =>
          q.eq("repositoryId", repo._id).eq("status", "open"),
        )
        .take(100);

      results.push({
        fullName: repo.fullName,
        openFindings: openFindings.length,
        lastScanned: repo.lastScannedAt
          ? new Date(repo.lastScannedAt).toLocaleDateString()
          : "never",
      });
    }
    return results;
  },
});
