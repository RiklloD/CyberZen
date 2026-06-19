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

import { ConvexError, v } from "convex/values";
import { action, internalAction, internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";
import { requireSessionAuth } from "./lib/sessionAuth";

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

// (internalQuery already imported at top)

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

// ── Sprint 4B: Slack OAuth Integration ───────────────────────────────────────
//
// Flow:
//   1. initiateSlackOAuth  (mutation) — creates pending row, returns OAuth URL
//   2. GET /api/slack/oauth/callback  (HTTP in http.ts) — exchanges code
//   3. storeSlackToken     (internalMutation) — persists encrypted token
//
// Config env vars required for OAuth:
//   SLACK_CLIENT_ID, SLACK_CLIENT_SECRET
//   CONVEX_SITE_URL  (already used elsewhere)
//   WEBHOOK_ENCRYPTION_KEY (reused for token encryption)

// ---------------------------------------------------------------------------
// AES-GCM helpers (mirrors pattern in webhooks.ts)
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function decryptToken(encrypted: string): Promise<string> {
  const keyHex = process.env.WEBHOOK_ENCRYPTION_KEY;
  if (!keyHex || keyHex.length !== 64) {
    throw new ConvexError("WEBHOOK_ENCRYPTION_KEY must be a 64-char hex string");
  }
  const [, ivHex, ctHex] = encrypted.split("$");
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    hexToBytes(keyHex),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(ivHex) },
    cryptoKey,
    hexToBytes(ctHex),
  );
  return new TextDecoder().decode(plain);
}

// ---------------------------------------------------------------------------
// initiateSlackOAuth — mutation: creates pending integration, returns OAuth URL
// ---------------------------------------------------------------------------

export const initiateSlackOAuth = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: v.object({ oauthUrl: v.string(), state: v.string() }),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken);
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`);

    const membership = await ctx.db
      .query("tenantMembers")
      .withIndex("by_tenant_and_user", (q) =>
        q.eq("tenantId", tenant._id).eq("userId", userId),
      )
      .unique();
    if (!membership || (membership.role !== "owner" && membership.role !== "admin")) {
      throw new ConvexError("Only owners and admins can configure Slack integration");
    }

    // Generate a random state token to prevent CSRF
    const stateBytes = crypto.getRandomValues(new Uint8Array(16));
    const state = bytesToHex(stateBytes);

    // Upsert the pending integration row
    const existing = await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, { oauthState: state, isActive: false });
    } else {
      await ctx.db.insert("slackIntegrations", {
        tenantId: tenant._id,
        isActive: false,
        oauthState: state,
      });
    }

    const clientId = process.env.SLACK_CLIENT_ID ?? "";
    const redirectUri = `${process.env.CONVEX_SITE_URL}/api/slack/oauth/callback`;
    const scopes = "chat:write,commands,channels:read,team:read";

    const oauthUrl = `https://slack.com/oauth/v2/authorize?client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(scopes)}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;

    return { oauthUrl, state };
  },
});

// ---------------------------------------------------------------------------
// getIntegrationByOAuthState — internalQuery for the HTTP OAuth callback
// ---------------------------------------------------------------------------

export const getIntegrationByOAuthState = internalQuery({
  args: { oauthState: v.string() },
  handler: async (ctx, { oauthState }) => {
    return await ctx.db
      .query("slackIntegrations")
      .withIndex("by_oauth_state", (q) => q.eq("oauthState", oauthState))
      .first();
  },
});

// ---------------------------------------------------------------------------
// storeSlackToken — internalMutation: persists encrypted token + team info
// ---------------------------------------------------------------------------

export const storeSlackToken = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    encryptedToken: v.string(),
    teamId: v.string(),
    teamName: v.string(),
    botUserId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { tenantId, encryptedToken, teamId, teamName, botUserId }) => {
    const existing = await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenantId))
      .first();

    const now = Date.now();
    const defaults = {
      tenantId,
      accessToken: encryptedToken,
      teamId,
      teamName,
      botUserId,
      isActive: true,
      connectedAt: now,
      oauthState: undefined,
    };

    if (existing) {
      await ctx.db.patch(existing._id, {
        accessToken: encryptedToken,
        teamId,
        teamName,
        botUserId,
        isActive: true,
        connectedAt: now,
        oauthState: undefined,
      });
    } else {
      await ctx.db.insert("slackIntegrations", defaults);
    }
    return null;
  },
});

// ---------------------------------------------------------------------------
// getSlackIntegration — public query: returns connection status (no token)
// ---------------------------------------------------------------------------

export const getSlackIntegration = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken);
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) return null;

    const membership = await ctx.db
      .query("tenantMembers")
      .withIndex("by_tenant_and_user", (q) =>
        q.eq("tenantId", tenant._id).eq("userId", userId),
      )
      .unique();
    if (!membership) return null;

    const integration = await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .first();
    if (!integration) return null;

    const alertConfig = integration.alertConfig
      ? (JSON.parse(integration.alertConfig) as {
          channel?: string
          events?: string[]
          minSeverity?: string
        })
      : {};

    return {
      _id: integration._id,
      teamId: integration.teamId,
      teamName: integration.teamName,
      isActive: integration.isActive,
      connectedAt: integration.connectedAt,
      alertChannel: alertConfig.channel ?? null,
      alertEvents: alertConfig.events ?? [],
      minSeverity: alertConfig.minSeverity ?? "high",
    };
  },
});

// ---------------------------------------------------------------------------
// configureSlackAlerts — mutation: save alert channel + event config
// ---------------------------------------------------------------------------

export const configureSlackAlerts = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    channel: v.string(),
    events: v.array(v.string()),
    minSeverity: v.union(
      v.literal("critical"),
      v.literal("high"),
      v.literal("medium"),
    ),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, channel, events, minSeverity }) => {
    const { userId } = await requireSessionAuth(ctx, authToken);
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`);

    const membership = await ctx.db
      .query("tenantMembers")
      .withIndex("by_tenant_and_user", (q) =>
        q.eq("tenantId", tenant._id).eq("userId", userId),
      )
      .unique();
    if (!membership || (membership.role !== "owner" && membership.role !== "admin")) {
      throw new ConvexError("Only owners and admins can configure Slack alerts");
    }

    const integration = await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .first();
    if (!integration) throw new ConvexError("No Slack integration found for this workspace");

    await ctx.db.patch(integration._id, {
      alertConfig: JSON.stringify({ channel, events, minSeverity }),
    });
    return null;
  },
});

// ---------------------------------------------------------------------------
// disconnectSlack — mutation: revoke integration (does not revoke Slack token)
// ---------------------------------------------------------------------------

export const disconnectSlack = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx, authToken);
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`);

    const membership = await ctx.db
      .query("tenantMembers")
      .withIndex("by_tenant_and_user", (q) =>
        q.eq("tenantId", tenant._id).eq("userId", userId),
      )
      .unique();
    if (!membership || (membership.role !== "owner" && membership.role !== "admin")) {
      throw new ConvexError("Only owners and admins can disconnect Slack");
    }

    const integration = await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .first();
    if (integration) {
      await ctx.db.patch(integration._id, {
        isActive: false,
        accessToken: undefined,
        oauthState: undefined,
      });
    }
    return null;
  },
});

// ---------------------------------------------------------------------------
// sendOAuthSlackMessage — internalAction: send via OAuth bot token
// ---------------------------------------------------------------------------

export const sendOAuthSlackMessage = internalAction({
  args: {
    tenantId: v.id("tenants"),
    channel: v.string(),
    text: v.string(),
    blocks: v.optional(v.string()),
  },
  returns: v.object({ ok: v.boolean(), error: v.optional(v.string()) }),
  handler: async (ctx, { tenantId, channel, text, blocks }) => {
    const integration = await ctx.runQuery(internal.slack.getSlackIntegrationById, {
      tenantId,
    });
    if (!integration?.accessToken) {
      return { ok: false, error: "No active Slack integration" };
    }

    const token = await decryptToken(integration.accessToken);
    const body: Record<string, unknown> = { channel, text };
    if (blocks) {
      try { body.blocks = JSON.parse(blocks); } catch { /* ignore */ }
    }

    const resp = await fetch("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });
    const data = await resp.json() as { ok: boolean; error?: string };
    return { ok: data.ok, error: data.error };
  },
});

// ---------------------------------------------------------------------------
// getSlackIntegrationById — internalQuery (token included for internal use)
// ---------------------------------------------------------------------------

export const getSlackIntegrationById = internalQuery({
  args: { tenantId: v.id("tenants") },
  handler: async (ctx, { tenantId }) => {
    return await ctx.db
      .query("slackIntegrations")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenantId))
      .first();
  },
});

// ---------------------------------------------------------------------------
// verifyAuthSession — internalQuery: validates session from action contexts
// ---------------------------------------------------------------------------

export const verifyAuthSession = internalQuery({
  args: { authToken: v.optional(v.string()) },
  returns: v.null(),
  handler: async (ctx, { authToken }): Promise<null> => {
    await requireSessionAuth(ctx, authToken);
    return null;
  },
});

// ---------------------------------------------------------------------------
// sendTestSlackNotification — public action: sends a test message
// ---------------------------------------------------------------------------

export const sendTestSlackNotification = action({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    channel: v.string(),
  },
  returns: v.object({ ok: v.boolean(), error: v.optional(v.string()) }),
  handler: async (ctx, { authToken, tenantSlug, channel }): Promise<{ ok: boolean; error?: string }> => {
    await ctx.runQuery(internal.slack.verifyAuthSession, { authToken });
    const tenant: { _id: import("./_generated/dataModel").Id<"tenants"> } | null =
      await ctx.runQuery(internal.slack.lookupTenantBySlug, { tenantSlug });
    if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`);

    const result: { ok: boolean; error?: string } = await ctx.runAction(
      internal.slack.sendOAuthSlackMessage,
      { tenantId: tenant._id, channel, text: "✅ *CyberZen test notification* — Slack integration is working!" },
    );
    return result;
  },
});

// ---------------------------------------------------------------------------
// handleSlashCommand — internalAction: /cyberzen slash command handler
// ---------------------------------------------------------------------------

export const handleSlashCommand = internalAction({
  args: {
    tenantId: v.id("tenants"),
    command: v.string(),
    text: v.string(),
    responseUrl: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, { tenantId, text, responseUrl }) => {
    const subcommand = text.trim().toLowerCase().split(/\s+/)[0] ?? "status";

    let responseText = "";

    if (subcommand === "status" || subcommand === "") {
      const data: {
        openCritical?: number
        totalOpen?: number
        repositories?: Array<{ fullName: string }>
      } = await ctx.runQuery(internal.slack.getTenantSecuritySummary, { tenantId });
      responseText =
        `📊 *Security Posture*\n` +
        `• Open critical findings: *${data.openCritical ?? 0}*\n` +
        `• Total open findings: *${data.totalOpen ?? 0}*\n` +
        `• Repositories monitored: *${data.repositories?.length ?? 0}*`;
    } else if (subcommand === "critical") {
      const findings: Array<{ title: string; repositoryFullName: string }> =
        await ctx.runQuery(internal.slack.getTopCriticalFindings, { tenantId });
      if (findings.length === 0) {
        responseText = "✅ No critical open findings — great work!";
      } else {
        const lines = findings
          .slice(0, 5)
          .map((f) => `• ${f.title} _(${f.repositoryFullName})_`);
        responseText = `🔴 *Top Critical Findings (${findings.length} total)*\n${lines.join("\n")}`;
      }
    } else if (subcommand === "score") {
      const score: { overallScore: number } =
        await ctx.runQuery(internal.slack.getTenantSecurityScore, { tenantId });
      const grade = score.overallScore >= 80 ? "🟢" : score.overallScore >= 60 ? "🟡" : "🔴";
      responseText = `${grade} *Security Score: ${score.overallScore}/100*`;
    } else {
      responseText =
        `*CyberZen Slash Commands*\n` +
        `• \`/cyberzen status\` — current security posture summary\n` +
        `• \`/cyberzen critical\` — list critical findings\n` +
        `• \`/cyberzen score\` — security score`;
    }

    // Respond to Slack via the response_url (supports delayed responses)
    await fetch(responseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response_type: "in_channel", text: responseText }),
    });
    return null;
  },
});

// ---------------------------------------------------------------------------
// Slash command support queries
// ---------------------------------------------------------------------------

export const getTenantSecuritySummary = internalQuery({
  args: { tenantId: v.id("tenants") },
  handler: async (ctx, { tenantId }) => {
    const repos = await ctx.db
      .query("repositories")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenantId))
      .take(50);

    let openCritical = 0;
    let totalOpen = 0;

    for (const repo of repos) {
      const open = await ctx.db
        .query("findings")
        .withIndex("by_repository_and_status", (q) =>
          q.eq("repositoryId", repo._id).eq("status", "open"),
        )
        .take(200);
      totalOpen += open.length;
      openCritical += open.filter((f) => f.severity === "critical").length;
    }

    return { openCritical, totalOpen, repositories: repos };
  },
});

export const getTopCriticalFindings = internalQuery({
  args: { tenantId: v.id("tenants") },
  handler: async (ctx, { tenantId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_tenant_and_status", (q) =>
        q.eq("tenantId", tenantId).eq("status", "open"),
      )
      .take(100);

    const critical = findings.filter((f) => f.severity === "critical");

    const repos = new Map<string, string>();
    for (const f of critical.slice(0, 5)) {
      if (!repos.has(f.repositoryId)) {
        const repo = await ctx.db.get(f.repositoryId);
        if (repo) repos.set(f.repositoryId, repo.fullName);
      }
    }

    return critical.slice(0, 10).map((f) => ({
      title: f.title,
      repositoryFullName: repos.get(f.repositoryId) ?? f.repositoryId,
    }));
  },
});

export const getTenantSecurityScore = internalQuery({
  args: { tenantId: v.id("tenants") },
  handler: async (ctx, { tenantId }) => {
    const scores = await ctx.db
      .query("repositoryHealthScoreResults")
      .withIndex("by_tenant_and_computed_at", (q) => q.eq("tenantId", tenantId))
      .take(50);

    if (scores.length === 0) return { overallScore: 0 };
    const avg = Math.round(
      scores.reduce((sum, s) => sum + s.overallScore, 0) / scores.length,
    );
    return { overallScore: avg };
  },
});

export const lookupTenantBySlug = internalQuery({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    return await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
  },
});

export const getIntegrationByTeamId = internalQuery({
  args: { teamId: v.string() },
  handler: async (ctx, { teamId }) => {
    // No teamId index — bounded scan is safe at MVP scale (few integrations)
    const all = await ctx.db.query("slackIntegrations").take(500);
    return all.find((i) => i.teamId === teamId) ?? null;
  },
});

