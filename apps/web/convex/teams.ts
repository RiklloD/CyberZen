"use node";
/**
 * Sentinel Microsoft Teams Integration
 *
 * Sends Adaptive Card alert messages to a Teams channel via an incoming
 * webhook for the same three alert kinds as the Slack integration:
 *   - Critical / high validated findings
 *   - Gate blocked events
 *   - Honeypot triggers (immediate breach indicator)
 *   - Weekly security posture digest (scheduled)
 *
 * Configuration:
 *   npx convex env set TEAMS_WEBHOOK_URL https://xxx.webhook.office.com/webhookb2/...
 *   npx convex env set TEAMS_MIN_SEVERITY "high"   (critical|high|medium, default high)
 *
 * Teams setup:
 *   Channel → ⋯ → Connectors → Incoming Webhook → Create → copy URL
 *   OR (newer): use Power Automate "Post to a channel" workflow to get URL
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import {
  buildTeamsPayload,
  meetsMinSeverity,
  type TeamsAlertPayload,
} from "./lib/teamsCards";

// ── Core dispatch ─────────────────────────────────────────────────────────────

export const sendTeamsAlert = internalAction({
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
  handler: async (ctx, args) => {
    const webhookUrl = process.env.TEAMS_WEBHOOK_URL;
    if (!webhookUrl) {
      console.log("[teams] TEAMS_WEBHOOK_URL not set — skipping notification");
      return { sent: false, reason: "no_webhook_url" };
    }

    const minSeverity = process.env.TEAMS_MIN_SEVERITY ?? "high";

    // Severity filter — honeypots always fire regardless
    if (
      args.kind === "finding_validated" &&
      !meetsMinSeverity(args.severity, minSeverity)
    ) {
      return { sent: false, reason: "below_min_severity" };
    }

    const payload = buildTeamsPayload(args as TeamsAlertPayload);

    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error(`[teams] webhook failed: ${resp.status} — ${body}`);
      return { sent: false, reason: `http_${resp.status}` };
    }

    await ctx.runMutation(internal.teams.recordTeamsDelivery, {
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

export const recordTeamsDelivery = internalMutation({
  args: {
    kind: v.string(),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    severity: v.optional(v.string()),
    success: v.boolean(),
  },
  handler: async (_ctx, args) => {
    console.log(
      `[teams] delivery recorded: kind=${args.kind} repo=${args.repositoryFullName} severity=${args.severity ?? "?"} success=${args.success}`,
    );
  },
});

// ── Weekly posture digest ─────────────────────────────────────────────────────

export const sendWeeklyTeamsDigest = internalAction({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const webhookUrl = process.env.TEAMS_WEBHOOK_URL;
    if (!webhookUrl) return;

    const repos: Array<{ fullName: string; openFindings: number; lastScanned: string }> =
      await ctx.runQuery(internal.teams.listRepoSummariesBySlug, { tenantSlug });
    if (!repos.length) return;

    const rows = repos
      .slice(0, 10)
      .map(
        (r) =>
          `- **${r.fullName}** — ${r.openFindings} open findings, last scanned ${r.lastScanned}`,
      )
      .join("\n");

    // Simple text card for digest
    const payload = {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          contentUrl: null,
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.4",
            body: [
              {
                type: "TextBlock",
                text: `📊 Sentinel Weekly Security Digest — ${tenantSlug}`,
                size: "Large",
                weight: "Bolder",
                wrap: true,
              },
              {
                type: "TextBlock",
                text: rows,
                wrap: true,
              },
              {
                type: "TextBlock",
                text: `${repos.length} repositories tracked · ${new Date().toUTCString()}`,
                isSubtle: true,
                size: "Small",
              },
            ],
          },
        },
      ],
    };

    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  },
});

// ── Internal query for digest (mirrors slack.listRepoSummariesBySlug) ─────────

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
