/**
 * Jira Cloud Integration — spec §4.6.4
 *
 * Creates Jira issues for Sentinel findings that require architectural changes.
 *
 * Configuration:
 *   npx convex env set JIRA_BASE_URL https://yourcompany.atlassian.net
 *   npx convex env set JIRA_API_TOKEN <base64(user@email:token)>
 *   npx convex env set JIRA_PROJECT_KEY SEC
 *   npx convex env set JIRA_ISSUE_TYPE "Security Vulnerability"  (optional, default: Bug)
 *   npx convex env set JIRA_ASSIGNEE_ACCOUNT_ID <accountId>      (optional)
 *   npx convex env set SENTINEL_DASHBOARD_URL https://sentinelsec.io (optional)
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Types ─────────────────────────────────────────────────────────────────────

type TextNode = { type: "text"; text: string; marks?: Array<{ type: string }> };
type DocContent =
  | { type: "paragraph"; content: TextNode[] }
  | { type: "heading"; attrs: { level: number }; content: TextNode[] }
  | { type: "bulletList"; content: Array<{ type: "listItem"; content: DocContent[] }> };

const SEVERITY_PRIORITY: Record<string, string> = {
  critical: "Highest", high: "High", medium: "Medium", low: "Low", informational: "Lowest",
};

// ── Document helpers ──────────────────────────────────────────────────────────

const t = (s: string): TextNode => ({ type: "text", text: s });
const bold = (s: string): TextNode => ({ type: "text", text: s, marks: [{ type: "strong" }] });
const para = (...items: TextNode[]): DocContent => ({ type: "paragraph", content: items });
const h = (level: number, s: string): DocContent => ({ type: "heading", attrs: { level }, content: [t(s)] });
const list = (items: string[]): DocContent => ({
  type: "bulletList",
  content: items.map((i) => ({ type: "listItem" as const, content: [para(t(i))] })),
});

// ── Core action ───────────────────────────────────────────────────────────────

export const createJiraIssue = internalAction({
  args: {
    findingId: v.id("findings"),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<{ created: boolean; reason?: string; key?: string; url?: string }> => {
    const baseUrl = process.env.JIRA_BASE_URL?.replace(/\/$/, "");
    const apiToken = process.env.JIRA_API_TOKEN;
    const projectKey = process.env.JIRA_PROJECT_KEY;

    if (!baseUrl || !apiToken || !projectKey) {
      console.log("[jira] not configured — set JIRA_BASE_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY");
      return { created: false, reason: "not_configured" };
    }

    const finding = await ctx.runQuery(internal.jira.loadFinding, { findingId: args.findingId });
    if (!finding) return { created: false, reason: "finding_not_found" };
    if (finding.reasoningLogUrl?.startsWith("jira:")) {
      return { created: false, reason: "already_has_ticket" };
    }

    const sentinelUrl = process.env.SENTINEL_DASHBOARD_URL ?? "https://sentinelsec.io";
    const issueType = process.env.JIRA_ISSUE_TYPE ?? "Bug";
    const assigneeId = process.env.JIRA_ASSIGNEE_ACCOUNT_ID;

    // Build Atlassian Document Format body
    const bodyContent: DocContent[] = [
      h(2, "🛡️ Sentinel Security Finding"),
      para(bold("Severity: "), t(finding.severity.toUpperCase())),
      para(bold("Class: "), t(finding.vulnClass.replace(/_/g, " "))),
      para(bold("Repository: "), t(args.repositoryFullName)),
      para(),
      h(3, "Summary"),
      para(t(finding.summary)),
      h(3, "Blast Radius"),
      para(t(finding.blastRadiusSummary)),
    ];

    if (finding.affectedFiles.length > 0) {
      bodyContent.push(h(3, "Affected Files"), list(finding.affectedFiles.slice(0, 10)));
    }
    if (finding.affectedPackages.length > 0) {
      bodyContent.push(h(3, "Affected Packages"), list(finding.affectedPackages.slice(0, 10)));
    }
    if (finding.regulatoryImplications.length > 0) {
      bodyContent.push(h(3, "Regulatory Implications"), list(finding.regulatoryImplications));
    }
    if (finding.prUrl) {
      bodyContent.push(h(3, "Fix PR"), para(t(`Sentinel opened a fix PR: ${finding.prUrl}`)));
    }
    bodyContent.push(
      para(),
      h(3, "Links"),
      list([
        `Sentinel Dashboard: ${sentinelUrl}/findings/${args.findingId}`,
        `Repository: https://github.com/${args.repositoryFullName}`,
      ]),
      para(bold("[Auto-created by Sentinel Security Agent — do not remove sentinel labels]")),
    );

    const fields: Record<string, unknown> = {
      project: { key: projectKey },
      summary: `[SENTINEL] ${finding.severity.toUpperCase()}: ${finding.title.slice(0, 200)}`,
      description: { type: "doc", version: 1, content: bodyContent },
      issuetype: { name: issueType },
      priority: { name: SEVERITY_PRIORITY[finding.severity] ?? "Medium" },
      labels: [
        "sentinel-auto",
        `severity-${finding.severity}`,
        `vuln-${finding.vulnClass.replace(/_/g, "-")}`,
        args.tenantSlug,
      ],
    };
    if (assigneeId) fields.assignee = { accountId: assigneeId };

    const resp = await fetch(`${baseUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${apiToken}`,
      },
      body: JSON.stringify({ fields }),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error(`[jira] ${resp.status}: ${body.slice(0, 300)}`);
      return { created: false, reason: `http_${resp.status}` };
    }

    const data = (await resp.json()) as { id: string; key: string };
    const issueUrl = `${baseUrl}/browse/${data.key}`;

    await ctx.runMutation(internal.jira.patchFindingWithJiraKey, {
      findingId: args.findingId,
      jiraKey: data.key,
      jiraUrl: issueUrl,
    });

    return { created: true, key: data.key, url: issueUrl };
  },
});

// ── Transition ────────────────────────────────────────────────────────────────

export const resolveJiraIssue = internalAction({
  args: { jiraKey: v.string(), resolutionComment: v.optional(v.string()) },
  handler: async (_ctx, args) => {
    const baseUrl = process.env.JIRA_BASE_URL?.replace(/\/$/, "");
    const apiToken = process.env.JIRA_API_TOKEN;
    if (!baseUrl || !apiToken) return;

    const headers = {
      "Content-Type": "application/json",
      Authorization: `Basic ${apiToken}`,
    };

    // Get available transitions
    const tResp = await fetch(
      `${baseUrl}/rest/api/3/issue/${args.jiraKey}/transitions`,
      { headers },
    );
    if (!tResp.ok) return;

    const tData = (await tResp.json()) as { transitions: Array<{ id: string; name: string }> };
    const done = tData.transitions.find((t) => /done|resolve|close/i.test(t.name));
    if (!done) return;

    await fetch(`${baseUrl}/rest/api/3/issue/${args.jiraKey}/transitions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ transition: { id: done.id } }),
    });
  },
});

// ── Public query ──────────────────────────────────────────────────────────────

export const getJiraTicketsForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_repository_and_status", (q) =>
        q.eq("repositoryId", repositoryId).eq("status", "open"),
      )
      .take(50);

    // Return findings that have a Jira key (stored as "jira:KEY:URL" in reasoningLogUrl)
    return findings
      .filter((f) => f.reasoningLogUrl?.startsWith("jira:"))
      .map((f) => {
        const parts = f.reasoningLogUrl!.split(":");
        return {
          findingId: f._id,
          title: f.title,
          severity: f.severity,
          jiraKey: parts[1] ?? "",
          jiraUrl: parts.slice(2).join(":"),
        };
      });
  },
});

// ── Internal helpers ──────────────────────────────────────────────────────────

export const loadFinding = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => ctx.db.get(findingId),
});

export const patchFindingWithJiraKey = internalMutation({
  args: {
    findingId: v.id("findings"),
    jiraKey: v.string(),
    jiraUrl: v.string(),
  },
  handler: async (ctx, { findingId, jiraKey, jiraUrl }) => {
    await ctx.db.patch(findingId, {
      reasoningLogUrl: `jira:${jiraKey}:${jiraUrl}`,
    });
  },
});

