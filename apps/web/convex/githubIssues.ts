/**
 * GitHub Issues Integration — spec §4.6.4
 *
 * Creates GitHub Issues for Sentinel findings as a fallback ticketing system
 * for teams that don't have Jira or Linear configured.
 *
 * Configuration:
 *   npx convex env set GITHUB_TOKEN ghp_...       (same token used for PR creation)
 *   npx convex env set GITHUB_ISSUES_REPO org/repo (optional — defaults to finding's repo)
 *   npx convex env set SENTINEL_DASHBOARD_URL https://sentinelsec.io
 *
 * Issue tracking:
 *   Finding.reasoningLogUrl is set to "ghissue:{number}:{html_url}" to record the reference.
 *   e.g. "ghissue:42:https://github.com/acme/payments-api/issues/42"
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";
import { buildGithubIssueCreateBody, buildGithubIssueCloseBody } from "./lib/githubIssuePayload";

// ── GitHub REST API helper ────────────────────────────────────────────────────

async function githubApiCall(
  path: string,
  method: string,
  token: string,
  body?: unknown,
): Promise<{ ok: boolean; status: number; data?: unknown }> {
  const resp = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `token ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error(`[github-issues] ${method} ${path} → ${resp.status}: ${text.slice(0, 300)}`);
    return { ok: false, status: resp.status };
  }

  const data = await resp.json().catch(() => undefined);
  return { ok: true, status: resp.status, data };
}

// ── Core action ───────────────────────────────────────────────────────────────

export const createGithubIssue = internalAction({
  args: {
    findingId: v.id("findings"),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ created: boolean; reason?: string; number?: number; url?: string }> => {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      console.log("[github-issues] not configured — set GITHUB_TOKEN");
      return { created: false, reason: "not_configured" };
    }

    const finding = await ctx.runQuery(internal.githubIssues.loadGithubFinding, {
      findingId: args.findingId,
    });
    if (!finding) return { created: false, reason: "finding_not_found" };
    if (finding.reasoningLogUrl?.startsWith("ghissue:")) {
      return { created: false, reason: "already_has_ticket" };
    }

    const targetRepo =
      process.env.GITHUB_ISSUES_REPO ?? args.repositoryFullName;
    const sentinelUrl =
      process.env.SENTINEL_DASHBOARD_URL ?? "https://sentinelsec.io";

    const issueBody = buildGithubIssueCreateBody({
      title: finding.title,
      summary: finding.summary,
      severity: finding.severity,
      vulnClass: finding.vulnClass,
      blastRadiusSummary: finding.blastRadiusSummary,
      affectedFiles: finding.affectedFiles,
      affectedPackages: finding.affectedPackages,
      regulatoryImplications: finding.regulatoryImplications,
      repositoryFullName: args.repositoryFullName,
      prUrl: finding.prUrl ?? undefined,
      findingId: args.findingId,
      sentinelUrl,
    });

    const result = await githubApiCall(
      `/repos/${targetRepo}/issues`,
      "POST",
      token,
      issueBody,
    );

    if (!result.ok || result.status !== 201) {
      return { created: false, reason: `http_${result.status}` };
    }

    const issue = result.data as { number: number; html_url: string };

    await ctx.runMutation(internal.githubIssues.patchFindingWithGithubIssue, {
      findingId: args.findingId,
      issueNumber: issue.number,
      issueUrl: issue.html_url,
    });

    console.log(
      `[github-issues] created issue #${issue.number} for finding ${args.findingId}`,
    );
    return { created: true, number: issue.number, url: issue.html_url };
  },
});

// ── Close issue ───────────────────────────────────────────────────────────────

export const closeGithubIssue = internalAction({
  args: {
    issueNumber: v.number(),
    repositoryFullName: v.string(),
    note: v.optional(v.string()),
  },
  handler: async (
    _ctx,
    args,
  ): Promise<{ closed: boolean; status: number }> => {
    const token = process.env.GITHUB_TOKEN;
    if (!token) return { closed: false, status: 0 };

    const result = await githubApiCall(
      `/repos/${args.repositoryFullName}/issues/${args.issueNumber}`,
      "PATCH",
      token,
      buildGithubIssueCloseBody(),
    );

    return { closed: result.ok, status: result.status };
  },
});

// ── Public query ──────────────────────────────────────────────────────────────

export const getGithubIssuesForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_repository_and_status", (q) =>
        q.eq("repositoryId", repositoryId).eq("status", "open"),
      )
      .take(50);

    return findings
      .filter((f) => f.reasoningLogUrl?.startsWith("ghissue:"))
      .map((f) => {
        // Format: "ghissue:{number}:{html_url}"
        const withoutPrefix = f.reasoningLogUrl!.slice("ghissue:".length);
        const colonIdx = withoutPrefix.indexOf(":");
        const issueNumber =
          colonIdx !== -1 ? Number(withoutPrefix.slice(0, colonIdx)) : NaN;
        const issueUrl = colonIdx !== -1 ? withoutPrefix.slice(colonIdx + 1) : "";
        return {
          findingId: f._id,
          title: f.title,
          severity: f.severity,
          issueNumber,
          issueUrl,
        };
      });
  },
});

// ── Internal helpers ──────────────────────────────────────────────────────────

export const loadGithubFinding = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => ctx.db.get(findingId),
});

export const patchFindingWithGithubIssue = internalMutation({
  args: {
    findingId: v.id("findings"),
    issueNumber: v.number(),
    issueUrl: v.string(),
  },
  handler: async (ctx, { findingId, issueNumber, issueUrl }) => {
    await ctx.db.patch(findingId, {
      reasoningLogUrl: `ghissue:${issueNumber}:${issueUrl}`,
    });
  },
});

