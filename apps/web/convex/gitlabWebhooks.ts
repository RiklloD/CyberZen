"use node";
/**
 * GitLab Webhook Integration — Push Hook + Merge Request Hook
 *
 * Configuration:
 *   npx convex env set GITLAB_WEBHOOK_TOKEN <your-secret-token>
 *
 * GitLab webhook setup (per-project):
 *   Settings → Webhooks → URL: https://<convex>.convex.site/webhooks/gitlab
 *   Secret token: <GITLAB_WEBHOOK_TOKEN>
 *   Trigger: Push events, Merge request events
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Token verification (shared-secret, not HMAC) ──────────────────────────────

function verifyGitLabToken(headerToken: string | null | undefined): boolean {
  const expectedToken = process.env.GITLAB_WEBHOOK_TOKEN;
  if (!expectedToken) return true; // fail-open in local dev
  return headerToken === expectedToken;
}

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteGitLabWebhook = internalAction({
  args: {
    body: v.string(),
    event: v.string(),
    token: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    if (!verifyGitLabToken(args.token)) {
      return { accepted: false, reason: "invalid_token", workflowRunId: null };
    }

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(args.body) as Record<string, unknown>;
    } catch {
      return { accepted: false, reason: "invalid_json", workflowRunId: null };
    }

    const eventLower = args.event.toLowerCase();

    if (eventLower === "push hook" || eventLower === "tag push hook") {
      const project = payload.project as Record<string, string> | undefined;
      const repoFullName = project?.path_with_namespace;
      if (!repoFullName) return { accepted: false, reason: "missing_project_path", workflowRunId: null };

      const commits = (payload.commits as Array<Record<string, unknown>> | undefined) ?? [];
      const changedFiles = [
        ...commits.flatMap((c) => (c.added as string[] | undefined) ?? []),
        ...commits.flatMap((c) => (c.modified as string[] | undefined) ?? []),
        ...commits.flatMap((c) => (c.removed as string[] | undefined) ?? []),
      ];
      const commitMessages = commits.map((c) => String(c.message ?? "")).filter(Boolean);
      const ref = String(payload.ref ?? "");
      const branch = ref.replace("refs/heads/", "") || project?.default_branch || "main";
      const commitSha = String(payload.checkout_sha ?? payload.after ?? "unknown");

      return await ctx.runAction(internal.gitlabWebhooks.ingestGitLabPush, {
        repositoryFullName: repoFullName,
        branch,
        commitSha,
        changedFiles: [...new Set(changedFiles)].slice(0, 200),
        commitMessages,
      });
    }

    if (eventLower === "merge request hook") {
      const project = payload.project as Record<string, string> | undefined;
      const attrs = payload.object_attributes as Record<string, unknown> | undefined;
      const mrAction = String(attrs?.action ?? "");

      if (mrAction !== "open" && mrAction !== "merge") {
        return { accepted: false, reason: `mr_action_ignored:${mrAction}`, workflowRunId: null };
      }

      const repoFullName = project?.path_with_namespace;
      if (!repoFullName) return { accepted: false, reason: "missing_project_path", workflowRunId: null };

      const lastCommit = attrs?.last_commit as Record<string, string> | undefined;

      return await ctx.runAction(internal.gitlabWebhooks.ingestGitLabPush, {
        repositoryFullName: repoFullName,
        branch: String(attrs?.source_branch ?? "unknown"),
        commitSha: String(lastCommit?.id ?? "unknown"),
        changedFiles: [],
        commitMessages: [String(attrs?.title ?? "")],
      });
    }

    return { accepted: false, reason: `unsupported_event:${args.event}`, workflowRunId: null };
  },
});

// ── Provider-agnostic push ingestion ──────────────────────────────────────────

export const ingestGitLabPush = internalAction({
  args: {
    repositoryFullName: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    changedFiles: v.array(v.string()),
    commitMessages: v.array(v.string()),
  },
  handler: async (ctx, args): Promise<{ accepted: boolean; workflowRunId: string | null; deduped?: boolean }> => {
    const repo: null | { _id: string; tenantId: string; fullName: string } = await ctx.runQuery(
      internal.gitlabWebhooks.findGitLabRepository,
      { fullName: args.repositoryFullName },
    ) as null | { _id: string; tenantId: string; fullName: string };

    if (!repo) {
      console.log(`[gitlab] no repository found for ${args.repositoryFullName}`);
      return { accepted: false, workflowRunId: null };
    }

    const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
      await ctx.runMutation(internal.gitlabWebhooks.recordGitLabPushEvent, {
        tenantId: repo.tenantId as unknown as import("./_generated/dataModel").Id<"tenants">,
        repositoryId: repo._id as unknown as import("./_generated/dataModel").Id<"repositories">,
        branch: args.branch,
        commitSha: args.commitSha,
        changedFiles: args.changedFiles,
      });

    if (result.accepted && args.commitMessages.length > 0) {
      ctx.scheduler.runAfter(0, internal.promptIntelligence.scanContentByRef, {
        repositoryFullName: repo.fullName,
        provider: "gitlab" as const,
        contentRef: "gitlab_commit_messages",
        content: args.commitMessages.join("\n").slice(0, 4000),
      });
    }

    return result;
  },
});

// ── Internal queries and mutations ────────────────────────────────────────────

export const findGitLabRepository = internalQuery({
  args: { fullName: v.string() },
  handler: async (ctx, { fullName }) => {
    return await ctx.db
      .query("repositories")
      .withIndex("by_provider_and_full_name", (q) =>
        q.eq("provider", "gitlab").eq("fullName", fullName),
      )
      .first();
  },
});

export const recordGitLabPushEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
    changedFiles: v.array(v.string()),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `gitlab-push-${args.repositoryId}-${args.commitSha}`;

    const existing = await ctx.db
      .query("ingestionEvents")
      .withIndex("by_dedupe_key", (q) => q.eq("dedupeKey", dedupeKey))
      .first();

    if (existing) {
      return { accepted: false, workflowRunId: null, deduped: true };
    }

    const repo = await ctx.db.get(args.repositoryId);
    if (!repo) return { accepted: false, workflowRunId: null };

    await ctx.db.patch(args.repositoryId, {
      latestCommitSha: args.commitSha,
      lastScannedAt: Date.now(),
    });

    const eventId = await ctx.db.insert("ingestionEvents", {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      dedupeKey,
      kind: "push",
      source: "gitlab",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: args.changedFiles,
      summary: `GitLab push to ${args.branch} (${args.commitSha.slice(0, 7)}) — ${args.changedFiles.length} files changed`,
      receivedAt: Date.now(),
    });

    const workflowRunId = await ctx.db.insert("workflowRuns", {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      eventId,
      workflowType: "repository_scan",
      status: "running",
      priority: "medium",
      currentStage: "sbom_scan",
      summary: `Repository scan triggered by GitLab push to ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
