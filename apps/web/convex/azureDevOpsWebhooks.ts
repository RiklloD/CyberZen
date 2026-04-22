"use node";
/**
 * Azure DevOps Webhook Integration (spec §4.6.1)
 *
 * Azure DevOps sends service hooks to an HTTPS endpoint.
 * Authentication uses a shared secret sent as Basic auth in the Authorization header.
 *
 * Supported event types:
 *   - git.push            → repository scan workflow
 *   - git.pullrequest.merged → post-fix validation
 *   - git.pullrequest.created → future: pre-merge gate check
 *
 * Setup in Azure DevOps:
 *   Project Settings → Service Hooks → Webhooks → Add subscription
 *   URL: https://<convex>.convex.site/webhooks/azure-devops
 *   Basic auth username: sentinel
 *   Basic auth password: <AZURE_DEVOPS_WEBHOOK_SECRET>
 *
 * Configuration:
 *   npx convex env set AZURE_DEVOPS_WEBHOOK_SECRET <your-secret>
 *
 * ADO payload docs: https://learn.microsoft.com/en-us/azure/devops/service-hooks/events
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Authentication ────────────────────────────────────────────────────────────

function verifyAzureDevOpsAuth(authorization: string | null | undefined): boolean {
  const secret = process.env.AZURE_DEVOPS_WEBHOOK_SECRET;
  if (!secret) return true; // fail-open in local dev

  if (!authorization?.startsWith("Basic ")) return false;

  try {
    const decoded = atob(authorization.slice(6)); // "username:password"
    const password = decoded.split(":").slice(1).join(":");
    return password === secret;
  } catch {
    return false;
  }
}

// ── ADO payload types ─────────────────────────────────────────────────────────

type AdoPushPayload = {
  eventType?: string;
  resource?: {
    commits?: Array<{
      commitId?: string;
      comment?: string;
      changes?: Array<{ item?: { path?: string } }>
    }>;
    refUpdates?: Array<{
      name?: string;      // "refs/heads/main"
      newObjectId?: string;
    }>;
    repository?: {
      name?: string;
      project?: { name?: string };
      remoteUrl?: string;
      defaultBranch?: string;
    };
    url?: string;
  };
};

type AdoPrPayload = {
  eventType?: string;
  resource?: {
    pullRequestId?: number;
    title?: string;
    status?: string;       // "completed" when merged
    url?: string;
    repository?: {
      name?: string;
      project?: { name?: string };
    };
    lastMergeCommit?: { commitId?: string };
    targetRefName?: string;  // "refs/heads/main"
  };
};

// ── Derive full name from ADO repo ────────────────────────────────────────────

function buildFullName(payload: AdoPushPayload | AdoPrPayload): string | null {
  const resource = payload.resource
  if (!resource) return null

  const repo = (payload as AdoPushPayload).resource?.repository
    ?? (payload as AdoPrPayload).resource?.repository
  if (!repo) return null

  const project = repo.project?.name
  const repoName = repo.name
  if (!project || !repoName) return null

  return `${project}/${repoName}` // ADO format: "ProjectName/RepoName"
}

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteAzureDevOpsWebhook = internalAction({
  args: {
    body: v.string(),
    authorization: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    if (!verifyAzureDevOpsAuth(args.authorization)) {
      return { accepted: false, reason: "invalid_auth" };
    }

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(args.body) as Record<string, unknown>;
    } catch {
      return { accepted: false, reason: "invalid_json" };
    }

    const eventType = String(payload.eventType ?? "");

    if (eventType === "git.push") {
      return await routePushEvent(ctx, payload as AdoPushPayload);
    }

    if (eventType === "git.pullrequest.merged") {
      return await routePrMergedEvent(ctx, payload as AdoPrPayload);
    }

    return { accepted: false, reason: `unsupported_event:${eventType}` };
  },
});

// ── Push event routing ────────────────────────────────────────────────────────

async function routePushEvent(
  ctx: import("./_generated/server").ActionCtx,
  payload: AdoPushPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const repoFullName = buildFullName(payload);
  if (!repoFullName) return { accepted: false, reason: "missing_repo_info" };

  const resource = payload.resource;
  const refUpdate = resource?.refUpdates?.[0];
  const branch = refUpdate?.name?.replace("refs/heads/", "") ?? "main";
  const commitSha = refUpdate?.newObjectId ?? "unknown";
  const commitMessages = resource?.commits?.map((c) => c.comment ?? "").filter(Boolean) ?? [];

  const repo = await ctx.runQuery(internal.azureDevOpsWebhooks.findAdoRepository, {
    fullName: repoFullName,
  });

  if (!repo) {
    console.log(`[ado] no repository found for ${repoFullName}`);
    return { accepted: false, workflowRunId: null };
  }

  const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
    await ctx.runMutation(internal.azureDevOpsWebhooks.recordAdoPushEvent, {
      tenantId: repo.tenantId,
      repositoryId: repo._id,
      branch,
      commitSha,
    });

  if (result.accepted && commitMessages.length > 0) {
    ctx.scheduler.runAfter(0, internal.promptIntelligence.scanContentByRef, {
      repositoryFullName: repoFullName,
      provider: "github" as const, // closest supported provider
      contentRef: "ado_commit_messages",
      content: commitMessages.join("\n").slice(0, 4000),
    });
  }

  return result;
}

// ── PR merged routing ─────────────────────────────────────────────────────────

async function routePrMergedEvent(
  ctx: import("./_generated/server").ActionCtx,
  payload: AdoPrPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const repoFullName = buildFullName(payload);
  const resource = payload.resource;
  if (!repoFullName || !resource) return { accepted: false, reason: "missing_pr_data" };

  // Construct a PR URL from the resource URL
  const prUrl = resource.url ?? `ado://${repoFullName}/pullrequests/${resource.pullRequestId}`;
  const prNumber = resource.pullRequestId ?? 0;

  ctx.scheduler.runAfter(0, internal.postFixValidation.handlePrMerged, {
    repositoryFullName: repoFullName,
    prNumber,
    prUrl,
    mergedAt: Date.now(),
  });

  return { accepted: true, workflowRunId: null };
}

// ── Internal queries and mutations ────────────────────────────────────────────

export const findAdoRepository = internalQuery({
  args: { fullName: v.string() },
  handler: async (ctx, { fullName }) => {
    // Try exact match first, then scan for ADO repos
    return await ctx.db
      .query("repositories")
      .take(100)
      .then((repos) => repos.find((r) => r.fullName === fullName) ?? null);
  },
});

export const recordAdoPushEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `ado-push-${args.repositoryId}-${args.commitSha}`;

    const existing = await ctx.db
      .query("ingestionEvents")
      .withIndex("by_dedupe_key", (q) => q.eq("dedupeKey", dedupeKey))
      .first();

    if (existing) return { accepted: false, workflowRunId: null, deduped: true };

    await ctx.db.patch(args.repositoryId, {
      latestCommitSha: args.commitSha,
      lastScannedAt: Date.now(),
    });

    const eventId = await ctx.db.insert("ingestionEvents", {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      dedupeKey,
      kind: "push",
      source: "azure_devops",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: [],
      summary: `Azure DevOps push to ${args.branch} (${args.commitSha.slice(0, 7)})`,
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
      summary: `Repository scan from Azure DevOps push to ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
