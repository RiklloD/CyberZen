"use node";
/**
 * Bitbucket Webhook Integration (spec §4.6.1)
 *
 * Supports Bitbucket Cloud webhooks for push and pull request events.
 * Bitbucket uses HMAC-SHA256 with header X-Hub-Signature (same format as GitHub).
 *
 * Supported events:
 *   - repo:push             → repository scan workflow
 *   - pullrequest:fulfilled → post-fix validation (PR merged)
 *   - pullrequest:created   → pre-merge gate check (future)
 *
 * Configuration:
 *   npx convex env set BITBUCKET_WEBHOOK_SECRET <your-secret>
 *
 * Bitbucket setup (per-repository):
 *   Repository settings → Webhooks → Add webhook
 *   URL: https://<convex>.convex.site/webhooks/bitbucket
 *   Secret: <BITBUCKET_WEBHOOK_SECRET>
 *   Triggers: Repository → Push, Pull request → Merged
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Signature verification ────────────────────────────────────────────────────

async function verifyBitbucketSignature(
  body: string,
  signature: string | null | undefined,
): Promise<boolean> {
  const secret = process.env.BITBUCKET_WEBHOOK_SECRET;
  if (!secret) return true; // fail-open in local dev

  if (!signature) return false;

  // Bitbucket uses "sha256=..." format (same as GitHub)
  const sigValue = signature.startsWith("sha256=")
    ? signature.slice(7)
    : signature;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  const expected = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Constant-time comparison
  if (expected.length !== sigValue.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ sigValue.charCodeAt(i);
  }
  return result === 0;
}

// ── Bitbucket payload types ───────────────────────────────────────────────────

type BitbucketPushPayload = {
  repository?: {
    full_name?: string;            // "workspace/repo"
    mainbranch?: { name?: string };
  };
  push?: {
    changes?: Array<{
      new?: { name?: string; target?: { hash?: string } };
      commits?: Array<{
        hash?: string;
        message?: string;
        type?: string;
      }>;
    }>;
  };
};

type BitbucketPrPayload = {
  repository?: { full_name?: string };
  pullrequest?: {
    id?: number;
    title?: string;
    state?: string;
    links?: { html?: { href?: string } };
    merge_commit?: { hash?: string };
    destination?: { branch?: { name?: string } };
  };
};

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteBitbucketWebhook = internalAction({
  args: {
    body: v.string(),
    event: v.string(),
    signature: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    const valid = await verifyBitbucketSignature(args.body, args.signature);
    if (!valid) return { accepted: false, reason: "invalid_signature" };

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(args.body) as Record<string, unknown>;
    } catch {
      return { accepted: false, reason: "invalid_json" };
    }

    const eventLower = args.event.toLowerCase().replace(":", "_");

    if (eventLower === "repo_push") {
      return await routePushEvent(ctx, payload as BitbucketPushPayload);
    }

    if (eventLower === "pullrequest_fulfilled") {
      return await routePrMergedEvent(ctx, payload as BitbucketPrPayload);
    }

    return { accepted: false, reason: `unsupported_event:${args.event}` };
  },
});

// ── Push routing ──────────────────────────────────────────────────────────────

async function routePushEvent(
  ctx: import("./_generated/server").ActionCtx,
  payload: BitbucketPushPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const repoFullName = payload.repository?.full_name;
  if (!repoFullName) return { accepted: false, reason: "missing_repo_full_name" };

  const changes = payload.push?.changes ?? [];
  const firstChange = changes[0];
  if (!firstChange) return { accepted: false, reason: "no_changes" };

  const branch = firstChange.new?.name ?? payload.repository?.mainbranch?.name ?? "main";
  const commitSha = firstChange.new?.target?.hash ?? "unknown";
  const commitMessages = firstChange.commits
    ?.map((c) => c.message ?? "")
    .filter(Boolean) ?? [];

  const repo = await ctx.runQuery(internal.bitbucketWebhooks.findBitbucketRepository, {
    fullName: repoFullName,
  });

  if (!repo) {
    console.log(`[bitbucket] no repository found for ${repoFullName}`);
    return { accepted: false, workflowRunId: null };
  }

  const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
    await ctx.runMutation(internal.bitbucketWebhooks.recordBitbucketPushEvent, {
      tenantId: repo.tenantId,
      repositoryId: repo._id,
      branch,
      commitSha,
    });

  if (result.accepted && commitMessages.length > 0) {
    ctx.scheduler.runAfter(0, internal.promptIntelligence.scanContentByRef, {
      repositoryFullName: repoFullName,
      provider: "github" as const, // closest supported provider
      contentRef: "bitbucket_commit_messages",
      content: commitMessages.join("\n").slice(0, 4000),
    });
  }

  return result;
}

// ── PR merged routing ─────────────────────────────────────────────────────────

async function routePrMergedEvent(
  ctx: import("./_generated/server").ActionCtx,
  payload: BitbucketPrPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const repoFullName = payload.repository?.full_name;
  const pr = payload.pullrequest;
  if (!repoFullName || !pr) return { accepted: false, reason: "missing_pr_data" };

  const prUrl = pr.links?.html?.href;
  const prNumber = pr.id;
  if (!prUrl || !prNumber) return { accepted: false, reason: "missing_pr_url" };

  ctx.scheduler.runAfter(0, internal.postFixValidation.handlePrMerged, {
    repositoryFullName: repoFullName,
    prNumber,
    prUrl,
    mergedAt: Date.now(),
  });

  return { accepted: true, workflowRunId: null };
}

// ── Internal queries and mutations ────────────────────────────────────────────

export const findBitbucketRepository = internalQuery({
  args: { fullName: v.string() },
  handler: async (ctx, { fullName }) => {
    // Bitbucket uses "workspace/repo" — try matching against our fullName field
    return await ctx.db
      .query("repositories")
      .withIndex("by_provider_and_full_name", (q) =>
        q.eq("provider", "github").eq("fullName", fullName),  // stored as-is
      )
      .first() ??
      await ctx.db
        .query("repositories")
        .take(100)
        .then((repos) => repos.find((r) => r.fullName === fullName) ?? null);
  },
});

export const recordBitbucketPushEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `bitbucket-push-${args.repositoryId}-${args.commitSha}`;

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
      source: "bitbucket",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: [],
      summary: `Bitbucket push to ${args.branch} (${args.commitSha.slice(0, 7)})`,
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
      summary: `Repository scan from Bitbucket push to ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
