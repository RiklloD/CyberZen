/**
 * CircleCI Webhook Integration (spec §4.6.1 — CI provider coverage)
 *
 * Supports CircleCI webhooks for workflow and job completion events.
 * CircleCI uses HMAC-SHA256 with the `circleci-signature` header value
 * formatted as "v1=<hex-digest>".
 *
 * Supported events:
 *   - workflow-completed  → repository scan workflow (pipeline VCS push)
 *   - job-completed       → informational only (no scan triggered)
 *   - ping                → connectivity test
 *
 * Configuration:
 *   npx convex env set CIRCLECI_WEBHOOK_SECRET <your-secret>
 *
 * CircleCI setup (per-project):
 *   Project Settings → Webhooks → Add Webhook
 *   URL:    https://<convex>.convex.site/webhooks/circleci
 *   Secret: <CIRCLECI_WEBHOOK_SECRET>
 *   Events: Workflow Completed
 *
 * Payload reference:
 *   project.slug  — "gh/org/repo", "bb/org/repo", "gl/org/repo"
 *   pipeline.vcs.revision — commit SHA
 *   pipeline.vcs.branch   — branch name (absent for tag builds)
 *   workflow.status       — success | failed | error | canceled | unauthorized
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify a CircleCI HMAC-SHA256 signature.
 *
 * CircleCI sends: `circleci-signature: v1=<hex>`
 * We compare against HMAC-SHA256(secret, raw-body).
 */
async function verifyCircleCiSignature(
  body: string,
  rawSignature: string | null | undefined,
): Promise<boolean> {
  const secret = process.env.CIRCLECI_WEBHOOK_SECRET;
  if (!secret) return true; // fail-open in local dev

  if (!rawSignature) return false;

  // Accept both "v1=<hex>" and bare hex
  const sigHex = rawSignature.startsWith("v1=")
    ? rawSignature.slice(3)
    : rawSignature;

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

  if (expected.length !== sigHex.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ sigHex.charCodeAt(i);
  }
  return diff === 0;
}

// ── CircleCI payload types ────────────────────────────────────────────────────

type CircleCiProjectSlug = string; // "gh/org/repo" | "bb/org/repo" | "gl/org/repo"

type CircleCiPayload = {
  type?: string;                   // "workflow-completed" | "job-completed" | "ping"
  id?: string;
  happened_at?: string;
  project?: {
    id?: string;
    slug?: CircleCiProjectSlug;
    name?: string;
    url?: string;
  };
  pipeline?: {
    id?: string;
    number?: number;
    vcs?: {
      revision?: string;           // commit SHA
      branch?: string;             // absent for tag builds
      tag?: string;
      origin_repository_url?: string;
      target_repository_url?: string;
    };
  };
  workflow?: {
    id?: string;
    name?: string;
    status?: string;               // "success" | "failed" | "error" | "canceled"
    url?: string;
  };
  job?: {
    id?: string;
    name?: string;
    status?: string;
    number?: number;
  };
  organization?: {
    id?: string;
    name?: string;
    slug?: string;
  };
};

// ── Slug parsing ──────────────────────────────────────────────────────────────

/**
 * Extract a normalised "org/repo" full name from a CircleCI project slug.
 *
 * CircleCI slug format: "<vcs-provider>/<org>/<repo>"
 *   - gh/acme/payments-api  → acme/payments-api
 *   - bb/acme/payments-api  → acme/payments-api
 *   - gl/acme/payments-api  → acme/payments-api
 *
 * Returns null when the slug does not match the expected format.
 */
export function parseCircleCiSlug(slug: CircleCiProjectSlug): string | null {
  const parts = slug.split("/");
  if (parts.length < 3) return null;
  // Drop the first segment (vcs provider prefix)
  return parts.slice(1).join("/");
}

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteCircleCiWebhook = internalAction({
  args: {
    body: v.string(),
    signature: v.optional(v.string()),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    const valid = await verifyCircleCiSignature(args.body, args.signature);
    if (!valid) return { accepted: false, reason: "invalid_signature" };

    let payload: CircleCiPayload;
    try {
      payload = JSON.parse(args.body) as CircleCiPayload;
    } catch {
      return { accepted: false, reason: "invalid_json" };
    }

    const eventType = payload.type ?? "";

    if (eventType === "ping") {
      return { accepted: true, reason: "ping_ok" };
    }

    if (eventType === "workflow-completed") {
      return await routeWorkflowCompleted(ctx, payload);
    }

    // job-completed is informational; acknowledge but don't trigger a scan
    if (eventType === "job-completed") {
      return { accepted: true, reason: "job_event_ignored" };
    }

    return { accepted: false, reason: `unsupported_event:${eventType}` };
  },
});

// ── Workflow-completed routing ────────────────────────────────────────────────

async function routeWorkflowCompleted(
  ctx: import("./_generated/server").ActionCtx,
  payload: CircleCiPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const slug = payload.project?.slug;
  if (!slug) return { accepted: false, reason: "missing_project_slug" };

  const fullName = parseCircleCiSlug(slug);
  if (!fullName) return { accepted: false, reason: "unparseable_slug" };

  const vcs = payload.pipeline?.vcs;
  const branch = vcs?.branch ?? "main";
  const commitSha = vcs?.revision ?? "unknown";
  const pipelineNumber = payload.pipeline?.number ?? 0;

  const repo = await ctx.runQuery(internal.circleciWebhooks.findCircleCiRepository, {
    fullName,
  });

  if (!repo) {
    console.log(`[circleci] no repository registered for ${fullName}`);
    return { accepted: false, workflowRunId: null };
  }

  const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
    await ctx.runMutation(internal.circleciWebhooks.recordCircleCiPushEvent, {
      tenantId: repo.tenantId,
      repositoryId: repo._id,
      branch,
      commitSha,
      pipelineNumber,
    });

  return result;
}

// ── Internal queries and mutations ────────────────────────────────────────────

export const findCircleCiRepository = internalQuery({
  args: { fullName: v.string() },
  handler: async (ctx, { fullName }) => {
    // Try matching via the by_provider_and_full_name index first (GitHub-backed repos)
    return (
      (await ctx.db
        .query("repositories")
        .withIndex("by_provider_and_full_name", (q) =>
          q.eq("provider", "github").eq("fullName", fullName),
        )
        .first()) ??
      // Fallback: scan up to 100 repos for any provider match
      (await ctx.db
        .query("repositories")
        .take(100)
        .then((repos) => repos.find((r) => r.fullName === fullName) ?? null))
    );
  },
});

export const recordCircleCiPushEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
    pipelineNumber: v.number(),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `circleci-push-${args.repositoryId}-${args.commitSha}`;

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
      source: "circleci",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: [],
      summary: `CircleCI pipeline #${args.pipelineNumber} on ${args.branch} (${args.commitSha.slice(0, 7)})`,
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
      summary: `Repository scan from CircleCI pipeline #${args.pipelineNumber} on ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
