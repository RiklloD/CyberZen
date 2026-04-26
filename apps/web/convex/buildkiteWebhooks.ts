/**
 * Buildkite Webhook Integration (spec §4.6.1 — CI provider coverage)
 *
 * Supports Buildkite webhooks for build lifecycle events.
 * Buildkite uses a simple shared-secret token sent in the
 * `X-Buildkite-Token` header (no HMAC). We compare verbatim
 * using a constant-time char-by-char XOR to avoid timing attacks.
 *
 * Supported events:
 *   - build.finished   → repository scan workflow (state = passed | failed)
 *   - build.running    → acknowledged, no scan triggered
 *   - build.scheduled  → acknowledged, no scan triggered
 *   - ping             → connectivity test
 *
 * Configuration:
 *   npx convex env set BUILDKITE_WEBHOOK_TOKEN <your-token>
 *
 * Buildkite setup (per-pipeline):
 *   Pipeline Settings → Notifications → Webhook → Add
 *   URL:    https://<convex>.convex.site/webhooks/buildkite
 *   Token:  <BUILDKITE_WEBHOOK_TOKEN>
 *   Events: Build Finished (and optionally Build Running, Build Scheduled)
 *
 * Payload reference:
 *   pipeline.repository — git remote URL (SSH or HTTPS)
 *   build.commit        — commit SHA
 *   build.branch        — branch name
 *   build.state         — passed | failed | blocked | canceled | skipped
 *   build.number        — build number
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Token verification ────────────────────────────────────────────────────────

/**
 * Verify a Buildkite shared-secret token.
 *
 * Buildkite sends: `X-Buildkite-Token: <token>`
 * We compare verbatim in constant time via char-by-char XOR.
 * Fail-open (return true) when BUILDKITE_WEBHOOK_TOKEN is not set.
 */
function verifyBuildkiteToken(receivedToken: string | null | undefined): boolean {
  const secret = process.env.BUILDKITE_WEBHOOK_TOKEN;
  if (!secret) return true; // fail-open in local dev / when not configured

  if (!receivedToken) return false;

  // Constant-time comparison: XOR every character, accumulate diff
  const a = secret;
  const b = receivedToken;

  // Length difference leaks information, but we still must prevent short-circuit
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length; // non-zero if lengths differ
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// ── Buildkite payload types ───────────────────────────────────────────────────

type BuildkitePayload = {
  event?: string;         // "build.finished" | "build.running" | "build.scheduled" | "ping"
  build?: {
    id?: string;
    number?: number;
    state?: string;       // "passed" | "failed" | "blocked" | "canceled" | "skipped"
    commit?: string;
    branch?: string;
    message?: string;
  };
  pipeline?: {
    id?: string;
    name?: string;
    slug?: string;
    repository?: string;  // git remote URL
  };
  organization?: {
    id?: string;
    slug?: string;
    name?: string;
  };
};

// ── Repository URL parsing ────────────────────────────────────────────────────

/**
 * Extract a normalised "org/repo" full name from a Buildkite pipeline
 * repository URL.
 *
 * Supported formats:
 *   SSH GitHub:    git@github.com:org/repo.git     → org/repo
 *   SSH Bitbucket: git@bitbucket.org:org/repo.git  → org/repo
 *   HTTPS + .git:  https://github.com/org/repo.git → org/repo
 *   HTTPS bare:    https://github.com/org/repo      → org/repo
 *
 * Returns null when the URL cannot be parsed into an "org/repo" shape.
 */
export function parseRepoUrlFromBuildkite(url: string): string | null {
  if (!url) return null;

  // SSH format: git@<host>:<org>/<repo>[.git]
  const sshMatch = url.match(/^git@[^:]+:(.+?)(?:\.git)?$/);
  if (sshMatch) {
    const path = sshMatch[1];
    if (!path || !path.includes("/")) return null;
    return path;
  }

  // HTTPS format: https://<host>/<org>/<repo>[.git]
  const httpsMatch = url.match(/^https?:\/\/[^/]+\/(.+?)(?:\.git)?$/);
  if (httpsMatch) {
    const path = httpsMatch[1];
    if (!path || !path.includes("/")) return null;
    return path;
  }

  return null;
}

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteBuildkiteWebhook = internalAction({
  args: {
    body: v.string(),
    token: v.optional(v.string()),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    const valid = verifyBuildkiteToken(args.token);
    if (!valid) return { accepted: false, reason: "invalid_token" };

    let payload: BuildkitePayload;
    try {
      payload = JSON.parse(args.body) as BuildkitePayload;
    } catch {
      return { accepted: false, reason: "invalid_json" };
    }

    const eventType = payload.event ?? "";

    if (eventType === "ping") {
      return { accepted: true, reason: "ping_ok" };
    }

    // Acknowledge lifecycle events that don't require a scan
    if (eventType === "build.running" || eventType === "build.scheduled") {
      return { accepted: true, reason: "build_event_ignored" };
    }

    if (eventType === "build.finished") {
      return await routeBuildFinished(ctx, payload);
    }

    return { accepted: false, reason: `unsupported_event:${eventType}` };
  },
});

// ── build.finished routing ────────────────────────────────────────────────────

async function routeBuildFinished(
  ctx: import("./_generated/server").ActionCtx,
  payload: BuildkitePayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const buildState = payload.build?.state ?? "";

  // Only trigger a scan for actionable terminal states
  if (buildState !== "passed" && buildState !== "failed") {
    if (buildState === "blocked") {
      return { accepted: true, reason: "build_blocked_ignored" };
    }
    // canceled, skipped, or unknown states
    return { accepted: true, reason: "build_state_ignored" };
  }

  const repositoryUrl = payload.pipeline?.repository;
  if (!repositoryUrl) {
    return { accepted: false, reason: "missing_pipeline_repository" };
  }

  const fullName = parseRepoUrlFromBuildkite(repositoryUrl);
  if (!fullName) {
    return { accepted: false, reason: "unparseable_repository_url" };
  }

  const branch = payload.build?.branch ?? "main";
  const commitSha = payload.build?.commit ?? "unknown";
  const buildNumber = payload.build?.number ?? 0;

  const repo = await ctx.runQuery(internal.buildkiteWebhooks.findBuildkiteRepository, {
    fullName,
  });

  if (!repo) {
    console.log(`[buildkite] no repository registered for ${fullName}`);
    return { accepted: false, workflowRunId: null };
  }

  const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
    await ctx.runMutation(internal.buildkiteWebhooks.recordBuildkiteEvent, {
      tenantId: repo.tenantId,
      repositoryId: repo._id,
      branch,
      commitSha,
      buildNumber,
      buildState,
    });

  return result;
}

// ── Internal queries and mutations ────────────────────────────────────────────

export const findBuildkiteRepository = internalQuery({
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

export const recordBuildkiteEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
    buildNumber: v.number(),
    buildState: v.string(),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `buildkite-build-${args.repositoryId}-${args.commitSha}`;

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
      source: "buildkite",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: [],
      summary: `Buildkite build #${args.buildNumber} (${args.buildState}) on ${args.branch} (${args.commitSha.slice(0, 7)})`,
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
      summary: `Repository scan from Buildkite build #${args.buildNumber} (${args.buildState}) on ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
