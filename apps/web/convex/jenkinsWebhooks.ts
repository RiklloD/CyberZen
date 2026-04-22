"use node";
/**
 * Jenkins Webhook Integration (spec §4.6.2 — last remaining CI provider)
 *
 * Supports the Jenkins "Notification Plugin" (and compatible shapes such as
 * the Generic Webhook Trigger plugin) for build lifecycle events. Jenkins has
 * no native outbound webhook standard and no HMAC — so we follow the same
 * pattern as Buildkite: a shared-secret token sent verbatim in a custom
 * header.
 *
 * Auth approach (choice B):
 *   Header: X-Jenkins-Token: <token>
 *   Env var: JENKINS_WEBHOOK_TOKEN
 *
 * Supported build phases (from the Notification Plugin):
 *   - FINALIZED → repository scan workflow (when status ∈ {SUCCESS, FAILURE})
 *   - COMPLETED → acknowledged, no scan triggered (duplicate of FINALIZED)
 *   - STARTED / QUEUED → acknowledged, no scan triggered
 *   - ping → connectivity test (non-standard but supported for parity)
 *
 * Configuration:
 *   npx convex env set JENKINS_WEBHOOK_TOKEN <your-token>
 *
 * Jenkins setup (per-job or global, Notification Plugin):
 *   Configure → Job Notifications → Add endpoint
 *   Format:    JSON
 *   Protocol:  HTTP
 *   URL:       https://<convex>.convex.site/webhooks/jenkins
 *   Event:     All Events (we filter in-process)
 *   Custom header: X-Jenkins-Token = <JENKINS_WEBHOOK_TOKEN>
 *
 * Notification Plugin payload reference:
 *   name                  — job name (e.g. "payments-api/main")
 *   url                   — job URL relative to Jenkins root
 *   build.number          — build number
 *   build.phase           — QUEUED | STARTED | COMPLETED | FINALIZED
 *   build.status          — SUCCESS | FAILURE | ABORTED | UNSTABLE (absent before COMPLETED)
 *   build.scm.url         — git remote URL
 *   build.scm.branch      — refspec, e.g. "origin/main" or "refs/heads/main"
 *   build.scm.commit      — commit SHA
 */

import { v } from "convex/values";
import { internalAction, internalQuery, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Token verification ────────────────────────────────────────────────────────

/**
 * Verify a Jenkins shared-secret token.
 *
 * Jenkins sends: `X-Jenkins-Token: <token>`
 * We compare verbatim in constant time via char-by-char XOR to avoid leaking
 * information through early-exit timing differences.
 * Fail-open (return true) when JENKINS_WEBHOOK_TOKEN is not set so that local
 * dev and first-boot scenarios don't reject every delivery.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  USER CONTRIBUTION BLOCK — implement this function
 * ─────────────────────────────────────────────────────────────────────────
 *  Requirements:
 *   1. Read the configured secret from `process.env.JENKINS_WEBHOOK_TOKEN`.
 *   2. If the env var is unset/empty, return `true` (fail-open for local dev).
 *   3. If `receivedToken` is null/undefined/empty, return `false`.
 *   4. Compare the two strings in constant time — do NOT use `===` directly,
 *      and do NOT short-circuit on length mismatch. See the XOR-accumulator
 *      pattern in `verifyBuildkiteToken` (buildkiteWebhooks.ts lines 46–63)
 *      for a worked example you can adapt verbatim.
 *
 *  Target: 5–10 lines inside the function body.
 * ─────────────────────────────────────────────────────────────────────────
 */
function verifyJenkinsToken(receivedToken: string | null | undefined): boolean {
  const secret = process.env.JENKINS_WEBHOOK_TOKEN;
  if (!secret) return true; // fail-open in local dev / when not configured

  if (!receivedToken) return false;

  // Constant-time comparison: walk the full length regardless of mismatch
  // position, so response timing cannot leak the secret byte-by-byte.
  const a = secret;
  const b = receivedToken;
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length; // non-zero if lengths differ
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// ── Jenkins payload types ─────────────────────────────────────────────────────

type JenkinsPayload = {
  event?: string;       // non-standard; used for "ping"
  name?: string;        // job name, e.g. "payments-api/main"
  url?: string;         // job URL (relative to Jenkins root)
  build?: {
    number?: number;
    phase?: string;     // QUEUED | STARTED | COMPLETED | FINALIZED
    status?: string;    // SUCCESS | FAILURE | ABORTED | UNSTABLE
    url?: string;
    full_url?: string;
    scm?: {
      url?: string;     // git remote URL
      branch?: string;  // "origin/main" or "refs/heads/main"
      commit?: string;  // commit SHA
    };
  };
};

// ── Repository URL / branch parsing ───────────────────────────────────────────

/**
 * Extract a normalised "org/repo" full name from a Jenkins SCM URL.
 *
 * Supported formats:
 *   SSH GitHub:    git@github.com:org/repo.git     → org/repo
 *   SSH Bitbucket: git@bitbucket.org:org/repo.git  → org/repo
 *   HTTPS + .git:  https://github.com/org/repo.git → org/repo
 *   HTTPS bare:    https://github.com/org/repo     → org/repo
 *
 * Returns null when the URL cannot be parsed into an "org/repo" shape.
 */
export function parseRepoUrlFromJenkins(url: string): string | null {
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

/**
 * Normalise a Jenkins branch refspec into a plain branch name.
 *   "origin/main"        → "main"
 *   "refs/heads/main"    → "main"
 *   "main"               → "main"
 *   ""                   → "main" (fallback)
 */
export function normaliseJenkinsBranch(ref: string | undefined): string {
  if (!ref) return "main";
  if (ref.startsWith("refs/heads/")) return ref.slice("refs/heads/".length);
  if (ref.startsWith("origin/")) return ref.slice("origin/".length);
  return ref;
}

// ── Event router ──────────────────────────────────────────────────────────────

export const verifyAndRouteJenkinsWebhook = internalAction({
  args: {
    body: v.string(),
    token: v.optional(v.string()),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> => {
    const valid = verifyJenkinsToken(args.token);
    if (!valid) return { accepted: false, reason: "invalid_token" };

    let payload: JenkinsPayload;
    try {
      payload = JSON.parse(args.body) as JenkinsPayload;
    } catch {
      return { accepted: false, reason: "invalid_json" };
    }

    // Non-standard ping event for connectivity testing
    if (payload.event === "ping") {
      return { accepted: true, reason: "ping_ok" };
    }

    const phase = payload.build?.phase ?? "";

    // Intermediate phases — acknowledge without scanning
    if (phase === "QUEUED" || phase === "STARTED") {
      return { accepted: true, reason: "build_phase_ignored" };
    }

    // COMPLETED fires right before FINALIZED. We prefer FINALIZED (post-run
    // artifacts are flushed) and ignore COMPLETED to avoid double-triggering.
    if (phase === "COMPLETED") {
      return { accepted: true, reason: "build_phase_duplicate_ignored" };
    }

    if (phase === "FINALIZED") {
      return await routeBuildFinalised(ctx, payload);
    }

    return { accepted: false, reason: `unsupported_phase:${phase}` };
  },
});

// ── FINALIZED routing ─────────────────────────────────────────────────────────

async function routeBuildFinalised(
  ctx: import("./_generated/server").ActionCtx,
  payload: JenkinsPayload,
): Promise<{ accepted: boolean; reason?: string; workflowRunId?: string | null }> {
  const status = payload.build?.status ?? "";

  // Only trigger a scan on actionable terminal states
  if (status !== "SUCCESS" && status !== "FAILURE") {
    if (status === "ABORTED") {
      return { accepted: true, reason: "build_aborted_ignored" };
    }
    if (status === "UNSTABLE") {
      return { accepted: true, reason: "build_unstable_ignored" };
    }
    return { accepted: true, reason: "build_status_ignored" };
  }

  const repositoryUrl = payload.build?.scm?.url;
  if (!repositoryUrl) {
    return { accepted: false, reason: "missing_scm_url" };
  }

  const fullName = parseRepoUrlFromJenkins(repositoryUrl);
  if (!fullName) {
    return { accepted: false, reason: "unparseable_repository_url" };
  }

  const branch = normaliseJenkinsBranch(payload.build?.scm?.branch);
  const commitSha = payload.build?.scm?.commit ?? "unknown";
  const buildNumber = payload.build?.number ?? 0;
  const jobName = payload.name ?? "unknown-job";

  const repo = await ctx.runQuery(internal.jenkinsWebhooks.findJenkinsRepository, {
    fullName,
  });

  if (!repo) {
    console.log(`[jenkins] no repository registered for ${fullName}`);
    return { accepted: false, workflowRunId: null };
  }

  const result: { accepted: boolean; workflowRunId: string | null; deduped?: boolean } =
    await ctx.runMutation(internal.jenkinsWebhooks.recordJenkinsEvent, {
      tenantId: repo.tenantId,
      repositoryId: repo._id,
      branch,
      commitSha,
      buildNumber,
      buildStatus: status,
      jobName,
    });

  return result;
}

// ── Internal queries and mutations ────────────────────────────────────────────

export const findJenkinsRepository = internalQuery({
  args: { fullName: v.string() },
  handler: async (ctx, { fullName }) => {
    // Prefer the GitHub-backed index first; fall back to a bounded scan for
    // repositories registered under a different provider.
    return (
      (await ctx.db
        .query("repositories")
        .withIndex("by_provider_and_full_name", (q) =>
          q.eq("provider", "github").eq("fullName", fullName),
        )
        .first()) ??
      (await ctx.db
        .query("repositories")
        .take(100)
        .then((repos) => repos.find((r) => r.fullName === fullName) ?? null))
    );
  },
});

export const recordJenkinsEvent = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    branch: v.string(),
    commitSha: v.string(),
    buildNumber: v.number(),
    buildStatus: v.string(),
    jobName: v.string(),
  },
  handler: async (ctx, args) => {
    const dedupeKey = `jenkins-build-${args.repositoryId}-${args.commitSha}-${args.buildNumber}`;

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
      source: "jenkins",
      workflowType: "repository_scan",
      status: "running",
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: [],
      summary: `Jenkins build #${args.buildNumber} (${args.buildStatus}) on ${args.branch} (${args.commitSha.slice(0, 7)}) — job ${args.jobName}`,
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
      summary: `Repository scan from Jenkins build #${args.buildNumber} (${args.buildStatus}) on ${args.branch}`,
      totalTaskCount: 6,
      completedTaskCount: 0,
      startedAt: Date.now(),
    });

    return { accepted: true, workflowRunId: workflowRunId as string, deduped: false };
  },
});
