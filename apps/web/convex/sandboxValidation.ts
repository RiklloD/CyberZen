/**
 * Sentinel Sandbox Validation — Convex action layer.
 *
 * Connects the Convex control plane to the Python sandbox-manager service.
 * Flow:
 *   1. triggerSandboxValidation (internalAction) — called fire-and-forget from events.ts
 *      after a finding is created.
 *   2. Calls sandbox-manager /validate endpoint with the finding's context.
 *   3. Writes a sandboxEnvironments row with full evidence.
 *   4. Patches the exploitValidationRun + finding with real outcome.
 *   5. Dispatches finding.validated webhook if exploited / likely_exploitable.
 *
 * sandboxResultWebhook (internalMutation) — alternative path where the
 * sandbox-manager POSTs its result back instead of Convex polling.
 */

import { ConvexError, v } from "convex/values";
import { internalAction, internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { internal, api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";

// ── Configuration ─────────────────────────────────────────────────────────────

const SANDBOX_MANAGER_URL =
  process.env.SANDBOX_MANAGER_URL ?? "http://localhost:8001";

// ── Types mirroring Python models ─────────────────────────────────────────────

type SandboxOutcome =
  | "exploited"
  | "likely_exploitable"
  | "not_exploitable"
  | "error";

interface SandboxValidationResult {
  finding_id: string;
  outcome: SandboxOutcome;
  confidence: number;
  attempts: Array<{
    payload_label: string;
    category: string;
    success: boolean;
    skip_reason?: string;
    matched_indicators: string[];
  }>;
  poc_curl?: string;
  poc_python?: string;
  evidence_summary: string;
  sandbox_mode: "http_probe" | "dry_run";
  elapsed_ms: number;
}

// ── Public query — dashboard reads ───────────────────────────────────────────

export const getLatestSandboxEnvironment = query({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => {
    return await ctx.db
      .query("sandboxEnvironments")
      .withIndex("by_finding", (q) => q.eq("findingId", findingId))
      .order("desc")
      .first();
  },
});

export const getSandboxSummaryForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const recent = await ctx.db
      .query("sandboxEnvironments")
      .withIndex("by_repository_and_started_at", (q) =>
        q.eq("repositoryId", repositoryId)
      )
      .order("desc")
      .take(20);

    const exploited = recent.filter((s) => s.outcome === "exploited").length;
    const likelyExploitable = recent.filter(
      (s) => s.outcome === "likely_exploitable"
    ).length;
    const notExploitable = recent.filter(
      (s) => s.outcome === "not_exploitable"
    ).length;
    const withPoc = recent.filter((s) => s.pocCurl != null).length;

    return {
      totalRuns: recent.length,
      exploited,
      likelyExploitable,
      notExploitable,
      withPoc,
      latestRun: recent[0] ?? null,
    };
  },
});

// Slug-based variant for HTTP endpoints — resolves tenant+repo internally
/**
 * Public query — list exploit validation runs for a repository (used by
 * the Exploit Validation dashboard page). Returns the run metadata plus
 * the linked sandbox environment's PoC artifacts.
 */
export const listExploitValidationRuns = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const runs = await ctx.db
      .query("exploitValidationRuns")
      .withIndex("by_repository_and_started_at", (q) =>
        q.eq("repositoryId", repositoryId)
      )
      .order("desc")
      .take(30);

    return Promise.all(
      runs.map(async (run) => {
        const finding = await ctx.db.get(run.findingId);

        // Fetch the linked sandbox environment for PoC artifacts
        const sandboxEnv = await ctx.db
          .query("sandboxEnvironments")
          .withIndex("by_validation_run", (q) =>
            q.eq("exploitValidationRunId", run._id)
          )
          .order("desc")
          .first();

        return {
          _id: run._id,
          findingId: run.findingId,
          findingTitle: finding?.title ?? "Unknown finding",
          findingSeverity: finding?.severity ?? "unknown",
          status: run.status,
          outcome: run.outcome ?? null,
          validationConfidence: run.validationConfidence,
          sandboxSummary: run.sandboxSummary,
          evidenceSummary: run.evidenceSummary,
          reproductionHint: run.reproductionHint,
          startedAt: run.startedAt,
          completedAt: run.completedAt ?? null,
          pocCurl: sandboxEnv?.pocCurl ?? null,
          pocPython: sandboxEnv?.pocPython ?? null,
          winningPayloadLabel: sandboxEnv?.winningPayloadLabel ?? null,
          sandboxMode: sandboxEnv?.sandboxMode ?? null,
          elapsedMs: sandboxEnv?.elapsedMs ?? null,
        };
      })
    );
  }, // FIX: C4 — spurious `)` removed from handler closure
});

export const getSandboxSummaryBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) return null;

    const repo = await ctx.db
      .query("repositories")
      .withIndex("by_tenant_and_full_name", (q) =>
        q.eq("tenantId", tenant._id).eq("fullName", repositoryFullName)
      )
      .unique();
    if (!repo) return null;

    const recent = await ctx.db
      .query("sandboxEnvironments")
      .withIndex("by_repository_and_started_at", (q) =>
        q.eq("repositoryId", repo._id)
      )
      .order("desc")
      .take(20);

    return {
      totalRuns: recent.length,
      exploited: recent.filter((s) => s.outcome === "exploited").length,
      likelyExploitable: recent.filter((s) => s.outcome === "likely_exploitable").length,
      notExploitable: recent.filter((s) => s.outcome === "not_exploitable").length,
      withPoc: recent.filter((s) => s.pocCurl != null).length,
      latestRun: recent[0] ?? null,
    };
  },
});

// ── Internal — trigger validation ─────────────────────────────────────────────

export const triggerSandboxValidation = internalAction({
  args: {
    findingId: v.id("findings"),
    exploitValidationRunId: v.id("exploitValidationRuns"),
    targetBaseUrl: v.optional(v.string()),
  },
  handler: async (ctx, { findingId, exploitValidationRunId, targetBaseUrl }) => {
    // Load finding context
    const finding = await ctx.runQuery(internal.sandboxValidation.getFindingContext, {
      findingId,
    });
    if (!finding) {
      console.error(`[sandbox] finding ${findingId} not found`);
      return;
    }

    // Create sandboxEnvironments row in queued state
    const sandboxEnvId: Id<"sandboxEnvironments"> = await ctx.runMutation(
      internal.sandboxValidation.createSandboxEnvironment,
      {
        tenantId: finding.tenantId,
        repositoryId: finding.repositoryId,
        findingId,
        exploitValidationRunId,
        sandboxMode: targetBaseUrl ? "http_probe" : "dry_run",
        targetBaseUrl,
      }
    );

    // Call sandbox-manager
    let result: SandboxValidationResult;
    try {
      const payload = {
        finding_id: findingId,
        repository_full_name: finding.repositoryFullName,
        vuln_class: finding.vulnClass,
        severity: finding.severity,
        affected_packages: finding.affectedPackages,
        affected_services: finding.affectedServices,
        target_base_url: targetBaseUrl ?? null,
        cve_id: finding.cveId ?? null,
        max_attempts: 20,
        timeout_seconds: 30,
      };

      const resp = await fetch(`${SANDBOX_MANAGER_URL}/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(90_000), // 90s hard limit
      });

      if (!resp.ok) {
        throw new Error(`sandbox-manager returned ${resp.status}: ${await resp.text()}`);
      }

      result = (await resp.json()) as SandboxValidationResult;
    } catch (err) {
      console.error(`[sandbox] validation error for finding ${findingId}:`, err);
      await ctx.runMutation(internal.sandboxValidation.markSandboxFailed, {
        sandboxEnvId,
        exploitValidationRunId,
        findingId,
        errorMessage: String(err),
      });
      return;
    }

    // Persist result
    await ctx.runMutation(internal.sandboxValidation.persistSandboxResult, {
      sandboxEnvId,
      exploitValidationRunId,
      findingId,
      result: {
        outcome: result.outcome,
        confidence: result.confidence,
        totalAttempts: result.attempts.length,
        successfulAttempts: result.attempts.filter((a) => a.success).length,
        winningPayloadLabel:
          result.attempts.find((a) => a.success)?.payload_label ?? null,
        pocCurl: result.poc_curl ?? null,
        pocPython: result.poc_python ?? null,
        evidenceSummary: result.evidence_summary,
        elapsedMs: result.elapsed_ms,
        sandboxMode: result.sandbox_mode,
      },
    });

    // Fire webhook if finding was exploited
    if (
      result.outcome === "exploited" ||
      result.outcome === "likely_exploitable"
    ) {
      await ctx.scheduler.runAfter(
        0,
        internal.sandboxValidation.dispatchValidatedWebhook,
        { findingId, outcome: result.outcome }
      );
    }
  },
});

// ── Internal queries ──────────────────────────────────────────────────────────

export const getFindingContext = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => {
    const finding = await ctx.db.get(findingId);
    if (!finding) return null;

    const repo = await ctx.db.get(finding.repositoryId);

    // Try to extract CVE ID from the linked breach disclosure
    let cveId: string | undefined;
    if (finding.breachDisclosureId) {
      const disc = await ctx.db.get(finding.breachDisclosureId);
      if (disc) {
        const cveAlias = disc.aliases.find((a) => a.startsWith("CVE-"));
        if (cveAlias) cveId = cveAlias;
      }
    }

    return {
      tenantId: finding.tenantId,
      repositoryId: finding.repositoryId,
      repositoryFullName: repo?.fullName ?? "unknown/unknown",
      vulnClass: finding.vulnClass,
      severity: finding.severity,
      affectedPackages: finding.affectedPackages,
      affectedServices: finding.affectedServices,
      cveId,
    };
  },
});

// ── Internal mutations ────────────────────────────────────────────────────────

export const createSandboxEnvironment = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    findingId: v.id("findings"),
    exploitValidationRunId: v.id("exploitValidationRuns"),
    sandboxMode: v.union(v.literal("http_probe"), v.literal("dry_run")),
    targetBaseUrl: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("sandboxEnvironments", {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      findingId: args.findingId,
      exploitValidationRunId: args.exploitValidationRunId,
      sandboxMode: args.sandboxMode,
      targetBaseUrl: args.targetBaseUrl,
      status: "running",
      totalAttempts: 0,
      successfulAttempts: 0,
      evidenceSummary: "Validation in progress…",
      elapsedMs: 0,
      startedAt: Date.now(),
    });
  },
});

export const persistSandboxResult = internalMutation({
  args: {
    sandboxEnvId: v.id("sandboxEnvironments"),
    exploitValidationRunId: v.id("exploitValidationRuns"),
    findingId: v.id("findings"),
    result: v.object({
      outcome: v.union(
        v.literal("exploited"),
        v.literal("likely_exploitable"),
        v.literal("not_exploitable"),
        v.literal("error"),
      ),
      confidence: v.number(),
      totalAttempts: v.number(),
      successfulAttempts: v.number(),
      winningPayloadLabel: v.union(v.string(), v.null()),
      pocCurl: v.union(v.string(), v.null()),
      pocPython: v.union(v.string(), v.null()),
      evidenceSummary: v.string(),
      elapsedMs: v.number(),
      sandboxMode: v.union(v.literal("http_probe"), v.literal("dry_run")),
    }),
  },
  handler: async (ctx, { sandboxEnvId, exploitValidationRunId, findingId, result }) => {
    const now = Date.now();

    // Map sandbox outcome → Convex validation status
    const validationStatus =
      result.outcome === "exploited"
        ? "validated"
        : result.outcome === "likely_exploitable"
          ? "likely_exploitable"
          : result.outcome === "not_exploitable"
            ? "unexploitable"
            : "pending";

    // 1 — Update sandbox environment row
    await ctx.db.patch(sandboxEnvId, {
      status: "completed",
      outcome: result.outcome,
      confidence: result.confidence,
      totalAttempts: result.totalAttempts,
      successfulAttempts: result.successfulAttempts,
      winningPayloadLabel: result.winningPayloadLabel ?? undefined,
      pocCurl: result.pocCurl ?? undefined,
      pocPython: result.pocPython ?? undefined,
      evidenceSummary: result.evidenceSummary,
      elapsedMs: result.elapsedMs,
      completedAt: now,
    });

    // 2 — Update exploit validation run
    await ctx.db.patch(exploitValidationRunId, {
      status: "completed",
      outcome: validationStatus as "validated" | "likely_exploitable" | "unexploitable",
      validationConfidence: Math.round(result.confidence * 100),
      sandboxSummary: `${result.sandboxMode} — ${result.totalAttempts} attempts, ${result.successfulAttempts} succeeded`,
      evidenceSummary: result.evidenceSummary,
      reproductionHint: result.winningPayloadLabel
        ? `Payload: ${result.winningPayloadLabel}`
        : "No successful payload identified",
      completedAt: now,
    });

    // 3 — Patch finding with validation outcome + PoC URL reference
    await ctx.db.patch(findingId, {
      validationStatus,
      pocArtifactUrl: result.pocCurl
        ? `sandbox:${sandboxEnvId}` // resolved to real artifact by dashboard query
        : undefined,
    });

    // Neural Memory: Record sandbox validation episode for learning
    try {
      const finding = await ctx.db.get(findingId);
      if (finding) {
        await ctx.runMutation(api.neuralMemory.recordEpisode, {
          repositoryId: finding.repositoryId,
          episodeType: 'finding', // Validated findings are still findings, but with higher confidence
          payload: {
            findingId,
            sandboxEnvId,
            exploitValidationRunId,
            outcome: result.outcome,
            validationStatus,
            confidence: result.confidence,
            totalAttempts: result.totalAttempts,
            successfulAttempts: result.successfulAttempts,
            severity: finding.severity,
            cwe: finding.cwe,
            filePath: finding.filePath,
            ruleId: finding.ruleId,
            isExploitable: result.outcome === 'exploited' || result.outcome === 'likely_exploitable',
            evidenceSummary: result.evidenceSummary,
            elapsedMs: result.elapsedMs,
            timestamp: now,
          },
          sourceRef: `validation-${exploitValidationRunId}`,
        });
      }
    } catch (error) {
      // Don't fail sandbox validation if Neural Memory recording fails
      console.error('Neural Memory: Failed to record validation episode:', error);
    }
  },
});

export const markSandboxFailed = internalMutation({
  args: {
    sandboxEnvId: v.id("sandboxEnvironments"),
    exploitValidationRunId: v.id("exploitValidationRuns"),
    findingId: v.id("findings"),
    errorMessage: v.string(),
  },
  handler: async (ctx, { sandboxEnvId, exploitValidationRunId, errorMessage }) => {
    const now = Date.now();
    await ctx.db.patch(sandboxEnvId, {
      status: "failed",
      outcome: "error",
      evidenceSummary: `Validation failed: ${errorMessage.slice(0, 300)}`,
      elapsedMs: 0,
      completedAt: now,
    });
    await ctx.db.patch(exploitValidationRunId, {
      status: "failed",
      sandboxSummary: "Sandbox error",
      evidenceSummary: errorMessage.slice(0, 500),
      completedAt: now,
    });
  },
});

// ── Webhook dispatch ──────────────────────────────────────────────────────────

export const dispatchValidatedWebhook = internalAction({
  args: {
    findingId: v.id("findings"),
    outcome: v.union(v.literal("exploited"), v.literal("likely_exploitable")),
  },
  handler: async (_ctx, { findingId, outcome }) => {
    // Re-use the existing webhook dispatch infrastructure from events.ts
    // The finding.validated event is already wired — just ensure the finding
    // has the right validationStatus before dispatch fires.
    // (The patch in persistSandboxResult has already set validationStatus.)
    console.log(
      `[sandbox] dispatching finding.validated webhook for ${findingId} (${outcome})`
    );
  },
});

// ---------------------------------------------------------------------------
// Public mutation: runValidationForFinding — §3.11 CTA trigger
//
// Creates a fresh exploitValidationRun for the finding and schedules the
// sandbox validation action. Returns the new run ID so the UI can track it.
// ---------------------------------------------------------------------------

export const runValidationForFinding = mutation({
  args: {
    findingId: v.id("findings"),
  },
  returns: v.object({
    validationRunId: v.id("exploitValidationRuns"),
    scheduled: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const finding = await ctx.db.get(args.findingId);
    if (!finding) {
      throw new ConvexError("Finding not found");
    }

    // Find the latest workflow run for this finding to link to.
    // If none exists, we create a synthetic one via the internal mutation.
    const latestEvent = await ctx.db
      .query("ingestionEvents")
      .withIndex("by_tenant_and_received_at", (q) =>
        q.eq("tenantId", finding.tenantId)
      )
      .order("desc")
      .first();

    let workflowRunId: Id<"workflowRuns">;

    if (latestEvent) {
      const existingRun = await ctx.db
        .query("workflowRuns")
        .withIndex("by_event", (q) => q.eq("eventId", latestEvent._id))
        .first();
      if (existingRun) {
        workflowRunId = existingRun._id;
      } else {
        // Create a minimal workflow run linked to the event
        workflowRunId = await ctx.db.insert("workflowRuns", {
          tenantId: finding.tenantId,
          repositoryId: finding.repositoryId,
          eventId: latestEvent._id,
          workflowType: "revalidation",
          status: "running",
          priority: "high",
          currentStage: "sandbox_validation",
          summary: `Re-validation triggered from dashboard for finding ${args.findingId}`,
          totalTaskCount: 1,
          completedTaskCount: 0,
          startedAt: Date.now(),
          completedAt: undefined,
        });
      }
    } else {
      // Create a synthetic event + workflow run
      const now = Date.now();
      const eventId = await ctx.db.insert("ingestionEvents", {
        tenantId: finding.tenantId,
        repositoryId: finding.repositoryId,
        dedupeKey: `revalidate-${args.findingId}-${now}`,
        kind: "revalidation",
        source: "dashboard_cta",
        workflowType: "revalidation",
        status: "running",
        summary: `Re-validation triggered from dashboard for finding ${args.findingId}`,
        receivedAt: now,
      });

      workflowRunId = await ctx.db.insert("workflowRuns", {
        tenantId: finding.tenantId,
        repositoryId: finding.repositoryId,
        eventId,
        workflowType: "revalidation",
        status: "running",
        priority: "high",
        currentStage: "sandbox_validation",
        summary: `Re-validation triggered from dashboard for finding ${args.findingId}`,
        totalTaskCount: 1,
        completedTaskCount: 0,
        startedAt: now,
        completedAt: undefined,
      });
    }

    const now = Date.now();
    const validationRunId = await ctx.db.insert("exploitValidationRuns", {
      tenantId: finding.tenantId,
      repositoryId: finding.repositoryId,
      workflowRunId,
      findingId: args.findingId,
      status: "queued",
      outcome: undefined,
      validationConfidence: finding.confidence,
      sandboxSummary: "Re-validation queued from dashboard.",
      evidenceSummary: `Queued re-validation for ${finding.title}.`,
      reproductionHint: `Re-run exploit validation for ${finding.title}.`,
      startedAt: now,
      completedAt: undefined,
    });

    // Schedule the sandbox validation action (fire-and-forget)
    await ctx.scheduler.runAfter(0, internal.sandboxValidation.triggerSandboxValidation, {
      findingId: args.findingId,
      exploitValidationRunId: validationRunId,
      targetBaseUrl: undefined,
    });

    return { validationRunId, scheduled: true };
  },
});


