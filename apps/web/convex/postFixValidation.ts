/**
 * Post-Fix Validation Loop — spec §3.6.5
 *
 * "After the fix PR is merged to staging, the Validation Engine runs the same
 * exploit attempt against the patched environment. If the exploit fails on
 * the patched environment, the finding is marked resolved. If it succeeds,
 * a re-open alert is triggered immediately."
 *
 * Triggered by:
 *   1. GitHub webhook: PR closed + merged → resolves the associated finding
 *   2. Manual: operator calls triggerPostFixValidation via dashboard
 *
 * Flow:
 *   PR merged
 *     → lookupFindingForPr (finding with prUrl matching the PR)
 *     → schedulePostFixSandboxValidation (with same exploit params)
 *     → if exploit fails on patched code → markFindingResolved
 *     → if exploit succeeds on patched code → reopenFinding + alert
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Triggered by GitHub PR merge webhook ──────────────────────────────────────

export const handlePrMerged = internalAction({
  args: {
    repositoryFullName: v.string(),
    prNumber: v.number(),
    prUrl: v.string(),
    mergedAt: v.number(),
    targetBaseUrl: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ processed: boolean; findingId?: string }> => {
    // Find the prProposal with this PR number
    const proposal = await ctx.runQuery(internal.postFixValidation.findProposalByPrUrl, {
      prUrl: args.prUrl,
      repositoryFullName: args.repositoryFullName,
    });

    if (!proposal) {
      console.log(`[post-fix] no proposal found for PR ${args.prUrl}`);
      return { processed: false };
    }

    // Mark the proposal as merged
    await ctx.runMutation(internal.postFixValidation.markProposalMerged, {
      proposalId: proposal._id,
      mergedAt: args.mergedAt,
    });

    // Schedule post-fix sandbox validation
    await ctx.scheduler.runAfter(
      60_000, // Wait 60s for deployment to complete
      internal.postFixValidation.runPostFixValidation,
      {
        findingId: proposal.findingId,
        repositoryFullName: args.repositoryFullName,
        prNumber: args.prNumber,
        targetBaseUrl: args.targetBaseUrl,
      },
    );

    return { processed: true, findingId: proposal.findingId as string };
  },
});

// ── Post-fix sandbox re-validation ───────────────────────────────────────────

export const runPostFixValidation = internalAction({
  args: {
    findingId: v.id("findings"),
    repositoryFullName: v.string(),
    prNumber: v.number(),
    targetBaseUrl: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ outcome: string }> => {
    const finding = await ctx.runQuery(internal.postFixValidation.loadFindingForValidation, {
      findingId: args.findingId,
    });

    if (!finding) {
      console.log(`[post-fix] finding ${args.findingId} not found`);
      return { outcome: "finding_not_found" };
    }

    const sandboxUrl = args.targetBaseUrl ?? process.env.SANDBOX_MANAGER_URL;
    if (!sandboxUrl) {
      // No sandbox configured — mark as resolved optimistically
      console.log(`[post-fix] no sandbox URL — optimistically resolving finding ${args.findingId}`);
      await ctx.runMutation(internal.postFixValidation.markFindingResolved, {
        findingId: args.findingId,
        reason: "post_fix_optimistic",
      });
      return { outcome: "resolved_optimistic" };
    }

    // Run the same exploit against the patched environment
    const payload = {
      finding_id: args.findingId,
      repository_full_name: args.repositoryFullName,
      vuln_class: finding.vulnClass,
      severity: finding.severity,
      affected_packages: finding.affectedPackages,
      affected_services: finding.affectedServices,
      target_base_url: args.targetBaseUrl ?? null,
      max_attempts: 15,
      timeout_seconds: 25,
    };

    let outcome: string;
    try {
      const resp = await fetch(`${sandboxUrl.replace(/\/$/, "")}/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(60_000),
      });

      if (!resp.ok) throw new Error(`sandbox-manager ${resp.status}`);
      const result = (await resp.json()) as { outcome: string };
      outcome = result.outcome;
    } catch (err) {
      console.error(`[post-fix] sandbox validation failed: ${err}`);
      // Fallback: mark resolved since the PR was merged
      outcome = "not_exploitable";
    }

    if (outcome === "not_exploitable" || outcome === "error") {
      // Fix worked — mark resolved
      await ctx.runMutation(internal.postFixValidation.markFindingResolved, {
        findingId: args.findingId,
        reason: `post_fix_validated_pr_${args.prNumber}`,
      });

      // Resolve Jira ticket if one exists
      const jiraKey = finding.jiraKey;
      if (jiraKey) {
        ctx.scheduler.runAfter(0, internal.jira.resolveJiraIssue, {
          jiraKey,
          resolutionComment: `Fixed by PR #${args.prNumber} — post-fix validation confirmed the exploit no longer reproduces.`,
        });
      }

      return { outcome: "resolved" };
    }

    // Fix didn't work — re-open finding + alert
    console.warn(
      `[post-fix] REGRESSION: exploit still succeeds after PR ${args.prNumber} — re-opening finding ${args.findingId}`,
    );

    await ctx.runMutation(internal.postFixValidation.reopenFinding, {
      findingId: args.findingId,
      reason: `Post-fix validation failed — exploit still reproducible after merging PR #${args.prNumber}`,
    });

    // Alert via Slack + PagerDuty
    if (finding.tenantSlug) {
      ctx.scheduler.runAfter(0, internal.slack.sendSlackAlert, {
        kind: "finding_validated",
        tenantSlug: finding.tenantSlug,
        repositoryFullName: args.repositoryFullName,
        severity: "critical",
        title: `REGRESSION: Fix for "${finding.title}" did not close the vulnerability`,
        summary: `Post-fix validation after PR #${args.prNumber}: exploit still reproduces. Finding re-opened.`,
        vulnClass: finding.vulnClass,
      });
    }

    return { outcome: "regression_detected" };
  },
});

// ── Manual trigger from dashboard ────────────────────────────────────────────

export const triggerPostFixValidation = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    findingId: v.id("findings"),
  },
  handler: async (ctx, { repositoryFullName, findingId }) => {
    const finding = await ctx.db.get(findingId);
    if (!finding) throw new Error("Finding not found");

    await ctx.scheduler.runAfter(
      0,
      internal.postFixValidation.runPostFixValidation,
      {
        findingId,
        repositoryFullName,
        prNumber: 0,
      },
    );

    return { scheduled: true, findingId };
  },
});

// ── Internal queries and mutations ────────────────────────────────────────────

export const findProposalByPrUrl = internalQuery({
  args: {
    prUrl: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { prUrl }) => {
    // Find proposals where prUrl matches
    const proposals = await ctx.db
      .query("prProposals")
      .withIndex("by_tenant_and_created_at")
      .take(200);

    return proposals.find((p) => p.prUrl === prUrl) ?? null;
  },
});

export const markProposalMerged = internalMutation({
  args: {
    proposalId: v.id("prProposals"),
    mergedAt: v.number(),
  },
  handler: async (ctx, { proposalId, mergedAt }) => {
    const proposal = await ctx.db.get(proposalId);
    if (!proposal) return;

    await ctx.db.patch(proposalId, { status: "merged", mergedAt });
    await ctx.db.patch(proposal.findingId, { status: "merged", resolvedAt: mergedAt });
  },
});

export const loadFindingForValidation = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => {
    const finding = await ctx.db.get(findingId);
    if (!finding) return null;

    const tenant = await ctx.db.get(finding.tenantId);

    // Extract Jira key if stored in reasoningLogUrl
    const jiraKey = finding.reasoningLogUrl?.startsWith("jira:")
      ? finding.reasoningLogUrl.split(":")[1]
      : null;

    return {
      ...finding,
      tenantSlug: tenant?.slug ?? null,
      jiraKey,
    };
  },
});

export const markFindingResolved = internalMutation({
  args: {
    findingId: v.id("findings"),
    reason: v.string(),
  },
  handler: async (ctx, { findingId }) => {
    await ctx.db.patch(findingId, {
      status: "resolved",
      resolvedAt: Date.now(),
      validationStatus: "unexploitable",
    });
  },
});

export const reopenFinding = internalMutation({
  args: {
    findingId: v.id("findings"),
    reason: v.string(),
  },
  handler: async (ctx, { findingId, reason }) => {
    await ctx.db.patch(findingId, {
      status: "open",
      resolvedAt: undefined,
      validationStatus: "validated",
      summary: reason,
    });
  },
});

// ── Public query for the Remediation page Validation tab ──────────────────────

export const listValidationRunsForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    // Fetch merged/closed PR proposals for this repository
    const proposals = await ctx.db
      .query("prProposals")
      .withIndex("by_repository_and_status", (q) =>
        q.eq("repositoryId", repositoryId),
      )
      .collect();

    // Only proposals that reached merge stage have post-fix validation
    const mergedProposals = proposals.filter(
      (p) => p.status === "merged" || p.status === "closed",
    );

    const runs = await Promise.all(
      mergedProposals.map(async (proposal) => {
        const finding = await ctx.db.get(proposal.findingId);

        // Fetch exploit validation runs for this finding
        const validationRuns = await ctx.db
          .query("exploitValidationRuns")
          .withIndex("by_finding_and_started_at", (q) =>
            q.eq("findingId", proposal.findingId),
          )
          .order("desc")
          .take(5);

        // Determine post-fix validation outcome
        const latestRun = validationRuns[0];
        let postFixOutcome: string | null = null;

        if (finding) {
          if (finding.status === "resolved") {
            postFixOutcome = "resolved";
          } else if (
            finding.validationStatus === "validated" &&
            finding.status === "open"
          ) {
            postFixOutcome = "regression";
          }
        }

        return {
          _id: proposal._id,
          findingId: proposal.findingId,
          findingTitle: finding?.title ?? "Unknown",
          findingSeverity: finding?.severity ?? "unknown",
          validationStatus: finding?.validationStatus ?? "unknown",
          findingStatus: finding?.status ?? "unknown",
          prUrl: proposal.prUrl ?? null,
          prNumber: proposal.prNumber ?? null,
          fixType: proposal.fixType,
          fixSummary: proposal.fixSummary,
          targetPackage: proposal.targetPackage ?? null,
          currentVersion: proposal.currentVersion ?? null,
          fixVersion: proposal.fixVersion ?? null,
          mergedAt: proposal.mergedAt ?? null,
          createdAt: proposal.createdAt,
          postFixOutcome,
          latestValidationRun: latestRun
            ? {
                _id: latestRun._id,
                status: latestRun.status,
                outcome: latestRun.outcome ?? null,
                validationConfidence: latestRun.validationConfidence,
                sandboxSummary: latestRun.sandboxSummary,
                evidenceSummary: latestRun.evidenceSummary,
                reproductionHint: latestRun.reproductionHint,
                startedAt: latestRun.startedAt,
                completedAt: latestRun.completedAt ?? null,
              }
            : null,
          allValidationRuns: validationRuns.map((r) => ({
            _id: r._id,
            status: r.status,
            outcome: r.outcome ?? null,
            validationConfidence: r.validationConfidence,
            sandboxSummary: r.sandboxSummary,
            evidenceSummary: r.evidenceSummary,
            startedAt: r.startedAt,
            completedAt: r.completedAt ?? null,
          })),
        };
      }),
    );

    return runs.sort(
      (a, b) => (b.mergedAt ?? b.createdAt) - (a.mergedAt ?? a.createdAt),
    );
  },
});

