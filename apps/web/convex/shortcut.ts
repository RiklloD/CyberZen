"use node";
/**
 * Shortcut Integration — spec §4.6.4
 *
 * Creates Shortcut stories for Sentinel findings via the Shortcut REST API v3.
 *
 * Configuration:
 *   npx convex env set SHORTCUT_API_TOKEN <api-token>
 *   npx convex env set SHORTCUT_WORKFLOW_STATE_ID <state-id>  (ID of "In Progress" or "Todo" state)
 *   npx convex env set SHORTCUT_PROJECT_ID <project-id>       (optional)
 *   npx convex env set SHORTCUT_TEAM_ID <team-id>             (optional)
 *   npx convex env set SENTINEL_DASHBOARD_URL https://sentinelsec.io
 *
 * Get your API token: Shortcut → Settings → API Tokens → Generate Token
 * Get workflow state ID: GET https://api.app.shortcut.com/api/v3/workflows
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Constants ─────────────────────────────────────────────────────────────────

const SHORTCUT_BASE = "https://api.app.shortcut.com/api/v3";

// Shortcut story points (estimate) by severity
const SEVERITY_TO_ESTIMATE: Record<string, number> = {
  critical: 8,
  high: 5,
  medium: 3,
  low: 1,
  informational: 1,
};

// ── Types ─────────────────────────────────────────────────────────────────────

interface ShortcutCreateStoryBody {
  name: string;
  description: string;
  story_type: "bug";
  workflow_state_id?: number;
  project_id?: number;
  team_id?: string;
  labels?: Array<{ name: string }>;
  estimate?: number;
}

interface ShortcutUpdateStoryBody {
  workflow_state_id?: number;
  completed?: boolean;
}

// ── Shortcut API helper ───────────────────────────────────────────────────────

async function shortcutApiCall(
  path: string,
  method: string,
  token: string,
  body?: unknown,
): Promise<{ ok: boolean; status: number; data?: unknown }> {
  const resp = await fetch(`${SHORTCUT_BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "Shortcut-Token": token,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error(`[shortcut] ${method} ${path} → ${resp.status}: ${text.slice(0, 300)}`);
    return { ok: false, status: resp.status };
  }

  const data = await resp.json().catch(() => undefined);
  return { ok: true, status: resp.status, data };
}

// ── Description builder ───────────────────────────────────────────────────────

function buildShortcutDescription(args: {
  title: string;
  summary: string;
  severity: string;
  vulnClass: string;
  blastRadiusSummary: string;
  affectedFiles: string[];
  affectedPackages: string[];
  regulatoryImplications: string[];
  repositoryFullName: string;
  prUrl?: string;
  findingId: string;
  sentinelUrl: string;
}): string {
  const lines: string[] = [
    `## 🛡️ Sentinel Security Finding`,
    ``,
    `**Severity:** ${args.severity.toUpperCase()}  `,
    `**Class:** ${args.vulnClass.replace(/_/g, " ")}  `,
    `**Repository:** \`${args.repositoryFullName}\``,
    ``,
    `## Summary`,
    args.summary,
    ``,
    `## Blast Radius`,
    args.blastRadiusSummary,
    ``,
  ];

  if (args.affectedFiles.length > 0) {
    lines.push(
      "## Affected Files",
      ...args.affectedFiles.slice(0, 10).map((f) => `- \`${f}\``),
      "",
    );
  }
  if (args.affectedPackages.length > 0) {
    lines.push(
      "## Affected Packages",
      ...args.affectedPackages.slice(0, 10).map((p) => `- \`${p}\``),
      "",
    );
  }
  if (args.regulatoryImplications.length > 0) {
    lines.push(
      "## Regulatory Implications",
      ...args.regulatoryImplications.map((r) => `- ${r}`),
      "",
    );
  }
  if (args.prUrl) {
    lines.push(`## Fix PR`, `[View fix PR →](${args.prUrl})`, "");
  }

  lines.push(
    `## Links`,
    `- [Sentinel Dashboard](${args.sentinelUrl}/findings/${args.findingId})`,
    `- [Repository on GitHub](https://github.com/${args.repositoryFullName})`,
    ``,
    `---`,
    `*Auto-created by [Sentinel Security Agent](https://sentinelsec.io)*`,
  );

  return lines.join("\n");
}

// ── Core action ───────────────────────────────────────────────────────────────

export const createShortcutStory = internalAction({
  args: {
    findingId: v.id("findings"),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (
    ctx,
    args,
  ): Promise<{ created: boolean; reason?: string; storyId?: number; url?: string }> => {
    const token = process.env.SHORTCUT_API_TOKEN;
    if (!token) {
      console.log("[shortcut] not configured — set SHORTCUT_API_TOKEN");
      return { created: false, reason: "not_configured" };
    }

    const finding = await ctx.runQuery(internal.shortcut.loadShortcutFinding, {
      findingId: args.findingId,
    });
    if (!finding) return { created: false, reason: "finding_not_found" };
    if (finding.reasoningLogUrl?.startsWith("shortcut:")) {
      return { created: false, reason: "already_has_ticket" };
    }

    const sentinelUrl = process.env.SENTINEL_DASHBOARD_URL ?? "https://sentinelsec.io";
    const workflowStateIdRaw = process.env.SHORTCUT_WORKFLOW_STATE_ID;
    const projectIdRaw = process.env.SHORTCUT_PROJECT_ID;
    const teamId = process.env.SHORTCUT_TEAM_ID;

    const description = buildShortcutDescription({
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

    const storyBody: ShortcutCreateStoryBody = {
      name: `[SENTINEL] ${finding.severity.toUpperCase()}: ${finding.title.slice(0, 200)}`,
      description,
      story_type: "bug",
      labels: [
        { name: "sentinel" },
        { name: "security" },
        { name: `sentinel:${finding.severity.toLowerCase()}` },
      ],
      estimate: SEVERITY_TO_ESTIMATE[finding.severity] ?? 3,
    };

    if (workflowStateIdRaw) {
      const parsed = parseInt(workflowStateIdRaw, 10);
      if (!isNaN(parsed)) storyBody.workflow_state_id = parsed;
    }
    if (projectIdRaw) {
      const parsed = parseInt(projectIdRaw, 10);
      if (!isNaN(parsed)) storyBody.project_id = parsed;
    }
    if (teamId) storyBody.team_id = teamId;

    const result = await shortcutApiCall("/stories", "POST", token, storyBody);

    if (!result.ok) {
      return { created: false, reason: `http_${result.status}` };
    }

    const story = result.data as { id: number; app_url: string };

    await ctx.runMutation(internal.shortcut.patchFindingWithShortcutKey, {
      findingId: args.findingId,
      storyId: story.id,
      storyUrl: story.app_url,
    });

    console.log(
      `[shortcut] created story ${story.id} for finding ${args.findingId}`,
    );
    return { created: true, storyId: story.id, url: story.app_url };
  },
});

// ── Complete story ────────────────────────────────────────────────────────────

export const completeShortcutStory = internalAction({
  args: {
    storyId: v.number(),
    note: v.optional(v.string()),
  },
  handler: async (_ctx, args) => {
    const token = process.env.SHORTCUT_API_TOKEN;
    if (!token) return;

    // Fetch all workflows to find a "Complete" / "Done" state
    const workflowsResult = await shortcutApiCall("/workflows", "GET", token);
    if (!workflowsResult.ok) return;

    type WorkflowState = { id: number; name: string; type: string };
    type Workflow = { states: WorkflowState[] };
    const workflows = workflowsResult.data as Workflow[];

    let completedStateId: number | undefined;
    for (const workflow of workflows) {
      const found = workflow.states.find(
        (s) =>
          s.type === "done" ||
          /^(complete|completed|done)$/i.test(s.name),
      );
      if (found) {
        completedStateId = found.id;
        break;
      }
    }

    const updateBody: ShortcutUpdateStoryBody = completedStateId
      ? { workflow_state_id: completedStateId }
      : { completed: true };

    await shortcutApiCall(`/stories/${args.storyId}`, "PUT", token, updateBody);
  },
});

// ── Public query ──────────────────────────────────────────────────────────────

export const getShortcutStoriesForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_repository_and_status", (q) =>
        q.eq("repositoryId", repositoryId).eq("status", "open"),
      )
      .take(50);

    return findings
      .filter((f) => f.reasoningLogUrl?.startsWith("shortcut:"))
      .map((f) => {
        // Format: "shortcut:{story_public_id}:{app_url}"
        const withoutPrefix = f.reasoningLogUrl!.slice("shortcut:".length);
        const colonIdx = withoutPrefix.indexOf(":");
        const storyId =
          colonIdx !== -1 ? Number(withoutPrefix.slice(0, colonIdx)) : NaN;
        const storyUrl = colonIdx !== -1 ? withoutPrefix.slice(colonIdx + 1) : "";
        return {
          findingId: f._id,
          title: f.title,
          severity: f.severity,
          storyId,
          storyUrl,
        };
      });
  },
});

// ── Internal helpers ──────────────────────────────────────────────────────────

export const loadShortcutFinding = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => ctx.db.get(findingId),
});

export const patchFindingWithShortcutKey = internalMutation({
  args: {
    findingId: v.id("findings"),
    storyId: v.number(),
    storyUrl: v.string(),
  },
  handler: async (ctx, { findingId, storyId, storyUrl }) => {
    await ctx.db.patch(findingId, {
      reasoningLogUrl: `shortcut:${storyId}:${storyUrl}`,
    });
  },
});
