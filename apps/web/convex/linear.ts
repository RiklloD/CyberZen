"use node";
/**
 * Linear Integration — spec §4.6.4
 *
 * Creates Linear issues for Sentinel findings via the Linear GraphQL API.
 *
 * Configuration:
 *   npx convex env set LINEAR_API_KEY lin_api_...
 *   npx convex env set LINEAR_TEAM_ID <team-id>   (from Linear Settings → Team → ID)
 *   npx convex env set LINEAR_PROJECT_ID <id>     (optional — links to a project)
 *   npx convex env set LINEAR_ASSIGNEE_ID <userId> (optional)
 *   npx convex env set SENTINEL_DASHBOARD_URL https://sentinelsec.io
 *
 * Get your API key: Linear → Settings → API → Personal API keys
 * Get team ID: Linear → Settings → Team → copy the UUID from the URL
 */

import { v } from "convex/values";
import { internalAction, internalMutation, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Priority mapping ──────────────────────────────────────────────────────────
// Linear priorities: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low

const SEVERITY_TO_PRIORITY: Record<string, number> = {
  critical: 1,  // Urgent
  high: 2,       // High
  medium: 3,     // Medium
  low: 4,        // Low
  informational: 4,
};

// ── GraphQL queries ───────────────────────────────────────────────────────────

const CREATE_ISSUE_MUTATION = `
  mutation CreateIssue($input: IssueCreateInput!) {
    issueCreate(input: $input) {
      success
      issue {
        id
        identifier
        url
      }
    }
  }
`;

const UPDATE_ISSUE_MUTATION = `
  mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
    issueUpdate(id: $id, input: $input) {
      success
      issue {
        id
        identifier
        state {
          name
        }
      }
    }
  }
`;

const GET_WORKFLOW_STATES_QUERY = `
  query GetWorkflowStates($teamId: String!) {
    workflowStates(filter: { team: { id: { eq: $teamId } } }) {
      nodes {
        id
        name
        type
      }
    }
  }
`;

async function linearGraphQL<T>(
  query: string,
  variables: Record<string, unknown>,
  apiKey: string,
): Promise<T> {
  const resp = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: apiKey,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`Linear API error ${resp.status}: ${body.slice(0, 300)}`);
  }

  const data = (await resp.json()) as { data: T; errors?: Array<{ message: string }> };
  if (data.errors && data.errors.length > 0) {
    throw new Error(`Linear GraphQL error: ${data.errors.map((e) => e.message).join(", ")}`);
  }

  return data.data;
}

// ── Core action ───────────────────────────────────────────────────────────────

export const createLinearIssue = internalAction({
  args: {
    findingId: v.id("findings"),
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<{ created: boolean; reason?: string; identifier?: string; url?: string }> => {
    const apiKey = process.env.LINEAR_API_KEY;
    const teamId = process.env.LINEAR_TEAM_ID;

    if (!apiKey || !teamId) {
      console.log("[linear] not configured — set LINEAR_API_KEY and LINEAR_TEAM_ID");
      return { created: false, reason: "not_configured" };
    }

    const finding = await ctx.runQuery(internal.linear.loadFinding, { findingId: args.findingId });
    if (!finding) return { created: false, reason: "finding_not_found" };
    if (finding.reasoningLogUrl?.startsWith("linear:")) {
      return { created: false, reason: "already_has_ticket" };
    }

    const projectId = process.env.LINEAR_PROJECT_ID;
    const assigneeId = process.env.LINEAR_ASSIGNEE_ID;
    const sentinelUrl = process.env.SENTINEL_DASHBOARD_URL ?? "https://sentinelsec.io";

    const description = buildLinearDescription({
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

    const input: Record<string, unknown> = {
      teamId,
      title: `[SENTINEL] ${finding.severity.toUpperCase()}: ${finding.title.slice(0, 200)}`,
      description,
      priority: SEVERITY_TO_PRIORITY[finding.severity] ?? 3,
      labelIds: [], // Labels require separate API calls to look up IDs
    };

    if (projectId) input.projectId = projectId;
    if (assigneeId) input.assigneeId = assigneeId;

    type CreateResult = {
      issueCreate: {
        success: boolean;
        issue: { id: string; identifier: string; url: string };
      };
    };

    const result = await linearGraphQL<CreateResult>(
      CREATE_ISSUE_MUTATION,
      { input },
      apiKey,
    );

    if (!result.issueCreate.success) {
      return { created: false, reason: "linear_api_failure" };
    }

    const issue = result.issueCreate.issue;

    await ctx.runMutation(internal.linear.patchFindingWithLinearKey, {
      findingId: args.findingId,
      linearId: issue.id,
      linearIdentifier: issue.identifier,
      linearUrl: issue.url,
    });

    console.log(`[linear] created issue ${issue.identifier} for finding ${args.findingId}`);
    return { created: true, identifier: issue.identifier, url: issue.url };
  },
});

// ── Complete issue when finding resolved ──────────────────────────────────────

export const completeLinearIssue = internalAction({
  args: { linearId: v.string(), comment: v.optional(v.string()) },
  handler: async (_ctx, args) => {
    const apiKey = process.env.LINEAR_API_KEY;
    const teamId = process.env.LINEAR_TEAM_ID;
    if (!apiKey || !teamId) return;

    // Find the "Done" workflow state
    type StatesResult = {
      workflowStates: { nodes: Array<{ id: string; name: string; type: string }> };
    };

    const statesData = await linearGraphQL<StatesResult>(
      GET_WORKFLOW_STATES_QUERY,
      { teamId },
      apiKey,
    );

    const doneState = statesData.workflowStates.nodes.find(
      (s) => s.type === "completed" || s.name.toLowerCase() === "done",
    );

    if (!doneState) return;

    await linearGraphQL(
      UPDATE_ISSUE_MUTATION,
      { id: args.linearId, input: { stateId: doneState.id } },
      apiKey,
    );
  },
});

// ── Public query ──────────────────────────────────────────────────────────────

export const getLinearTicketsForRepository = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_repository_and_status", (q) =>
        q.eq("repositoryId", repositoryId).eq("status", "open"),
      )
      .take(50);

    return findings
      .filter((f) => f.reasoningLogUrl?.startsWith("linear:"))
      .map((f) => {
        const parts = f.reasoningLogUrl!.split(":");
        return {
          findingId: f._id,
          title: f.title,
          severity: f.severity,
          linearIdentifier: parts[1] ?? "",
          linearUrl: parts.slice(2).join(":"),
        };
      });
  },
});

// ── Internal helpers ──────────────────────────────────────────────────────────

export const loadFinding = internalQuery({
  args: { findingId: v.id("findings") },
  handler: async (ctx, { findingId }) => ctx.db.get(findingId),
});

export const patchFindingWithLinearKey = internalMutation({
  args: {
    findingId: v.id("findings"),
    linearId: v.string(),
    linearIdentifier: v.string(),
    linearUrl: v.string(),
  },
  handler: async (ctx, { findingId, linearIdentifier, linearUrl }) => {
    await ctx.db.patch(findingId, {
      reasoningLogUrl: `linear:${linearIdentifier}:${linearUrl}`,
    });
  },
});

// ── Description builder ───────────────────────────────────────────────────────

function buildLinearDescription(args: {
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
    lines.push("## Affected Files", ...args.affectedFiles.slice(0, 10).map((f) => `- \`${f}\``), "");
  }
  if (args.affectedPackages.length > 0) {
    lines.push("## Affected Packages", ...args.affectedPackages.slice(0, 10).map((p) => `- \`${p}\``), "");
  }
  if (args.regulatoryImplications.length > 0) {
    lines.push("## Regulatory Implications", ...args.regulatoryImplications.map((r) => `- ${r}`), "");
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
