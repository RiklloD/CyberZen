/**
 * GitHub Check Run builder for Sentinel findings.
 *
 * Posts a rich check run to the PR with:
 *   - Summary table of validated findings
 *   - Blast radius context
 *   - Links to fix PRs
 *   - Security posture score
 */

import * as github from "@actions/github";
import type { SentinelFinding, SentinelPostureResponse } from "./sentinel-api";

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  informational: "⚪",
};

export type CheckRunResult = {
  conclusion: "success" | "failure" | "neutral";
  url: string;
};

/**
 * Post a GitHub Check Run with Sentinel findings.
 * Returns the check run URL.
 */
export async function postCheckRun(opts: {
  token: string;
  owner: string;
  repo: string;
  sha: string;
  findings: SentinelFinding[];
  posture: SentinelPostureResponse | null;
  blockedFindings: SentinelFinding[];
  sentinelDashboardUrl: string;
}): Promise<CheckRunResult> {
  const octokit = github.getOctokit(opts.token);

  const validatedFindings = opts.findings.filter(
    (f) => f.validationStatus === "validated" || f.validationStatus === "likely_exploitable",
  );

  const conclusion: "success" | "failure" | "neutral" =
    opts.blockedFindings.length > 0 ? "failure" : "success";

  const summary = buildSummary(validatedFindings, opts.posture, opts.blockedFindings);
  const text = buildDetailText(validatedFindings);

  const checkRun = await octokit.rest.checks.create({
    owner: opts.owner,
    repo: opts.repo,
    name: "Sentinel Security Gate",
    head_sha: opts.sha,
    status: "completed",
    conclusion,
    completed_at: new Date().toISOString(),
    output: {
      title: buildTitle(opts.blockedFindings, validatedFindings, opts.posture),
      summary,
      text: text || undefined,
    },
  });

  return {
    conclusion,
    url: checkRun.data.html_url ?? "",
  };
}

function buildTitle(
  blocked: SentinelFinding[],
  validated: SentinelFinding[],
  posture: SentinelPostureResponse | null,
): string {
  if (blocked.length > 0) {
    const critical = blocked.filter((f) => f.severity === "critical").length;
    const high = blocked.filter((f) => f.severity === "high").length;
    const parts = [];
    if (critical > 0) parts.push(`${critical} critical`);
    if (high > 0) parts.push(`${high} high`);
    return `🚫 Gate blocked — ${parts.join(", ")} confirmed finding${blocked.length > 1 ? "s" : ""}`;
  }

  if (validated.length > 0) {
    return `⚠️ ${validated.length} finding${validated.length > 1 ? "s" : ""} detected — below block threshold`;
  }

  const scoreLabel = posture ? ` (posture score: ${posture.postureScore}/100)` : "";
  return `✅ No blocking security findings${scoreLabel}`;
}

function buildSummary(
  validated: SentinelFinding[],
  posture: SentinelPostureResponse | null,
  blocked: SentinelFinding[],
): string {
  const lines: string[] = [];

  if (posture) {
    lines.push(
      `**Security Posture:** ${posture.postureScore}/100 (${posture.postureLevel})`,
      "",
    );
  }

  if (validated.length === 0) {
    lines.push("✅ No validated findings detected on this commit.");
    return lines.join("\n");
  }

  lines.push(
    `**Sentinel found ${validated.length} validated finding${validated.length > 1 ? "s" : ""}:**`,
    "",
    "| Severity | Finding | Class | Status | Fix PR |",
    "|----------|---------|-------|--------|--------|",
  );

  for (const f of validated.slice(0, 20)) {
    const emoji = SEVERITY_EMOJI[f.severity] ?? "⚪";
    const prLink = f.prUrl ? `[View PR](${f.prUrl})` : "—";
    const statusLabel =
      f.validationStatus === "validated" ? "Confirmed" : "Likely";
    lines.push(
      `| ${emoji} ${f.severity} | ${f.title.slice(0, 60)} | \`${f.vulnClass}\` | ${statusLabel} | ${prLink} |`,
    );
  }

  if (validated.length > 20) {
    lines.push(`| ... | +${validated.length - 20} more findings | | | |`);
  }

  if (blocked.length > 0) {
    lines.push(
      "",
      "---",
      "### 🚫 Findings blocking this build",
      "",
      "The following confirmed findings exceed the configured severity threshold:",
      "",
    );
    for (const f of blocked) {
      lines.push(
        `- **${SEVERITY_EMOJI[f.severity]} ${f.severity.toUpperCase()}** — ${f.title}`,
      );
      if (f.blastRadiusSummary) {
        lines.push(`  > ${f.blastRadiusSummary.slice(0, 200)}`);
      }
      if (f.prUrl) {
        lines.push(`  > [View fix PR →](${f.prUrl})`);
      }
    }
  }

  if (posture?.topActions && posture.topActions.length > 0) {
    lines.push("", "---", "### Recommended actions", "");
    for (const action of posture.topActions.slice(0, 3)) {
      lines.push(`- **${action.priority.toUpperCase()}**: ${action.title}`);
    }
  }

  return lines.join("\n");
}

function buildDetailText(validated: SentinelFinding[]): string {
  if (validated.length === 0) return "";

  const lines: string[] = [
    "## Finding details",
    "",
  ];

  for (const f of validated.slice(0, 10)) {
    lines.push(
      `### ${SEVERITY_EMOJI[f.severity]} ${f.title}`,
      "",
      f.summary,
      "",
    );

    if (f.affectedFiles.length > 0) {
      lines.push(`**Affected files:** ${f.affectedFiles.slice(0, 5).join(", ")}`);
    }
    if (f.affectedPackages.length > 0) {
      lines.push(`**Affected packages:** ${f.affectedPackages.slice(0, 5).join(", ")}`);
    }
    if (f.blastRadiusSummary) {
      lines.push(`**Blast radius:** ${f.blastRadiusSummary}`);
    }
    if (f.prUrl) {
      lines.push(`**Fix PR:** ${f.prUrl}`);
    }
    lines.push("---", "");
  }

  return lines.join("\n");
}
