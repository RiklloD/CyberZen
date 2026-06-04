// GitHub Issues Payload Builder — pure library, no Convex dependencies.
//
// Spec §4.6.4 — Ticketing Integrations:
//   GitHub Issues: Fallback for teams without a dedicated ticketing system

export interface GithubIssueCreateBody {
  title: string;
  body: string;
  labels: string[];
  assignees?: string[];
}

export interface GithubIssueCloseBody {
  state: "closed";
  state_reason: "completed" | "not_planned";
}

export interface FindingIssueInput {
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
}

// ── Title ─────────────────────────────────────────────────────────────────────

export function buildGithubIssueTitle(severity: string, title: string): string {
  const truncated = title.slice(0, 200);
  return `[SENTINEL] ${severity.toUpperCase()}: ${truncated}`;
}

// ── Labels ────────────────────────────────────────────────────────────────────

export function buildGithubIssueLabels(severity: string): string[] {
  return ["sentinel", "security", `sentinel:${severity.toLowerCase()}`];
}

// ── Body ──────────────────────────────────────────────────────────────────────

export function buildGithubIssueBody(input: FindingIssueInput): string {
  const lines: string[] = [
    `## 🛡️ Sentinel Security Finding`,
    ``,
    `**Severity:** ${input.severity.toUpperCase()}  `,
    `**Class:** ${input.vulnClass.replace(/_/g, " ")}  `,
    `**Repository:** \`${input.repositoryFullName}\``,
    ``,
    `## Summary`,
    input.summary,
    ``,
    `## Blast Radius`,
    input.blastRadiusSummary,
    ``,
  ];

  if (input.affectedFiles.length > 0) {
    lines.push(
      "## Affected Files",
      ...input.affectedFiles.slice(0, 10).map((f) => `- \`${f}\``),
      "",
    );
  }

  if (input.affectedPackages.length > 0) {
    lines.push(
      "## Affected Packages",
      ...input.affectedPackages.slice(0, 10).map((p) => `- \`${p}\``),
      "",
    );
  }

  if (input.regulatoryImplications.length > 0) {
    lines.push(
      "## Regulatory Implications",
      ...input.regulatoryImplications.map((r) => `- ${r}`),
      "",
    );
  }

  if (input.prUrl) {
    lines.push(`## Fix PR`, `[View fix PR →](${input.prUrl})`, "");
  }

  lines.push(
    `## Links`,
    `- [Sentinel Dashboard](${input.sentinelUrl}/findings/${input.findingId})`,
    `- [Repository on GitHub](https://github.com/${input.repositoryFullName})`,
    ``,
    `---`,
    `*Auto-created by [Sentinel Security Agent](https://sentinelsec.io)*`,
  );

  return lines.join("\n");
}

// ── Composite ─────────────────────────────────────────────────────────────────

export function buildGithubIssueCreateBody(
  input: FindingIssueInput,
): GithubIssueCreateBody {
  return {
    title: buildGithubIssueTitle(input.severity, input.title),
    body: buildGithubIssueBody(input),
    labels: buildGithubIssueLabels(input.severity),
  };
}

export function buildGithubIssueCloseBody(): GithubIssueCloseBody {
  return { state: "closed", state_reason: "completed" };
}
