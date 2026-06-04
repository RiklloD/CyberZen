/**
 * Sentinel Security Gate — GitHub Actions Entry Point
 *
 * Usage in workflow:
 *
 *   - name: Sentinel Security Gate
 *     uses: sentinel-sec/gate@v1
 *     with:
 *       sentinel-api-key: ${{ secrets.SENTINEL_API_KEY }}
 *       tenant-slug: my-company
 *       block-on-severity: high
 *     permissions:
 *       checks: write
 *       pull-requests: read
 */

import * as core from "@actions/core";
import * as github from "@actions/github";
import { SentinelApiClient } from "./sentinel-api";
import { postCheckRun } from "./check-run";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

function severityMeetsThreshold(severity: string, threshold: string): boolean {
  const sIdx = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  const tIdx = SEVERITY_ORDER.indexOf(threshold.toLowerCase());
  if (sIdx === -1 || tIdx === -1) return false;
  return sIdx <= tIdx; // lower index = higher severity
}

async function run(): Promise<void> {
  try {
    // ── Read inputs ──────────────────────────────────────────────────────────
    const apiKey = core.getInput("sentinel-api-key", { required: true });
    const sentinelUrl = core.getInput("sentinel-url") || "https://quick-echidna-102.eu-west-1.convex.site";
    const tenantSlug = core.getInput("tenant-slug", { required: true });
    const repositoryFullName =
      core.getInput("repository-full-name") || github.context.repo.repo
        ? `${github.context.repo.owner}/${github.context.repo.repo}`
        : github.context.payload.repository?.full_name ?? "";
    const blockOnSeverity = core.getInput("block-on-severity") || "high";
    const postCheckRunEnabled = core.getInput("post-check-run") !== "false";
    const failOnError = core.getInput("fail-on-error") === "true";

    const sha = github.context.sha;

    core.info(`🛡️  Sentinel Security Gate`);
    core.info(`   Repository: ${repositoryFullName}`);
    core.info(`   Commit:     ${sha.slice(0, 7)}`);
    core.info(`   Threshold:  block on ${blockOnSeverity}+`);
    core.info(`   API:        ${sentinelUrl}`);

    // ── Query Sentinel API ───────────────────────────────────────────────────
    const client = new SentinelApiClient({
      baseUrl: sentinelUrl,
      apiKey,
      tenantSlug,
      repositoryFullName,
    });

    let findings: Awaited<ReturnType<typeof client.getFindings>>["findings"] = [];
    let posture = null;

    try {
      const [findingsResult, postureResult] = await Promise.allSettled([
        client.getFindings({ status: "open", limit: 100 }),
        client.getSecurityPosture(),
      ]);

      if (findingsResult.status === "fulfilled") {
        findings = findingsResult.value.findings;
      } else {
        core.warning(`Could not fetch findings: ${findingsResult.reason}`);
      }

      if (postureResult.status === "fulfilled") {
        posture = postureResult.value;
      }
    } catch (err) {
      const message = `Failed to connect to Sentinel API: ${err}`;
      if (failOnError) {
        core.setFailed(message);
        return;
      }
      core.warning(`${message} — continuing in non-blocking mode`);

      // Set skip outputs and exit
      core.setOutput("gate-decision", "skip");
      core.setOutput("finding-count", "0");
      core.setOutput("critical-count", "0");
      core.setOutput("high-count", "0");
      return;
    }

    // ── Classify findings ────────────────────────────────────────────────────
    const validatedFindings = findings.filter(
      (f) =>
        f.validationStatus === "validated" ||
        f.validationStatus === "likely_exploitable",
    );

    const blockedFindings = blockOnSeverity !== "none"
      ? validatedFindings.filter((f) => severityMeetsThreshold(f.severity, blockOnSeverity))
      : [];

    const criticalCount = validatedFindings.filter((f) => f.severity === "critical").length;
    const highCount = validatedFindings.filter((f) => f.severity === "high").length;

    // ── Set outputs ───────────────────────────────────────────────────────────
    core.setOutput("finding-count", String(validatedFindings.length));
    core.setOutput("critical-count", String(criticalCount));
    core.setOutput("high-count", String(highCount));

    // ── Log summary ──────────────────────────────────────────────────────────
    if (validatedFindings.length === 0) {
      core.info("✅ No validated findings — gate passing");
    } else {
      core.info(`\n📋 Validated findings: ${validatedFindings.length}`);
      for (const f of validatedFindings.slice(0, 10)) {
        const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" }[f.severity] ?? "⚪";
        core.info(`   ${emoji} [${f.severity.toUpperCase()}] ${f.title}`);
        if (f.prUrl) core.info(`      Fix PR: ${f.prUrl}`);
      }
    }

    // ── Post check run ────────────────────────────────────────────────────────
    let checkRunUrl = "";
    if (postCheckRunEnabled) {
      try {
        const githubToken = process.env.GITHUB_TOKEN;
        if (!githubToken) {
          core.warning("GITHUB_TOKEN not available — skipping check run post");
        } else {
          const result = await postCheckRun({
            token: githubToken,
            owner: github.context.repo.owner,
            repo: github.context.repo.repo,
            sha,
            findings: validatedFindings,
            posture,
            blockedFindings,
            sentinelDashboardUrl: sentinelUrl,
          });
          checkRunUrl = result.url;
          core.info(`\n✓ Check run posted: ${checkRunUrl}`);
        }
      } catch (err) {
        core.warning(`Could not post check run: ${err}`);
      }
    }

    core.setOutput("check-run-url", checkRunUrl);

    // ── Gate decision ─────────────────────────────────────────────────────────
    if (blockedFindings.length > 0) {
      core.setOutput("gate-decision", "block");

      const severityCounts = blockedFindings.reduce(
        (acc, f) => {
          acc[f.severity] = (acc[f.severity] ?? 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );

      const summary = Object.entries(severityCounts)
        .map(([s, n]) => `${n} ${s}`)
        .join(", ");

      core.setFailed(
        `🚫 Sentinel gate blocked — ${summary} confirmed finding${blockedFindings.length > 1 ? "s" : ""} on this commit.\n` +
        `   Resolve the findings or use \`block-on-severity: none\` to bypass.\n` +
        (checkRunUrl ? `   Details: ${checkRunUrl}` : ""),
      );
    } else {
      core.setOutput("gate-decision", "pass");
      if (posture) {
        core.info(`\n🛡️  Security posture: ${posture.postureScore}/100 (${posture.postureLevel})`);
      }
      core.info("✅ Sentinel gate passed");
    }
  } catch (error) {
    core.setFailed(`Sentinel action error: ${error instanceof Error ? error.message : String(error)}`);
  }
}

run();
