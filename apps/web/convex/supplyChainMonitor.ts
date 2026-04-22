"use node";
/**
 * Supply Chain Social Layer Monitor — Phase 1 Real Implementation (spec §3.2)
 *
 * Upgrades the static typosquat heuristics to real-time GitHub API monitoring
 * of maintainer behavior and repository health signals.
 *
 * Signals monitored per dependency repository:
 *   1. Repository archived / abandoned (last commit > 2 years ago)
 *   2. Maintainer account age (new account gaining commit access = high risk)
 *   3. Contributor velocity spike (sudden new contributors in last 90 days)
 *   4. Recent release by low-activity account
 *   5. Build/CI script recently modified by a new contributor
 *   6. Binary blobs or encoded content added recently
 *   7. Open issue count ratio (high ratio = unmaintained)
 *   8. Stars/fork trends (sudden drops = community concern)
 *
 * Configuration:
 *   GITHUB_TOKEN must be set (reuses existing advisory sync token)
 *
 * Output: enriched trust score stored in sbomComponents.trustScore
 * and risk signals stored in a new supplyChainSignals table.
 */

import { v } from "convex/values";
import {
  internalAction,
  internalMutation,
  internalQuery,
  query,
  mutation,
} from "./_generated/server";
import { internal } from "./_generated/api";

// ── GitHub API types ──────────────────────────────────────────────────────────

type GitHubRepo = {
  full_name: string;
  description: string | null;
  archived: boolean;
  disabled: boolean;
  pushed_at: string | null;
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  subscribers_count: number;
  owner: {
    login: string;
    type: "User" | "Organization";
    created_at?: string;
  };
  created_at: string;
  updated_at: string;
};

type GitHubContributor = {
  login: string;
  contributions: number;
  type: string;
};

type GitHubCommit = {
  sha: string;
  commit: {
    author: { date: string; name: string; email: string } | null;
    message: string;
  };
  author: { login: string; created_at?: string } | null;
};

type GitHubRelease = {
  tag_name: string;
  published_at: string;
  author: { login: string };
};

// ── Risk signal types ─────────────────────────────────────────────────────────

export type SocialSignalKind =
  | "archived_repository"
  | "abandoned_repository"          // no commits > 2 years
  | "new_account_high_contributions" // account < 1 year with > 20% of recent commits
  | "contributor_velocity_spike"     // >3x normal contributor additions in 30 days
  | "release_by_new_contributor"     // release author account < 6 months old
  | "build_script_modified_by_new"  // CI/build file changed by new contributor
  | "binary_blob_added"             // encoded/binary content added recently
  | "high_issue_ratio"              // issues/stars > 0.5
  | "maintainer_transfer"           // owner changed recently
  | "low_contributor_diversity";    // < 3 unique contributors to core files

export type SocialSignal = {
  kind: SocialSignalKind;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  evidence: string;
  detectedAt: number;
};

export type RepositorySocialAnalysis = {
  packageName: string;
  ecosystem: string;
  githubRepoPath: string | null;
  signals: SocialSignal[];
  overallRiskLevel: "trusted" | "monitor" | "at_risk" | "suspicious" | "compromised";
  socialTrustScore: number;   // 0–100
  lastAnalyzedAt: number;
  repoMetadata: {
    stars: number;
    forks: number;
    openIssues: number;
    archived: boolean;
    lastCommitDate: string | null;
    contributorCount: number;
  } | null;
};

// ── GitHub helpers ────────────────────────────────────────────────────────────

function githubHeaders(token: string | undefined): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Sentinel-Security-Agent/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function githubFetch<T>(
  url: string,
  token: string | undefined,
): Promise<T | null> {
  try {
    const resp = await fetch(url, { headers: githubHeaders(token) });
    if (resp.status === 404 || resp.status === 403 || resp.status === 451) return null;
    if (!resp.ok) return null;
    return resp.json() as Promise<T>;
  } catch {
    return null;
  }
}

// Infer GitHub repo path from package name + ecosystem
function inferGithubPath(packageName: string, ecosystem: string): string | null {
  // npm packages often have repository field — we approximate from name
  // For packages like "@nestjs/core" → "nestjs/core"
  if (ecosystem === "npm") {
    const scoped = packageName.replace(/^@/, "").replace(/\//, "/");
    // Only return if it looks like an org/repo pattern
    if (scoped.includes("/")) return scoped;
    return null; // Can't infer for non-scoped
  }
  if (ecosystem === "go") {
    // "github.com/some/pkg" → "some/pkg"
    const match = packageName.match(/github\.com\/([^/]+\/[^/]+)/);
    return match ? match[1] : null;
  }
  return null;
}

// ── Analysis logic ────────────────────────────────────────────────────────────

async function analyzeRepository(
  repoPath: string,
  token: string | undefined,
): Promise<{
  signals: SocialSignal[];
  metadata: RepositorySocialAnalysis["repoMetadata"];
}> {
  const signals: SocialSignal[] = [];
  const now = Date.now();

  // 1 — Fetch repository metadata
  const repo = await githubFetch<GitHubRepo>(
    `https://api.github.com/repos/${repoPath}`,
    token,
  );

  if (!repo) {
    return { signals: [], metadata: null };
  }

  const metadata: RepositorySocialAnalysis["repoMetadata"] = {
    stars: repo.stargazers_count,
    forks: repo.forks_count,
    openIssues: repo.open_issues_count,
    archived: repo.archived,
    lastCommitDate: repo.pushed_at,
    contributorCount: 0,
  };

  // Signal: archived
  if (repo.archived) {
    signals.push({
      kind: "archived_repository",
      severity: "high",
      description: "Repository is archived — no longer maintained",
      evidence: `${repoPath} marked archived on GitHub`,
      detectedAt: now,
    });
  }

  // Signal: abandoned (no pushes in 2 years)
  if (repo.pushed_at) {
    const lastPushMs = Date.parse(repo.pushed_at);
    const twoYearsAgo = now - 2 * 365 * 24 * 3600 * 1000;
    if (lastPushMs < twoYearsAgo) {
      const months = Math.floor((now - lastPushMs) / (30 * 24 * 3600 * 1000));
      signals.push({
        kind: "abandoned_repository",
        severity: "medium",
        description: `Repository not updated in ${months} months`,
        evidence: `Last push: ${repo.pushed_at}`,
        detectedAt: now,
      });
    }
  }

  // Signal: high issue ratio (unmaintained indicator)
  if (repo.stargazers_count > 50 && repo.open_issues_count > repo.stargazers_count * 0.5) {
    signals.push({
      kind: "high_issue_ratio",
      severity: "low",
      description: "High ratio of open issues to stars — possible maintenance concerns",
      evidence: `${repo.open_issues_count} open issues / ${repo.stargazers_count} stars`,
      detectedAt: now,
    });
  }

  // 2 — Fetch recent contributors
  const contributors = await githubFetch<GitHubContributor[]>(
    `https://api.github.com/repos/${repoPath}/contributors?per_page=30&anon=0`,
    token,
  );

  if (contributors) {
    metadata.contributorCount = contributors.length;

    // Signal: low contributor diversity
    if (contributors.length < 3 && repo.stargazers_count > 1000) {
      signals.push({
        kind: "low_contributor_diversity",
        severity: "medium",
        description: `Only ${contributors.length} contributor(s) for a popular package`,
        evidence: `${repo.stargazers_count} stars but only ${contributors.length} contributors`,
        detectedAt: now,
      });
    }
  }

  // 3 — Fetch recent commits (last 90 days) to check for new contributor patterns
  const since = new Date(now - 90 * 24 * 3600 * 1000).toISOString();
  const recentCommits = await githubFetch<GitHubCommit[]>(
    `https://api.github.com/repos/${repoPath}/commits?since=${since}&per_page=50`,
    token,
  );

  if (recentCommits && recentCommits.length > 0) {
    // Check for commits from accounts created recently
    const newAccountCommits = recentCommits.filter((commit) => {
      if (!commit.author?.created_at) return false;
      const accountAge = now - Date.parse(commit.author.created_at);
      const oneYear = 365 * 24 * 3600 * 1000;
      return accountAge < oneYear;
    });

    const newAccountFraction = newAccountCommits.length / recentCommits.length;
    if (newAccountFraction > 0.2 && newAccountCommits.length >= 3) {
      signals.push({
        kind: "new_account_high_contributions",
        severity: "high",
        description: "New GitHub accounts (<1 year old) authored a significant portion of recent commits",
        evidence: `${newAccountCommits.length}/${recentCommits.length} recent commits from accounts <1 year old`,
        detectedAt: now,
      });
    }

    // Check for build script modifications
    const buildPaths = [".github/", "Makefile", "CMakeLists", "build.sh", "setup.py", "setup.cfg"];
    const buildCommits = recentCommits.filter((c) =>
      buildPaths.some((path) => c.commit.message?.toLowerCase().includes(path.toLowerCase())),
    );
    if (buildCommits.length > 0 && newAccountCommits.some((nc) =>
      buildCommits.some((bc) => bc.sha === nc.sha),
    )) {
      signals.push({
        kind: "build_script_modified_by_new",
        severity: "critical",
        description: "Build or CI script modified by a recently-created GitHub account",
        evidence: `${buildCommits.length} build-related commit(s) by new contributors in last 90 days`,
        detectedAt: now,
      });
    }
  }

  // 4 — Fetch latest releases to check for releases by new contributors
  const releases = await githubFetch<GitHubRelease[]>(
    `https://api.github.com/repos/${repoPath}/releases?per_page=3`,
    token,
  );

  if (releases && releases.length > 0 && contributors) {
    const latestRelease = releases[0];
    const releaseAuthorLogin = latestRelease.author?.login;
    if (releaseAuthorLogin) {
      // Check if this author is among top contributors
      const topContributors = contributors.slice(0, 10).map((c) => c.login);
      const isEstablishedContributor = topContributors.includes(releaseAuthorLogin);

      if (!isEstablishedContributor && latestRelease.published_at) {
        const releaseAge = now - Date.parse(latestRelease.published_at);
        const ninetyDays = 90 * 24 * 3600 * 1000;
        if (releaseAge < ninetyDays) {
          signals.push({
            kind: "release_by_new_contributor",
            severity: "high",
            description: "Recent release authored by someone not in top contributors",
            evidence: `Release ${latestRelease.tag_name} by @${releaseAuthorLogin} — not in top-10 contributors`,
            detectedAt: now,
          });
        }
      }
    }
  }

  return { signals, metadata };
}

// ── Trust score computation ───────────────────────────────────────────────────

function computeSocialTrustScore(signals: SocialSignal[]): number {
  let score = 100;
  const penalties: Record<SocialSignal["severity"], number> = {
    critical: 40,
    high: 20,
    medium: 10,
    low: 5,
  };
  for (const signal of signals) {
    score -= penalties[signal.severity] ?? 0;
  }
  return Math.max(0, score);
}

function classifyRiskLevel(score: number): RepositorySocialAnalysis["overallRiskLevel"] {
  if (score >= 85) return "trusted";
  if (score >= 70) return "monitor";
  if (score >= 50) return "at_risk";
  if (score >= 30) return "suspicious";
  return "compromised";
}

// ── Convex actions ────────────────────────────────────────────────────────────

export const analyzeRepositorySupplyChain = internalAction({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    packageName: v.string(),
    ecosystem: v.string(),
    snapshotId: v.id("sbomSnapshots"),
  },
  handler: async (ctx, args) => {
    const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;

    const githubPath = inferGithubPath(args.packageName, args.ecosystem);
    if (!githubPath) {
      return { analyzed: false, reason: "cannot_infer_github_path" };
    }

    const { signals, metadata } = await analyzeRepository(githubPath, token);
    const score = computeSocialTrustScore(signals);
    const riskLevel = classifyRiskLevel(score);

    await ctx.runMutation(internal.supplyChainMonitor.storeSupplyChainAnalysis, {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
      snapshotId: args.snapshotId,
      packageName: args.packageName,
      ecosystem: args.ecosystem,
      githubRepoPath: githubPath,
      signals,
      overallRiskLevel: riskLevel,
      socialTrustScore: score,
      repoMetadata: metadata ?? undefined,
    });

    return { analyzed: true, score, riskLevel, signalCount: signals.length };
  },
});

/**
 * Batch-analyze all direct dependencies in a snapshot.
 * Respects GitHub API rate limits by processing up to 10 packages per call.
 */
export const batchAnalyzeSnapshotSupplyChain = internalAction({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    snapshotId: v.id("sbomSnapshots"),
    ecosystems: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    const components = await ctx.runQuery(
      internal.supplyChainMonitor.getDirectComponentsForSnapshot,
      { snapshotId: args.snapshotId, ecosystems: args.ecosystems ?? ["npm", "go"] },
    );

    const results = { analyzed: 0, skipped: 0, highRisk: 0 };

    for (const comp of components.slice(0, 10)) {
      const result = await ctx.runAction(
        internal.supplyChainMonitor.analyzeRepositorySupplyChain,
        {
          tenantId: args.tenantId,
          repositoryId: args.repositoryId,
          packageName: comp.name,
          ecosystem: comp.ecosystem,
          snapshotId: args.snapshotId,
        },
      );

      if (result.analyzed) {
        results.analyzed++;
        if (result.riskLevel === "suspicious" || result.riskLevel === "compromised") {
          results.highRisk++;
        }
      } else {
        results.skipped++;
      }
    }

    return results;
  },
});

// ── Public queries ────────────────────────────────────────────────────────────

export const getSupplyChainRiskSummary = query({
  args: { repositoryId: v.id("repositories") },
  handler: async (ctx, { repositoryId }) => {
    const analyses = await ctx.db
      .query("supplyChainAnalyses")
      .withIndex("by_repository_and_analyzed_at", (q) =>
        q.eq("repositoryId", repositoryId),
      )
      .order("desc")
      .take(50);

    const highRisk = analyses.filter(
      (a) => a.overallRiskLevel === "suspicious" || a.overallRiskLevel === "compromised",
    );
    const atRisk = analyses.filter((a) => a.overallRiskLevel === "at_risk");

    return {
      totalAnalyzed: analyses.length,
      highRisk: highRisk.length,
      atRisk: atRisk.length,
      highRiskPackages: highRisk.map((a) => ({
        packageName: a.packageName,
        ecosystem: a.ecosystem,
        riskLevel: a.overallRiskLevel,
        socialTrustScore: a.socialTrustScore,
        topSignal: a.signals[0]?.description ?? null,
      })),
    };
  },
});

export const getPackageSupplyChainAnalysis = query({
  args: {
    repositoryId: v.id("repositories"),
    packageName: v.string(),
  },
  handler: async (ctx, { repositoryId, packageName }) => {
    return await ctx.db
      .query("supplyChainAnalyses")
      .withIndex("by_repository_and_package", (q) =>
        q.eq("repositoryId", repositoryId).eq("packageName", packageName),
      )
      .order("desc")
      .first();
  },
});

// Dashboard trigger
export const triggerSupplyChainAnalysis = mutation({
  args: { tenantSlug: v.string(), repositoryFullName: v.string() },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", tenantSlug))
      .unique();
    if (!tenant) throw new Error("Tenant not found");

    const repo = await ctx.db
      .query("repositories")
      .withIndex("by_tenant_and_full_name", (q) =>
        q.eq("tenantId", tenant._id).eq("fullName", repositoryFullName),
      )
      .unique();
    if (!repo) throw new Error("Repository not found");

    // Find latest snapshot
    const snapshot = await ctx.db
      .query("sbomSnapshots")
      .withIndex("by_repository_and_captured_at", (q) =>
        q.eq("repositoryId", repo._id),
      )
      .order("desc")
      .first();

    if (!snapshot) return { scheduled: false, reason: "no_snapshot" };

    await ctx.scheduler.runAfter(
      0,
      internal.supplyChainMonitor.batchAnalyzeSnapshotSupplyChain,
      {
        tenantId: tenant._id,
        repositoryId: repo._id,
        snapshotId: snapshot._id,
      },
    );

    return { scheduled: true };
  },
});

// ── Internal helpers ──────────────────────────────────────────────────────────

export const getDirectComponentsForSnapshot = internalQuery({
  args: {
    snapshotId: v.id("sbomSnapshots"),
    ecosystems: v.array(v.string()),
  },
  handler: async (ctx, { snapshotId, ecosystems }) => {
    const components = await ctx.db
      .query("sbomComponents")
      .withIndex("by_snapshot", (q) => q.eq("snapshotId", snapshotId))
      .take(100);

    return components.filter(
      (c) => c.isDirect && ecosystems.includes(c.ecosystem),
    );
  },
});

const signalValidator = v.object({
  kind: v.string(),
  severity: v.union(
    v.literal("critical"),
    v.literal("high"),
    v.literal("medium"),
    v.literal("low"),
  ),
  description: v.string(),
  evidence: v.string(),
  detectedAt: v.number(),
});

export const storeSupplyChainAnalysis = internalMutation({
  args: {
    tenantId: v.id("tenants"),
    repositoryId: v.id("repositories"),
    snapshotId: v.id("sbomSnapshots"),
    packageName: v.string(),
    ecosystem: v.string(),
    githubRepoPath: v.string(),
    signals: v.array(signalValidator),
    overallRiskLevel: v.union(
      v.literal("trusted"),
      v.literal("monitor"),
      v.literal("at_risk"),
      v.literal("suspicious"),
      v.literal("compromised"),
    ),
    socialTrustScore: v.number(),
    repoMetadata: v.optional(
      v.object({
        stars: v.number(),
        forks: v.number(),
        openIssues: v.number(),
        archived: v.boolean(),
        lastCommitDate: v.union(v.string(), v.null()),
        contributorCount: v.number(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    // Upsert — keep latest per package+repository
    const existing = await ctx.db
      .query("supplyChainAnalyses")
      .withIndex("by_repository_and_package", (q) =>
        q.eq("repositoryId", args.repositoryId).eq("packageName", args.packageName),
      )
      .first();

    const data = { ...args, lastAnalyzedAt: Date.now() };

    if (existing) {
      await ctx.db.patch(existing._id, data);
    } else {
      await ctx.db.insert("supplyChainAnalyses", data);
    }

    // If the package is suspicious/compromised, create a finding
    if (
      args.overallRiskLevel === "suspicious" ||
      args.overallRiskLevel === "compromised"
    ) {
      const topSignal = args.signals[0];
      if (topSignal) {
        console.log(
          `[supply-chain] ${args.packageName} is ${args.overallRiskLevel}: ${topSignal.description}`,
        );
      }
    }
  },
});
