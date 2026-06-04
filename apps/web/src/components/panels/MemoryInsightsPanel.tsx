import type { FunctionReturnType } from "convex/server";
import { useQuery } from "convex/react";
import { Brain, GitBranch, Share2, AlertTriangle } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { PanelSkeleton } from "./SharedPanelComponents";

type Insights = NonNullable<FunctionReturnType<typeof api.neuralMemory.getMemoryInsightsBySlug>>;
type SharedPattern = Insights['sharedPatterns'][number];
type RepoCoverage = Insights['repoCoverage'][number];

const severityToneMap: Record<string, "danger" | "warning" | "neutral" | "info"> = {
  critical: "danger",
  high: "warning",
  medium: "neutral",
  low: "info",
  informational: "info",
};

export default function MemoryInsightsPanel({ tenantSlug }: { tenantSlug: string }) {
  const insights = useQuery(api.neuralMemory.getMemoryInsightsBySlug, { tenantSlug });

  if (insights === undefined) return <PanelSkeleton count={3} />;

  const sharedCount = insights.sharedPatterns.length;
  const repoCount = insights.totalRepos;

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-1">
            <Share2 className="w-4 h-4 text-[var(--sea-blue)]" />
            <p className="panel-label">Shared Patterns</p>
          </div>
          <p className="text-2xl font-mono font-semibold mt-1">{sharedCount}</p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Patterns appearing in 2+ repositories
          </p>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-1">
            <Brain className="w-4 h-4 text-[var(--sea-green)]" />
            <p className="panel-label">Total Patterns</p>
          </div>
          <p className="text-2xl font-mono font-semibold mt-1">{insights.totalPatterns}</p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Across {repoCount} active {repoCount === 1 ? "repository" : "repositories"}
          </p>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-1">
            <GitBranch className="w-4 h-4 text-[var(--sea-purple)]" />
            <p className="panel-label">Memory Coverage</p>
          </div>
          <p className="text-2xl font-mono font-semibold mt-1">{insights.repoCoverage.length}</p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Repositories with active memory
          </p>
        </div>
      </div>

      {/* Shared patterns list */}
      <div className="card card-sm">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-4 h-4 text-[var(--sea-yellow)]" />
          <p className="panel-label">Cross-Repository Patterns</p>
        </div>

        {insights.sharedPatterns.length === 0 ? (
          <p className="text-sm text-[var(--sea-ink-soft)] py-4 text-center">
            No shared patterns detected yet. Patterns appear here once the same vulnerability type
            is observed in 2 or more repositories.
          </p>
        ) : (
          <div className="space-y-2">
            {insights.sharedPatterns.map((pattern: SharedPattern, idx: number) => (
              <div
                key={`${pattern.patternType}-${pattern.name}-${idx}`}
                className="flex items-center gap-3 py-2 border-b border-[var(--sea-gray-light)] last:border-0"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{pattern.name}</p>
                  <p className="text-xs text-[var(--sea-ink-soft)]">
                    {pattern.patternType.replace(/_/g, " ")}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <StatusPill
                    label={`${pattern.repoCount} repos`}
                    tone="neutral"
                  />
                  <StatusPill
                    label={pattern.severity}
                    tone={severityToneMap[pattern.severity] ?? "neutral"}
                  />
                  <span className="text-xs font-mono text-[var(--sea-ink-soft)]">
                    {Math.round(pattern.avgConfidence * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Per-repo coverage */}
      {insights.repoCoverage.length > 0 && (
        <div className="card card-sm">
          <p className="panel-label mb-3">Memory Coverage per Repository</p>
          <div className="space-y-3">
            {insights.repoCoverage.map((repo: RepoCoverage) => (
              <div key={repo.repositoryId} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="font-mono text-[var(--sea-ink-soft)]">{repo.repositoryId.slice(-8)}</span>
                  <span className="font-mono">{Math.round(repo.coverageScore * 100)}%</span>
                </div>
                <div className="w-full bg-[rgba(130,122,110,0.1)] rounded-full h-1.5">
                  <div
                    className="h-full bg-[var(--sea-green)] rounded-full transition-all"
                    style={{ width: `${repo.coverageScore * 100}%` }}
                  />
                </div>
                <div className="flex gap-3 text-xs text-[var(--sea-ink-soft)]">
                  <span>{repo.totalEpisodes} episodes</span>
                  <span>{repo.totalPatterns} patterns</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
