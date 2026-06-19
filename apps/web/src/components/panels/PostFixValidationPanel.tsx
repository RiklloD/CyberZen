/**
 * PostFixValidationPanel — §1.15
 *
 * Lists post-fix validation runs for a repository, one row per merged PR.
 * Each row shows finding title, fix type, validation outcome (resolved /
 * regression / pending), and the PR link.
 */

import type { FunctionReturnType } from "convex/server";
import { CheckCircle2, ExternalLink, AlertTriangle, Clock } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type ValidationRun = NonNullable<
  FunctionReturnType<
    typeof api.postFixValidation.listValidationRunsForRepository
  >
>[number];

function outcomeTone(
  outcome: string | null,
): "success" | "danger" | "warning" | "neutral" {
  if (outcome === "resolved") return "success";
  if (outcome === "regression") return "danger";
  return "neutral";
}

function outcomeLabel(outcome: string | null): string {
  if (outcome === "resolved") return "Fix verified";
  if (outcome === "regression") return "Regression";
  return "Pending";
}

function outcomeIcon(outcome: string | null) {
  if (outcome === "resolved")
    return <CheckCircle2 size={14} className="text-[var(--success)]" />;
  if (outcome === "regression")
    return <AlertTriangle size={14} className="text-[var(--danger)]" />;
  return <Clock size={14} className="text-[var(--sea-ink-soft)]" />;
}

function fixTypeLabel(ft: string): string {
  switch (ft) {
    case "version_bump":
      return "Version bump";
    case "patch":
      return "Patch";
    case "config_change":
      return "Config change";
    case "manual":
      return "Manual";
    default:
      return ft;
  }
}

export interface PostFixValidationPanelProps {
  runs: ValidationRun[] | undefined;
  onSelect: (run: ValidationRun) => void;
}

export default function PostFixValidationPanel({
  runs,
  onSelect }: PostFixValidationPanelProps) {
  if (!runs) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <CheckCircle2 size={16} className="text-[var(--signal)]" />
          <h3 className="section-title">Post-Fix Validation</h3>
        </div>
        <div className="grid gap-3">
          {["a", "b"].map((k) => (
            <div key={k} className="loading-panel h-24 rounded-2xl" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-2">
        <CheckCircle2 size={16} className="text-[var(--signal)]" />
        <h3 className="section-title">Post-Fix Validation</h3>
        <StatusPill label={`${runs.length} runs`} tone="neutral" />
      </div>

      {runs.length === 0 ? (
        <div className="card card-sm">
          <p className="text-xs text-[var(--sea-ink-soft)]">
            No merged PR proposals with post-fix validation recorded for this
            repository yet.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {runs.map((run) => (
            <button
              key={run._id}
              type="button"
              className="card card-sm w-full text-left cursor-pointer transition hover:border-[var(--signal)]/40"
              onClick={() => onSelect(run)}
            >
              {/* Row 1: status icon + finding title */}
              <div className="flex items-start gap-2">
                <span className="mt-0.5 shrink-0">{outcomeIcon(run.postFixOutcome)}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
                    {run.findingTitle}
                  </p>
                </div>
              </div>

              {/* Row 2: pills */}
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <StatusPill
                  label={outcomeLabel(run.postFixOutcome)}
                  tone={outcomeTone(run.postFixOutcome)}
                />
                <StatusPill label={fixTypeLabel(run.fixType)} tone="info" />
                <StatusPill
                  label={run.findingSeverity}
                  tone={
                    run.findingSeverity === "critical"
                      ? "danger"
                      : run.findingSeverity === "high"
                        ? "warning"
                        : "neutral"
                  }
                />
                {run.prNumber != null && (
                  <span className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
                    <ExternalLink size={10} />
                    PR #{run.prNumber}
                  </span>
                )}
              </div>

              {/* Row 3: meta */}
              <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
                {run.targetPackage && (
                  <span className="font-mono">{run.targetPackage}</span>
                )}
                {run.currentVersion && run.fixVersion && (
                  <span>
                    {run.currentVersion} → {run.fixVersion}
                  </span>
                )}
                <span>{formatTimestamp(run.mergedAt ?? run.createdAt)}</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
