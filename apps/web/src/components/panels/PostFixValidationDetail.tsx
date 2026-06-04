/**
 * PostFixValidationDetail — §1.15
 *
 * Shows the pre/post diff for a selected post-fix validation run:
 *  - Finding summary & severity
 *  - Validation outcome (resolved / regression)
 *  - Pre-fix vs post-fix exploit validation comparison
 *  - Regression flags when exploit still succeeds after fix
 *  - Sandbox URL link for the validation run
 */

import { CheckCircle2, ExternalLink, FlaskConical, AlertTriangle, XCircle } from "lucide-react";
import StatusPill from "../StatusPill";
import { formatTimestamp } from "../../lib/utils";

type ValidationRun = {
  _id: string;
  findingId: string;
  findingTitle: string;
  findingSeverity: string;
  validationStatus: string;
  findingStatus: string;
  prUrl: string | null;
  prNumber: number | null;
  fixType: string;
  fixSummary: string;
  targetPackage: string | null;
  currentVersion: string | null;
  fixVersion: string | null;
  mergedAt: number | null;
  createdAt: number;
  postFixOutcome: string | null;
  latestValidationRun: {
    _id: string;
    status: string;
    outcome: string | null;
    validationConfidence: number;
    sandboxSummary: string;
    evidenceSummary: string;
    reproductionHint: string;
    startedAt: number;
    completedAt: number | null;
  } | null;
  allValidationRuns: Array<{
    _id: string;
    status: string;
    outcome: string | null;
    validationConfidence: number;
    sandboxSummary: string;
    evidenceSummary: string;
    startedAt: number;
    completedAt: number | null;
  }>;
};

export interface PostFixValidationDetailProps {
  run: ValidationRun;
}

function confidencePct(v: number): string {
  return `${Math.round(v * 100)}%`;
}

function outcomeTone(
  outcome: string | null,
): "success" | "danger" | "warning" | "neutral" {
  if (outcome === "resolved" || outcome === "not_exploitable") return "success";
  if (outcome === "regression" || outcome === "likely_exploitable") return "danger";
  if (outcome === "error") return "warning";
  return "neutral";
}

export default function PostFixValidationDetail({ run }: PostFixValidationDetailProps) {
  const isRegression = run.postFixOutcome === "regression";
  const isResolved = run.postFixOutcome === "resolved";
  const latestRun = run.latestValidationRun;

  // Build a pre/post comparison from the validation runs
  // The last run is the post-fix run; any prior run is pre-fix
  const postFixRun = latestRun;
  const preFixRun = run.allValidationRuns.length > 1
    ? run.allValidationRuns[run.allValidationRuns.length - 1]
    : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-2">
        <FlaskConical size={16} className="text-[var(--signal)]" />
        <h3 className="section-title">Validation Detail</h3>
      </div>

      {/* Finding summary card */}
      <div className="card card-sm">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm font-semibold text-[var(--sea-ink)]">
              {run.findingTitle}
            </p>
            <p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
              {run.fixSummary}
            </p>
          </div>
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
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
          {run.targetPackage && (
            <span>
              <span className="font-semibold text-[var(--sea-ink)]">Package:</span>{" "}
              <span className="font-mono">{run.targetPackage}</span>
            </span>
          )}
          {run.currentVersion && run.fixVersion && (
            <span>
              <span className="font-semibold text-[var(--sea-ink)]">Fix:</span>{" "}
              <span className="font-mono">{run.currentVersion} → {run.fixVersion}</span>
            </span>
          )}
          {run.mergedAt && (
            <span>Merged {formatTimestamp(run.mergedAt)}</span>
          )}
        </div>
      </div>

      {/* Outcome banner */}
      {isResolved && (
        <div className="card card-sm border border-[var(--success)]/30 bg-[var(--success)]/5">
          <div className="flex items-center gap-2">
            <CheckCircle2 size={16} className="text-[var(--success)]" />
            <span className="text-sm font-semibold text-[var(--success)]">
              Fix verified — exploit no longer reproduces
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
            Post-fix validation confirmed the vulnerability is resolved.
            The finding has been marked as resolved.
          </p>
        </div>
      )}

      {isRegression && (
        <div className="card card-sm border border-[var(--danger)]/30 bg-[var(--danger)]/5">
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="text-[var(--danger)]" />
            <span className="text-sm font-semibold text-[var(--danger)]">
              Regression detected — exploit still succeeds
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
            Post-fix validation after merging the PR showed the exploit is still
            reproducible. The finding has been re-opened and an alert was sent.
          </p>
        </div>
      )}

      {!isResolved && !isRegression && (
        <div className="card card-sm border border-[var(--warning)]/30 bg-[var(--warning)]/5">
          <div className="flex items-center gap-2">
            <XCircle size={16} className="text-[var(--warning)]" />
            <span className="text-sm font-semibold text-[var(--warning)]">
              Validation pending
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
            Post-fix validation has not completed yet for this fix.
          </p>
        </div>
      )}

      {/* Pre / Post comparison */}
      {postFixRun && (
        <div>
          <h4 className="section-title mb-3">Pre / Post Exploit Comparison</h4>
          <div className="grid gap-3 sm:grid-cols-2">
            {/* Pre-fix */}
            <div className="card card-sm">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--sea-ink-soft)]">
                  Pre-Fix
                </span>
                {preFixRun ? (
                  <StatusPill
                    label={preFixRun.outcome ?? preFixRun.status}
                    tone={outcomeTone(preFixRun.outcome)}
                  />
                ) : (
                  <StatusPill label="exploitable" tone="danger" />
                )}
              </div>
              {preFixRun ? (
                <>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-[var(--sea-ink-soft)]">Confidence</span>
                    <span className="font-mono text-[var(--sea-ink)]">
                      {confidencePct(preFixRun.validationConfidence)}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-[var(--sea-ink-soft)] break-words">
                    {preFixRun.evidenceSummary || preFixRun.sandboxSummary || "—"}
                  </p>
                </>
              ) : (
                <p className="text-xs text-[var(--sea-ink-soft)]">
                  Finding was initially validated as exploitable before the fix was applied.
                </p>
              )}
            </div>

            {/* Post-fix */}
            <div className="card card-sm">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--sea-ink-soft)]">
                  Post-Fix
                </span>
                <StatusPill
                  label={postFixRun.outcome ?? postFixRun.status}
                  tone={outcomeTone(postFixRun.outcome)}
                />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--sea-ink-soft)]">Confidence</span>
                <span className="font-mono text-[var(--sea-ink)]">
                  {confidencePct(postFixRun.validationConfidence)}
                </span>
              </div>
              <p className="mt-2 text-xs text-[var(--sea-ink-soft)] break-words">
                {postFixRun.evidenceSummary || postFixRun.sandboxSummary || "—"}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Regression flags */}
      {isRegression && (
        <div>
          <h4 className="section-title mb-3">Regression Flags</h4>
          <div className="card card-sm space-y-2">
            <div className="flex items-center gap-2">
              <AlertTriangle size={12} className="text-[var(--danger)]" />
              <span className="text-xs text-[var(--danger)] font-semibold">
                Finding re-opened
              </span>
            </div>
            <div className="flex items-center gap-2">
              <AlertTriangle size={12} className="text-[var(--danger)]" />
              <span className="text-xs text-[var(--danger)] font-semibold">
                Slack + PagerDuty alert dispatched
              </span>
            </div>
            {postFixRun?.reproductionHint && (
              <p className="text-xs text-[var(--sea-ink-soft)] break-words">
                <span className="font-semibold text-[var(--sea-ink)]">Repro hint:</span>{" "}
                {postFixRun.reproductionHint}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Sandbox validation history */}
      {run.allValidationRuns.length > 0 && (
        <div>
          <h4 className="section-title mb-3">
            Validation History ({run.allValidationRuns.length})
          </h4>
          <div className="card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Status</th>
                  <th>Outcome</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {run.allValidationRuns.map((vr) => (
                  <tr key={vr._id}>
                    <td className="text-[var(--sea-ink-soft)]">
                      {formatTimestamp(vr.startedAt)}
                    </td>
                    <td>
                      <StatusPill label={vr.status} tone={vr.status === "completed" ? "success" : "neutral"} />
                    </td>
                    <td>
                      <StatusPill
                        label={vr.outcome ?? "—"}
                        tone={outcomeTone(vr.outcome)}
                      />
                    </td>
                    <td className="font-mono text-[var(--sea-ink)]">
                      {confidencePct(vr.validationConfidence)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* PR link & sandbox URL */}
      <div className="card card-sm">
        <div className="flex flex-wrap items-center gap-4">
          {run.prUrl && (
            <a
              href={run.prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--signal)] hover:underline"
            >
              <ExternalLink size={12} />
              View PR #{run.prNumber ?? ""}
            </a>
          )}
          {latestRun?.sandboxSummary && latestRun.sandboxSummary.startsWith("http") && (
            <a
              href={latestRun.sandboxSummary}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--teal)] hover:underline"
            >
              <FlaskConical size={12} />
              Sandbox Report
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
