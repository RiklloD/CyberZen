/**
 * GateDecisionListPanel — §1.17
 *
 * Lists gate decisions for a repository with pass/block/override status pills.
 * Each row shows the finding title, severity, decision, actor, and timestamp.
 * Clicking a row calls onSelect with the decision's _id.
 */

import type { FunctionReturnType } from "convex/server";
import { ShieldCheck, ShieldAlert, ShieldOff, Clock } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type GateDecision = NonNullable<
  FunctionReturnType<
    typeof api.gateEnforcement.listGateDecisionsForRepository
  >
>[number];

function decisionTone(
  decision: string,
): "success" | "danger" | "warning" {
  if (decision === "approved") return "success";
  if (decision === "blocked") return "danger";
  return "warning";
}

function decisionIcon(decision: string) {
  if (decision === "approved")
    return <ShieldCheck size={14} className="text-[var(--success)]" />;
  if (decision === "blocked")
    return <ShieldAlert size={14} className="text-[var(--danger)]" />;
  return <ShieldOff size={14} className="text-[var(--warning)]" />;
}

function severityTone(
  severity: string,
): "danger" | "warning" | "neutral" {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "neutral";
}

export interface GateDecisionListPanelProps {
  decisions: GateDecision[] | undefined;
  selectedId: string | null;
  onSelect: (decisionId: string) => void;
}

export default function GateDecisionListPanel({
  decisions,
  selectedId,
  onSelect,
}: GateDecisionListPanelProps) {
  if (!decisions) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <ShieldCheck size={16} className="text-[var(--signal)]" />
          <h3 className="section-title">Gate Decisions</h3>
        </div>
        <div className="grid gap-3">
          {["a", "b", "c"].map((k) => (
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
        <ShieldCheck size={16} className="text-[var(--signal)]" />
        <h3 className="section-title">Gate Decisions</h3>
        <StatusPill label={`${decisions.length} decisions`} tone="neutral" />
      </div>

      {decisions.length === 0 ? (
        <div className="card card-sm">
          <p className="text-xs text-[var(--sea-ink-soft)]">
            No gate decisions recorded for this repository yet.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {decisions.map((d) => (
            <button
              key={d._id}
              type="button"
              className={`card card-sm w-full text-left cursor-pointer transition hover:border-[var(--signal)]/40 ${
                selectedId === d._id ? "border-[var(--signal)]/60" : ""
              }`}
              onClick={() => onSelect(d._id)}
            >
              {/* Row 1: icon + finding title */}
              <div className="flex items-start gap-2">
                <span className="mt-0.5 shrink-0">{decisionIcon(d.decision)}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
                    {d.findingTitle}
                  </p>
                </div>
              </div>

              {/* Row 2: pills */}
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <StatusPill label={d.decision} tone={decisionTone(d.decision)} />
                <StatusPill
                  label={d.findingSeverity}
                  tone={severityTone(d.findingSeverity)}
                />
                <StatusPill
                  label={d.stage.replace(/_/g, " ")}
                  tone="neutral"
                />
                <StatusPill
                  label={d.actorType === "agent" ? "Agent" : d.actorId.replace(/_/g, " ")}
                  tone="info"
                />
                {d.expiresAt && (
                  <StatusPill label="Expiring" tone="warning" />
                )}
              </div>

              {/* Row 3: meta */}
              <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
                <span>{d.repositoryName}</span>
                <span className="inline-flex items-center gap-1">
                  <Clock size={10} />
                  {formatTimestamp(d.createdAt)}
                </span>
              </div>

              {/* Justification preview */}
              {d.justification && (
                <p className="mt-1 text-xs text-[var(--sea-ink-soft)] line-clamp-2">
                  {d.justification}
                </p>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
