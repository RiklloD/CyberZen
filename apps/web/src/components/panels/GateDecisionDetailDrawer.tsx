/**
 * GateDecisionDetailDrawer — §1.17, §3.2
 *
 * Full policy trace for a single gate decision: shows the decision chain,
 * override history with justifications, "Override" CTA (§3.2), and a
 * "Replay" CTA placeholder.
 * Receives the full detail object fetched via getGateDecisionDetail.
 */

import type { FunctionReturnType } from "convex/server";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  ArrowRight,
  Clock,
  RotateCcw,
  User,
  Bot,
} from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import GateOverrideModal from "../modals/GateOverrideModal";

type GateDetail = NonNullable<
  FunctionReturnType<typeof api.gateEnforcement.getGateDecisionDetail>
>;

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

export interface GateDecisionDetailDrawerProps {
  detail: GateDetail | undefined | null;
  onReplay?: (workflowRunId: string) => void;
  onOverride?: () => void;
}

export default function GateDecisionDetailDrawer({
  detail,
  onReplay,
  onOverride,
}: GateDecisionDetailDrawerProps) {
  const [showOverrideModal, setShowOverrideModal] = useState(false);

  if (!detail) {
    return (
      <div className="card card-sm">
        <p className="text-xs text-[var(--sea-ink-soft)]">
          Select a gate decision to view its policy trace.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-2">
        {decisionIcon(detail.decision)}
        <h3 className="section-title">Decision Detail</h3>
        <StatusPill
          label={detail.decision}
          tone={decisionTone(detail.decision)}
        />
      </div>

      {/* Finding info card */}
      <div className="card card-sm">
        <p className="text-sm font-semibold text-[var(--sea-ink)]">
          {detail.findingTitle}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <StatusPill label={detail.findingSeverity} tone={
            detail.findingSeverity === "critical" || detail.findingSeverity === "high"
              ? "danger"
              : detail.findingSeverity === "medium"
                ? "warning"
                : "neutral"
          } />
          <StatusPill label={detail.findingSource} tone="info" />
          <StatusPill
            label={detail.stage.replace(/_/g, " ")}
            tone="neutral"
          />
          <StatusPill
            label={detail.actorType === "agent" ? "Agent" : detail.actorId.replace(/_/g, " ")}
            tone="info"
          />
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
          <span>{detail.repositoryFullName}</span>
          <span className="inline-flex items-center gap-1">
            <Clock size={10} />
            {formatTimestamp(detail.createdAt)}
          </span>
        </div>
        {detail.justification && (
          <div className="mt-2 rounded-lg bg-[var(--surface-alt)] p-2.5">
            <p className="text-xs font-semibold text-[var(--sea-ink)] mb-1">
              Justification
            </p>
            <p className="text-xs text-[var(--sea-ink-soft)]">
              {detail.justification}
            </p>
          </div>
        )}
        {detail.expiresAt && (
          <p className="mt-1.5 text-xs text-[var(--warning)]">
            Expires: {formatTimestamp(detail.expiresAt)}
          </p>
        )}
      </div>

      {/* Policy Trace */}
      <div>
        <h4 className="section-title mb-2">Policy Trace</h4>
        {detail.policyTrace.length === 0 ? (
          <p className="text-xs text-[var(--sea-ink-soft)]">
            No policy trace available.
          </p>
        ) : (
          <div className="space-y-2">
            {detail.policyTrace.map((step: GateDetail["policyTrace"][number], i: number) => (
              <div key={step._id} className="flex items-start gap-2">
                {/* Connector line */}
                <div className="flex flex-col items-center">
                  <span className="mt-0.5 shrink-0">{decisionIcon(step.decision)}</span>
                  {i < detail.policyTrace.length - 1 && (
                    <div className="w-px flex-1 bg-[var(--line)] min-h-[12px]" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <StatusPill
                      label={step.decision}
                      tone={decisionTone(step.decision)}
                    />
                    <span className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
                      {step.actorType === "agent" ? <Bot size={10} /> : <User size={10} />}
                      {step.actorType === "agent" ? "Agent" : step.actorId.replace(/_/g, " ")}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
                    {formatTimestamp(step.createdAt)}
                  </p>
                  {step.justification && (
                    <p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
                      {step.justification}
                    </p>
                  )}
                  {step.expiresAt && (
                    <p className="mt-0.5 text-xs text-[var(--warning)]">
                      Expires: {formatTimestamp(step.expiresAt)}
                    </p>
                  )}
                </div>
                {i < detail.policyTrace.length - 1 && (
                  <span className="mt-1 shrink-0 text-[var(--sea-ink-soft)]">
                    <ArrowRight size={12} />
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Override History */}
      {detail.overrideHistory.length > 0 && (
        <div>
          <h4 className="section-title mb-2">Override History</h4>
          <div className="space-y-2">
            {detail.overrideHistory.map((ov: GateDetail["overrideHistory"][number]) => (
              <div
                key={ov._id}
                className="card card-sm border-[var(--warning)]/30"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <ShieldOff size={12} className="text-[var(--warning)]" />
                  <StatusPill label="overridden" tone="warning" />
                  <span className="inline-flex items-center gap-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
                    <User size={10} />
                    {ov.actorId.replace(/_/g, " ")}
                  </span>
                </div>
                {ov.justification && (
                  <p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
                    {ov.justification}
                  </p>
                )}
                <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
                  <span className="inline-flex items-center gap-1">
                    <Clock size={10} />
                    {formatTimestamp(ov.createdAt)}
                  </span>
                  {ov.expiresAt && (
                    <span className="text-[var(--warning)]">
                      Expires: {formatTimestamp(ov.expiresAt)}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Override CTA — §3.2 */}
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-xl border border-[var(--warning)]/30 bg-[var(--warning)]/8 px-3 py-2 text-xs font-semibold text-[var(--warning)] transition hover:bg-[var(--warning)]/15 cursor-pointer"
          onClick={() => setShowOverrideModal(true)}
        >
          <ShieldOff size={12} />
          Override Decision
        </button>

        {/* Replay CTA */}
        {onReplay && (
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--signal)]/30 bg-[var(--signal)]/8 px-3 py-2 text-xs font-semibold text-[var(--signal)] transition hover:bg-[var(--signal)]/15 cursor-pointer"
            onClick={() => onReplay(detail.workflowRunId)}
          >
            <RotateCcw size={12} />
            Replay Gate Evaluation
          </button>
        )}
      </div>

      {/* Override Modal — §3.2 */}
      {showOverrideModal && (
        <GateOverrideModal
          gateDecisionId={detail._id}
          currentDecision={detail.decision}
          findingTitle={detail.findingTitle}
          onClose={() => setShowOverrideModal(false)}
          onOverridden={onOverride}
        />
      )}
    </div>
  );
}
