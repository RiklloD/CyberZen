/**
 * GateOverrideModal — §3.2
 *
 * Confirmation modal for overriding a gate decision.
 * Shows the current decision, requires a justification textarea,
 * and fires the `gateEnforcement.overrideGateDecision` mutation.
 */

import { useState } from "react";
import { useMutation } from "convex/react";
import { ShieldOff, AlertTriangle } from "lucide-react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import { track } from "../../lib/analytics";

export interface GateOverrideModalProps {
  gateDecisionId: string;
  currentDecision: string;
  findingTitle: string;
  onClose: () => void;
  onOverridden?: () => void;
}

export default function GateOverrideModal({
  gateDecisionId,
  currentDecision,
  findingTitle,
  onClose,
  onOverridden }: GateOverrideModalProps) {
  const [justification, setJustification] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const overrideMutation = useMutation(api.gateEnforcement.overrideGateDecision);

  async function handleSubmit() {
    if (!justification.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      await overrideMutation({
        gateDecisionId: gateDecisionId as Id<"gateDecisions">,
        justification: justification.trim() });
      track("gate.overridden", {
        gateDecisionId,
        findingTitle });
      onOverridden?.();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to override gate decision");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
    >
      <div className="card w-full max-w-lg mx-4 space-y-5">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-[var(--warning)]/15">
            <AlertTriangle size={20} className="text-[var(--warning)]" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-[var(--sea-ink)]">
              Override Gate Decision
            </h3>
            <p className="text-xs text-[var(--sea-ink-soft)]">
              This action will override the current{" "}
              <span className="font-semibold">{currentDecision}</span> decision.
            </p>
          </div>
        </div>

        {/* Finding info */}
        <div className="rounded-lg bg-[var(--surface-alt)] p-3">
          <div className="flex items-center gap-2 mb-1">
            <ShieldOff size={14} className="text-[var(--warning)]" />
            <span className="text-xs font-semibold text-[var(--sea-ink)]">
              {findingTitle}
            </span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Decision ID: {gateDecisionId}
          </p>
        </div>

        {/* Justification */}
        <div>
          <label
            htmlFor="override-justification"
            className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5"
          >
            Justification <span className="text-[var(--danger)]">*</span>
          </label>
          <textarea
            id="override-justification"
            className="w-full rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-2.5 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)]/60 focus:outline-none focus:ring-2 focus:ring-[var(--warning)]/40 focus:border-[var(--warning)]/60 resize-none"
            rows={3}
            placeholder="Explain why this gate decision should be overridden…"
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            disabled={isSubmitting}
          />
        </div>

        {/* Error */}
        {error && (
          <p className="text-xs text-[var(--danger)]">{error}</p>
        )}

        {/* Actions */}
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            className="signal-button secondary-button"
            style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
            onClick={onClose}
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="signal-button"
            style={{
              padding: "0.5rem 0.9rem",
              fontSize: "0.78rem",
              backgroundColor: "var(--warning)",
              borderColor: "var(--warning)" }}
            onClick={handleSubmit}
            disabled={isSubmitting || !justification.trim()}
          >
            {isSubmitting ? "Overriding…" : "Override Decision"}
          </button>
        </div>
      </div>
    </div>
  );
}
