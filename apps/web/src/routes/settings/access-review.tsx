import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "../../lib/clerk-compat";
import { useMutation, useQuery } from "convex/react";
import { CheckCircle, Flag, Plus, ClipboardList } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/access-review")({
  errorComponent: QueryErrorFallback,
  component: AccessReviewPage,
});

function AccessReviewPage() {
  const TENANT = useTenantSlug();
  const authToken = useAuthToken() ?? "";
  const [modalOpen, setModalOpen] = useState(false);
  const [period, setPeriod] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [justificationModal, setJustificationModal] = useState<{
    itemId: string;
    action: "approve" | "flag";
  } | null>(null);
  const [justification, setJustification] = useState("");
  const [activeCycleId, setActiveCycleId] = useState<string | undefined>(undefined);
  const [, startTransition] = useTransition();

  const pendingItems = useQuery(
    api.accessReview.listPendingReviews,
    authToken ? { authToken, tenantSlug: TENANT, cycleId: activeCycleId as any } : "skip",
  );
  const cycles = useQuery(
    api.accessReview.listReviewCycles,
    authToken ? { authToken, tenantSlug: TENANT } : "skip",
  );

  const scheduleReview = useMutation(api.accessReview.scheduleAccessReview);
  const approveAccess = useMutation(api.accessReview.approveAccess);
  const flagForRemoval = useMutation(api.accessReview.flagForRemoval);
  const completeReview = useMutation(api.accessReview.completeAccessReview);

  const activeCycle = cycles?.find((c: any) => c.status === "in_progress");
  const pastCycles = cycles?.filter((c: any) => c.status !== "in_progress") ?? [];
  const allReviewed = pendingItems?.length > 0 && pendingItems.every((i: any) => i.decision);

  async function handleStartReview() {
    if (!period || !dueDate) return;
    startTransition(async () => {
      try {
        const cycleId = await scheduleReview({
          authToken,
          tenantSlug: TENANT,
          period,
          dueDate: new Date(dueDate).getTime(),
        });
        setActiveCycleId(cycleId as string);
        setModalOpen(false);
        setPeriod("");
        setDueDate("");
      } catch (e) {
        console.error(e);
      }
    });
  }

  async function handleReviewAction() {
    if (!justificationModal) return;
    startTransition(async () => {
      try {
        if (justificationModal.action === "approve") {
          await approveAccess({
            authToken,
            tenantSlug: TENANT,
            reviewItemId: justificationModal.itemId as any,
            justification,
          });
        } else {
          await flagForRemoval({
            authToken,
            tenantSlug: TENANT,
            reviewItemId: justificationModal.itemId as any,
            reason: justification,
          });
        }
        setJustificationModal(null);
        setJustification("");
      } catch (e) {
        console.error(e);
      }
    });
  }

  async function handleComplete() {
    if (!activeCycle) return;
    startTransition(async () => {
      try {
        await completeReview({
          authToken,
          tenantSlug: TENANT,
          cycleId: activeCycle._id as any,
        });
      } catch (e) {
        console.error(e);
      }
    });
  }

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <ClipboardList size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">Access Review</h1>
            <p className="page-subtitle">
              SOC2/SOX quarterly access review — approve or flag members for removal
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Active cycle */}
        <div className="section-header mb-3">
          <h2 className="section-title">Current Review Cycle</h2>
          {activeCycle && (
            <StatusPill
              label={`Due ${new Date(activeCycle.dueDate).toLocaleDateString()}`}
              tone="warning"
            />
          )}
          {!activeCycle && (
            <button
              type="button"
              onClick={() => setModalOpen(true)}
              className="signal-button ml-auto"
              style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
            >
              <Plus size={14} className="mr-1" />
              Start Review
            </button>
          )}
        </div>

        {activeCycle ? (
          <>
            <div className="mb-3 p-3 rounded-xl border border-[var(--line)] bg-[var(--surface-soft)]">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-[var(--sea-ink)]">{activeCycle.period}</span>
                  <span className="text-xs text-[var(--sea-ink-soft)] ml-3">
                    Due {new Date(activeCycle.dueDate).toLocaleDateString()}
                  </span>
                </div>
                {allReviewed && (
                  <button
                    type="button"
                    onClick={handleComplete}
                    className="signal-button"
                    style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
                  >
                    <CheckCircle size={14} className="mr-1" />
                    Complete Review
                  </button>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-[var(--line)] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--line)] bg-[var(--surface-soft)]">
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Member</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Role</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Decision</th>
                    <th className="px-4 py-2 text-right text-xs font-semibold text-[var(--sea-ink-soft)]">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingItems?.map((item: any) => (
                    <tr key={item._id} className="border-b border-[var(--line)] last:border-0">
                      <td className="px-4 py-3">
                        <div className="font-medium text-[var(--sea-ink)]">{item.userName ?? "Unknown"}</div>
                        <div className="text-xs text-[var(--sea-ink-soft)]">{item.userEmail ?? ""}</div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusPill label={item.role} tone="neutral" />
                      </td>
                      <td className="px-4 py-3">
                        {item.decision === "approved" && (
                          <StatusPill label="Approved" tone="success" />
                        )}
                        {item.decision === "flagged_for_removal" && (
                          <StatusPill label="Flagged" tone="danger" />
                        )}
                        {!item.decision && (
                          <StatusPill label="Pending" tone="neutral" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {!item.decision && (
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => setJustificationModal({ itemId: item._id, action: "approve" })}
                              className="signal-button"
                              style={{ padding: "0.35rem 0.7rem", fontSize: "0.75rem" }}
                            >
                              <CheckCircle size={12} className="mr-1" />
                              Approve
                            </button>
                            <button
                              type="button"
                              onClick={() => setJustificationModal({ itemId: item._id, action: "flag" })}
                              className="danger-button"
                              style={{ padding: "0.35rem 0.7rem", fontSize: "0.75rem" }}
                            >
                              <Flag size={12} className="mr-1" />
                              Flag
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {(!pendingItems || pendingItems.length === 0) && (
                    <tr>
                      <td colSpan={4} className="px-4 py-6 text-center text-xs text-[var(--sea-ink-soft)]">
                        No members in this review cycle
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="text-center py-8 text-sm text-[var(--sea-ink-soft)]">
            No active review cycle. Start a new one to review member access.
          </div>
        )}

        {/* Past cycles */}
        {pastCycles.length > 0 && (
          <div className="mt-8">
            <div className="section-header mb-3">
              <h2 className="section-title">Past Cycles</h2>
            </div>
            <div className="rounded-xl border border-[var(--line)] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--line)] bg-[var(--surface-soft)]">
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Period</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Status</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {pastCycles.map((cycle: any) => (
                    <tr key={cycle._id} className="border-b border-[var(--line)] last:border-0">
                      <td className="px-4 py-3 font-medium text-[var(--sea-ink)]">{cycle.period}</td>
                      <td className="px-4 py-3">
                        <StatusPill label={cycle.status} tone={cycle.status === "completed" ? "success" : "neutral"} />
                      </td>
                      <td className="px-4 py-3 text-xs text-[var(--sea-ink-soft)]">
                        {cycle.completedAt ? new Date(cycle.completedAt).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Start Review Modal */}
      {modalOpen && (
        <div className="modal-overlay" onClick={() => setModalOpen(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-[var(--sea-ink)] mb-4">Start Access Review</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--sea-ink-soft)] mb-1">Period</label>
                <input
                  className="input w-full"
                  placeholder="e.g. Q2 2026"
                  value={period}
                  onChange={(e) => setPeriod(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--sea-ink-soft)] mb-1">Due Date</label>
                <input
                  type="date"
                  className="input w-full"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button type="button" className="ghost-button" onClick={() => setModalOpen(false)}>Cancel</button>
              <button type="button" className="signal-button" onClick={handleStartReview} disabled={!period || !dueDate}>Start</button>
            </div>
          </div>
        </div>
      )}

      {/* Justification Modal */}
      {justificationModal && (
        <div className="modal-overlay" onClick={() => setJustificationModal(null)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-[var(--sea-ink)] mb-4">
              {justificationModal.action === "approve" ? "Approve Access" : "Flag for Removal"}
            </h3>
            <div>
              <label className="block text-xs font-medium text-[var(--sea-ink-soft)] mb-1">
                {justificationModal.action === "approve" ? "Justification" : "Reason"}
              </label>
              <textarea
                className="input w-full"
                rows={3}
                placeholder={justificationModal.action === "approve" ? "Why is this access appropriate?" : "Why should this access be removed?"}
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button type="button" className="ghost-button" onClick={() => { setJustificationModal(null); setJustification(""); }}>Cancel</button>
              <button
                type="button"
                className={justificationModal.action === "approve" ? "signal-button" : "danger-button"}
                onClick={handleReviewAction}
                disabled={!justification}
              >
                {justificationModal.action === "approve" ? "Approve" : "Flag"}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
