import { createFileRoute, useSearch } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Clock } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import SecurityTimelinePanel from "../components/panels/SecurityTimelinePanel";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/timeline")({ errorComponent: RouteErrorBoundary, component: TimelinePage });

type OverviewData = NonNullable<
  FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function TimelinePage() {
  const TENANT = useTenantSlug();
  const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const search = useSearch({ strict: false }) as { event?: string };
  const highlightId = search.event ?? null;

  if (!overview) {
    return (
      <main className="page-body-padded">
        <div className="grid gap-3">
          {["a", "b"].map((k) => (
            <div key={k} className="loading-panel h-40 rounded-2xl" />
          ))}
        </div>
      </main>
    );
  }

  const { repositories } = overview;
  const activeRepo = selectedRepo
    ? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
    : repositories[0];

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Clock size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">Security Timeline</h1>
            <p className="page-subtitle">
              Chronological audit log of all security lifecycle events
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
          {/* Left: Repo selector */}
          <div>
            {repositories.length > 1 && (
              <div className="tab-bar mb-4">
                {repositories.map((r: OverviewRepository) => (
                  <button
                    key={r._id}
                    type="button"
                    className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
                    onClick={() => setSelectedRepo(r._id)}
                  >
                    {r.fullName.split("/").pop()}
                  </button>
                ))}
              </div>
            )}
            {activeRepo && (
              <RepoTimeline
                tenantSlug={TENANT}
                repositoryFullName={activeRepo.fullName}
                highlightId={highlightId}
              />
            )}
          </div>

          {/* Right: Event summary */}
          <div>
            {activeRepo && (
              <TimelineSummary
                tenantSlug={TENANT}
                repositoryFullName={activeRepo.fullName}
              />
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

/* -------------------------------------------------------------------------- */
/* Repo Timeline — loads events + counts for a single repository              */
/* -------------------------------------------------------------------------- */

function RepoTimeline({
  tenantSlug,
  repositoryFullName,
  highlightId,
}: {
  tenantSlug: string;
  repositoryFullName: string;
  highlightId: string | null;
}) {
  const events = useQuery(
    api.securityTimelineIntel.getSecurityTimelineForRepository,
    { tenantSlug, repositoryFullName },
  );
  const counts = useQuery(
    api.securityTimelineIntel.getTimelineEventCountsByType,
    { tenantSlug, repositoryFullName },
  );
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to highlighted event on load
  useEffect(() => {
    if (highlightId && events) {
      requestAnimationFrame(() => {
        const el = document.getElementById(`timeline-${highlightId}`);
        el?.scrollIntoView({ behavior: "smooth", block: "center" });
      });
    }
  }, [highlightId, events]);

  return (
    <div ref={scrollRef}>
      <SecurityTimelinePanel
        events={events}
        counts={counts}
        highlightId={highlightId}
      />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Timeline Summary — event-type breakdown card                               */
/* -------------------------------------------------------------------------- */

function TimelineSummary({
  tenantSlug,
  repositoryFullName,
}: {
  tenantSlug: string;
  repositoryFullName: string;
}) {
  const counts = useQuery(
    api.securityTimelineIntel.getTimelineEventCountsByType,
    { tenantSlug, repositoryFullName },
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Clock size={16} className="text-[var(--signal)]" />
        <h3 className="section-title">Event Breakdown</h3>
      </div>

      {!counts ? (
        <div className="grid gap-3">
          {["a", "b", "c"].map((k) => (
            <div key={k} className="loading-panel h-10 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="card">
          <div className="space-y-3">
            <SummaryRow label="Findings Created" count={counts.finding_created} tone="danger" />
            <SummaryRow label="Escalations" count={counts.finding_escalated} tone="warning" />
            <SummaryRow label="Triage Actions" count={counts.finding_triaged} tone="info" />
            <SummaryRow label="Gate Blocked" count={counts.gate_blocked} tone="danger" />
            <SummaryRow label="Gate Approved" count={counts.gate_approved} tone="success" />
            <SummaryRow label="Gate Overridden" count={counts.gate_overridden} tone="warning" />
            <SummaryRow label="Fix PRs Opened" count={counts.pr_opened} tone="info" />
            <SummaryRow label="Fix PRs Merged" count={counts.pr_merged} tone="success" />
            <SummaryRow label="SLA Breaches" count={counts.sla_breached} tone="danger" />
            <SummaryRow label="Risk Accepted" count={counts.risk_accepted} tone="neutral" />
            <SummaryRow label="Risk Revoked" count={counts.risk_revoked} tone="neutral" />
            <SummaryRow label="Red Agent Wins" count={counts.red_agent_win} tone="danger" />
            <SummaryRow
              label="Auto-Remediations"
              count={counts.auto_remediation_dispatched}
              tone="info"
            />
            <SummaryRow label="Secrets Detected" count={counts.secret_detected} tone="danger" />
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--line)] flex items-center gap-2">
            <StatusPill label={`${counts.total} total events`} tone="neutral" />
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryRow({
  label,
  count,
  tone,
}: {
  label: string;
  count: number;
  tone: "success" | "danger" | "warning" | "neutral" | "info";
}) {
  if (count === 0) return null;
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-xs text-[var(--sea-ink-soft)]">{label}</span>
      <StatusPill label={String(count)} tone={tone} />
    </div>
  );
}
