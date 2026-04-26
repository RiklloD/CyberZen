import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { p as priorityTierTone, e as severityTone, c as slaComplianceTone, f as formatTimestamp } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { W as Wrench } from "../_libs/lucide-react.mjs";
import "../_libs/tanstack__react-router.mjs";
import "../_libs/tanstack__router-core.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "../_libs/tanstack__history.mjs";
import "node:stream/web";
import "node:stream";
import "../_libs/react-dom.mjs";
import "util";
import "crypto";
import "async_hooks";
import "stream";
import "../_libs/isbot.mjs";
import "../_libs/t3-oss__env-core.mjs";
import "../_libs/convex-dev__react-query.mjs";
import "../_libs/tanstack__query-core.mjs";
import "../_libs/zod.mjs";
const TENANT = TENANT_SLUG;
function RemediationPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selectedRepo, setSelectedRepo] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3", children: ["a", "b"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-40 rounded-2xl" }, k)) }) });
  }
  const {
    repositories
  } = overview;
  const activeRepo = selectedRepo ? repositories.find((r) => r._id === selectedRepo) : repositories[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Wrench, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Remediation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "page-subtitle", children: "Automated priority queue · SLA enforcement · Auto-fix history" })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
      activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoRemediationView, { tenantSlug: TENANT, repositoryId: activeRepo._id, repositoryFullName: activeRepo.fullName })
    ] })
  ] });
}
function RepoRemediationView({
  tenantSlug,
  repositoryId,
  repositoryFullName
}) {
  const queue = useQuery(api.remediationQueueIntel.getRemediationQueueForRepository, {
    repositoryId
  });
  const autoRemediation = useQuery(api.autoRemediationIntel.getAutoRemediationHistoryForRepository, {
    repositoryId
  });
  const escalation = useQuery(api.escalationIntel.getEscalationSummaryForRepository, {
    repositoryId
  });
  const sla = useQuery(api.slaIntel.getSlaStatusForRepository, {
    repositoryId
  });
  const depUpdates = useQuery(api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations, {
    tenantSlug,
    repositoryFullName
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[1.4fr_1fr]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      queue && queue.summary.totalCandidates > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "section-header mb-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Priority Queue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${queue.summary.totalCandidates} items`, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-4", children: [
          queue.summary.p0Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "P0", tone: "danger" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-bold text-[var(--sea-ink)]", children: queue.summary.p0Count }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: "critical" })
          ] }),
          queue.summary.p1Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "P1", tone: "warning" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-bold text-[var(--sea-ink)]", children: queue.summary.p1Count }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: "high" })
          ] }),
          queue.summary.p2Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "P2", tone: "info" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-bold text-[var(--sea-ink)]", children: queue.summary.p2Count }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: "medium" })
          ] }),
          queue.summary.p3Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "P3", tone: "neutral" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-lg font-bold text-[var(--sea-ink)]", children: queue.summary.p3Count }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: "low" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: queue.queue.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: item.priorityTier.toUpperCase(), tone: priorityTierTone(item.priorityTier) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: item.severity, tone: severityTone(item.severity) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${item.priorityScore.toFixed(0)}`, tone: "neutral" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1.5 text-sm font-semibold text-[var(--sea-ink)]", children: item.title }),
          item.priorityRationale.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: item.priorityRationale[0] }),
          item.slaStatus === "breached_sla" && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-[var(--danger)]", children: "SLA breached" })
        ] }, item.findingId)) })
      ] }),
      sla && sla.summary.totalTracked > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "SLA Enforcement" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${Math.round(sla.summary.complianceRate * 100)}% compliant`, tone: slaComplianceTone(sla.summary.complianceRate) }),
            sla.summary.breachedSla > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sla.summary.breachedSla} breached`, tone: "danger" }),
            sla.summary.approachingSla > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sla.summary.approachingSla} approaching`, tone: "warning" }),
            sla.summary.mttrHours !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `MTTR ${Math.round(sla.summary.mttrHours)}h`, tone: "neutral" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            sla.summary.withinSla,
            " within · ",
            sla.summary.approachingSla,
            " approaching ·",
            " ",
            sla.summary.breachedSla,
            " breached of ",
            sla.summary.totalTracked,
            " active"
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      autoRemediation && autoRemediation.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Auto-Remediation History" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: autoRemediation.slice(0, 10).map((run) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${run.dispatchedCount} dispatched`, tone: run.dispatchedCount > 0 ? "success" : "neutral" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${run.candidateCount} candidates`, tone: "info" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: [
            "Skipped: ",
            run.skippedAlreadyHasPr,
            " with PR · ",
            run.skippedBelowTier,
            " below tier · ",
            run.skippedBelowSeverity,
            " below severity"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: formatTimestamp(run.computedAt) })
        ] }, run._id)) })
      ] }),
      escalation && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Escalation Summary" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "card card-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${escalation.totalEscalations} escalated`, tone: escalation.totalEscalations > 0 ? "warning" : "success" }),
          escalation.uniqueFindingsEscalated > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${escalation.uniqueFindingsEscalated} unique findings`, tone: "danger" })
        ] }) })
      ] }),
      depUpdates && depUpdates.recommendations.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Dependency Update Recommendations" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: depUpdates.recommendations.slice(0, 8).map((update) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: update.urgency, tone: update.urgency === "critical" ? "danger" : update.urgency === "high" ? "warning" : "neutral" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: update.effort, tone: "info" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs font-mono font-medium text-[var(--sea-ink)]", children: update.packageName }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: [
            update.currentVersion,
            " → ",
            update.recommendedVersion
          ] })
        ] }, `${update.packageName}-${update.currentVersion}`)) })
      ] })
    ] })
  ] });
}
export {
  RemediationPage as component
};
