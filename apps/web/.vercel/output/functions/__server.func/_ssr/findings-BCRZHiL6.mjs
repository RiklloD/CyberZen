import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { e as severityTone, f as formatTimestamp, b as blastTierTone, p as priorityTierTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery, f as useMutation } from "../_libs/convex.mjs";
import { T as TriangleAlert, d as Funnel } from "../_libs/lucide-react.mjs";
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
const SEVERITY_LEVELS = ["all", "critical", "high", "medium", "low", "informational"];
function FindingsPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [severityFilter, setSeverityFilter] = reactExports.useState("all");
  const [selected, setSelected] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3", children: ["a", "b", "c", "d"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-24 rounded-2xl" }, k)) }) });
  }
  const findings = overview.findings.filter((f) => severityFilter === "all" || f.severity === severityFilter);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(TriangleAlert, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Findings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
          overview.findings.length,
          " total open findings ·",
          " ",
          overview.stats.criticalFindings,
          " critical/high"
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-4 flex-wrap", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Funnel, { size: 14, className: "text-[var(--sea-ink-soft)]" }),
        SEVERITY_LEVELS.map((level) => {
          const count = level === "all" ? overview.findings.length : overview.findings.filter((f) => f.severity === level).length;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => setSeverityFilter(level), className: `tab-btn ${severityFilter === level ? "is-active" : ""}`, children: [
            level === "all" ? "All" : level.charAt(0).toUpperCase() + level.slice(1),
            count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "ml-1.5 text-[var(--sea-ink-soft)]", children: [
              "(",
              count,
              ")"
            ] })
          ] }, level);
        })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
        findings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => setSelected(selected === finding._id ? null : finding._id), className: `card card-sm w-full text-left ${selected === finding._id ? "border-[rgba(158,255,100,0.35)]" : ""}`, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.severity, tone: severityTone(finding.severity) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.source, tone: "info" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.validationStatus, tone: finding.validationStatus === "validated" ? "success" : finding.validationStatus === "likely_exploitable" ? "warning" : "neutral" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.status.replace(/_/g, " "), tone: finding.status === "open" ? "danger" : "neutral" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-sm font-semibold text-[var(--sea-ink)]", children: finding.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--sea-ink-soft)]", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                "Confidence: ",
                Math.round(finding.confidence * 100),
                "%"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                "Raised: ",
                formatTimestamp(finding.createdAt)
              ] })
            ] })
          ] }),
          selected === finding._id && /* @__PURE__ */ jsxRuntimeExports.jsx(FindingDetailPanel, { findingId: finding._id, finding })
        ] }, finding._id)),
        findings.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(TriangleAlert, { size: 24, className: "mb-2 opacity-40" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No findings match the current filter." })
        ] })
      ] })
    ] })
  ] });
}
function FindingDetailPanel({
  findingId,
  finding
}) {
  const blastRadius = useQuery(api.blastRadiusIntel.getBlastRadius, {
    findingId
  });
  const triageMutation = useMutation(api.findingTriage.markFalsePositive);
  const [isPending, startTransition] = reactExports.useTransition();
  function handleFalsePositive() {
    startTransition(() => {
      void triageMutation({
        findingId,
        note: "Marked false positive via operator dashboard"
      });
    });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 card border-l-2 border-l-[var(--lagoon)] rounded-tl-none rounded-bl-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
      blastRadius && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Blast Radius" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: blastRadius.riskTier, tone: blastTierTone(blastRadius.riskTier) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `impact ${blastRadius.businessImpactScore}`, tone: "neutral" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `depth ${blastRadius.attackPathDepth}`, tone: "neutral" })
        ] }),
        blastRadius.reachableServices.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: blastRadius.reachableServices.slice(0, 5).map((svc) => /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: svc, tone: "neutral" }, svc)) }),
        blastRadius.exposedDataLayers.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: [
          "Layers: ",
          blastRadius.exposedDataLayers.join(", ")
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: blastRadius.summary })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Triage" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-[var(--sea-ink)]", children: "Status:" }),
            " ",
            finding.status.replace(/_/g, " ")
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-[var(--sea-ink)]", children: "Validation:" }),
            " ",
            finding.validationStatus
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-[var(--sea-ink)]", children: "Source:" }),
            " ",
            finding.source
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-[var(--sea-ink)]", children: "Confidence:" }),
            " ",
            Math.round(finding.confidence * 100),
            "%"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: handleFalsePositive, disabled: isPending, className: "signal-button secondary-button", style: {
            padding: "0.5rem 0.9rem",
            fontSize: "0.78rem"
          }, children: "Mark false positive" }) })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(FindingRemediationEntry, { findingId })
  ] });
}
function FindingRemediationEntry({
  findingId
}) {
  const repos = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const firstRepo = repos?.repositories[0];
  const queue = useQuery(api.remediationQueueIntel.getRemediationQueueForRepository, firstRepo ? {
    repositoryId: firstRepo._id
  } : "skip");
  if (!queue) return null;
  const entry = queue.queue.find((i) => i.findingId === findingId);
  if (!entry) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 pt-3 border-t border-[var(--line)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-1.5", children: "Remediation Priority" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: entry.priorityTier.toUpperCase(), tone: priorityTierTone(entry.priorityTier) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `priority score ${entry.priorityScore.toFixed(0)}`, tone: "neutral" })
    ] }),
    Array.isArray(entry.priorityRationale) && entry.priorityRationale.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: entry.priorityRationale[0] })
  ] });
}
export {
  FindingsPage as component
};
