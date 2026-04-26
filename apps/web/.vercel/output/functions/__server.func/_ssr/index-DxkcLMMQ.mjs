import { j as jsxRuntimeExports } from "../_libs/react.mjs";
import { L as Link } from "../_libs/tanstack__react-router.mjs";
import { a as api } from "./router-BK-LlCXj.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { T as TENANT_SLUG } from "./config-DL9xF4p6.mjs";
import { e as severityTone, f as formatTimestamp, w as workflowTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { e as ShieldCheck, T as TriangleAlert, f as Waypoints, B as Boxes, g as Sparkles, b as GitMerge, h as FlaskConical } from "../_libs/lucide-react.mjs";
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
const SKELETONS = ["a", "b", "c", "d", "e"];
function DashboardPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT_SLUG
  });
  if (overview === void 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "page-body-padded", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stats-grid mb-6", children: SKELETONS.map((id) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-24 rounded-2xl" }, id)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[1.3fr_1fr]", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-64 rounded-2xl" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-64 rounded-2xl" })
      ] })
    ] });
  }
  if (overview === null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl py-16", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ShieldCheck, { size: 32, className: "mb-3 opacity-30" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-[var(--sea-ink)] mb-1", children: "No data" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)]", children: "No workspace data found for this tenant." })
    ] }) });
  }
  const {
    tenant,
    stats,
    findings,
    workflows,
    ciGateEnforcement,
    repositories
  } = overview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: tenant.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
        tenant.deploymentMode.replace(/_/g, " "),
        " · ",
        tenant.currentPhase.replace(/_/g, " ")
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stats-grid", children: [{
        label: "Open findings",
        value: stats.openFindings,
        hint: "Unresolved risk",
        icon: TriangleAlert
      }, {
        label: "Critical / High",
        value: stats.criticalFindings,
        hint: "Merge blockers",
        icon: ShieldCheck
      }, {
        label: "Active workflows",
        value: stats.activeWorkflows,
        hint: "Queued or running",
        icon: Waypoints
      }, {
        label: "SBOM components",
        value: stats.sbomComponents,
        hint: "Known inventory",
        icon: Boxes
      }, {
        label: "Validated",
        value: stats.validatedFindings,
        hint: "Exploit-confirmed",
        icon: Sparkles
      }].map(({
        label,
        value,
        hint,
        icon: Icon
      }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "stat-card rise-in", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "stat-label", children: label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { size: 14 }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "stat-value", children: value }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "stat-hint", children: hint })
      ] }, label)) }),
      repositories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Repositories" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/repositories", className: "text-xs font-semibold text-[var(--lagoon-deep)] hover:underline", children: "View all →" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "repo-grid mb-6", children: repositories.slice(0, 6).map((repo) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "repo-header", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "repo-name", children: repo.fullName }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: repo.latestSnapshot ? "has SBOM" : "no SBOM", tone: repo.latestSnapshot ? "success" : "neutral" })
          ] }),
          repo.latestSnapshot && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${repo.latestSnapshot.previewComponents.length} components`, tone: "neutral" }),
            repo.latestSnapshot.vulnerablePreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${repo.latestSnapshot.vulnerablePreview.length} vulnerable`, tone: "danger" })
          ] })
        ] }, repo._id)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[1.3fr_1fr]", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-center justify-between", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Open findings" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
              findings.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${findings.length} visible`, tone: "warning" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/findings", className: "text-xs font-semibold text-[var(--lagoon-deep)] hover:underline", children: "All findings →" })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            findings.slice(0, 8).map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.severity, tone: severityTone(finding.severity) }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.source, tone: "info" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.validationStatus, tone: finding.validationStatus === "validated" ? "success" : "warning" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-sm font-semibold text-[var(--sea-ink)]", children: finding.title }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--sea-ink-soft)]", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: finding.status.replace(/_/g, " ") }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                  "Confidence: ",
                  Math.round(finding.confidence * 100),
                  "%"
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: formatTimestamp(finding.createdAt) })
              ] })
            ] }, finding._id)),
            findings.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(ShieldCheck, { size: 20, className: "mb-2 opacity-30" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No open findings." })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-3 flex items-center justify-between", children: /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Recent workflows" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
              workflows.slice(0, 5).map((workflow) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-[var(--sea-ink)]", children: workflow.workflowType.replace(/_/g, " ") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: workflow.status, tone: workflowTone(workflow.status) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: workflow.summary }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--sea-ink-soft)]", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                    "Priority: ",
                    workflow.priority
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                    workflow.completedTaskCount,
                    "/",
                    workflow.totalTaskCount,
                    " tasks"
                  ] }),
                  workflow.currentStage && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: workflow.currentStage.replace(/_/g, " ") })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: workflow.tasks.slice(0, 6).map((task) => /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${task.order + 1}. ${task.stage}`, tone: workflowTone(task.status) }, task._id)) })
              ] }, workflow._id)),
              workflows.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Waypoints, { size: 20, className: "mb-2 opacity-30" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No recent workflows." })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-3 flex items-center justify-between", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(GitMerge, { size: 15, className: "text-[var(--signal)]" }),
                "CI/CD Gate enforcement"
              ] }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/ci-cd", className: "text-xs font-semibold text-[var(--lagoon-deep)] hover:underline", children: "Full view →" })
            ] }),
            ciGateEnforcement.blockedCount === 0 && ciGateEnforcement.approvedCount === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(GitMerge, { size: 20, className: "mb-2 opacity-30" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No gate decisions yet." })
            ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.blockedCount} blocked`, tone: ciGateEnforcement.blockedCount > 0 ? "danger" : "success" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.approvedCount} approved`, tone: "success" }),
                ciGateEnforcement.overrideCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.overrideCount} overridden`, tone: "warning" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: ciGateEnforcement.recentDecisions.slice(0, 3).map((d) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.decision, tone: d.decision === "blocked" ? "danger" : d.decision === "approved" ? "success" : "warning" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.stage.replace(/_/g, " "), tone: "neutral" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs font-medium text-[var(--sea-ink)]", children: d.findingTitle }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: [
                  d.repositoryName,
                  " · ",
                  formatTimestamp(d.createdAt)
                ] })
              ] }, d._id)) })
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4", children: [{
        to: "/findings",
        label: "Findings",
        description: "Triage and review all security findings",
        icon: TriangleAlert
      }, {
        to: "/sbom",
        label: "SBOM Explorer",
        description: "Browse software bill of materials snapshots",
        icon: Boxes
      }, {
        to: "/breach-intel",
        label: "Breach Intel",
        description: "Advisory aggregator and disclosure watchlist",
        icon: ShieldCheck
      }, {
        to: "/supply-chain",
        label: "Supply Chain",
        description: "Supply chain posture and injection risk",
        icon: Waypoints
      }, {
        to: "/compliance",
        label: "Compliance",
        description: "Regulatory drift across SOC 2, GDPR, HIPAA",
        icon: ShieldCheck
      }, {
        to: "/remediation",
        label: "Remediation",
        description: "P0–P3 priority queue and auto-fix history",
        icon: Sparkles
      }, {
        to: "/agents",
        label: "Agents",
        description: "Red/Blue adversarial rounds and learning profiles",
        icon: FlaskConical
      }, {
        to: "/integrations",
        label: "Integrations",
        description: "Vendor trust, webhooks, and external tools",
        icon: Waypoints
      }].map(({
        to,
        label,
        description,
        icon: Icon
      }) => /* @__PURE__ */ jsxRuntimeExports.jsxs(Link, { to, className: "card card-sm block no-underline group", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "metric-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { size: 14 }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-[var(--sea-ink)]", children: label })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)]", children: description })
      ] }, to)) })
    ] })
  ] });
}
export {
  DashboardPage as component
};
