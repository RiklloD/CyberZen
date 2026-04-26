import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { f as formatTimestamp } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { b as GitMerge } from "../_libs/lucide-react.mjs";
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
function CiCdPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selectedRepo, setSelectedRepo] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3", children: ["a", "b"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-40 rounded-2xl" }, k)) }) });
  }
  const {
    ciGateEnforcement,
    repositories
  } = overview;
  const activeRepo = selectedRepo ? repositories.find((r) => r._id === selectedRepo) : repositories[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(GitMerge, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "CI / CD Gates" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
          "Policy-driven gate enforcement · ",
          ciGateEnforcement.blockedCount,
          " blocked ·",
          " ",
          ciGateEnforcement.approvedCount,
          " approved"
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-body", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[1fr_1.2fr]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card mb-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Gate Summary" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.blockedCount} blocked`, tone: ciGateEnforcement.blockedCount > 0 ? "danger" : "success" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.approvedCount} approved`, tone: "success" }),
            ciGateEnforcement.overrideCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${ciGateEnforcement.overrideCount} overridden`, tone: "warning" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Recent Decisions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
          ciGateEnforcement.recentDecisions.map((d) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.decision, tone: d.decision === "blocked" ? "danger" : d.decision === "approved" ? "success" : "warning" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.stage.replace(/_/g, " "), tone: "neutral" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.actorId.replace(/_/g, " "), tone: "info" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-sm font-semibold text-[var(--sea-ink)]", children: d.findingTitle }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: [
              d.repositoryName,
              " · ",
              formatTimestamp(d.createdAt)
            ] }),
            d.justification && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: d.justification }),
            d.expiresAt && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--warning)]", children: [
              "Expires: ",
              formatTimestamp(d.expiresAt)
            ] })
          ] }, d._id)),
          ciGateEnforcement.recentDecisions.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No gate decisions recorded yet." }) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
        activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoCiCdIntelligence, { tenantSlug: TENANT, repositoryFullName: activeRepo.fullName })
      ] })
    ] }) })
  ] });
}
function RepoCiCdIntelligence({
  tenantSlug,
  repositoryFullName
}) {
  const cicdScan = useQuery(api.cicdScanIntel.getLatestCicdScan, {
    tenantSlug,
    repositoryFullName
  });
  const branchProtection = useQuery(api.branchProtectionIntel.getLatestBranchProtectionBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const buildConfig = useQuery(api.buildConfigIntel.getLatestBuildConfigScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const commitMsg = useQuery(api.commitMessageIntel.getLatestCommitMessageScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const gitIntegrity = useQuery(api.gitIntegrityIntel.getLatestGitIntegrityScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const highRisk = useQuery(api.highRiskChangeIntel.getLatestHighRiskChangeScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const depLock = useQuery(api.depLockIntel.getLatestDepLockVerifyScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const testCoverage = useQuery(api.testCoverageGapIntel.getLatestTestCoverageGapBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const iacScan = useQuery(api.iacScanIntel.getLatestIacScan, {
    tenantSlug,
    repositoryFullName
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2", children: [
    cicdScan && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "CI/CD Pipeline Scan" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: cicdScan.overallRisk, tone: cicdScan.overallRisk === "critical" || cicdScan.overallRisk === "high" ? "danger" : cicdScan.overallRisk === "medium" ? "warning" : "success" }),
        cicdScan.totalFindings > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${cicdScan.totalFindings} issues`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: cicdScan.summary })
    ] }),
    branchProtection && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Branch Protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: branchProtection.riskLevel, tone: branchProtection.riskLevel === "critical" || branchProtection.riskLevel === "high" ? "danger" : branchProtection.riskLevel === "medium" ? "warning" : "success" }),
        branchProtection.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${branchProtection.criticalCount} critical`, tone: "danger" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: branchProtection.summary })
    ] }),
    buildConfig && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Build Config" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: buildConfig.riskLevel, tone: buildConfig.riskLevel === "critical" || buildConfig.riskLevel === "high" ? "danger" : buildConfig.riskLevel === "medium" ? "warning" : "success" }),
        buildConfig.totalFindings > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${buildConfig.totalFindings} issues`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: buildConfig.summary })
    ] }),
    commitMsg && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Commit Messages" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: commitMsg.riskLevel, tone: commitMsg.riskLevel === "none" || commitMsg.riskLevel === "low" ? "success" : commitMsg.riskLevel === "medium" ? "warning" : "danger" }),
        commitMsg.totalFindings > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${commitMsg.totalFindings} findings`, tone: "neutral" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: commitMsg.summary })
    ] }),
    gitIntegrity && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Git Integrity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: gitIntegrity.riskLevel, tone: gitIntegrity.riskLevel === "none" || gitIntegrity.riskLevel === "low" ? "success" : gitIntegrity.riskLevel === "medium" ? "warning" : "danger" }),
        gitIntegrity.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${gitIntegrity.criticalCount} critical`, tone: "danger" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: gitIntegrity.summary })
    ] }),
    highRisk && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "High-Risk Changes" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        highRisk.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${highRisk.criticalCount} critical`, tone: "danger" }),
        highRisk.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${highRisk.highCount} high`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: highRisk.summary })
    ] }),
    depLock && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Dependency Lock" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        depLock.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${depLock.criticalCount} critical discrepancies`, tone: "danger" }),
        depLock.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${depLock.highCount} high`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: depLock.summary })
    ] }),
    testCoverage && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Test Coverage Gaps" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        testCoverage.totalFindings > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${testCoverage.totalFindings} gaps`, tone: "danger" }),
        testCoverage.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${testCoverage.highCount} high`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: testCoverage.summary })
    ] }),
    iacScan && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "IaC Security" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        iacScan.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${iacScan.criticalCount} critical issues`, tone: "danger" }),
        iacScan.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${iacScan.highCount} high`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: iacScan.summary })
    ] })
  ] });
}
export {
  CiCdPage as component
};
