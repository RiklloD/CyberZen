import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { g as driftLevelTone, j as frameworkScoreTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { F as FileCheckCorner } from "../_libs/lucide-react.mjs";
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
function CompliancePage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selectedRepo, setSelectedRepo] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: ["a", "b"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-40 rounded-2xl" }, k)) }) });
  }
  const {
    repositories
  } = overview;
  const activeRepo = selectedRepo ? repositories.find((r) => r._id === selectedRepo) : repositories[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(FileCheckCorner, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Compliance" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "page-subtitle", children: "Regulatory drift · SOC 2 · GDPR · HIPAA · PCI-DSS · NIS2" })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
      activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoComplianceIntelligence, { tenantSlug: TENANT, repositoryFullName: activeRepo.fullName })
    ] })
  ] });
}
function RepoComplianceIntelligence({
  tenantSlug,
  repositoryFullName
}) {
  const regulatoryDrift = useQuery(api.regulatoryDriftIntel.getLatestRegulatoryDrift, {
    tenantSlug,
    repositoryFullName
  });
  const complianceAttestation = useQuery(api.complianceAttestationIntel.getLatestComplianceAttestation, {
    tenantSlug,
    repositoryFullName
  });
  const complianceRemediation = useQuery(api.complianceRemediationIntel.getLatestComplianceRemediationPlan, {
    tenantSlug,
    repositoryFullName
  });
  const licenseCompliance = useQuery(api.licenseComplianceIntel.getLatestLicenseCompliance, {
    tenantSlug,
    repositoryFullName
  });
  const licenseScan = useQuery(api.licenseScanIntel.getLatestLicenseComplianceScan, {
    tenantSlug,
    repositoryFullName
  });
  const securityDebt = useQuery(api.securityDebtIntel.getLatestSecurityDebtBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const databaseSecurity = useQuery(api.databaseSecurityDriftIntel.getLatestDatabaseSecurityDriftBySlug, {
    tenantSlug,
    repositoryFullName
  });
  const sensitiveFiles = useQuery(api.sensitiveFileIntel.getLatestSensitiveFileScanBySlug, {
    tenantSlug,
    repositoryFullName
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    regulatoryDrift && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Regulatory Drift" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: regulatoryDrift.overallDriftLevel.replace("_", " "), tone: driftLevelTone(regulatoryDrift.overallDriftLevel) }),
        regulatoryDrift.openGapCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${regulatoryDrift.openGapCount} open gaps`, tone: "neutral" }),
        regulatoryDrift.criticalGapCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${regulatoryDrift.criticalGapCount} critical`, tone: "danger" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 sm:grid-cols-3 lg:grid-cols-5", children: [{
        key: "soc2",
        label: "SOC 2",
        score: regulatoryDrift.soc2Score
      }, {
        key: "gdpr",
        label: "GDPR",
        score: regulatoryDrift.gdprScore
      }, {
        key: "hipaa",
        label: "HIPAA",
        score: regulatoryDrift.hipaaScore
      }, {
        key: "pci_dss",
        label: "PCI-DSS",
        score: regulatoryDrift.pciDssScore
      }, {
        key: "nis2",
        label: "NIS2",
        score: regulatoryDrift.nis2Score
      }].map(({
        key,
        label,
        score
      }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "inset-panel text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-bold text-[var(--sea-ink-soft)] mb-1", children: label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `text-lg font-bold ${score >= 80 ? "text-[var(--success)]" : score >= 60 ? "text-[var(--warning)]" : "text-[var(--danger)]"}`, children: score }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: score >= 80 ? "good" : score >= 60 ? "at risk" : "failing", tone: frameworkScoreTone(score) })
      ] }, key)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-[var(--sea-ink-soft)]", children: regulatoryDrift.summary })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: [
      complianceAttestation && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Compliance Attestation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: complianceAttestation.overallStatus.replace(/_/g, " "), tone: complianceAttestation.overallStatus === "compliant" ? "success" : complianceAttestation.overallStatus === "at_risk" ? "warning" : "danger" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${complianceAttestation.fullyCompliantCount} fully compliant`, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: complianceAttestation.summary })
      ] }),
      complianceRemediation && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Compliance Remediation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${complianceRemediation.actions.length} actions`, tone: complianceRemediation.actions.length > 0 ? "warning" : "success" }),
          complianceRemediation.criticalActions > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${complianceRemediation.criticalActions} critical`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: complianceRemediation.summary })
      ] }),
      (licenseCompliance || licenseScan) && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "License Compliance" }),
        licenseCompliance && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mb-1", children: [
          licenseCompliance.violations.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${licenseCompliance.violations.length} violations`, tone: "danger" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${licenseCompliance.totalComponents} components checked`, tone: "neutral" })
        ] }),
        licenseScan && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)]", children: licenseScan.summary })
      ] }),
      securityDebt && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Security Debt" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${securityDebt.debtScore}`, tone: securityDebt.debtScore > 70 ? "danger" : securityDebt.debtScore > 40 ? "warning" : "success" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: securityDebt.trend, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: securityDebt.summary })
      ] }),
      databaseSecurity && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Database Security" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          databaseSecurity.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${databaseSecurity.criticalCount} critical`, tone: "danger" }),
          databaseSecurity.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${databaseSecurity.highCount} high`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: databaseSecurity.summary })
      ] }),
      sensitiveFiles && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Sensitive Files" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          sensitiveFiles.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sensitiveFiles.criticalCount} critical`, tone: "danger" }),
          sensitiveFiles.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sensitiveFiles.highCount} high risk`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: sensitiveFiles.summary })
      ] })
    ] })
  ] });
}
export {
  CompliancePage as component
};
