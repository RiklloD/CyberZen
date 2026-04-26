import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-BK-LlCXj.mjs";
import { T as TENANT_SLUG } from "./config-DL9xF4p6.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { s as supplyChainRiskTone, i as injectionRiskTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { a as Link2 } from "../_libs/lucide-react.mjs";
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
function SupplyChainPage() {
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
      /* @__PURE__ */ jsxRuntimeExports.jsx(Link2, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Supply Chain" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "page-subtitle", children: "Supply chain posture, prompt injection risk, and dependency health" })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
      activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoSupplyChainIntelligence, { tenantSlug: TENANT, repositoryFullName: activeRepo.fullName })
    ] })
  ] });
}
function RepoSupplyChainIntelligence({
  tenantSlug,
  repositoryFullName
}) {
  const supplyChainPosture = useQuery(api.supplyChainPostureIntel.getLatestSupplyChainPosture, {
    tenantSlug,
    repositoryFullName
  });
  const promptScans = useQuery(api.promptIntelligence.recentScans, {
    tenantSlug,
    repositoryFullName,
    limit: 10
  });
  const supplyChainAnalysis = useQuery(api.promptIntelligence.supplyChainAnalysis, {
    tenantSlug,
    repositoryFullName
  });
  const confusionAttack = useQuery(api.confusionAttackIntel.getLatestConfusionScan, {
    tenantSlug,
    repositoryFullName
  });
  const maliciousPackage = useQuery(api.maliciousPackageIntel.getLatestMaliciousScan, {
    tenantSlug,
    repositoryFullName
  });
  const abandonment = useQuery(api.abandonmentScanIntel.getLatestAbandonmentScan, {
    tenantSlug,
    repositoryFullName
  });
  const eolDetection = useQuery(api.eolDetectionIntel.getLatestEolScan, {
    tenantSlug,
    repositoryFullName
  });
  const cryptoWeakness = useQuery(api.cryptoWeaknessIntel.getLatestCryptoWeaknessScan, {
    tenantSlug,
    repositoryFullName
  });
  const trafficAnomaly = useQuery(api.trafficAnomalyIntel.getLatestTrafficAnomaly, {
    tenantSlug,
    repositoryFullName
  });
  const secretDetection = useQuery(api.secretDetectionIntel.getLatestSecretScan, {
    tenantSlug,
    repositoryFullName
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    supplyChainPosture && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Supply Chain Posture" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: supplyChainPosture.riskLevel, tone: supplyChainRiskTone(supplyChainPosture.riskLevel) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${supplyChainPosture.score.toFixed(0)}`, tone: "neutral" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `grade ${supplyChainPosture.grade}`, tone: "neutral" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: supplyChainPosture.summary })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
      supplyChainAnalysis && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Supply Chain Risk Analysis" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: supplyChainAnalysis.riskLevel, tone: supplyChainRiskTone(supplyChainAnalysis.riskLevel) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${supplyChainAnalysis.overallRiskScore.toFixed(0)}`, tone: "neutral" }),
          supplyChainAnalysis.typosquatCandidates.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${supplyChainAnalysis.typosquatCandidates.length} typosquat candidates`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: supplyChainAnalysis.summary }),
        supplyChainAnalysis.flaggedComponents.slice(0, 3).map((c) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${c.name}@${c.version}`, tone: supplyChainRiskTone(c.riskLevel) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: c.isDirect ? "direct" : "transitive", tone: "neutral" })
        ] }, `${c.name}-${c.version}`))
      ] }),
      promptScans && promptScans.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Prompt Injection Scans" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${promptScans.length} scans`, tone: "neutral" }),
          promptScans.some((s) => s.riskLevel === "confirmed_injection" || s.riskLevel === "likely_injection") ? /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "injection detected", tone: "danger" }) : promptScans.some((s) => s.riskLevel === "suspicious") ? /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "suspicious", tone: "warning" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "all clear", tone: "success" })
        ] }),
        promptScans.map((scan) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: scan.riskLevel.replace(/_/g, " "), tone: injectionRiskTone(scan.riskLevel) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: scan.contentRef, tone: "neutral" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${scan.score}`, tone: scan.score > 50 ? "danger" : scan.score > 20 ? "warning" : "success" })
        ] }, scan._id))
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: [
      confusionAttack && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Confusion Attack" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: confusionAttack.overallRisk, tone: supplyChainRiskTone(confusionAttack.overallRisk) }),
          confusionAttack.totalSuspicious > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${confusionAttack.totalSuspicious} suspicious`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: confusionAttack.summary })
      ] }),
      maliciousPackage && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Malicious Package Scan" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: maliciousPackage.overallRisk, tone: supplyChainRiskTone(maliciousPackage.overallRisk) }),
          maliciousPackage.totalSuspicious > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${maliciousPackage.totalSuspicious} suspicious`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: maliciousPackage.summary })
      ] }),
      abandonment && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Abandonment Scan" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${abandonment.totalAbandoned} abandoned`, tone: abandonment.totalAbandoned > 0 ? "danger" : "success" }),
          abandonment.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${abandonment.highCount} high risk`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: abandonment.summary })
      ] }),
      eolDetection && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "End-of-Life Detection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${eolDetection.eolCount} EOL`, tone: eolDetection.eolCount > 0 ? "danger" : "success" }),
          eolDetection.nearEolCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${eolDetection.nearEolCount} near EOL`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: eolDetection.summary })
      ] }),
      cryptoWeakness && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Crypto Weakness" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: cryptoWeakness.overallRisk, tone: supplyChainRiskTone(cryptoWeakness.overallRisk) }),
          cryptoWeakness.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${cryptoWeakness.criticalCount} critical`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: cryptoWeakness.summary })
      ] }),
      trafficAnomaly && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Traffic Anomaly" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: trafficAnomaly.level, tone: trafficAnomaly.level === "critical" ? "danger" : trafficAnomaly.level === "suspicious" ? "warning" : trafficAnomaly.level === "anomalous" ? "info" : "success" }),
          trafficAnomaly.patterns.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${trafficAnomaly.patterns.length} patterns`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: trafficAnomaly.summary })
      ] }),
      secretDetection && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Secret Detection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${secretDetection.totalFound} secrets found`, tone: secretDetection.totalFound > 0 ? "danger" : "success" }),
          secretDetection.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${secretDetection.criticalCount} critical`, tone: "danger" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: secretDetection.summary })
      ] })
    ] })
  ] });
}
export {
  SupplyChainPage as component
};
