import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { e as severityTone, f as formatTimestamp, v as validationTone, m as maturityTone, l as learningTrendTone, d as multiplierTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { c as Bot } from "../_libs/lucide-react.mjs";
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
function AgentsPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selectedRepo, setSelectedRepo] = reactExports.useState(null);
  const [activeTab, setActiveTab] = reactExports.useState("overview");
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: ["a", "b", "c"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-32 rounded-2xl" }, k)) }) });
  }
  const {
    repositories,
    semanticFingerprint,
    exploitValidation
  } = overview;
  const activeRepo = selectedRepo ? repositories.find((r) => r._id === selectedRepo) : repositories[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Bot, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Agents & Learning" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "page-subtitle", children: "Red/Blue adversarial rounds · Semantic fingerprinting · Exploit validation · Learning profiles" })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "tab-bar mb-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeTab === "overview" ? "is-active" : ""}`, onClick: () => setActiveTab("overview"), children: "Global overview" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeTab === "repo" ? "is-active" : ""}`, onClick: () => setActiveTab("repo"), children: "Per-repository" })
      ] }),
      activeTab === "overview" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "section-header mb-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Semantic Fingerprinting" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${semanticFingerprint.openCandidateCount} candidates`, tone: semanticFingerprint.openCandidateCount > 0 ? "warning" : "success" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "card mb-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${semanticFingerprint.openCandidateCount} open candidates`, tone: semanticFingerprint.openCandidateCount > 0 ? "warning" : "success" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${semanticFingerprint.pendingValidationCount} pending validation`, tone: "neutral" })
          ] }) }),
          semanticFingerprint.recentFindings.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: semanticFingerprint.recentFindings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.severity, tone: severityTone(finding.severity) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: finding.vulnClass.replace(/_/g, " "), tone: "info" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${(finding.confidence * 100).toFixed(0)}% confidence`, tone: "neutral" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: [
              finding.repositoryName,
              " · ",
              formatTimestamp(finding.createdAt)
            ] })
          ] }, finding._id)) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "section-header mb-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Exploit Validation" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
            exploitValidation.recentRuns.map((run) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: run.outcome ?? run.status, tone: validationTone(run.outcome ?? void 0) }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: run.status, tone: "neutral" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs font-medium text-[var(--sea-ink)]", children: run.findingTitle }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: [
                run.repositoryName,
                " · ",
                formatTimestamp(run.startedAt)
              ] }),
              run.evidenceSummary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: run.evidenceSummary })
            ] }, run._id)),
            exploitValidation.recentRuns.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No exploit validation runs." }) })
          ] })
        ] })
      ] }),
      activeTab === "repo" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
        activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoAgentIntelligence, { tenantSlug: TENANT, repositoryId: activeRepo._id, repositoryFullName: activeRepo.fullName })
      ] })
    ] })
  ] });
}
function RepoAgentIntelligence({
  tenantSlug,
  repositoryId,
  repositoryFullName
}) {
  const adversarialSummary = useQuery(api.redBlueIntel.adversarialSummaryForRepository, {
    tenantSlug,
    repositoryFullName
  });
  const redAgentFindingCount = useQuery(api.redAgentEscalation.getRedAgentFindingCount, {
    tenantSlug,
    repositoryFullName
  });
  const agentMemory = useQuery(api.agentMemory.getRepositoryMemory, {
    tenantSlug,
    repositoryFullName
  });
  const learningProfile = useQuery(api.learningProfileIntel.getLatestLearningProfile, {
    tenantSlug,
    repositoryFullName
  });
  const agenticScan = useQuery(api.agenticWorkflowIntel.getLatestAgenticScan, {
    repositoryId
  });
  const semanticAnalysis = useQuery(api.semanticFingerprintIntel.getLatestCodeAnalysis, {
    repositoryId
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
    adversarialSummary && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Red/Blue Adversarial Rounds" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${adversarialSummary.totalRounds} rounds`, tone: "neutral" }),
        adversarialSummary.redWins > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `Red ${adversarialSummary.redWins}W`, tone: "danger" }),
        adversarialSummary.blueWins > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `Blue ${adversarialSummary.blueWins}W`, tone: "success" }),
        adversarialSummary.draws > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${adversarialSummary.draws} draws`, tone: "neutral" }),
        redAgentFindingCount != null && redAgentFindingCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${redAgentFindingCount} escalated`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `coverage ${adversarialSummary.avgAttackSurfaceCoverage}%`, tone: adversarialSummary.avgAttackSurfaceCoverage > 60 ? "warning" : "neutral" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `detection ${adversarialSummary.avgBlueDetectionScore}%`, tone: adversarialSummary.avgBlueDetectionScore > 70 ? "success" : "neutral" })
      ] }),
      adversarialSummary.latestRound && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: [
          "Latest: ",
          adversarialSummary.latestRound.redStrategySummary
        ] }),
        adversarialSummary.latestRound.exploitChains.slice(0, 3).map((chain, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "p",
          {
            className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]",
            children: [
              "→ ",
              chain
            ]
          },
          i
        ))
      ] })
    ] }),
    agentMemory && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Agent Memory" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: agentMemory.dominantSeverity, tone: severityTone(agentMemory.dominantSeverity) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `FP ${Math.round(agentMemory.falsePositiveRate * 100)}%`, tone: agentMemory.falsePositiveRate > 0.3 ? "warning" : "neutral" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${agentMemory.totalFindingsAnalyzed} analyzed`, tone: "neutral" })
      ] }),
      agentMemory.recurringVulnClasses.slice(0, 2).map((vc) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: vc.vulnClass.replaceAll("_", " "), tone: "info" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
          vc.count,
          "× · avg severity ",
          (vc.avgSeverityWeight * 100).toFixed(0),
          "%"
        ] })
      ] }, vc.vulnClass)),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: agentMemory.summary })
    ] }),
    learningProfile && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Learning Profile" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `maturity ${learningProfile.adaptedConfidenceScore}/100`, tone: maturityTone(learningProfile.adaptedConfidenceScore) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: learningProfile.attackSurfaceTrend, tone: learningTrendTone(learningProfile.attackSurfaceTrend) }),
        learningProfile.recurringCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${learningProfile.recurringCount} recurring`, tone: "warning" }),
        learningProfile.suppressedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${learningProfile.suppressedCount} suppressed`, tone: "neutral" }),
        learningProfile.successfulExploitPaths.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${learningProfile.successfulExploitPaths.length} exploit paths`, tone: "danger" })
      ] }),
      learningProfile.vulnClassPatterns.slice(0, 3).map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: p.vulnClass.replaceAll("_", " "), tone: multiplierTone(p.confidenceMultiplier) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `×${p.confidenceMultiplier} confidence`, tone: multiplierTone(p.confidenceMultiplier) })
      ] }, p.vulnClass)),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: learningProfile.summary })
    ] }),
    semanticAnalysis && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Semantic Fingerprint (this repo)" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-[var(--sea-ink-soft)] mb-2", children: [
        "Commit: ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: semanticAnalysis.commitSha.slice(0, 7) }),
        " on ",
        semanticAnalysis.branch
      ] }),
      semanticAnalysis.topMatches.slice(0, 5).map((m) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5 mt-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: m.severity, tone: m.severity === "critical" ? "danger" : m.severity === "high" ? "warning" : "neutral" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)] truncate", children: m.vulnClass.replace(/_/g, " ") }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-[var(--sea-ink-soft)] ml-auto", children: [
          (m.similarity * 100).toFixed(0),
          "%"
        ] })
      ] }, m.patternId)),
      semanticAnalysis.topMatches.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--success)]", children: "No semantic matches above threshold" })
    ] }),
    agenticScan && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm col-span-full sm:col-span-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Agentic Workflow Scan" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
        agenticScan.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${agenticScan.criticalCount} critical`, tone: "danger" }),
        agenticScan.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${agenticScan.highCount} high`, tone: "warning" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: agenticScan.summary })
    ] })
  ] });
}
export {
  AgentsPage as component
};
