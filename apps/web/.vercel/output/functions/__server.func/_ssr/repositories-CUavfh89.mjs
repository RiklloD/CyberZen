import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-BK-LlCXj.mjs";
import { T as TENANT_SLUG } from "./config-DL9xF4p6.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { f as formatTimestamp, r as repositoryHealthTone, b as blastTierTone, a as attackSurfaceTone, t as trendTone, c as slaComplianceTone, p as priorityTierTone, m as maturityTone, l as learningTrendTone, d as multiplierTone, h as honeypotScoreTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { G as GitBranch } from "../_libs/lucide-react.mjs";
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
function RepositoriesPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selected, setSelected] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: ["a", "b", "c"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-36 rounded-2xl" }, k)) }) });
  }
  const {
    repositories
  } = overview;
  const selectedRepo = selected ? repositories.find((r) => r._id === selected) ?? null : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(GitBranch, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Repositories" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
          repositories.length,
          " repositories tracked"
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "repo-grid mb-6", children: repositories.map((repo) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => setSelected(selected === repo._id ? null : repo._id), className: `card card-sm text-left w-full ${selected === repo._id ? "border-[rgba(158,255,100,0.4)] bg-[rgba(158,255,100,0.06)]" : ""}`, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "repo-header", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "repo-name", children: repo.fullName }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: repo.latestSnapshot ? "SBOM active" : "no SBOM", tone: repo.latestSnapshot ? "success" : "neutral" })
        ] }),
        repo.latestSnapshot && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${repo.latestSnapshot.previewComponents.length} components`, tone: "neutral" }),
          repo.latestSnapshot.vulnerablePreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${repo.latestSnapshot.vulnerablePreview.length} vulnerable`, tone: "danger" }),
          repo.latestSnapshot.comparison && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${repo.latestSnapshot.comparison.addedPreview.length} added`, tone: "info" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: formatTimestamp(repo.latestSnapshot?.capturedAt) })
      ] }, repo._id)) }),
      selectedRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepositoryDrillDown, { tenantSlug: TENANT, repo: selectedRepo }),
      !selectedRepo && repositories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(GitBranch, { size: 24, className: "mb-2 opacity-40" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Select a repository to view its full intelligence profile" })
      ] })
    ] })
  ] });
}
function RepositoryDrillDown({
  tenantSlug,
  repo
}) {
  const repositoryId = repo._id;
  const repositoryFullName = repo.fullName;
  const trustScore = useQuery(api.trustScoreIntel.getRepositoryTrustScoreSummary, {
    tenantSlug,
    repositoryFullName
  });
  const blastRadius = useQuery(api.blastRadiusIntel.blastRadiusSummaryForRepository, {
    tenantSlug,
    repositoryFullName
  });
  const attackSurface = useQuery(api.attackSurfaceIntel.getAttackSurfaceDashboard, {
    tenantSlug,
    repositoryFullName
  });
  const sla = useQuery(api.slaIntel.getSlaStatusForRepository, {
    repositoryId
  });
  const remediationQueue = useQuery(api.remediationQueueIntel.getRemediationQueueForRepository, {
    repositoryId
  });
  const healthScore = useQuery(api.repositoryHealthIntel.getLatestRepositoryHealthScore, {
    tenantSlug,
    repositoryFullName
  });
  const learningProfile = useQuery(api.learningProfileIntel.getLatestLearningProfile, {
    tenantSlug,
    repositoryFullName
  });
  const honeypot = useQuery(api.honeypotIntel.getLatestHoneypotPlan, {
    tenantSlug,
    repositoryFullName
  });
  const riskAcceptance = useQuery(api.riskAcceptanceIntel.getAcceptanceSummaryForRepository, {
    repositoryId
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(GitBranch, { size: 14, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-bold text-[var(--sea-ink)]", children: repo.fullName })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-2 xl:grid-cols-3", children: [
      trustScore && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Trust Score" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${trustScore.repositoryScore}`, tone: trustScore.repositoryScore >= 70 ? "success" : trustScore.repositoryScore >= 40 ? "warning" : "danger" }),
          trustScore.untrustedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${trustScore.untrustedCount} untrusted`, tone: "danger" }),
          trustScore.vulnerableCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${trustScore.vulnerableCount} vulnerable`, tone: "warning" })
        ] })
      ] }),
      healthScore && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Repository Health" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${healthScore.overallScore}`, tone: repositoryHealthTone(healthScore.overallScore) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `grade ${healthScore.overallGrade}`, tone: repositoryHealthTone(healthScore.overallScore) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: healthScore.summary })
      ] }),
      blastRadius && blastRadius.maxRiskTier !== "low" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Blast Radius" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `max risk: ${blastRadius.maxRiskTier}`, tone: blastTierTone(blastRadius.maxRiskTier) }),
          blastRadius.totalReachableServices.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${blastRadius.totalReachableServices.length} reachable services`, tone: "neutral" })
        ] }),
        blastRadius.topFindings.slice(0, 3).map((f) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: f.riskTier, tone: blastTierTone(f.riskTier) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${f.businessImpactScore}`, tone: "neutral" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)] truncate max-w-[200px]", children: f.title })
        ] }, f.findingId))
      ] }),
      attackSurface && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Attack Surface" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${attackSurface.snapshot.score}`, tone: attackSurfaceTone(attackSurface.snapshot.score) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: attackSurface.snapshot.trend, tone: trendTone(attackSurface.snapshot.trend) }),
          attackSurface.snapshot.openCriticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${attackSurface.snapshot.openCriticalCount} critical`, tone: "danger" })
        ] }),
        attackSurface.history.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex h-6 items-end gap-[2px]", children: attackSurface.history.slice(-12).map((p, i) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "div",
          {
            className: "flex-1 rounded-sm bg-[var(--sea-ink-soft)]/25",
            style: {
              height: `${Math.max(8, p.score)}%`
            },
            title: `Score ${p.score}`
          },
          i
        )) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: attackSurface.snapshot.summary })
      ] }),
      sla && sla.summary.totalTracked > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "SLA Enforcement" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${Math.round(sla.summary.complianceRate * 100)}% compliant`, tone: slaComplianceTone(sla.summary.complianceRate) }),
          sla.summary.breachedSla > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sla.summary.breachedSla} breached`, tone: "danger" }),
          sla.summary.approachingSla > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${sla.summary.approachingSla} approaching`, tone: "warning" }),
          sla.summary.mttrHours !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `MTTR ${Math.round(sla.summary.mttrHours)}h`, tone: "neutral" })
        ] })
      ] }),
      remediationQueue && remediationQueue.summary.totalCandidates > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Remediation Queue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${remediationQueue.summary.totalCandidates} in queue`, tone: "neutral" }),
          remediationQueue.summary.p0Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `P0: ${remediationQueue.summary.p0Count}`, tone: "danger" }),
          remediationQueue.summary.p1Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `P1: ${remediationQueue.summary.p1Count}`, tone: "warning" }),
          remediationQueue.summary.p2Count > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `P2: ${remediationQueue.summary.p2Count}`, tone: "info" })
        ] }),
        remediationQueue.queue.slice(0, 3).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 inset-panel", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: item.priorityTier.toUpperCase(), tone: priorityTierTone(item.priorityTier) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${item.priorityScore.toFixed(0)}`, tone: "neutral" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)] truncate", children: item.title })
        ] }, item.findingId))
      ] }),
      learningProfile && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Learning Profile" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `maturity ${learningProfile.adaptedConfidenceScore}/100`, tone: maturityTone(learningProfile.adaptedConfidenceScore) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `surface ${learningProfile.attackSurfaceTrend}`, tone: learningTrendTone(learningProfile.attackSurfaceTrend) }),
          learningProfile.recurringCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${learningProfile.recurringCount} recurring`, tone: "warning" })
        ] }),
        learningProfile.vulnClassPatterns.slice(0, 2).map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: p.vulnClass.replaceAll("_", " "), tone: multiplierTone(p.confidenceMultiplier) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `×${p.confidenceMultiplier} confidence`, tone: multiplierTone(p.confidenceMultiplier) })
        ] }, p.vulnClass)),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: learningProfile.summary })
      ] }),
      honeypot && honeypot.totalProposals > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Honeypot Plan" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${honeypot.totalProposals} proposals`, tone: "neutral" }),
          honeypot.endpointCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${honeypot.endpointCount} endpoints`, tone: "neutral" }),
          honeypot.tokenCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${honeypot.tokenCount} tokens`, tone: "neutral" })
        ] }),
        honeypot.proposals.slice(0, 2).map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${p.attractivenessScore}`, tone: honeypotScoreTone(p.attractivenessScore) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs text-[var(--sea-ink-soft)] truncate", children: p.path })
        ] }, p.path))
      ] }),
      riskAcceptance && riskAcceptance.totalActive > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label", children: "Risk Acceptances" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${riskAcceptance.totalActive} active`, tone: "neutral" }),
          riskAcceptance.expiringSoon > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${riskAcceptance.expiringSoon} expiring soon`, tone: "warning" }),
          riskAcceptance.permanent > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${riskAcceptance.permanent} permanent`, tone: "neutral" })
        ] })
      ] })
    ] })
  ] });
}
export {
  RepositoriesPage as component
};
