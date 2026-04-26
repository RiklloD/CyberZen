import { j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-BK-LlCXj.mjs";
import { T as TENANT_SLUG } from "./config-DL9xF4p6.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { k as disclosureTone, f as formatTimestamp, n as syncTone } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { S as Shield } from "../_libs/lucide-react.mjs";
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
function BreachIntelPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const epss = useQuery(api.epssIntel.getLatestEpssSnapshot);
  const tier3 = useQuery(api.tier3Intel.getRecentTier3Signals, {
    limit: 10
  });
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: ["a", "b", "c"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-32 rounded-2xl" }, k)) }) });
  }
  const {
    disclosures,
    advisoryAggregator
  } = overview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Breach Intel" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
          advisoryAggregator.recentImportedDisclosures,
          " recent imports ·",
          " ",
          advisoryAggregator.recentMatchedDisclosures,
          " matched disclosures"
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-body", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[1.3fr_1fr]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "section-header", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Disclosure Watchlist" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${disclosures.length} disclosures`, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
          disclosures.map((d) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.matchStatus, tone: disclosureTone(d.matchStatus) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: d.severity, tone: d.severity === "critical" ? "danger" : d.severity === "high" ? "warning" : d.severity === "medium" ? "info" : "neutral" }),
              d.exploitAvailable && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "exploit available", tone: "danger" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-sm font-semibold text-[var(--sea-ink)]", children: d.packageName }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: [
              d.sourceName,
              d.repositoryName ? ` / ${d.repositoryName}` : "",
              " ·",
              " ",
              d.sourceRef,
              " · ",
              formatTimestamp(d.publishedAt)
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: d.matchSummary }),
            d.affectedVersions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: [
              "Affected: ",
              d.affectedVersions.join(" ; ")
            ] }),
            d.fixVersion && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-[var(--success)]", children: [
              "Fixed in: ",
              d.fixVersion
            ] })
          ] }, d._id)),
          disclosures.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { size: 24, className: "mb-2 opacity-40" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No disclosures found for your current SBOM inventory." })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "section-header mb-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Advisory Aggregator" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "card card-sm mb-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${advisoryAggregator.recentImportedDisclosures} imported`, tone: "neutral" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${advisoryAggregator.recentMatchedDisclosures} matched`, tone: advisoryAggregator.recentMatchedDisclosures > 0 ? "warning" : "success" }),
            advisoryAggregator.lastCompletedAt && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `Last sync: ${formatTimestamp(advisoryAggregator.lastCompletedAt)}`, tone: "neutral" })
          ] }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: advisoryAggregator.recentRuns.map((run) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: run.status, tone: syncTone(run.status) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: run.triggerType, tone: "info" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${run.packageCount} packages`, tone: "neutral" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: [
              run.repositoryName,
              " · ",
              formatTimestamp(run.startedAt)
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-2 text-xs text-[var(--sea-ink-soft)]", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                "GitHub: ",
                run.githubImported,
                "/",
                run.githubFetched
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                "OSV: ",
                run.osvImported,
                "/",
                run.osvFetched
              ] })
            ] }),
            run.reason && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-[var(--warning)]", children: run.reason })
          ] }, run._id)) })
        ] }),
        advisoryAggregator.sourceCoverage.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Source Coverage" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "card", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "data-table", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Source" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Tier" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Disclosures" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Matched" })
            ] }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: advisoryAggregator.sourceCoverage.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "font-medium", children: s.sourceName }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: s.sourceTier, tone: "info" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { children: s.disclosureCount }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${s.matchedCount}`, tone: s.matchedCount > 0 ? "warning" : "neutral" }) })
            ] }, s.sourceName)) })
          ] }) })
        ] }),
        epss && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "EPSS Threat Intel" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${epss.enrichedCount} tracked CVEs`, tone: "neutral" }),
              epss.criticalRiskCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${epss.criticalRiskCount} critical EPSS`, tone: "danger" }),
              epss.highRiskCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${epss.highRiskCount} high EPSS`, tone: "warning" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)]", children: epss.summary }),
            epss.topCves?.slice(0, 5).map((cve) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: cve.cveId, tone: cve.epssScore > 0.5 ? "danger" : cve.epssScore > 0.2 ? "warning" : "neutral" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `EPSS ${(cve.epssScore * 100).toFixed(1)}%`, tone: "neutral" }),
              cve.packageName && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: cve.packageName, tone: "info" })
            ] }, cve.cveId))
          ] })
        ] }),
        tier3 && tier3.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { className: "section-title mb-3", children: [
            "Tier-3 Intel (",
            tier3.length,
            " signals)"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: tier3.map((signal) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5 mb-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: signal.threatLevel, tone: signal.threatLevel === "critical" || signal.threatLevel === "high" ? "danger" : signal.threatLevel === "medium" ? "warning" : "neutral" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: signal.source, tone: "info" }),
              signal.hasExploitKeywords && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "exploit", tone: "danger" }),
              signal.hasRansomwareKeywords && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "ransomware", tone: "danger" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)] line-clamp-2", children: signal.text })
          ] }, signal._id)) })
        ] })
      ] })
    ] }) })
  ] });
}
export {
  BreachIntelPage as component
};
