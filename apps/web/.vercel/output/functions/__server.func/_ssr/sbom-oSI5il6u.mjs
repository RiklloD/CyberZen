import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-XsWVnAhB.mjs";
import { T as TENANT_SLUG } from "./config-CgDsmXdW.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import { f as formatTimestamp } from "./utils-Dorwyjrb.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { B as Boxes } from "../_libs/lucide-react.mjs";
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
function componentLayerTone(layer, hasVulns = false) {
  if (hasVulns) return "danger";
  if (layer === "direct") return "success";
  if (layer === "build") return "warning";
  if (layer === "ai_model") return "info";
  return "neutral";
}
function SbomPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const [selectedRepo, setSelectedRepo] = reactExports.useState(null);
  if (!overview) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "page-body-padded", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: ["a", "b"].map((k) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "loading-panel h-40 rounded-2xl" }, k)) }) });
  }
  const reposWithSbom = overview.repositories.filter((r) => r.latestSnapshot !== void 0);
  const active = selectedRepo ? reposWithSbom.find((r) => r._id === selectedRepo) : reposWithSbom[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "page-header", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Boxes, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "SBOM Explorer" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "page-subtitle", children: [
          overview.stats.sbomComponents,
          " total components ·",
          " ",
          reposWithSbom.length,
          " repositories with active snapshots"
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body", children: [
      reposWithSbom.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "tab-bar mb-4", children: reposWithSbom.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${active?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) }),
      active?.latestSnapshot ? /* @__PURE__ */ jsxRuntimeExports.jsx(SbomRepoView, { tenantSlug: TENANT, repo: active, snapshot: active.latestSnapshot }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "empty-state border border-dashed border-[var(--line)] rounded-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Boxes, { size: 24, className: "mb-2 opacity-40" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No SBOM snapshots available." })
      ] })
    ] })
  ] });
}
function SbomRepoView({
  tenantSlug,
  repo,
  snapshot
}) {
  const repositoryFullName = repo.fullName;
  const quality = useQuery(api.sbomQualityIntel.getSbomQualityForRepository, {
    tenantSlug,
    repositoryFullName
  });
  const attestation = useQuery(api.sbomAttestationIntel.getLatestAttestation, {
    tenantSlug,
    repositoryFullName
  });
  const cveScan = useQuery(api.cveVersionScanIntel.getLatestCveScan, {
    tenantSlug,
    repositoryFullName
  });
  const containerScan = useQuery(api.containerImageIntel.getLatestContainerImageScan, {
    tenantSlug,
    repositoryFullName
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-1", children: "Latest Snapshot" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-bold text-[var(--sea-ink)]", children: repo.fullName }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-[var(--sea-ink-soft)] mt-0.5", children: formatTimestamp(snapshot.capturedAt) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${snapshot.previewComponents.length} preview components`, tone: "neutral" }),
          snapshot.vulnerablePreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${snapshot.vulnerablePreview.length} vulnerable`, tone: "danger" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Component preview" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-1.5", children: snapshot.previewComponents.slice(0, 10).map((c) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: c.layer, tone: componentLayerTone(c.layer, c.hasKnownVulnerabilities) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-xs text-[var(--sea-ink)]", children: [
            c.name,
            "@",
            c.version
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: c.ecosystem }),
          c.hasKnownVulnerabilities && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "vulnerable", tone: "danger" })
        ] }, `${c.name}-${c.version}`)) })
      ] }),
      snapshot.vulnerablePreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "panel-label mb-2", children: [
          "Vulnerable Components (",
          snapshot.vulnerablePreview.length,
          ")"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-1.5", children: snapshot.vulnerablePreview.map((c) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 inset-panel", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "vulnerable", tone: "danger" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-xs text-[var(--sea-ink)]", children: [
            c.name,
            "@",
            c.version
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: c.ecosystem, tone: "neutral" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: c.layer, tone: "neutral" })
        ] }, `${c.name}-${c.version}`)) })
      ] }),
      snapshot.comparison && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Changes since last snapshot" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
          snapshot.comparison.addedPreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${snapshot.comparison.addedPreview.length} added`, tone: "info" }),
          snapshot.comparison.removedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${snapshot.comparison.removedCount} removed`, tone: "warning" }),
          snapshot.comparison.updatedPreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${snapshot.comparison.updatedPreview.length} updated`, tone: "neutral" })
        ] }),
        snapshot.comparison.addedPreview.slice(0, 5).map((c) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "+ added", tone: "info" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-mono text-xs", children: [
            c.name,
            "@",
            c.version
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: c.ecosystem })
        ] }, `${c.name}-${c.version}`)),
        snapshot.comparison.updatedPreview.slice(0, 5).map((c) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 mt-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "↑ updated", tone: "neutral" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: c.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-[var(--sea-ink-soft)]", children: [
            c.previousVersion,
            " → ",
            c.nextVersion
          ] })
        ] }, c.name))
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
      quality && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "SBOM Quality" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${quality.overallScore}/100`, tone: quality.overallScore >= 80 ? "success" : quality.overallScore >= 60 ? "warning" : "danger" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: quality.grade, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: quality.summary })
      ] }),
      attestation && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "SBOM Attestation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: attestation.status, tone: attestation.status === "valid" ? "success" : attestation.status === "tampered" ? "danger" : "warning" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `v${attestation.attestationVersion}`, tone: "neutral" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: [
          attestation.componentCount,
          " components attested"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-[var(--sea-ink-soft)]", children: formatTimestamp(attestation.attestedAt) })
      ] }),
      cveScan && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "CVE Version Scan" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${cveScan.totalVulnerable} CVE matches`, tone: cveScan.totalVulnerable > 0 ? "danger" : "success" }),
          cveScan.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${cveScan.criticalCount} critical`, tone: "danger" }),
          cveScan.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${cveScan.highCount} high`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: cveScan.summary })
      ] }),
      containerScan && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "panel-label mb-2", children: "Container Image Scan" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${containerScan.totalImages} images`, tone: "neutral" }),
          containerScan.criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${containerScan.criticalCount} critical`, tone: "danger" }),
          containerScan.highCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${containerScan.highCount} high`, tone: "warning" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: containerScan.summary })
      ] })
    ] })
  ] });
}
export {
  SbomPage as component
};
