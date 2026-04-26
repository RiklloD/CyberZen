import { j as jsxRuntimeExports } from "../_libs/react.mjs";
import { L as Link } from "../_libs/tanstack__react-router.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
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
const chosenStack = [["Dashboard", "TanStack Start + React + Tailwind + Bun"], ["Control plane", "Convex"], ["Analytics", "PostHog"], ["Agent logic", "Python"], ["High-throughput services", "Go later when the toolchain is installed"]];
const buildOrder = ["Decision layer", "Repository and platform foundation", "Minimal runtime and data plane", "GitHub integration first", "SBOM Living Registry", "Breach Intel Aggregator", "Findings API and dashboard slices"];
function ArchitecturePage() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "page-body-padded", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "island-kicker mb-4", children: "Architecture synthesis" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl", children: "The four project Markdown files converge on one message: build the workflow spine first, not the flashy autonomy features." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 max-w-3xl text-base text-[var(--sea-ink-soft)] sm:text-lg", children: "The spec is product-complete, but the implementation docs correctly call for a layered build. That is why the first runnable slice in this repo focuses on typed control-plane state, operator visibility, and a clean path into GitHub, SBOM, and breach-intel workflows." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-8 flex flex-wrap gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "ws-01 done", tone: "success" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "ws-02 in progress", tone: "warning" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "github first", tone: "info" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 grid gap-4 lg:grid-cols-[1fr_1fr]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "panel rounded-[1.75rem] p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "island-kicker mb-2", children: "Chosen stack" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-2xl font-semibold text-[var(--sea-ink)]", children: "What we locked in for the first build." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 space-y-3", children: chosenStack.map(([label, value]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "signal-row", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "tiny-label", children: label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-[var(--sea-ink)]", children: value })
        ] }, label)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "panel rounded-[1.75rem] p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "island-kicker mb-2", children: "Recommended build order" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-2xl font-semibold text-[var(--sea-ink)]", children: "The tracker and split doc already told us how not to get lost." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 grid gap-3", children: buildOrder.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "timeline-step", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "timeline-index", children: index + 1 }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-[var(--sea-ink)]", children: step })
        ] }, step)) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "panel rounded-[1.75rem] p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "island-kicker mb-2", children: "Convex fit" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-2xl font-semibold text-[var(--sea-ink)]", children: "Convex is a good first system of record if we keep the contract clean." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "It is a strong fit for the control plane because it gives us typed functions, realtime UI state, and fast iteration on tenants, workflows, findings, and SBOM data." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "It is not the final answer for every heavyweight analysis problem. Large semantic vector indexes, deep graph traversal, and some compliance export workloads can still graduate into specialized stores later." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "That hybrid path keeps us honest: fast MVP now, room for the spec's mature data plane later." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "panel rounded-[1.75rem] p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "island-kicker mb-2", children: "Service boundaries" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-2xl font-semibold text-[var(--sea-ink)]", children: "Python and Go stay in the design, but only where they truly help." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Python is reserved for the orchestration and intelligence layer: embeddings, scraping, reasoning, and exploit execution." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Go remains the target for the sandbox manager and high-throughput event gateway once those contracts harden and the local toolchain is installed." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "The dashboard and control plane stay in one fast-moving TypeScript surface for now so we can keep shipping." })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 flex flex-wrap gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/", className: "signal-button", children: "Back to dashboard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "https://docs.convex.dev/quickstart/tanstack-start", target: "_blank", rel: "noreferrer", className: "signal-button secondary-button", children: "Convex + TanStack docs" })
    ] })
  ] });
}
export {
  ArchitecturePage as component
};
