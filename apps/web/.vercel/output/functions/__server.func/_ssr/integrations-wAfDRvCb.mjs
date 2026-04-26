import { r as reactExports, j as jsxRuntimeExports } from "../_libs/react.mjs";
import { a as api } from "./router-BK-LlCXj.mjs";
import { T as TENANT_SLUG } from "./config-DL9xF4p6.mjs";
import { S as StatusPill } from "./StatusPill-CBg4y-u3.mjs";
import "../_libs/posthog__react.mjs";
import "../_libs/posthog-js.mjs";
import { u as useQuery } from "../_libs/convex.mjs";
import { P as Plug } from "../_libs/lucide-react.mjs";
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
function IntegrationsPage() {
  const overview = useQuery(api.dashboard.overview, {
    tenantSlug: TENANT
  });
  const vendors = useQuery(api.vendorTrust.listVendorsBySlug, {
    tenantSlug: TENANT
  });
  const marketplace = useQuery(api.communityMarketplace.listContributions, {
    limit: 12
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
      /* @__PURE__ */ jsxRuntimeExports.jsx(Plug, { size: 20, className: "text-[var(--signal)]" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "page-title", children: "Integrations" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "page-subtitle", children: "Vendor trust · Webhooks · Community marketplace" })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "page-body space-y-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Webhook Configuration" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: [{
          label: "GitHub",
          envVar: "GITHUB_WEBHOOK_SECRET",
          path: "/webhooks/github"
        }, {
          label: "GitLab",
          envVar: "GITLAB_WEBHOOK_SECRET",
          path: "/webhooks/gitlab"
        }, {
          label: "Jenkins",
          envVar: "JENKINS_WEBHOOK_SECRET",
          path: "/webhooks/jenkins"
        }, {
          label: "CircleCI",
          envVar: "CIRCLECI_WEBHOOK_SECRET",
          path: "/webhooks/circleci"
        }, {
          label: "Buildkite",
          envVar: "BUILDKITE_WEBHOOK_TOKEN",
          path: "/webhooks/buildkite"
        }, {
          label: "Azure DevOps",
          envVar: "AZURE_DEVOPS_WEBHOOK_SECRET",
          path: "/webhooks/azure-devops"
        }, {
          label: "Bitbucket",
          envVar: "BITBUCKET_WEBHOOK_SECRET",
          path: "/webhooks/bitbucket"
        }, {
          label: "Slack",
          envVar: "SLACK_WEBHOOK_URL",
          path: "outbound"
        }, {
          label: "PagerDuty",
          envVar: "PAGERDUTY_ROUTING_KEY",
          path: "outbound"
        }, {
          label: "Jira",
          envVar: "JIRA_API_TOKEN",
          path: "outbound"
        }, {
          label: "Linear",
          envVar: "LINEAR_API_KEY",
          path: "outbound"
        }, {
          label: "Datadog",
          envVar: "DATADOG_API_KEY",
          path: "outbound"
        }, {
          label: "OpsGenie",
          envVar: "OPSGENIE_API_KEY",
          path: "outbound"
        }].map(({
          label,
          envVar,
          path
        }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between mb-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-[var(--sea-ink)]", children: label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: path === "outbound" ? "outbound" : "inbound", tone: path === "outbound" ? "info" : "neutral" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-mono text-[var(--sea-ink-soft)]", children: envVar }),
          path !== "outbound" && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-[var(--sea-ink-soft)]", children: [
            "Endpoint: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: path })
          ] })
        ] }, label)) })
      ] }),
      vendors && vendors.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { className: "section-title mb-3", children: [
          "Vendor Trust (",
          vendors.length,
          " vendors)"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: vendors.map((vendor) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-[var(--sea-ink)]", children: vendor.name }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `risk ${vendor.latestRisk?.riskScore ?? "—"}`, tone: vendor.latestRisk?.riskLevel === "critical" || vendor.latestRisk?.riskLevel === "high" ? "danger" : vendor.latestRisk?.riskLevel === "medium" ? "warning" : "success" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: vendor.category, tone: "info" }),
            vendor.latestRisk?.breachDetected && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: "known breach", tone: "danger" }),
            vendor.latestRisk?.riskLevel && vendor.latestRisk.riskLevel !== "trusted" && vendor.latestRisk.riskLevel !== "low" && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: vendor.latestRisk.recommendation, tone: vendor.latestRisk.riskLevel === "critical" || vendor.latestRisk.riskLevel === "high" ? "danger" : "warning" })
          ] }),
          vendor.latestRisk?.breachSummary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: vendor.latestRisk.breachSummary })
        ] }, vendor._id)) })
      ] }),
      repositories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between mb-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title", children: "Repository Gamification" }),
          repositories.length > 1 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex gap-1", children: repositories.map((r) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: `tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`, onClick: () => setSelectedRepo(r._id), children: r.fullName.split("/").pop() }, r._id)) })
        ] }),
        activeRepo && /* @__PURE__ */ jsxRuntimeExports.jsx(RepoGamification, { tenantSlug: TENANT, repositoryFullName: activeRepo.fullName })
      ] }),
      marketplace && marketplace.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { className: "section-title mb-3", children: [
          "Community Marketplace (",
          marketplace.length,
          " integrations)"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: marketplace.map((item, idx) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-[var(--sea-ink)]", children: item.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: item.type, tone: "info" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs text-[var(--sea-ink-soft)]", children: item.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex flex-wrap gap-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: item.status, tone: item.status === "approved" ? "success" : item.status === "under_review" ? "warning" : "neutral" }),
            item.upvoteCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `${item.upvoteCount} upvotes`, tone: "neutral" })
          ] })
        ] }, `${item.title}-${idx}`)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "section-title mb-3", children: "Integration Status" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "card", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "data-table", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Integration" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Category" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Direction" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { children: "Env Variable" })
          ] }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: [{
            label: "GitHub",
            category: "VCS",
            path: "inbound + outbound",
            envVar: "GITHUB_TOKEN"
          }, {
            label: "Slack",
            category: "Notifications",
            path: "outbound",
            envVar: "SLACK_WEBHOOK_URL"
          }, {
            label: "Jira",
            category: "Ticketing",
            path: "outbound",
            envVar: "JIRA_API_TOKEN"
          }, {
            label: "Linear",
            category: "Ticketing",
            path: "outbound",
            envVar: "LINEAR_API_KEY"
          }, {
            label: "Datadog",
            category: "Observability",
            path: "inbound",
            envVar: "DATADOG_API_KEY"
          }, {
            label: "PagerDuty",
            category: "Alerting",
            path: "outbound",
            envVar: "PAGERDUTY_ROUTING_KEY"
          }, {
            label: "OpenAI",
            category: "AI",
            path: "outbound",
            envVar: "OPENAI_API_KEY"
          }].map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "font-medium", children: row.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "text-[var(--sea-ink-soft)]", children: row.category }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "text-[var(--sea-ink-soft)]", children: row.path }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("td", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-xs text-[var(--teal)]", children: row.envVar }) })
          ] }, row.label)) })
        ] }) })
      ] })
    ] })
  ] });
}
function RepoGamification({
  tenantSlug,
  repositoryFullName
}) {
  const gamification = useQuery(api.gamificationIntel.getLatestGamification, {
    tenantSlug
  });
  if (!gamification) return null;
  const repoEntry = gamification.repositoryLeaderboard.find((r) => r.repositoryName === repositoryFullName.split("/").pop()) ?? gamification.repositoryLeaderboard[0];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "card card-sm", children: [
    repoEntry && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 mb-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `score ${repoEntry.currentScore}`, tone: "info" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: `rank #${repoEntry.rank}`, tone: "neutral" }),
      repoEntry.badge && /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: repoEntry.badge, tone: "success" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusPill, { label: repoEntry.trend, tone: repoEntry.trend === "improving" ? "success" : repoEntry.trend === "stable" ? "neutral" : "warning" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-[var(--sea-ink-soft)]", children: gamification.summary })
  ] });
}
export {
  IntegrationsPage as component
};
