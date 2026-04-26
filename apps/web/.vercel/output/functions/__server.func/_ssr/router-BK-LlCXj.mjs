import { c as createRouter, a as createRootRoute, b as createFileRoute, l as lazyRouteComponent, H as HeadContent, S as Scripts, u as useRouterState, L as Link } from "../_libs/tanstack__react-router.mjs";
import { j as jsxRuntimeExports, r as reactExports } from "../_libs/react.mjs";
import { c as createEnv } from "../_libs/t3-oss__env-core.mjs";
import { C as ConvexQueryClient } from "../_libs/convex-dev__react-query.mjs";
import { P as PostHogProvider$1 } from "../_libs/posthog__react.mjs";
import { s as sa } from "../_libs/posthog-js.mjs";
import { b as componentsGeneric, d as ConvexProvider, e as anyApi } from "../_libs/convex.mjs";
import { S as Shield, L as LayoutDashboard, T as TriangleAlert, a as Link2, G as GitBranch, B as Boxes, b as GitMerge, W as Wrench, F as FileCheckCorner, c as Bot, P as Plug, X, M as Menu } from "../_libs/lucide-react.mjs";
import { s as string } from "../_libs/zod.mjs";
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
import "../_libs/tanstack__query-core.mjs";
const __vite_import_meta_env__ = { "BASE_URL": "/", "DEV": false, "MODE": "production", "PROD": true, "SSR": true, "TSS_DEV_SERVER": "false", "TSS_DEV_SSR_STYLES_BASEPATH": "/", "TSS_DEV_SSR_STYLES_ENABLED": "true", "TSS_INLINE_CSS_ENABLED": "false", "TSS_ROUTER_BASEPATH": "", "TSS_SERVER_FN_BASE": "/_serverFn/", "VITE_CONVEX_URL": "https://animated-viper-811.eu-west-1.convex.cloud", "VITE_POSTHOG_HOST": "https://eu.i.posthog.com", "VITE_POSTHOG_KEY": "phc_wdZbNCtDzZhFaGqcHaiJzt84fWLghhqcEqcjnHmBVk9V" };
const env = createEnv({
  server: {
    SERVER_URL: string().url().optional()
  },
  clientPrefix: "VITE_",
  client: {
    VITE_APP_TITLE: string().min(1).default("CyberZen"),
    VITE_CONVEX_URL: string().url().optional(),
    VITE_POSTHOG_KEY: string().min(1).optional(),
    VITE_POSTHOG_HOST: string().url().default("https://us.i.posthog.com"),
    VITE_TENANT_SLUG: string().min(1).default("atlas-fintech")
  },
  runtimeEnv: __vite_import_meta_env__,
  emptyStringAsUndefined: true
});
function getInitialMode() {
  if (typeof window === "undefined") {
    return "auto";
  }
  const stored = window.localStorage.getItem("theme");
  if (stored === "light" || stored === "dark" || stored === "auto") {
    return stored;
  }
  return "auto";
}
function applyThemeMode(mode) {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const resolved = mode === "auto" ? prefersDark ? "dark" : "light" : mode;
  document.documentElement.classList.remove("light", "dark");
  document.documentElement.classList.add(resolved);
  if (mode === "auto") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", mode);
  }
  document.documentElement.style.colorScheme = resolved;
}
function ThemeToggle() {
  const [mode, setMode] = reactExports.useState("auto");
  reactExports.useEffect(() => {
    const initialMode = getInitialMode();
    setMode(initialMode);
    applyThemeMode(initialMode);
  }, []);
  reactExports.useEffect(() => {
    if (mode !== "auto") {
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyThemeMode("auto");
    media.addEventListener("change", onChange);
    return () => {
      media.removeEventListener("change", onChange);
    };
  }, [mode]);
  function toggleMode() {
    const nextMode = mode === "light" ? "dark" : mode === "dark" ? "auto" : "light";
    setMode(nextMode);
    applyThemeMode(nextMode);
    window.localStorage.setItem("theme", nextMode);
  }
  const label = mode === "auto" ? "Theme mode: auto (system). Click to switch to light mode." : `Theme mode: ${mode}. Click to switch mode.`;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      onClick: toggleMode,
      "aria-label": label,
      title: label,
      className: "rounded-full border border-[var(--chip-line)] bg-[var(--chip-bg)] px-2.5 py-1 text-[0.75rem] font-semibold text-[var(--sea-ink-soft)] transition hover:text-[var(--sea-ink)] hover:-translate-y-0.5",
      children: mode === "auto" ? "Auto" : mode === "dark" ? "Dark" : "Light"
    }
  );
}
const navGroups = [
  {
    label: "Overview",
    items: [{ to: "/", label: "Dashboard", icon: LayoutDashboard }]
  },
  {
    label: "Security",
    items: [
      { to: "/findings", label: "Findings", icon: TriangleAlert },
      { to: "/breach-intel", label: "Breach Intel", icon: Shield },
      { to: "/supply-chain", label: "Supply Chain", icon: Link2 }
    ]
  },
  {
    label: "Inventory",
    items: [
      { to: "/repositories", label: "Repositories", icon: GitBranch },
      { to: "/sbom", label: "SBOM", icon: Boxes }
    ]
  },
  {
    label: "Operations",
    items: [
      { to: "/ci-cd", label: "CI / CD Gates", icon: GitMerge },
      { to: "/remediation", label: "Remediation", icon: Wrench },
      { to: "/compliance", label: "Compliance", icon: FileCheckCorner }
    ]
  },
  {
    label: "Intelligence",
    items: [{ to: "/agents", label: "Agents & Learning", icon: Bot }]
  },
  {
    label: "System",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug }
    ]
  }
];
function Sidebar() {
  const [mobileOpen, setMobileOpen] = reactExports.useState(false);
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  function isActive(to) {
    if (to === "/") return currentPath === "/";
    return currentPath === to || currentPath.startsWith(`${to}/`);
  }
  const nav = /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-inner", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-brand", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sidebar-brand-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Shield, { size: 18 }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-brand-text", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sidebar-brand-name", children: "CyberZen" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sidebar-brand-sub", children: "Sentinel control plane" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "sidebar-nav", children: navGroups.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sidebar-group", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sidebar-group-label", children: group.label }),
      group.items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        Link,
        {
          to: item.to,
          className: `sidebar-item${isActive(item.to) ? " is-active" : ""}`,
          onClick: () => setMobileOpen(false),
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(item.icon, { size: 15 }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: item.label })
          ]
        },
        item.to
      ))
    ] }, group.label)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sidebar-footer", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ThemeToggle, {}) })
  ] });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        className: "sidebar-mobile-toggle",
        onClick: () => setMobileOpen(!mobileOpen),
        "aria-label": "Toggle navigation",
        children: mobileOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(X, { size: 20 }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Menu, { size: 20 })
      }
    ),
    mobileOpen && // biome-ignore lint/a11y/useKeyWithClickEvents: overlay dismiss
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "sidebar-overlay",
        onClick: () => setMobileOpen(false),
        "aria-hidden": "true"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("aside", { className: `sidebar${mobileOpen ? " is-open" : ""}`, children: nav })
  ] });
}
const convexQueryClient = env.VITE_CONVEX_URL ? new ConvexQueryClient(env.VITE_CONVEX_URL) : null;
function AppConvexProvider({
  children
}) {
  if (!convexQueryClient) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(ConvexProvider, { client: convexQueryClient.convexClient, children });
}
if (typeof window !== "undefined" && env.VITE_POSTHOG_KEY) {
  sa.init(env.VITE_POSTHOG_KEY, {
    api_host: env.VITE_POSTHOG_HOST,
    person_profiles: "identified_only",
    capture_pageview: false,
    defaults: "2025-11-30"
  });
}
function PostHogProvider({ children }) {
  if (!env.VITE_POSTHOG_KEY) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(PostHogProvider$1, { client: sa, children });
}
const appCss = "/assets/styles-BhW7w_GS.css";
const THEME_INIT_SCRIPT = `(function(){try{var stored=window.localStorage.getItem('theme');var mode=(stored==='light'||stored==='dark'||stored==='auto')?stored:'auto';var prefersDark=window.matchMedia('(prefers-color-scheme: dark)').matches;var resolved=mode==='auto'?(prefersDark?'dark':'light'):mode;var root=document.documentElement;root.classList.remove('light','dark');root.classList.add(resolved);if(mode==='auto'){root.removeAttribute('data-theme')}else{root.setAttribute('data-theme',mode)}root.style.colorScheme=resolved;}catch(e){}})();`;
const Route$c = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: env.VITE_APP_TITLE },
      {
        name: "description",
        content: "CyberZen is autonomous cybersecurity intelligence for engineering teams — SBOM control plane, breach intel watchlist, exploit validation, and operator dashboard."
      }
    ],
    links: [{ rel: "stylesheet", href: appCss }]
  }),
  shellComponent: RootDocument
});
function RootDocument({ children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("html", { lang: "en", suppressHydrationWarning: true, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("head", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("script", { dangerouslySetInnerHTML: { __html: THEME_INIT_SCRIPT } }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HeadContent, {})
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("body", { className: "font-sans antialiased [overflow-wrap:anywhere] selection:bg-[rgba(158,255,100,0.24)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(AppConvexProvider, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(PostHogProvider, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "app-shell", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Sidebar, {}),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "app-content", children })
        ] }),
        false
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Scripts, {})
    ] })
  ] });
}
const api = anyApi;
componentsGeneric();
const $$splitComponentImporter$b = () => import("./supply-chain-ZsXifZfn.mjs");
const Route$b = createFileRoute("/supply-chain")({
  component: lazyRouteComponent($$splitComponentImporter$b, "component")
});
const $$splitComponentImporter$a = () => import("./sbom-DHjAeg-v.mjs");
const Route$a = createFileRoute("/sbom")({
  component: lazyRouteComponent($$splitComponentImporter$a, "component")
});
const $$splitComponentImporter$9 = () => import("./repositories-CUavfh89.mjs");
const Route$9 = createFileRoute("/repositories")({
  component: lazyRouteComponent($$splitComponentImporter$9, "component")
});
const $$splitComponentImporter$8 = () => import("./remediation-CZ4OqBiQ.mjs");
const Route$8 = createFileRoute("/remediation")({
  component: lazyRouteComponent($$splitComponentImporter$8, "component")
});
const $$splitComponentImporter$7 = () => import("./integrations-wAfDRvCb.mjs");
const Route$7 = createFileRoute("/integrations")({
  component: lazyRouteComponent($$splitComponentImporter$7, "component")
});
const $$splitComponentImporter$6 = () => import("./findings-nPgHwOxT.mjs");
const Route$6 = createFileRoute("/findings")({
  component: lazyRouteComponent($$splitComponentImporter$6, "component")
});
const $$splitComponentImporter$5 = () => import("./compliance-Cp_6EZwt.mjs");
const Route$5 = createFileRoute("/compliance")({
  component: lazyRouteComponent($$splitComponentImporter$5, "component")
});
const $$splitComponentImporter$4 = () => import("./ci-cd-KEd4neCE.mjs");
const Route$4 = createFileRoute("/ci-cd")({
  component: lazyRouteComponent($$splitComponentImporter$4, "component")
});
const $$splitComponentImporter$3 = () => import("./breach-intel-BMIuqomo.mjs");
const Route$3 = createFileRoute("/breach-intel")({
  component: lazyRouteComponent($$splitComponentImporter$3, "component")
});
const $$splitComponentImporter$2 = () => import("./agents-6vdPJXAk.mjs");
const Route$2 = createFileRoute("/agents")({
  component: lazyRouteComponent($$splitComponentImporter$2, "component")
});
const $$splitComponentImporter$1 = () => import("./about-BkeGnZFF.mjs");
const Route$1 = createFileRoute("/about")({
  component: lazyRouteComponent($$splitComponentImporter$1, "component")
});
const $$splitComponentImporter = () => import("./index-DxkcLMMQ.mjs");
const Route = createFileRoute("/")({
  component: lazyRouteComponent($$splitComponentImporter, "component")
});
const SupplyChainRoute = Route$b.update({
  id: "/supply-chain",
  path: "/supply-chain",
  getParentRoute: () => Route$c
});
const SbomRoute = Route$a.update({
  id: "/sbom",
  path: "/sbom",
  getParentRoute: () => Route$c
});
const RepositoriesRoute = Route$9.update({
  id: "/repositories",
  path: "/repositories",
  getParentRoute: () => Route$c
});
const RemediationRoute = Route$8.update({
  id: "/remediation",
  path: "/remediation",
  getParentRoute: () => Route$c
});
const IntegrationsRoute = Route$7.update({
  id: "/integrations",
  path: "/integrations",
  getParentRoute: () => Route$c
});
const FindingsRoute = Route$6.update({
  id: "/findings",
  path: "/findings",
  getParentRoute: () => Route$c
});
const ComplianceRoute = Route$5.update({
  id: "/compliance",
  path: "/compliance",
  getParentRoute: () => Route$c
});
const CiCdRoute = Route$4.update({
  id: "/ci-cd",
  path: "/ci-cd",
  getParentRoute: () => Route$c
});
const BreachIntelRoute = Route$3.update({
  id: "/breach-intel",
  path: "/breach-intel",
  getParentRoute: () => Route$c
});
const AgentsRoute = Route$2.update({
  id: "/agents",
  path: "/agents",
  getParentRoute: () => Route$c
});
const AboutRoute = Route$1.update({
  id: "/about",
  path: "/about",
  getParentRoute: () => Route$c
});
const IndexRoute = Route.update({
  id: "/",
  path: "/",
  getParentRoute: () => Route$c
});
const rootRouteChildren = {
  IndexRoute,
  AboutRoute,
  AgentsRoute,
  BreachIntelRoute,
  CiCdRoute,
  ComplianceRoute,
  FindingsRoute,
  IntegrationsRoute,
  RemediationRoute,
  RepositoriesRoute,
  SbomRoute,
  SupplyChainRoute
};
const routeTree = Route$c._addFileChildren(rootRouteChildren)._addFileTypes();
function getRouter() {
  const router2 = createRouter({
    routeTree,
    scrollRestoration: true,
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0
  });
  return router2;
}
const router = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  getRouter
}, Symbol.toStringTag, { value: "Module" }));
export {
  api as a,
  env as e,
  router as r
};
