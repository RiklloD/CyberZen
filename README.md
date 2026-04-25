# CyberZen

**Autonomous cybersecurity intelligence for engineering teams.** CyberZen continuously monitors your software supply chain, correlates breach disclosures with your actual dependency graph, validates exploitability, and enforces security gates — without requiring a dedicated security team to operate it.

Built in controlled layers on the [Sentinel specification](docs/foundation-decisions.md).

---

## What It Does

| Capability | Description |
|---|---|
| **SBOM Intelligence** | Ingests and snapshots software bills of materials from manifests and lockfiles |
| **Breach Correlation** | Matches vendor breach disclosures against your dependency graph using semantic fingerprinting |
| **CVE & Exploit Validation** | Enriches CVEs with EPSS scoring, validates exploitability in your environment |
| **Security Drift Detection** | Continuously monitors CI/CD pipelines, containers, cloud config, IAM, cryptography, and 30+ other domains |
| **Gate Enforcement** | Blocks or warns CI/CD runs based on configurable risk thresholds |
| **Auto-Remediation** | Generates PRs with dependency updates and configuration fixes |
| **Integrations** | GitHub, GitLab, Jenkins, CircleCI, Jira, Linear, Slack, PagerDuty, Datadog, and more |

---

## Tech Stack

```
Frontend      TanStack Start (React 19, SSR) + Tailwind CSS 4
Backend       Convex (typed real-time backend-as-a-service)
Runtime       Bun 1.3.7
Language      TypeScript 5.7 throughout
Testing       Vitest 3 + Testing Library
Linting       Biome
Analytics     PostHog
Future        Python (agent orchestration, embeddings) · Go (webhook gateway, sandbox)
```

---

## Repository Layout

```
apps/
  web/                  Main application — TanStack Start + Convex
  github-action/        GitHub Actions integration (scaffolded)
  vscode-extension/     IDE extension (scaffolded)

services/               Future service boundaries (not yet runnable)
  agent-core/           Python orchestration and ML adapters
  event-gateway/        High-throughput webhook routing
  sbom-ingest/          SBOM parsing and extraction
  breach-intel/         Disclosure aggregation
  sandbox-manager/      Exploit execution control
  shared/               Cross-service contracts and types

docs/                   Architecture decisions and design docs
```

---

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) 1.3.7+
- A [Convex](https://convex.dev) account (free tier is fine for development)

### 1. Install dependencies

```bash
bun install
```

### 2. Configure environment

Create `apps/web/.env.local`:

```bash
# Convex — get these from `bunx convex dev` on first run
CONVEX_DEPLOYMENT=dev:<your-instance-slug>
VITE_CONVEX_URL=https://<your-instance-slug>.convex.cloud
CONVEX_SITE_URL=https://<your-instance-slug>.convex.site

# PostHog — optional, omit to disable analytics
VITE_POSTHOG_KEY=phc_...
VITE_POSTHOG_HOST=https://us.i.posthog.com

# App
VITE_APP_TITLE=CyberZen
```

### 3. Start the backend

```bash
bun run convex:dev
```

This starts the Convex dev instance and watches for schema/function changes.

### 4. Start the app

```bash
bun run dev
```

App available at [http://localhost:3000](http://localhost:3000).

---

## Commands

| Command | Description |
|---|---|
| `bun run dev` | Start TanStack Start dev server |
| `bun run build` | Production build |
| `bun run convex:dev` | Start Convex dev backend |
| `bun run convex:codegen` | Regenerate Convex TypeScript types |
| `bun run test` | Run Vitest test suite |
| `bun run check` | Biome lint + format check |
| `bun run format` | Auto-format with Biome |
| `bun run lint` | Lint only |
| `bun run sbom:import` | Import SBOM from local manifests and lockfiles |
| `bun run advisory:sync` | Sync security advisories from upstream sources |

---

## Architecture

CyberZen is structured as a **staged rollout** — a working product at every phase rather than a big-bang deployment.

```
Phase 0  Foundation          Convex schema, tenant model, repo inventory UI  ✓
Phase 1  SBOM + Breach       Ingestion, semantic fingerprinting, breach matching  ✓
Phase 2  Exploit Validation  EPSS enrichment, CI/CD gate enforcement  ✓
Phase 3  Drift Detection     30+ security domain monitors, auto-remediation PRs  ✓
Phase 4  Agent Services      Python orchestration, embedding-based correlation  →
Phase 5  Edge Services       Go webhook gateway, sandbox manager  ·
```

**Convex as the control plane** — all tenant state, findings, SBOM snapshots, gate decisions, and workflow events live in Convex. Python and Go services connect via HTTP actions and scheduled functions when they come online.

See [docs/foundation-decisions.md](docs/foundation-decisions.md) for full architecture rationale.

---

## Contributing

This repo uses [Biome](https://biomejs.dev) for formatting and linting. Run `bun run check` before committing. TypeScript strict mode is on throughout — no `any` escapes without a comment explaining why.

When working on Convex backend code, read `convex/_generated/ai/guidelines.md` first — it contains patterns that override standard Convex documentation.
