# CyberZen

**Autonomous cybersecurity intelligence for engineering teams.**

CyberZen continuously monitors your software supply chain, correlates breach disclosures with your actual dependency graph, validates exploitability in sandboxed environments, and enforces security gates in CI/CD — without requiring a dedicated security team to operate it.

The platform is designed around one principle: **never surface an alert that hasn't been proven exploitable.** Every finding goes through exploit-first validation before it reaches an engineer. False positives are discarded silently. Real vulnerabilities ship with proof-of-concept reproduction, blast radius analysis, and auto-generated fix PRs.

Built in controlled layers on the [Sentinel specification](sentinel-platform-spec.md).

---

## What CyberZen Does

| Capability | Description |
|---|---|
| **SBOM Living Registry** | Continuously reconciled software bills of materials across six dependency layers: direct packages, transitive deps, build tools, container images, runtime services, and AI models. Exportable as CycloneDX or SPDX. |
| **Breach Intel Aggregation** | Monitors NVD, GitHub Security Advisories, OSV.dev, CISA KEV, security mailing lists, and dark web sources. Cross-references every disclosure against your live SBOM and opens a fix PR within minutes of a match. |
| **Semantic Vulnerability Fingerprinting** | Embeds your codebase into a vector space and matches it against known vulnerability patterns — catching custom implementations and vendor forks that CVE version matching misses entirely. |
| **Exploit-First Validation** | Every candidate finding is reproduced in a production-grade sandbox before any alert is raised. Confirmed exploits include a machine-readable PoC, HTTP reproduction script, and sandbox video recording. |
| **Red/Blue Adversarial Agents** | A Red Agent continuously probes your staging environment with attack strategies tailored to your architecture. A Blue Agent learns to detect the Red Agent's activity. Both improve over time through a self-play loop. |
| **Prompt Injection Shield** | Static analysis maps every LLM call chain in your codebase. Adversarial payloads are generated per-chain and executed in a sandbox to test for role override, context exfiltration, tool hijacking, RAG poisoning, and agent goal hijacking. |
| **Blast Radius Causality Graph** | Traces the full attack path from any vulnerability to business impact: what services can be reached, what data can be exfiltrated, what regulatory fines apply, and what the estimated breach cost range is. |
| **Supply Chain Social Layer Monitor** | Monitors contributor trust graphs for every dependency — tracking trust escalation velocity, maintainer burnout signals, commit timing anomalies, and binary blob injection patterns (the xz-utils attack class). |
| **Regulatory Drift Detection** | Monitors NIS2, GDPR, SOC 2, HIPAA, PCI-DSS, and EU AI Act obligations. Maps regulatory changes to specific files and functions in your codebase. Generates both legal gap analysis and draft fix PRs. |
| **Attack Surface Reduction** | Identifies dead code, unused dependencies, overly permissive IAM, exposed internal surfaces, and secret sprawl. Tracks an attack surface score over time with optional team gamification. |
| **Honeypot Auto-Injection** | Injects canary API endpoints, fake database records, decoy files, and tracking tokens adjacent to your real assets. Any interaction with a honeypot is treated as a near-certain breach indicator. |
| **CI/CD Gate Enforcement** | Blocks or warns on PRs and deployments based on confirmed exploitable findings — not theoretical ones. Engineers can override with a written justification that is logged, time-limited, and audit-trailed. |
| **Auto-Remediation** | Generates PRs with dependency updates, configuration fixes, and code patches. Each PR contains the full reasoning chain: what was detected, how it was confirmed, the blast radius, and what was tested after the fix. |
| **Learning Loop** | Every finding, false positive, exploit, and fix is fed back into a per-codebase learning profile. Sensitivity adapts over time — recurring vulnerability classes get higher attention, consistently dismissed patterns get downweighted. |

---

## Architecture

CyberZen is a **staged rollout** — a working product at every phase, not a big-bang deployment.

```
Phase 0  Foundation          Convex schema, tenant model, repo inventory UI
Phase 1  SBOM + Breach       Ingestion, semantic fingerprinting, breach matching
Phase 2  Exploit Validation  EPSS enrichment, CI/CD gate enforcement
Phase 3  Drift Detection     30+ security domain monitors, auto-remediation PRs
Phase 4  Agent Services      Python orchestration, embedding-based correlation
Phase 5  Edge Services       Go webhook gateway, sandbox manager
```

**Convex serves as the control plane** — all tenant state, findings, SBOM snapshots, gate decisions, workflow events, and intelligence outputs live in Convex. Python and Go services connect via HTTP actions and scheduled functions when they come online.

The architecture rationale is documented in [docs/foundation-decisions.md](docs/foundation-decisions.md). The implementation phasing is in [IMPLEMENTATION_SPLIT.md](IMPLEMENTATION_SPLIT.md). The full product specification is in [sentinel-platform-spec.md](sentinel-platform-spec.md).

---

## Tech Stack

```
Frontend      TanStack Start (React 19, SSR) + Tailwind CSS 4
Backend       Convex (typed real-time backend-as-a-service)
Runtime       Bun
Language      TypeScript throughout; Python (agent orchestration, embeddings); Go later (webhook gateway, sandbox)
Testing       Vitest + Testing Library
Linting       Biome
Analytics     PostHog
```

---

## Repository Layout

```
apps/
  web/                    Main application — TanStack Start + Convex control plane
  github-action/          GitHub Actions integration — CI gate enforcement
  vscode-extension/       VS Code extension — inline findings, CodeLens overlays, manifest scanning

services/                 Long-term service boundaries (staged, not yet independently runnable)
  agent-core/             Python orchestration and ML adapters
  event-gateway/          High-throughput webhook routing
  sbom-ingest/            SBOM parsing and extraction
  breach-intel/           Disclosure aggregation and normalization
  sandbox-manager/        Exploit execution control
  shared/                 Cross-service contracts and types

docs/                     Architecture decisions and design documents
convex/                   Convex schema and backend functions
```

---

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) 1.3.7+
- A [Convex](https://convex.dev) account (free tier works for development)

### Install

```bash
bun install
```

### Configure environment

Create `apps/web/.env.local` with the minimum required variables:

```bash
CONVEX_DEPLOYMENT=dev:<your-instance-slug>
VITE_CONVEX_URL=https://<your-instance-slug>.convex.cloud
CONVEX_SITE_URL=https://<your-instance-slug>.convex.site
```

Backend integration variables (GitHub token, Slack webhook, Jira, OpenAI, Telegram, etc.) are set via Convex directly:

```bash
bunx convex env set GITHUB_TOKEN ghp_...
bunx convex env set SLACK_WEBHOOK_URL https://hooks.slack.com/...
```

See [docs/env-vars.md](docs/env-vars.md) for the full reference — every variable across 15 integration categories, with defaults, required flags, and setup notes.

### Start the backend

```bash
bun run convex:dev
```

Starts the Convex dev instance and watches for schema and function changes.

### Start the app

```bash
bun run dev
```

Available at [http://localhost:3000](http://localhost:3000).

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

## Integrations

CyberZen connects to the tools your team already uses:

| Category | Integrations |
|---|---|
| Source control | GitHub, GitLab |
| CI/CD | GitHub Actions, GitLab CI, Jenkins, CircleCI |
| Issue tracking | Jira, Linear |
| Notifications | Slack, PagerDuty |
| Observability | Datadog |
| AI providers | OpenAI, Anthropic (for semantic analysis and prompt injection testing) |
| Threat intel | NVD, GitHub Security Advisories, OSV.dev, CISA KEV, security mailing lists |
| IDE | VS Code extension with inline diagnostics and CodeLens |

---

## What Is Currently Running

The first foundation slice is live in `apps/web`:

- Tenant overview and multi-tenant model
- Repository inventory with real-time Convex sync
- Workflow and event spine
- SBOM snapshot summary with component-level drill-down
- Breach intel watchlist with disclosure matching
- Findings pipeline with severity classification and triage
- CI/CD gate enforcement dashboard
- Semantic fingerprinting status and pattern library
- Exploit validation run tracking
- Blast radius causality graph (per-finding and per-repository)
- Prompt injection scan results and supply chain risk analysis
- Red/Blue adversarial round tracking
- Attack surface scoring with trend history
- Regulatory drift monitoring (SOC 2, GDPR, HIPAA, PCI-DSS, NIS2)
- Honeypot plan proposals
- Learning profile with per-codebase confidence adaptation
- SLA enforcement and mean-time-to-remediate tracking
- Automated remediation priority queue (P0–P3)
- Severity escalation with multi-signal triggers
- Auto-remediation dispatch history
- Agentic workflow security scanning
- Vendor trust and OAuth/SaaS risk monitoring
- Risk acceptance tracking with expiry
- GitHub Action for CI gate enforcement (scaffolded)
- VS Code extension with inline findings (scaffolded)

The next implementation steps are documented in the about page of the running app and in [docs/foundation-decisions.md](docs/foundation-decisions.md).

---

## Contributing

This repo uses [Biome](https://biomejs.dev) for formatting and linting. Run `bun run check` before committing. TypeScript strict mode is on throughout — no `any` escapes without a comment explaining why.

When working on Convex backend code, read `convex/_generated/ai/guidelines.md` first — it contains patterns that override standard Convex documentation.
