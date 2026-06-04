# Sentinel Foundation Decisions

This document translates the four source Markdown files into an executable starting architecture.

## What The Four Docs Say

### `sentinel-platform-spec.md`

- The long-term product is multi-layered: orchestration, intelligence, data plane, sandboxing, integrations, and operator surfaces.
- The Phase 1 value path is not "all agents"; it is SBOM, breach intel, semantic fingerprinting, exploit validation, CI/CD gates, and PR generation.
- The most critical durable models are findings, SBOM snapshots, trust signals, workflow state, and auditable decisions.

### `IMPLEMENTATION_SPLIT.md`

- The correct order is technical decisions first, then repo foundation, then runtime/data plane, then MVP features.
- The recommended first product slice is:
  1. decision layer
  2. repo/platform foundation
  3. minimal runtime and data plane
  4. GitHub integration
  5. SBOM registry
  6. breach intel
  7. findings API and simple dashboard

### `PROJECT_TRACKER.md`

- The project was still at Phase 0 with stack choices undefined.
- The immediate risk was starting advanced intelligence features before the workflow and storage backbone existed.

### `TODO.md`

- The first concrete asks were stack choice, repo layout, local infrastructure, repo scaffold, schema creation, event routing, and GitHub-first integration.

## Chosen Stack For The First Real Build

| Layer | Choice | Why |
|---|---|---|
| Dashboard | TanStack Start + React + Tailwind | Matches your preference, SSR-ready, strong DX with Bun |
| Runtime / package manager | Bun | Fast installs, simple scripts, aligned with the frontend ask |
| Control plane DB | Convex | Fastest path to a typed backend, realtime operator UI, built-in auth/data/functions model |
| Analytics | PostHog | Sensible product analytics default with official TanStack add-on support |
| Agent and intelligence services | Python | Best fit for embeddings, AST tooling, ML, scraping, async orchestration |
| High-throughput gateways and sandbox manager | Go later | Still the right long-term choice, but not scaffolded as runnable services yet because Go is not installed locally |

## Convex Versus PostgreSQL / pgvector

The spec assumes PostgreSQL + pgvector as the mature end-state data plane. Your preference for Convex is workable for the first implementation slice if we split the problem cleanly:

- Convex becomes the control plane and operator system of record for:
  - tenants
  - repositories
  - incoming events
  - workflow runs and tasks
  - SBOM snapshots and components
  - findings
  - gate decisions
  - disclosure normalization outputs
- A dedicated vector and heavy-analysis store can be introduced later for:
  - very large semantic fingerprint indexes
  - long-term graph traversal workloads
  - heavyweight retention and compliance export pipelines

This keeps the MVP moving while leaving room to graduate into the spec's larger data plane.

## Initial Service Boundaries

| Boundary | Role | First state |
|---|---|---|
| `apps/web` | Dashboard + app shell + Convex functions | Running now |
| `services/agent-core` | Python orchestration, planner/executor, intelligence adapters | Scaffolded |
| `services/sbom-ingest` | Language-aware SBOM extraction and normalization | Planned |
| `services/breach-intel` | Disclosure ingestion and package matching | Planned |
| `services/event-gateway` | High-throughput webhook router | Planned |
| `services/sandbox-manager` | Sandbox lifecycle and exploit job control | Planned |

## What We Are Explicitly Not Building Yet

- Full Red/Blue self-play
- Full blast-radius graph infrastructure
- Enterprise auth and RBAC
- Multi-cloud deployment automation
- Production-grade sandbox orchestration
- Complete cross-language semantic fingerprinting

Those remain in scope for the product, but out of scope for the first foundation slice.

## Immediate Execution Plan

1. Make the repo runnable with Bun, TanStack Start, Convex, and PostHog.
2. Replace demo data with Sentinel domain models.
3. Implement an auditable event/workflow spine.
4. Seed a realistic baseline workspace to drive UI and API design.
5. Build GitHub-first ingestion and SBOM registry next.
