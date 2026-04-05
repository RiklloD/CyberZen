# Sentinel Project Tracker

Reference spec: [sentinel-platform-spec.md](./sentinel-platform-spec.md)

This file tracks overall program progress for the Sentinel platform. Keep it stable, high-signal, and current. Use `CURRENT_CONTEXT.md` for the current working state, `TODO.md` for the immediate queue, and this file for phase-level status and major milestones.

## Status Legend

- `[done]` Completed and accepted
- `[in-progress]` Actively being built
- `[blocked]` Waiting on a decision or dependency
- `[not-started]` Not started yet

## Current Program State

- Current phase: `Phase 0 - foundation implementation underway`
- Current objective: establish a runnable Sentinel control plane with the chosen stack and begin the Phase 1 event/workflow spine
- Tracking cadence: update this file whenever a milestone changes state

## Delivery Model

We will not build Sentinel as one large feature drop. We will build it in layers:

1. Platform foundation
2. Core data plane and orchestration
3. Phase 1 MVP capabilities
4. Operator-facing API and dashboard
5. Advanced intelligence and autonomy

## Workstreams

| ID | Workstream | Scope | Depends On | Status |
|---|---|---|---|---|
| WS-00 | Delivery setup | Tracking docs, repo conventions, milestone definitions, implementation split | None | `[done]` |
| WS-01 | Technical decisions | Monorepo shape, service boundaries, primary languages, deployment approach, local dev strategy | WS-00 | `[done]` |
| WS-02 | Repository bootstrap | App skeletons, package management, linting, formatting, CI, environment config | WS-01 | `[in-progress]` |
| WS-03 | Core platform services | API gateway, auth, tenant model, event router, workflow runner, agent task execution | WS-02 | `[in-progress]` |
| WS-04 | Data plane | PostgreSQL, pgvector, Redis, object storage, graph store abstraction, schema migrations | WS-02 | `[in-progress]` |
| WS-05 | Integration layer | GitHub, GitLab, CI providers, Slack, webhook ingest/emit | WS-03 | `[not-started]` |
| WS-06 | SBOM registry MVP | Dependency ingestion, snapshot storage, diffing, export endpoints | WS-04, WS-05 | `[in-progress]` |
| WS-07 | Breach intel MVP | Feed ingestion, normalization, deduplication, impact fanout | WS-03, WS-04 | `[not-started]` |
| WS-08 | Semantic fingerprinting MVP | Parsing, chunking, embeddings pipeline, vector search, candidate findings | WS-04 | `[not-started]` |
| WS-09 | Exploit validation MVP | Sandbox job lifecycle, reproducible validation flow, artifact storage | WS-03, WS-04 | `[not-started]` |
| WS-10 | CI/CD gate MVP | Policy engine, PR checks, deploy gates, override auditing | WS-03, WS-05, WS-06, WS-09 | `[not-started]` |
| WS-11 | PR generation MVP | Fix proposal pipeline, audit trail, provider integration | WS-03, WS-05, WS-06, WS-09 | `[not-started]` |
| WS-12 | API and dashboard v1 | Findings, SBOM, trust scores, attack surface, reports | WS-03, WS-04, WS-06, WS-07, WS-08 | `[not-started]` |
| WS-13 | Prompt and supply-chain intelligence | Prompt Injection Shield, trust scoring, maintainer signal analysis | WS-03, WS-04, WS-05 | `[not-started]` |
| WS-14 | Graph and autonomy systems | Blast radius graph, Red/Blue loop, memory controller, learning loop | WS-03, WS-04, WS-09 | `[not-started]` |
| WS-15 | Compliance and hardening | Regulatory drift, privacy controls, deployment modes, auditability, observability | WS-03, WS-04, WS-12 | `[not-started]` |

## Milestones

| Milestone | Outcome | Target Workstreams | Status |
|---|---|---|---|
| M0 | Repo is ready for implementation | WS-01, WS-02 | `[in-progress]` |
| M1 | Core platform can receive events and persist workflow state | WS-03, WS-04 | `[in-progress]` |
| M2 | Phase 1 scanning pipeline works end-to-end on a single repo | WS-05, WS-06, WS-07, WS-08, WS-09 | `[not-started]` |
| M3 | Sentinel can block or annotate CI and open auditable PRs | WS-10, WS-11 | `[not-started]` |
| M4 | Dashboard and public API expose customer-facing value | WS-12 | `[not-started]` |
| M5 | Phase 2 intelligence features begin landing incrementally | WS-13, WS-14, WS-15 | `[not-started]` |

## Phase Mapping To The Spec

| Spec phase | What we should actually build |
|---|---|
| Phase 1: Foundation | WS-01 through WS-12 |
| Phase 2: Intelligence | WS-13 plus early WS-14 |
| Phase 3: Autonomy | Mature WS-14 plus enterprise deployment pieces in WS-15 |
| Phase 4: Ecosystem | Extensions, SDKs, marketplace, IDE integrations |

## Immediate Risks

- The chosen stack is now defined, but Convex still needs to be initialized locally before backend type generation can happen normally.
- The routed event/workflow backbone now exists in code, but it still needs a live Convex deployment and GitHub webhook path to be exercised end-to-end.
- The SBOM pipeline now includes local Node/Python manifest parsing, a bridge command that can import worker output into Convex, and dashboard snapshot surfacing, but it still needs breach-matching logic and broader ecosystem coverage.
- The local machine does not currently have Go installed, so the Go services are architectural boundaries rather than verified runtimes today.
- The long-term spec still requires specialized stores for vectors, graphs, and sandbox artifacts; we should keep the MVP control-plane contracts clean so those additions remain incremental.

## Working Rules

- Every new major feature must map back to a workstream and milestone.
- `CURRENT_CONTEXT.md` must be updated at the end of every meaningful run.
- `TODO.md` should only contain the near-term build queue.
- If scope changes, update `IMPLEMENTATION_SPLIT.md` first, then reflect the status change here.
