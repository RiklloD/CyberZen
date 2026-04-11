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
- Current objective: establish a runnable Sentinel control plane with the chosen stack, turn the completed SBOM and breach-intel foundations into live integrations, and keep moving M1 toward a real deployment-backed repository scan path
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
| WS-05 | Integration layer | GitHub, GitLab, CI providers, Slack, webhook ingest/emit | WS-03 | `[in-progress]` |
| WS-06 | SBOM registry MVP | Dependency ingestion, snapshot storage, diffing, export endpoints | WS-04, WS-05 | `[in-progress]` |
| WS-07 | Breach intel MVP | Feed ingestion, normalization, deduplication, impact fanout | WS-03, WS-04 | `[in-progress]` |
| WS-08 | Semantic fingerprinting MVP | Parsing, chunking, embeddings pipeline, vector search, candidate findings | WS-04 | `[in-progress]` |
| WS-09 | Exploit validation MVP | Sandbox job lifecycle, reproducible validation flow, artifact storage | WS-03, WS-04 | `[in-progress]` |
| WS-10 | CI/CD gate MVP | Policy engine, PR checks, deploy gates, override auditing | WS-03, WS-05, WS-06, WS-09 | `[in-progress]` |
| WS-11 | PR generation MVP | Fix proposal pipeline, audit trail, provider integration | WS-03, WS-05, WS-06, WS-09 | `[done]` |
| WS-12 | API and dashboard v1 | Findings, SBOM, trust scores, attack surface, reports | WS-03, WS-04, WS-06, WS-07, WS-08 | `[in-progress]` |
| WS-13 | Prompt and supply-chain intelligence | Prompt Injection Shield, trust scoring, maintainer signal analysis | WS-03, WS-04, WS-05 | `[done]` |
| WS-14 | Graph and autonomy systems | Blast radius graph, Red/Blue loop, memory controller, learning loop | WS-03, WS-04, WS-09 | `[in-progress]` |
| WS-15 | Compliance and hardening | Regulatory drift, privacy controls, deployment modes, auditability, observability | WS-03, WS-04, WS-12 | `[done]` |

## Milestones

| Milestone | Outcome | Target Workstreams | Status |
|---|---|---|---|
| M0 | Repo is ready for implementation | WS-01, WS-02 | `[in-progress]` |
| M1 | Core platform can receive events and persist workflow state | WS-03, WS-04 | `[in-progress]` |
| M2 | Phase 1 scanning pipeline works end-to-end on a single repo | WS-05, WS-06, WS-07, WS-08, WS-09 | `[not-started]` |
| M3 | Sentinel can block or annotate CI and open auditable PRs | WS-10, WS-11 | `[done]` |

| M4 | Dashboard and public API expose customer-facing value | WS-12 | `[done]` |
| M5 | Phase 2 intelligence features begin landing incrementally | WS-13, WS-14, WS-15 | `[in-progress]` |

## Phase Mapping To The Spec

| Spec phase | What we should actually build |
|---|---|
| Phase 1: Foundation | WS-01 through WS-12 |
| Phase 2: Intelligence | WS-13 plus early WS-14 |
| Phase 3: Autonomy | Mature WS-14 plus enterprise deployment pieces in WS-15 |
| Phase 4: Ecosystem | Extensions, SDKs, marketplace, IDE integrations |

## Immediate Risks

- Convex is now initialized locally and deployment-backed code generation works, but the GitHub webhook path still needs a real repository secret and delivery test to be exercised end-to-end.
- The SBOM pipeline now includes local multi-ecosystem parsing across npm, pnpm, Yarn, Bun, Python, Go, Rust, and container-native sources, plus a bridge command that can import worker output into Convex and dashboard drilldowns with drift and vulnerable-inventory summaries, but it still needs a live Convex deployment and GitHub delivery path to be exercised end-to-end.
- Breach intake now supports GitHub Security Advisory and OSV normalization, version-aware SBOM matching, live ID-based advisory imports, the GitHub webhook path in code, scheduled or bulk sync in code, and aggregator-style sync-run visibility in the dashboard, but it still needs the first live sync run plus broader Tier 2 and Tier 3 feed coverage beyond the current authoritative sources.
- Semantic fingerprinting now has a path-aware MVP in the Convex control plane with candidate findings, workflow-stage advancement, and dashboard visibility, but it still lacks the full embedding, tree-sitter, and vector-search stack from the long-term spec.
- Exploit validation now has a local-first MVP that records validation runs, classifies findings, advances validation workflow stages, and exposes recent evidence in the dashboard, but it still lacks the real sandbox lifecycle, artifact capture, and post-fix replay loop from the long-term design.
- The local machine does not currently have Go installed, so the Go services are architectural boundaries rather than verified runtimes today.
- The long-term spec still requires specialized stores for vectors, graphs, and sandbox artifacts; we should keep the MVP control-plane contracts clean so those additions remain incremental.
- WS-11 (PR generation) is fully complete including real manifest file editing for pypi/npm ecosystems with a transparent tracking-file fallback; M3 is now done.
- WS-12 (API and dashboard v1) is complete: operator findings API (list/get/stats), SBOM export (CycloneDX 1.5), trust score Strategy B (direct-weighted mean), repository drilldown, HTTP auth guard via `SENTINEL_API_KEY`. M4 is done.
- WS-13 (Prompt and supply-chain intelligence) is fully complete: 18-pattern prompt injection scanner, supply chain typosquat detection + dependency risk signals, Convex entrypoints (`scanContent`, `scanContentByRef`, `recentScans`, `supplyChainAnalysis`), `promptInjectionScans` schema table, fire-and-forget ingestion wiring into GitHub push (commit messages) and breach sync (advisory summary+description) paths, and `RepositoryIntelligencePanel` dashboard component surfacing supply chain risk + injection scan history per repository card. All checks green (125 tests, tsc, biome, build).
- WS-14 Phase 1 (Blast Radius Causality Graph foundation) is complete: `convex/lib/blastRadius.ts` pure computation library (computeBlastRadius → BlastRadiusResult with spec formula), `convex/lib/blastRadius.test.ts` (19 tests: no-components, direct-dep, transitive chain, multi-service blast, risk tier boundaries, score cap), `blastRadiusSnapshots` schema table (with by_finding + by_repository_and_computed_at indexes), `convex/blastRadiusIntel.ts` (computeAndStoreBlastRadius internalMutation, getBlastRadius + blastRadiusSummaryForRepository public queries), fire-and-forget scheduling via `ctx.scheduler.runAfter` wired into `ingestCanonicalDisclosure`, `FindingBlastRadiusPanel` + `RepositoryBlastRadiusSummary` dashboard components. All checks green (144 tests, tsc, biome, build).
- WS-14 Phase 2 (Memory Controller + Red/Blue Loop MVP) is complete: pure libs (memoryController 17 tests + redBlueSimulator 14 tests), schema tables (agentMemorySnapshots + redBlueRounds), Convex entrypoints (agentMemory.ts + redBlueIntel.ts), fire-and-forget wiring, dashboard panels. All checks green (175 tests).
- WS-14 Phase 3 (Attack Surface Reduction Agent MVP) is complete: pure lib attackSurface.ts (29 tests, score formula max=100), attackSurfaceSnapshots schema table, attackSurfaceIntel.ts Convex entrypoints, fire-and-forget wiring in events.ts, RepositoryAttackSurfacePanel with CSS sparkline. All checks green (204 tests).
- WS-14 Phase 4 (Red Agent Finding Escalation) is complete: pure lib redAgentEscalator.ts (37 tests; parses package/depth exploit chain formats, builds FindingCandidate[]), redAgentEscalation.ts Convex entrypoints (escalateRedAgentFindings internalMutation with dedupeKey idempotency guard, getRedAgentFindingCount query), fire-and-forget on red_wins in redBlueIntel.ts, escalation count pill in AdversarialRoundPanel. All checks green (241 tests, tsc, biome, build).

## Working Rules

- Every new major feature must map back to a workstream and milestone.
- `CURRENT_CONTEXT.md` must be updated at the end of every meaningful run.
- `TODO.md` should only contain the near-term build queue.
- If scope changes, update `IMPLEMENTATION_SPLIT.md` first, then reflect the status change here.
