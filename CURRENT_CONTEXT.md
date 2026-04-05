# Current Context

Reference docs:

- [sentinel-platform-spec.md](./sentinel-platform-spec.md)
- [IMPLEMENTATION_SPLIT.md](./IMPLEMENTATION_SPLIT.md)
- [PROJECT_TRACKER.md](./PROJECT_TRACKER.md)
- [TODO.md](./TODO.md)

This is the always-on context file for fast session recovery. Read this first at the start of every run, then keep it updated before ending the run.

## Current State

- Current phase: `Phase 0 - foundation implementation underway`
- Current milestone focus: `M0 -> M1`
- Current objective: build the runnable Sentinel control plane and move from breach-disclosure normalization into live advisory ingestion and deeper operator drilldowns
- Canonical frontend/runtime stack: `TanStack Start + React + Tailwind + Bun`
- Canonical control-plane backend: `Convex`
- Planned analytics: `PostHog`
- Planned intelligence layer: `Python`
- Planned high-throughput edge and sandbox services: `Go`

## What Exists Right Now

- Root workspace scaffold with repository docs and service boundaries
- Runnable web app in `apps/web`
- Sentinel-styled dashboard and architecture view
- Convex control-plane schema for:
  - tenants
  - repositories
  - ingestion events
  - workflow runs and tasks
  - SBOM snapshots and components
  - breach disclosures
  - findings
  - gate decisions
- Seed mutation and sample event-ingestion mutation
- Reusable event-router templates for GitHub push and breach-disclosure workflows
- Workflow progress mutations with task-level state rollups back into workflow and event status
- Dashboard workflow progress view with staged task visibility and local simulation controls
- Python `sbom-ingest` worker with real repository parsing for `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `go.sum`, `Cargo.toml`, and `Cargo.lock`
- Convex SBOM ingestion mutation scaffold for normalized inventory snapshots
- Bun bridge command in `apps/web` to run the Python SBOM worker and import snapshot payloads into Convex
- Dashboard repository inventory cards now surface latest SBOM snapshot metadata, source manifests, and preview components
- Dashboard repository inventory cards now compare the latest snapshot against the previous import with added, removed, updated, and vulnerable-component delta summaries
- Breach-disclosure intake now matches the latest repository SBOM snapshot, flags vulnerable components, creates findings, and advances workflow state automatically
- Breach-disclosure normalization now includes GitHub Security Advisory and OSV adapter helpers with repo-aware package selection
- Breach matching is now version aware, distinguishing affected, unaffected, unknown, unmatched, and no-snapshot states instead of relying on name-only matches
- Dashboard breach watchlist now shows per-repository match status, matched versions, and vulnerable inventory previews
- Python `agent-core` scaffold with a FastAPI health endpoint

## Verified Status

- `bun run check` in `apps/web`: passing
- `bun run build` in `apps/web`: passing
- `bun run test` in `apps/web`: passing
- `bunx tsc --noEmit` in `apps/web`: passing
- `bun run sbom:import -- . --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit local-dryrun` in `apps/web`: passing
- `python -m compileall services\agent-core\src`: passing
- `python -m unittest discover -s tests` in `services\sbom-ingest`: passing
- `python -m compileall src` in `services\sbom-ingest`: passing
- `bun run convex:codegen`: blocked until Convex is initialized locally

## Current Blockers

- Convex local project initialization is still required
- `CONVEX_DEPLOYMENT` and `VITE_CONVEX_URL` are not configured yet
- Go is not installed on this machine yet, so Go service folders are architectural placeholders only

## Immediate Next Steps

1. Wire live advisory ingestion paths for GitHub Security Advisories and OSV into the routed event layer
2. Extend SBOM parsing to remaining ecosystem sources like `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and container-native inventory inputs
3. Deepen repository inventory drilldowns beyond the dashboard card summaries
4. Initialize Convex locally and regenerate backend types from a live deployment
5. Wire GitHub webhook delivery into the routed ingestion mutations

## Roadmap Position

- Done:
  - stack decisions
  - repo scaffold
  - initial service boundaries
  - first control-plane schema
  - first dashboard shell
- In progress:
  - repository bootstrap
  - core platform services
  - data plane foundation
  - SBOM ingestion pipeline
  - breach intel MVP
- Not started:
  - GitHub integration
  - SBOM ingestion pipeline
  - breach intel MVP
  - semantic fingerprinting MVP
  - exploit validation MVP

## Update Rule

Every run must update these files before ending if anything meaningful changed:

1. `CURRENT_CONTEXT.md` for the latest working state and blockers
2. `TODO.md` for the near-term active queue
3. `PROJECT_TRACKER.md` when a workstream or milestone status changes
4. `IMPLEMENTATION_SPLIT.md` only when scope or build order changes
