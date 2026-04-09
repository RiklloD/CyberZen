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
- Current objective: build the runnable Sentinel control plane, carry the SBOM, breach-intel, semantic-fingerprint, and exploit-validation foundations into live integrations, and push the initialized Convex backend toward first real repository scan runs
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
- Python `sbom-ingest` worker with real repository parsing for `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`, compose manifests, and Kubernetes-style image references
- Convex SBOM ingestion mutation scaffold for normalized inventory snapshots
- Bun bridge command in `apps/web` to run the Python SBOM worker and import snapshot payloads into Convex
- Dashboard repository inventory cards now surface latest SBOM snapshot metadata, source manifests, layer breakdowns, vulnerable inventory previews, and preview components
- Dashboard repository inventory cards now compare the latest snapshot against the previous import with added, removed, updated, and vulnerable-component delta summaries
- Breach-disclosure intake now matches the latest repository SBOM snapshot, flags vulnerable components, creates findings, and advances workflow state automatically
- Breach-disclosure normalization now includes GitHub Security Advisory and OSV adapter helpers with repo-aware package selection
- Breach matching is now version aware, distinguishing affected, unaffected, unknown, unmatched, and no-snapshot states instead of relying on name-only matches
- Live advisory ingest now includes Convex action entrypoints plus a Bun bridge command that fetch GitHub Security Advisories or OSV records by ID and route them through the existing disclosure workflow mutations
- GitHub webhook delivery is now wired in code through a Convex HTTP endpoint, signature-verifying internal action, and repository-aware push routing that feeds the existing workflow ingestion mutation path
- Scheduled and bulk advisory sync is now wired in code through repository-target queries, GitHub advisory list batching, OSV query-batch ingestion, a recurring Convex cron, and a Bun bridge command for manual sync runs
- The Breach Intel Aggregator MVP now persists advisory sync runs, captures skipped and failed sync outcomes per repository, and surfaces feed-health summaries plus recent sync activity in the dashboard
- Dashboard breach watchlist now shows per-repository match status, matched versions, and vulnerable inventory previews
- Semantic Fingerprinting MVP now creates path-aware candidate findings from changed-file metadata, carries push context into workflow events, and surfaces semantic candidate state in the dashboard
- Exploit Validation MVP now records local-first validation runs, classifies findings as validated, likely exploitable, or unexploitable, advances workflow validation stages, and surfaces recent validation evidence in the dashboard
- CI/CD Gate Enforcement MVP now evaluates findings against a configurable gate policy, writes per-finding gate decisions (approved/blocked/overridden), advances the policy workflow stage, surfaces enriched gate decision history in the dashboard, and supports manual override mutations with expiry
- PR Generation MVP now proposes fix branches from confirmed findings, generates typed PR proposals (version_bump / patch / manual), calls the GitHub API to create a branch + tracking commit + draft PR when GITHUB_TOKEN is configured, records the proposal state and PR URL back into the finding, and surfaces the prGeneration panel in the dashboard; the `simulate-github-push.mjs` script enables live webhook testing without a real GitHub repository webhook
- Python `agent-core` scaffold with a FastAPI health endpoint

## Verified Status

- `bun run check` in `apps/web`: passing
- `bun run build` in `apps/web`: passing
- `bun run test` in `apps/web`: passing (63 tests, 9 files)
- `bunx tsc --noEmit` in `apps/web`: passing
- `bun run convex:codegen` in `apps/web`: passing
- `bun run advisory:sync -- --tenant atlas-fintech --repository atlas-fintech/payments-api --hours 72`: not run yet because this is a live external-integration path we are deferring until final integration testing
- `bun run sbom:import -- . --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit local-dryrun` in `apps/web`: passing
- `bun run sbom:import -- . --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit lockfile-dryrun` in `apps/web`: passing
- `bun run sbom:import -- <temp-container-fixture> --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit container-dryrun` in `apps/web`: passing
- `python -m compileall services\agent-core\src`: passing
- `python -m unittest discover -s tests` in `services\sbom-ingest`: passing
- `python -m compileall src` in `services\sbom-ingest`: passing
## Current Blockers

- Go is not installed on this machine yet, so Go service folders are architectural placeholders only
- GitHub webhook secret must be set as `GITHUB_WEBHOOK_SECRET` in the Convex deployment env before the first live webhook delivery can be exercised; use `npx convex env set GITHUB_WEBHOOK_SECRET <value>`
- GitHub token must be set as `GITHUB_TOKEN` in the Convex deployment env for the advisory sync live run and for the `proposeFix` action to open real PRs
- The webhook, advisory sync, semantic fingerprint, and exploit validation paths are all implemented locally, but the first fully live end-to-end repository scan still needs to be exercised against a real deployment and repository
- The PR Generation MVP creates a branch + tracking file + draft PR; actual file modification (bumping `requirements.txt` / `package.json`) is a follow-on capability

## Immediate Next Steps

1. Set `GITHUB_WEBHOOK_SECRET` in Convex: `npx convex env set GITHUB_WEBHOOK_SECRET <secret>`
2. Test the webhook end-to-end with the simulation script: `bun scripts/simulate-github-push.mjs --url https://quick-echidna-102.eu-west-1.convex.site/webhooks/github --secret <secret>`
3. Set `GITHUB_TOKEN` in Convex and run the first live advisory sync: `bun run advisory:sync -- --tenant atlas-fintech --repository atlas-fintech/payments-api --hours 72`
4. Deepen PR generation: implement actual file modification (version bump in requirements.txt / package.json) so the PR contains a real diff instead of a tracking file

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
- Recently completed:
  - local Convex initialization and backend code generation
  - GitHub webhook HTTP ingest path in code
  - scheduled and bulk advisory sync path in code
  - Breach Intel Aggregator MVP with sync-run persistence and dashboard feed health
  - Semantic Fingerprinting MVP with path-aware candidate findings and dashboard visibility
  - Exploit Validation MVP with validation-run persistence and workflow advancement
  - CI/CD Gate Enforcement MVP with policy engine, per-finding gate decisions, override support, and dashboard enforcement panel
  - PR Generation MVP with proposal generation, GitHub API integration (branch + draft PR), finding lifecycle advancement, and dashboard prGeneration panel
- Not started:
  - PR generation file-modification capability (actual version bump in requirements.txt / package.json)

## Update Rule

Every run must update these files before ending if anything meaningful changed:

1. `CURRENT_CONTEXT.md` for the latest working state and blockers
2. `TODO.md` for the near-term active queue
3. `PROJECT_TRACKER.md` when a workstream or milestone status changes
4. `IMPLEMENTATION_SPLIT.md` only when scope or build order changes
