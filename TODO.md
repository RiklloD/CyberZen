# TODO

Current focus: `Phase 0 - foundation implementation underway`

## Done

- [x] Read and structure the project spec
- [x] Create a durable tracker in `PROJECT_TRACKER.md`
- [x] Split the platform into separate implementation parts in `IMPLEMENTATION_SPLIT.md`
- [x] Choose the core stack and monorepo layout
- [x] Define the initial service boundaries
- [x] Decide the local infrastructure baseline
- [x] Scaffold the repository and shared tooling
- [x] Create the first control-plane schema set from the spec data models
- [x] Implement the event router and workflow-run skeleton beyond sample data
- [x] Start real SBOM manifest and lockfile parsing for the first supported ecosystems
- [x] Add the first Convex SBOM ingestion scaffold for normalized inventory snapshots
- [x] Connect the `sbom-ingest` worker output into the Convex SBOM ingestion mutation
- [x] Surface repository SBOM snapshots and source manifests in the dashboard
- [x] Connect breach-disclosure intake to SBOM package matching and finding creation
- [x] Expand SBOM parsing to additional ecosystems and lockfiles
- [x] Add SBOM snapshot diffing and richer repository drilldown views
- [x] Broaden breach-disclosure normalization with feed adapters and version-aware matching

## Next Up

- [ ] Extend SBOM parsing to remaining ecosystem sources like `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and container-native inventory inputs
- [ ] Deepen repository inventory drilldowns beyond the dashboard card summaries
- [ ] Wire live advisory ingestion paths for GitHub Security Advisories and OSV into the routed event layer

## Later

- [ ] Initialize Convex locally and regenerate backend types from a live deployment
- [ ] Wire GitHub webhook delivery into the routed ingestion layer
- [ ] Add Breach Intel Aggregator MVP
- [ ] Add Semantic Fingerprinting MVP
- [ ] Add Exploit Validation MVP
- [ ] Add CI/CD Gate Enforcement MVP
- [ ] Add PR Generation MVP
- [ ] Add dashboard and public API v1

## Rule

- `CURRENT_CONTEXT.md` is the first file to read at the start of every run.
- Keep this file limited to the near-term build queue only.
- When a task becomes active, move it here from the tracker.
- When the active context changes, update `CURRENT_CONTEXT.md`.
- When a workstream or milestone changes, update `PROJECT_TRACKER.md`.
- When scope or build order changes, update `IMPLEMENTATION_SPLIT.md` first.
