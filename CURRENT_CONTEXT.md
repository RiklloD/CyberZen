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
- PR Generation file-modification capability now implemented: `proposeFix` fetches the repository's actual manifest file via the GitHub Contents API, applies a version-bump patch (requirements.txt → `==fixVersion` pin; pyproject.toml/Pipfile → `>=fixVersion` floor; package.json → preserves `^`/`~` prefix + bumps version), commits the real diff to the PR branch, and falls back transparently to the `.sentinel/fix-proposal.md` tracking placeholder when no manifest is found or the patch does not apply
- Python `agent-core` scaffold with a FastAPI health endpoint
- WS-12 API and dashboard v1 now has: `findings.list` / `findings.get` / `findings.stats` operator queries (filterable by status / severity / repositoryId, enriched with disclosure and PR context); `sbom.exportSnapshot` returning a full CycloneDX 1.5 BOM; `repositories.drilldown` returning SBOM summary, trust score aggregate, open findings, gate decisions, PR proposals, validation runs, and advisory sync health per repository; HTTP endpoints at `GET /api/sbom/export?snapshotId=<id>` (CycloneDX JSON download) and `GET /api/findings?tenantSlug=<slug>` (findings list); `convex/lib/cyclonedx.ts` pure BOM builder with PURL generation per ecosystem; `convex/lib/trustScore.ts` repositoryScore implemented as Strategy B (direct-weighted mean: 2×direct + 1×transitive / 3, with no-dep-aware fallbacks); HTTP endpoints now guarded by `requireApiKey` — reads `SENTINEL_API_KEY` from Convex env, fail-open in local dev, supports `X-Sentinel-Api-Key` and `Authorization: Bearer` headers
- WS-13 Prompt and supply-chain intelligence MVP now has: `convex/lib/promptInjection.ts` — 18-pattern heuristic scanner across role-escalation, system-prompt-leak, jailbreak, privilege-escalation, data-exfiltration, and encoding-obfuscation categories with cumulative 0–100 scoring and 4-tier risk levels; `convex/lib/supplyChainIntel.ts` — typosquat detection (bounded Levenshtein ≤2 edits against 100+ well-known package corpus across npm/pypi/cargo/go), suspicious-name detection, vulnerable-direct-dep flagging, untrusted-direct-dep flagging, high-blast-radius flagging, per-component and repository-level risk scores; `schema.ts` extended with `promptInjectionScans` table (indexed by tenant and repository); `convex/promptIntelligence.ts` — `scanContent` internal mutation (run scan + persist), `scanContentByRef` internal mutation (slug/provider-based adapter for action callers), `recentScans` public query (dashboard injection panel), `supplyChainAnalysis` public query (on-demand from latest SBOM snapshot)
- WS-13 Ingestion wiring complete: `convex/lib/githubWebhooks.ts` — extended `GithubPushPayload` with `head_commit.message` and per-commit `message` fields; new `collectCommitMessages` helper; `convex/githubWebhooks.ts` — `verifyAndRouteGithubWebhook` action now fire-and-forgets a `scanContentByRef` call on commit messages for every new (non-deduped) push event; `convex/breachIngest.ts` — `ingestGithubAdvisoriesForRepository` and `ingestOsvAdvisoriesForRepository` now fire-and-forget `scanContentByRef` calls on advisory summary+description text for every new advisory ingested; scan failures are logged and swallowed so they can never abort a sync batch
- WS-13 Dashboard panel complete: `dashboard.ts` — `repositories` array now includes `fullName`; `src/routes/index.tsx` — new `RepositoryIntelligencePanel` sub-component issues per-repository `recentScans` + `supplyChainAnalysis` queries and renders supply chain risk (overall score, flagged components, typosquat candidates) and injection scan history (risk level, score, category) inline in each repository card; tone helpers `injectionRiskTone` and `supplyChainRiskTone` map risk levels to StatusPill tones
- WS-14 Phase 1 (Blast Radius Causality Graph foundation) complete: `convex/lib/blastRadius.ts` — pure computation library, `computeBlastRadius(input)` → `BlastRadiusResult` with reachableServices, exposedDataLayers, directExposureCount, transitiveExposureCount, attackPathDepth, businessImpactScore (spec formula: severity_weight×40 + directCap30 + exploit20 + transitive5bonus), summary, riskTier; `convex/lib/blastRadius.test.ts` — 19 tests covering no-components, direct-dep, transitive chain (depth 2/3), container (depth 3), multi-service blast, dedup, case-insensitive matching, risk tier boundaries, score cap; `schema.ts` — `blastRadiusSnapshots` table (findingId, repositoryId, tenantId, reachableServices, exposedDataLayers, directExposureCount, transitiveExposureCount, attackPathDepth, businessImpactScore, riskTier, summary, computedAt) with by_finding and by_repository_and_computed_at indexes; `convex/blastRadiusIntel.ts` — `computeAndStoreBlastRadius` internalMutation (loads finding+SBOM+disclosure, runs pure fn, patches finding, inserts snapshot), `getBlastRadius` public query, `blastRadiusSummaryForRepository` public query (maxRiskTier, totalReachableServices union, top 3 by score); `convex/events.ts` — `internal` import added, fire-and-forget `ctx.scheduler.runAfter(0, internal.blastRadiusIntel.computeAndStoreBlastRadius, { findingId })` wired into `ingestCanonicalDisclosure` after finding creation; `src/routes/index.tsx` — `FindingBlastRadiusPanel` per-finding sub-component (riskTier pill, reachableServices list, attackPathDepth, businessImpactScore), `RepositoryBlastRadiusSummary` per-repository aggregate (maxRiskTier, service count, top-3 findings) at top of each repository card

## Verified Status

- `bun run check` in `apps/web`: passing
- `bun run build` in `apps/web`: passing (55 modules, 497ms)
- `bun run test` in `apps/web`: passing (410 tests, 21 files; +30 webhookDispatcher)
- `bunx tsc --noEmit` in `apps/web`: passing (webhooks added to _generated/api.d.ts manually; next convex dev run will regenerate automatically)
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (55 modules, 736ms)
- `bunx tsc --noEmit` in `apps/web`: passing
- `bun run convex:codegen` in `apps/web`: passing
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (2075 modules)
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
- WS-11 PR generation is now complete including real manifest file editing; no known blockers remain for that workstream
- WS-13 is now fully complete: backend intelligence (scanner, supply chain analysis, Convex entrypoints), ingestion wiring (breach intake + webhook push), and dashboard panel (per-repository supply chain + injection scan panels) are all implemented and verified
- WS-14 Phase 1 (Blast Radius Causality Graph foundation) is complete: pure computation library + 19 unit tests, `blastRadiusSnapshots` schema table, `blastRadiusIntel.ts` Convex entrypoints, fire-and-forget wiring into `ingestCanonicalDisclosure`, `FindingBlastRadiusPanel` + `RepositoryBlastRadiusSummary` dashboard components. All checks green (144 tests, tsc, biome, build).
- WS-14 Phase 2 (Memory Controller + Red/Blue Loop MVP) is complete: `convex/lib/memoryController.ts` (pure aggregateFindingMemory, 17 tests), `convex/lib/redBlueSimulator.ts` (pure simulateAdversarialRound, 14 tests), `agentMemorySnapshots` + `redBlueRounds` schema tables, `convex/agentMemory.ts` (`refreshRepositoryMemory` internalMutation + `getRepositoryMemory` public query) and `convex/redBlueIntel.ts` (`runAdversarialRound` internalMutation, `runAdversarialRoundForRepository` public mutation, `getLatestRound` + `adversarialSummaryForRepository` public queries), fire-and-forget `refreshRepositoryMemory` wired into `ingestCanonicalDisclosure` after blast radius scheduling, `RepositoryMemoryPanel` + `AdversarialRoundPanel` dashboard components per repository card, "Run adversarial round" hero button. All checks green (175 tests, tsc, biome, build 2075+ modules).
- WS-14 Phase 3 (Attack Surface Reduction Agent MVP) is complete: `convex/lib/attackSurface.ts` (pure computeAttackSurface, score formula: remediationScore×50 + mitigationBonus + validationBonus + memoryHealthBonus + sbomBonus + noValidatedCriticalBonus, max=100; 29 tests), `attackSurfaceSnapshots` schema table, `convex/attackSurfaceIntel.ts` (`refreshAttackSurface` internalMutation, `refreshAttackSurfaceForRepository` public mutation, `getAttackSurfaceDashboard` combined query returning snapshot+history for sparkline), fire-and-forget `refreshAttackSurface` wired into `ingestCanonicalDisclosure`, `EMPTY_MEMORY_RECORD` exported from `memoryController.ts` (shared by redBlueIntel + attackSurfaceIntel), `RepositoryAttackSurfacePanel` dashboard component with score pill, trend pill, open critical/high counts, active PR pill, CSS-only sparkline. All checks green (204 tests, tsc, biome, build).
- WS-14 Phase 4 (Red Agent Finding Escalation) is complete: `convex/lib/redAgentEscalator.ts` (pure escalateRedAgentRound function; parses package-chain and depth-chain exploit chain formats, maps to FindingCandidate[] with severity/confidence/businessImpactScore/vulnClass/affectedPackages/affectedServices/blastRadiusSummary; 37 tests), `convex/redAgentEscalation.ts` (`escalateRedAgentFindings` internalMutation with dedupeKey idempotency guard + synthetic ingestionEvent + workflowRun + findings insertion; `getRedAgentFindingCount` public query), fire-and-forget `escalateRedAgentFindings` wired into `redBlueIntel.runAdversarialRound` on `roundOutcome === 'red_wins'`, `AdversarialRoundPanel` extended with `getRedAgentFindingCount` subscription + "N escalated findings" warning pill. All checks green (241 tests, tsc, biome, build).
- Security Posture Report is complete: `convex/lib/securityPosture.ts` (pure computeSecurityPosture; penalty model — findings cap 50, attack surface 0–25 by score tier, regulatory drift 0–20 by level, red agent 0–10 by win rate, learning maturity +0–5 bonus; 5-tier postureLevel; up to 4 topActions; 39 tests), `convex/securityPosture.ts` (getSecurityPostureReport query assembling findings/attackSurface/regulatoryDrift/redBlue/learningProfile/honeypot), `GET /api/reports/security-posture` HTTP endpoint in http.ts, `RepositoryPosturePanel` dashboard component at the top of each repository card. All checks green (380 tests, biome, build).
- WS-15 Phase 3 (Memory and Learning Loop) is complete: `convex/lib/learningLoop.ts` (pure computeLearningProfile; groups findings by normalised vuln class, calculates confirmed/FP counts, isRecurring when confirmed≥2, isSuppressed when FP rate>0.6, confidenceMultiplier 0.5–2.0; detects attack surface trend by comparing avg score of oldest vs newest half; adaptedConfidenceScore min(100, confirmed×5+rounds×3); collects unique exploit chains from red_wins rounds; 34 tests), `learningProfiles` schema table (vulnClassPatterns array + aggregates + successfulExploitPaths + trend + adaptedConfidenceScore + redAgentWinRate; indexed by_repository_and_computed_at), `convex/learningProfileIntel.ts` (3 entrypoints loading 500 findings + 100 rounds + 50 attack surface points), fire-and-forget wiring in events.ts as final post-ingestion step, `RepositoryLearningPanel` dashboard component. All checks green (341 tests, biome, build).
- WS-15 Phase 2 (Honeypot Code Auto-Injection) is complete: `convex/lib/honeypotInjector.ts` (pure computeHoneypotPlan; 8 endpoint templates, 4 DB field templates, 4 file templates, 2 token templates; affinity-scored against blast radius reachableServices+exposedDataLayers; depth bonus 5pts/level capped at 15; scores capped at 100; proposals sorted descending; 30 tests), `honeypotSnapshots` schema table (per-repo plan with per-kind counts, topAttractiveness, proposals array, summary; indexed by_repository_and_computed_at), `convex/honeypotIntel.ts` (`refreshHoneypotPlan` internalMutation aggregating blast radius across 50 snapshots + counting open criticals, `refreshHoneypotPlanForRepository` public mutation, `getLatestHoneypotPlan` public query), fire-and-forget wiring in `events.ts` after regulatory drift, `RepositoryHoneypotPanel` dashboard component (proposal count pills by kind, top-3 proposals by attractiveness with score pill + path, summary text). All checks green (307 tests, biome, build).
- Outbound Webhook System (spec §7.2) is complete: `convex/lib/webhookDispatcher.ts` (pure library — all 10 event types, HMAC-SHA256 signing via Web Crypto API, HTTP delivery, event filtering, URL/event validation; 30 tests), `webhookEndpoints` + `webhookDeliveries` schema tables (by_tenant, by_tenant_and_active, by_tenant_and_attempted_at, by_endpoint_and_attempted_at indexes), `convex/webhooks.ts` (registerEndpoint/deleteEndpoint/listEndpoints/listRecentDeliveries public entrypoints; queryActiveEndpoints internalQuery that returns secrets; recordDelivery internalMutation; dispatchWebhookEvent internalAction — fans out to all active subscribed endpoints, signs each payload, POSTs with X-Sentinel-Signature-256 header, records delivery audit row), HTTP endpoints: `POST/GET/DELETE /api/webhooks`, `GET /api/webhooks/deliveries` (all API-key-guarded in http.ts), fire-and-forget wiring for 5 event types: `finding.validated` (events.ts, after exploit validation patch), `finding.pr_opened` (prGeneration.ts, after recordPrOpened), `gate.blocked` (gateEnforcement.ts, evaluateGateForWorkflow), `gate.override` (gateEnforcement.ts, recordManualOverride), `regulatory.gap_detected` (regulatoryDriftIntel.ts, when criticalGapCount > 0), `attack_surface.increased` (attackSurfaceIntel.ts, when trend = degrading + previousSnapshot exists). All checks green (410 tests).
- WS-15 Phase 1 (Regulatory Drift Detection) is complete: `convex/lib/regulatoryDrift.ts` (pure computeRegulatoryDrift; VULN_CLASS_FRAMEWORKS mapping for SOC 2/GDPR/HIPAA/PCI-DSS/NIS2, severity penalties critical=20/high=12/medium=6/low=2/informational=0, validation multipliers validated=1.5/likely_exploitable=1.2, pr_opened 0.5× status multiplier, score floor at 0, drift levels compliant/drifting/at_risk/non_compliant; 36 tests), `regulatoryDriftSnapshots` schema table (per-framework score columns + overallDriftLevel + openGapCount + criticalGapCount + affectedFrameworks + summary + computedAt; indexed by_repository_and_computed_at), `convex/regulatoryDriftIntel.ts` (`refreshRegulatoryDrift` internalMutation loading up to 200 findings, `refreshRegulatoryDriftForRepository` public mutation with scheduler trigger, `getLatestRegulatoryDrift` public query), fire-and-forget `refreshRegulatoryDrift` wired into `events.ts` after attack surface refresh, `RepositoryRegulatoryDriftPanel` dashboard component with drift level pill, gap count pills, per-framework score pills (only drifting ones), summary text. All checks green (277 tests, biome, build).

- REST API completeness (spec §7.1) is now complete: all 24 spec-defined endpoints implemented across 28 HTTP routes in `http.ts`.
- Trust Score Computation Pipeline is now complete (this session): `convex/lib/componentTrustScore.ts` (pure library — 7-signal penalty model: known CVE -30, extra CVEs up to -20, direct-dep surcharge -5, typosquat -25, suspicious name -15, pre-release -8, unknown version -12; score clamped 0–100; 30 tests), `convex/trustScoreIntel.ts` (`refreshComponentTrustScores` internalMutation — batch-loads breach disclosures once, computes scores for all snapshot components, patches sbomComponents.trustScore + hasKnownVulnerabilities, dispatches trust_score.degraded when delta ≥ 10 and trust_score.compromised when score newly crosses below 30; `getRepositoryTrustScoreSummary` public query with 4-tier breakdown: trusted/acceptable/at_risk/compromised), fire-and-forget wiring in `sbom.ingestRepositoryInventory` (after snapshot creation) and `events.ingestCanonicalDisclosure` (after hasKnownVulnerabilities patch), `trust_score.compromised` type + data shape added to `webhookDispatcher.ts` — 11th spec §7.2 event type.
- Webhook event coverage (spec §7.2) is now **11/11 complete**: `finding.validated`, `finding.pr_opened`, `finding.resolved`, `trust_score.degraded`, `trust_score.compromised`, `honeypot.triggered`, `gate.blocked`, `gate.override`, `regulatory.gap_detected`, `sbom.drift_detected`, `attack_surface.increased`.

## Verified Status

- `bun run test` in `apps/web`: passing (442 tests, 22 files)
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (55 modules, 79 kB index bundle)
- `bunx tsc --noEmit` in `apps/web`: passing — `convex/_generated/api.d.ts` updated manually to include `trustScoreIntel` + `lib/componentTrustScore` (next `convex dev` run will regenerate automatically)

- Dashboard UX pass is now fully complete (this session): `RepositoryTrustScorePanel` added to `src/routes/index.tsx` — shows repo score, direct/transitive breakdown, CVE-tagged + untrusted counts, 4-tier distribution pills, and `TrustScoreTierBar` stacked-bar visualization (trusted=green/acceptable=blue/at_risk=amber/compromised=red; `overflow-hidden rounded-full` container; zero-count segments skipped; hover `title` tooltips); `TrustScoreSummary` + `TrustScoreBreakdownEntry` type aliases; `trustScoreIntel` + `lib/componentTrustScore` registered in `convex/_generated/api.d.ts`. tsc clean, biome clean, 442/442 tests.

## Immediate Next Steps

1. Set `GITHUB_WEBHOOK_SECRET` in Convex: `npx convex env set GITHUB_WEBHOOK_SECRET <secret>`
2. Test the webhook end-to-end with the simulation script: `bun scripts/simulate-github-push.mjs --url https://quick-echidna-102.eu-west-1.convex.site/webhooks/github --secret <secret>`
3. Set `GITHUB_TOKEN` in Convex and run the first live advisory sync: `bun run advisory:sync -- --tenant atlas-fintech --repository atlas-fintech/payments-api --hours 72`
4. Set `SENTINEL_API_KEY` in Convex env to activate the HTTP endpoint auth guard: `npx convex env set SENTINEL_API_KEY <value>`
5. Run `npx convex dev` once against a live deployment to regenerate `_generated/api.d.ts` automatically (removes the manual entry added this session)

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
- Recently completed:
  - WS-13 ingestion wiring and dashboard panel (injection scans on push + advisory intake; `RepositoryIntelligencePanel`)
  - WS-14 Phase 2: Memory Controller + Red/Blue simulation loop MVP
  - Trust Score Computation Pipeline: `componentTrustScore.ts` pure lib (30 tests), `trustScoreIntel.ts` Convex entrypoints, fire-and-forget wiring in sbom.ts + events.ts, `trust_score.compromised` 11th webhook event type, 11/11 webhook coverage
  - Dashboard UX pass: `RepositoryTrustScorePanel` + `TrustScoreTierBar` fully implemented; `convex/_generated/api.d.ts` updated; tsc + biome + 442 tests all green

## Update Rule

Every run must update these files before ending if anything meaningful changed:

1. `CURRENT_CONTEXT.md` for the latest working state and blockers
2. `TODO.md` for the near-term active queue
3. `PROJECT_TRACKER.md` when a workstream or milestone status changes
4. `IMPLEMENTATION_SPLIT.md` only when scope or build order changes
