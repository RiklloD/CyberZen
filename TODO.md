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
- [x] Wire live advisory ingestion paths for GitHub Security Advisories and OSV into the routed event layer
- [x] Extend SBOM parsing to `pnpm-lock.yaml`, `yarn.lock`, and `bun.lock`
- [x] Extend SBOM parsing to container-native inventory inputs
- [x] Deepen repository inventory drilldowns beyond the dashboard card summaries
- [x] Initialize Convex locally and regenerate backend types from a live deployment
- [x] Wire GitHub webhook delivery into the routed ingestion layer
- [x] Expand advisory ingest from ID-based live imports into scheduled or bulk feed sync
- [x] Add Breach Intel Aggregator MVP
- [x] Add Semantic Fingerprinting MVP
- [x] Add Exploit Validation MVP
- [x] Add CI/CD Gate Enforcement MVP
- [x] Add PR Generation MVP

## Next Up

- [ ] Set `GITHUB_WEBHOOK_SECRET` in Convex and exercise the first live webhook delivery using the simulate-github-push.mjs script
- [ ] Set `GITHUB_TOKEN` in Convex and run the first live advisory bulk-sync pass
- [ ] Exercise the first live GitHub-backed repository scan path end to end
- [x] Deepen PR generation: implement actual version-bump file modification (requirements.txt, package.json) so PRs contain a real diff

## Next Up (continuing)

- [x] Outbound webhook event system (spec §7.2) — `webhookDispatcher.ts` pure lib (30 tests; HMAC-SHA256 signing, 10 event types, isSubscribed filtering, postWebhookPayload, URL/event validation), `webhookEndpoints` + `webhookDeliveries` schema tables, `convex/webhooks.ts` entrypoints (registerEndpoint/deleteEndpoint/listEndpoints/listRecentDeliveries/queryActiveEndpoints/recordDelivery/dispatchWebhookEvent), `POST/GET/DELETE /api/webhooks` + `GET /api/webhooks/deliveries` HTTP endpoints, fire-and-forget wiring for finding.validated / finding.pr_opened / gate.blocked / gate.override / regulatory.gap_detected / attack_surface.increased. All checks green (410 tests).
- [x] Begin WS-12: operator-facing findings list query and API route
- [x] WS-12: SBOM export endpoint (JSON/CycloneDX)
- [x] WS-12: trust score surface and repository drilldown API
- [x] WS-12 repositoryScore: implemented Strategy B (direct-weighted mean) in `convex/lib/trustScore.ts`
- [x] WS-13: Prompt Injection Shield — 18-pattern heuristic scanner with cumulative scoring (`convex/lib/promptInjection.ts`)
- [x] WS-13: Supply-chain intelligence — typosquat detection + dependency risk signals (`convex/lib/supplyChainIntel.ts`)
- [x] WS-13: Convex entrypoints — `scanContent` internal mutation, `recentScans` + `supplyChainAnalysis` public queries (`convex/promptIntelligence.ts`)
- [x] HTTP API auth guard — `requireApiKey` on `/api/sbom/export` and `/api/findings`, reads `SENTINEL_API_KEY` from Convex env
- [x] Wire `promptIntelligence.scanContent` into breach intake / webhook push workflow mutations (`scanContentByRef` adapter + fire-and-forget calls in `githubWebhooks.ts` and `breachIngest.ts`)
- [x] WS-13 dashboard panel: `RepositoryIntelligencePanel` surfaces `recentScans` + `supplyChainAnalysis` per repository card
- [ ] Activate HTTP auth: `npx convex env set SENTINEL_API_KEY <value>`
- [x] REST API completeness (spec §7.1) — all 24 spec endpoints now implemented across 28 HTTP routes; new last session: `GET /api/findings/poc`, `GET /api/findings/reasoning`, `GET /api/sbom/commit`, `GET /api/sbom/diff`, `GET /api/trust-scores/detail`, `GET /api/trust-scores/history`, `GET /api/attack-surface/components`, `GET /api/blast-radius/graph`, `POST /api/reports/generate`, `POST /api/honeypot/trigger`. All checks green (410 tests).
- [x] Trust Score Computation Pipeline — `convex/lib/componentTrustScore.ts` (pure 7-signal penalty model, 30 tests), `convex/trustScoreIntel.ts` (`refreshComponentTrustScores` internalMutation + `getRepositoryTrustScoreSummary` query), fire-and-forget wiring in `sbom.ingestRepositoryInventory` + `events.ingestCanonicalDisclosure`, `trust_score.compromised` event type added to webhookDispatcher.ts. Webhook coverage now 11/11. All checks green (442 tests, biome, build).
- [x] WS-14 Phase 1: Blast Radius Causality Graph foundation — pure library + tests, schema, Convex entrypoints, fire-and-forget wiring, dashboard panels
- [x] WS-14 Phase 2: Memory controller + Red/Blue loop MVP — `memoryController.ts` (aggregateFindingMemory, 17 tests), `redBlueSimulator.ts` (simulateAdversarialRound, 14 tests), `agentMemorySnapshots` + `redBlueRounds` schema tables, `agentMemory.ts` + `redBlueIntel.ts` Convex entrypoints, fire-and-forget `refreshRepositoryMemory` wired into events.ts, `RepositoryMemoryPanel` + `AdversarialRoundPanel` dashboard components, "Run adversarial round" hero button
- [x] WS-14 Phase 3: Attack Surface Reduction Agent MVP — `attackSurface.ts` pure lib (29 tests), `attackSurfaceSnapshots` schema, `attackSurfaceIntel.ts` Convex entrypoints (refreshAttackSurface internalMutation, combined getAttackSurfaceDashboard query), fire-and-forget wiring in events.ts, `RepositoryAttackSurfacePanel` with score/trend/sparkline. All checks green (204 tests).
- [x] WS-14 Phase 4: Red Agent Finding Escalation — `redAgentEscalator.ts` pure lib (37 tests), `redAgentEscalation.ts` Convex entrypoints (escalateRedAgentFindings internalMutation with dedupeKey idempotency, getRedAgentFindingCount query), fire-and-forget wiring in redBlueIntel.ts on red_wins, AdversarialRoundPanel escalation count pill. All checks green (241 tests).
- [x] WS-15 Phase 1: Regulatory Drift Detection — `regulatoryDrift.ts` pure lib (36 tests; vuln-class→framework mapping for SOC 2/GDPR/HIPAA/PCI-DSS/NIS2, severity penalties, validation multipliers, pr_opened half-penalty, score floor, drift level classification), `regulatoryDriftSnapshots` schema table, `regulatoryDriftIntel.ts` Convex entrypoints (refreshRegulatoryDrift internalMutation, refreshRegulatoryDriftForRepository public mutation, getLatestRegulatoryDrift public query), fire-and-forget wiring in events.ts, `RepositoryRegulatoryDriftPanel` dashboard component. All checks green (277 tests).
- [x] Security Posture Report (spec §7.1 /reports/security-posture) — `securityPosture.ts` pure lib (39 tests; penalty model: findings up to -50/critical×12/high×6/medium×2/low×0.5, attack surface up to -25/score-tiered, regulatory drift up to -20/level-tiered, red agent up to -10/win-rate-tiered, learning bonus +0–5; score clamped 0–100; postureLevel 5 tiers; topActions up to 4 prioritised recommendations), `convex/securityPosture.ts` Convex query assembling all signals (findings+attackSurface+regulatoryDrift+redBlue+learningProfile+honeypot), `GET /api/reports/security-posture` HTTP endpoint (guarded by API key), `RepositoryPosturePanel` dashboard component shown at top of each repository card with score pill, level pill, and action list. All checks green (380 tests).
- [x] WS-15 Phase 3: Memory and Learning Loop (spec §3.13) — `learningLoop.ts` pure lib (34 tests; vuln-class grouping/normalisation, confirmed/FP counting, isRecurring when confirmed≥2, isSuppressed when FP rate>0.6, confidenceMultiplier 0.5–2.0, attack surface trend improving/stable/degrading/unknown from oldest-first history with DELTA≥5 threshold, adaptedConfidenceScore min(100, confirmed×5+rounds×3), redAgentWinRate, exploit path deduplication, blank chain filtering), `learningProfiles` schema table, `learningProfileIntel.ts` Convex entrypoints (refreshLearningProfile internalMutation loading 500 findings+100 rounds+50 surface points, refreshLearningProfileForRepository public mutation, getLatestLearningProfile public query), fire-and-forget wiring in events.ts after honeypot, `RepositoryLearningPanel` dashboard component (maturity score, trend, recurring/suppressed counts, exploit paths pill, top-3 vuln class patterns with confidence multipliers). All checks green (341 tests).
- [x] WS-15 Phase 2: Honeypot Code Auto-Injection (spec §3.9) — `honeypotInjector.ts` pure lib (30 tests; template-based canary generation for endpoints/DB-fields/files/tokens; affinity scoring against blast radius reachableServices + exposedDataLayers; depth bonus 5pts/level capped at 15; attractiveness score capped at 100), `honeypotSnapshots` schema table, `honeypotIntel.ts` Convex entrypoints (refreshHoneypotPlan internalMutation aggregating blast radius across 50 snapshots, refreshHoneypotPlanForRepository public mutation, getLatestHoneypotPlan public query), fire-and-forget wiring in events.ts after regulatory drift, `RepositoryHoneypotPanel` dashboard component. All checks green (307 tests).
- [x] Dashboard UX pass — `RepositoryTrustScorePanel` added to `src/routes/index.tsx` (repo/direct/transitive score pills, CVE-tagged + untrusted counts); `TrustScoreTierBar` stacked-bar visualization fully implemented (trusted=green / acceptable=blue / at_risk=amber / compromised=red; `overflow-hidden rounded-full` container; zero-count segments skipped; hover `title` tooltips); `TrustScoreSummary` + `TrustScoreBreakdownEntry` type aliases; `trustScoreIntel` + `lib/componentTrustScore` registered in `convex/_generated/api.d.ts`. tsc clean, biome clean, 442/442 tests.

## Later

- [ ] Tier 2 and Tier 3 breach-feed coverage beyond GitHub Security Advisories and OSV

## Rule

- `CURRENT_CONTEXT.md` is the first file to read at the start of every run.
- Keep this file limited to the near-term build queue only.
- When a task becomes active, move it here from the tracker.
- When the active context changes, update `CURRENT_CONTEXT.md`.
- When a workstream or milestone changes, update `PROJECT_TRACKER.md`.
- When scope or build order changes, update `IMPLEMENTATION_SPLIT.md` first.
