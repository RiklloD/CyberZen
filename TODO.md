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

- [x] Exploit-First Sandbox Validation — Phase 1 (real HTTP exploit execution engine)
  - Python `services/sandbox-manager` service with FastAPI + httpx (replacing Go placeholder)
  - `ExploitModule` ABC + 3 modules: `HttpProbeModule`, `InjectionModule`, `AuthBypassModule`
  - CVE pattern registry (`cve_patterns.py`) with Log4Shell, Spring4Shell, path traversal, etc.
  - `executor.py` — selects modules by vuln_class, executes HTTP attempts, generates PoC
  - `poc.py` — curl one-liner + runnable Python script from winning attempt
  - `app.py` — FastAPI `/health`, `/validate`, `/poc` endpoints
  - 45 tests passing across exploits, executor helpers, and PoC generation
  - `sandboxEnvironments` Convex table (separate from `exploitValidationRuns` for size safety)
  - `convex/sandboxValidation.ts` — `triggerSandboxValidation` internalAction + persist/fail mutations + summary queries
  - Fire-and-forget wiring in `events.ts` → overrides local-first classification when sandbox completes
  - `GET /api/sandbox/environment` + `GET /api/sandbox/summary` HTTP endpoints
  - `RepositorySandboxPanel` dashboard component — exploit counts, PoC badge, winning payload label
  - ⚠️ `classify_outcome()` in `executor.py` left as **user contribution** (see below)

## Next Up

- [x] Implement `classify_outcome()` in `services/sandbox-manager/src/sentinel_sandbox/executor.py`
  - Confidence-tiered: definitive indicators (uid=, root:, jndi:) → EXPLOITED 0.85+
  - Corroboration rule: 2+ independent successes → EXPLOITED 0.70+
  - Single weak match → LIKELY_EXPLOITABLE 0.50
  - Error response with SQL/traceback keywords → LIKELY_EXPLOITABLE 0.30
  - 16 tests covering all branches including dry_run, severity weighting, confidence cap
- [x] Complete Tier 1 breach feeds — NVD, npm advisory, PyPI Safety DB, RustSec, Go vuln DB
  - 5 new normalizer functions in `convex/lib/breachFeeds.ts` + 5 sync actions in `breachIngest.ts`
  - `NormalizedFeedSourceType` extended to 8 types; schema `sourceType` validator updated
  - 14 new tests for new adapters — 453 total Convex tests passing
- [x] Slack alert integration — `convex/slack.ts`
  - Block Kit messages: finding_validated / gate_blocked / honeypot_triggered / posture_digest
  - `SLACK_WEBHOOK_URL` + `SLACK_MIN_SEVERITY` env vars
  - Fire-and-forget wired into events.ts (finding validated) + gateEnforcement.ts (gate blocked)
  - Weekly digest cron (every Monday 09:00 UTC) in `crons.ts`
- [x] GitLab webhook integration — `convex/gitlabWebhooks.ts`
  - `POST /webhooks/gitlab` HTTP route
  - Push Hook + Merge Request Hook (open/merge actions)
  - `GITLAB_WEBHOOK_TOKEN` shared-secret verification
  - Idempotent `recordGitLabPushEvent` mutation with dedupeKey guard
  - Fire-and-forget prompt injection scan on commit messages (provider=gitlab)

- [x] Semantic Fingerprinting Phase 1 — Real Embeddings
  - `convex/lib/codeEmbedding.ts` — cosine similarity, normalize(), embedText(), embedBatch(), searchPatterns(), buildCodeContext(); 30 tests
  - `convex/lib/vulnerabilityPatternLibrary.ts` — 52 curated vulnerability descriptions (OWASP + AI/LLM)
  - `convex/semanticFingerprintIntel.ts` — initializePatternLibrary, analyzeCodeChange, dashboard queries
  - `vulnerabilityPatternEmbeddings` + `codeContextEmbeddings` schema tables
  - Wired into events.ts push workflow; falls back to path-aware when OPENAI_API_KEY absent
  - `RepositorySemanticFingerprintPanel` dashboard component
- [x] SPDX 2.3 export — `convex/lib/spdx.ts` (pure builder, 20 tests); `exportSnapshotAsSpdx` query; `GET /api/sbom/export?format=spdx`
- [x] Maven/Gradle/Ruby SBOM parsers — pom.xml (namespace-aware), build.gradle/kts, Gemfile.lock/Gemfile; wired into analyze_repository(); 11 new Python tests
- [x] PagerDuty integration — `convex/pagerduty.ts`; Events API v2; trigger/resolve; wired into honeypotIntel.ts; `PAGERDUTY_INTEGRATION_KEY` env var

- [x] GitHub Actions native CI action — `apps/github-action/` (14 tests)
  - sentinel-api.ts + check-run.ts + index.ts; action.yml with block-on-severity, post-check-run inputs
  - Posts PR check runs with severity table, blast radius, fix PR links, posture score
  - `examples/security-gate.yml` ready-to-use workflow template
- [x] Supply Chain Social Monitor Phase 1 — `convex/supplyChainMonitor.ts`
  - Real GitHub API: archived/abandoned detection, new-account commit analysis, contributor velocity spike, build-script-by-new-contributor, release-by-non-established-contributor
  - `supplyChainAnalyses` schema table; batch analysis action; dashboard query
- [x] Jira integration — `convex/jira.ts`
  - Jira Cloud REST API v3 with ADF body; createJiraIssue + resolveJiraIssue + getJiraTicketsForRepository
  - Env vars: JIRA_BASE_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
- [x] NuGet + Composer SBOM parsers — completes all 8 spec §3.11 Layer 1 ecosystems
  - NuGet: csproj regex + packages.lock.json; Composer: composer.lock + bare composer.json
  - 6 new Python tests → 22 total sbom-ingest tests

## Session 42 additions
- [x] WS-45: Container Image Security Analyzer — static base-image EOL/near-EOL/outdated/unpinned/deprecated scanner
  - `convex/lib/containerImageSecurity.ts` — pure library: `CONTAINER_IMAGE_DATABASE` (~45 entries: ubuntu/debian/alpine/node/python/postgres/php/mysql/redis/nginx + deprecated node codenames); `CONTAINER_ECOSYSTEMS = new Set(['docker','container','oci'])`; `NEAR_EOL_WINDOW_DAYS = 90`; signals: `eol_base_image` (critical), `near_eol` (high), `outdated_base` (medium/low), `no_version_tag` (medium), `deprecated_image` (high/critical); `isUnpinnedTag` (UNPINNED_TAGS set); `matchVersionPrefix` (exact | `prefix-` | `prefix.` | `prefix_` separators — no substring false-positives); `checkContainerImage` (ecosystem filter → unpinned → DB lookup with registry-prefix stripping, e.g. `docker.io/library/ubuntu` → `ubuntu`); `computeContainerImageReport` (container-ecosystem filter, dedup by `ecosystem:name@version`, findings sort critical-first, aggregate counts + summary)
  - `convex/lib/containerImageSecurity.test.ts` — 74 tests: `isUnpinnedTag` ×11, `matchVersionPrefix` ×8, `checkContainerImage` ecosystem ×6, unpinned ×4, EOL ×7, near-EOL ×4, outdated ×2, deprecated ×2, registry-strip ×3, safe ×3, `computeContainerImageReport` empty/no-containers ×5, risk-aggregation ×6, deduplication ×3, summary ×3, `CONTAINER_IMAGE_DATABASE integrity` ×7; 74/74 ✓
  - `schema.ts` — `containerImageScanResults` table (tenantId/repositoryId/totalImages/criticalCount/highCount/mediumCount/lowCount/overallRisk/findings[]{imageName/imageVersion/signal/riskLevel/eolDateText nullable/recommendedVersion/detail/evidence}/summary/computedAt; 2 indexes)
  - `convex/containerImageIntel.ts` — 5 entrypoints: `recordContainerImageScan` (internalMutation: load snapshot → load ≤500 components → computeContainerImageReport → insert → prune to 30/repo), `triggerContainerImageScanForRepository`, `getLatestContainerImageScan`, `getContainerImageScanHistory` (lean, no findings), `getContainerImageScanSummaryByTenant` (criticalRepos/highRepos/mediumRepos/lowRepos/cleanRepos counts + totalFindings + worstRepositoryId/OverallRisk)
  - `sbom.ts` — fire-and-forget `recordContainerImageScan` as final step in chain (after posture score, WS-45 block)
  - `http.ts` — `GET /api/sbom/container-image-scan?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `containerImageIntel` + `lib/containerImageSecurity` registered
  - `index.tsx` — `RepositoryContainerImagePanel`: risk pill + images-scanned count pill + criticalCount/highCount/mediumCount pills; top-5 findings each showing `imageName:imageVersion` + signal label pill + `→ recommendedVersion` + EOL date annotation; suppressed when overallRisk==='none'; wired after `RepositorySupplyChainPosturePanel`
  - Verified: 74/74 tests, 0 TS errors

## Session 41 additions
- [x] WS-44: Supply Chain Posture Score — synthesis aggregator across all five supply-chain scanners
  - `convex/lib/supplyChainPostureScorer.ts` — pure library: penalty model with per-category caps (CVE–50, Malicious–50, Confusion–40, Abandonment–35, EOL–25, Attestation–20/–5); `scoreToGrade` (A≥90/B≥75/C≥55/D≥35/F<35); `scoreToRiskLevel` (critical escalates on any critical finding regardless of score); `computeSupplyChainPosture` produces `{ score, grade, riskLevel, breakdown[], summary, cveRisk, maliciousRisk, confusionRisk, abandonmentRisk, eolRisk }`; `buildDetail`/`buildSummary` private helpers
  - `convex/lib/supplyChainPostureScorer.test.ts` — 67 tests: `scoreToGrade` ×10, `scoreToRiskLevel` ×7, clean baseline ×5, CVE penalty ×5, malicious penalty ×4, confusion penalty ×3, abandonment penalty ×3, EOL penalty ×4, attestation penalty ×6, clamping/compound ×4, summary ×5, pass-through ×4, constants integrity ×7; 67/67 ✓
  - `schema.ts` — `supplyChainPostureScores` table (score/grade/riskLevel/componentCount/breakdown[]{category/label/penalty/detail}/summary/cveRisk/maliciousRisk/confusionRisk/abandonmentRisk/eolRisk/computedAt; 2 indexes)
  - `convex/supplyChainPostureIntel.ts` — 5 entrypoints: `recordSupplyChainPosture` (internalMutation: load snapshot → load ≤500 components → load attestation → run all 5 sub-scanners inline → computeSupplyChainPosture → insert → prune to 30/repo), `triggerSupplyChainPostureForRepository`, `getLatestSupplyChainPosture`, `getSupplyChainPostureHistory` (lean), `getSupplyChainPostureSummaryByTenant` (gradeA/B/C/D/F counts + averageScore + worstRepositoryId/Score/Grade)
  - `sbom.ts` — fire-and-forget `recordSupplyChainPosture` as final step in chain (after CVE scan, WS-44 block)
  - `http.ts` — `GET /api/sbom/supply-chain-posture?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `supplyChainPostureIntel` + `lib/supplyChainPostureScorer` registered
  - `index.tsx` — `RepositorySupplyChainPosturePanel`: prominent A–F grade letter (66px, color-coded) + score/100 + riskLevel pill; per-category breakdown chips (label + −penalty + detail); summary text; suppressed when riskLevel==='clean'; wired after `RepositoryCveScanPanel`
  - Verified: 67/67 tests, 0 TS errors

## Session 40 additions
- [x] WS-43: Known CVE Version Range Scanner — offline static CVE database with version-range matching
  - `convex/lib/cveVersionScanner.ts` — pure library: `KNOWN_CVE_DATABASE` (30 CveEntry objects across npm/maven/pypi), `_CVE_INDEX` Map pre-built at module load (O(1) lookup by `${ecosystem}:${name.toLowerCase()}`); `parseVersionTuple` (strips v-prefix, `.RELEASE`/`.SNAPSHOT`/`.BUILD-SNAPSHOT`/`.GA`, PyPI pre-release `a|alpha|b|beta|rc|.post|.dev`); `compareVersionTuples` (-1/0/1); `isVersionVulnerable(installed, threshold)` (boolean|null); `cvssToRiskLevel` (≥9.0=critical/≥7.0=high/≥4.0=medium/else=low); `checkComponentCves` (CveFinding[] via O(1) index); `computeCveReport` (ecosystem-lowercased dedup, CVSS-desc sort)
  - Notable CVEs: CVE-2021-44228 Log4Shell (log4j-core < 2.15.0, CVSS 10.0), CVE-2021-45046 second bypass (< 2.16.0, 9.0), CVE-2022-22965 Spring4Shell (< 5.3.18, 9.8), CVE-2022-42889 Text4Shell (< 1.10.0, 9.8), CVE-2023-29017 vm2 (< 3.9.17, 9.8), CVE-2024-34069 werkzeug (< 3.0.3, 9.8), CVE-2021-44906 minimist (< 1.2.6, 9.8)
  - `convex/lib/cveVersionScanner.test.ts` — 50 tests: `parseVersionTuple` ×7, `compareVersionTuples` ×5, `isVersionVulnerable` ×6, `cvssToRiskLevel` ×7, `checkComponentCves` ×10, `computeCveReport` ×10, `KNOWN_CVE_DATABASE integrity` ×5; 50/50 ✓
  - `schema.ts` — `cveVersionScanResults` table (tenantId/repositoryId/totalVulnerable/criticalCount/highCount/mediumCount/lowCount/overallRisk/findings[]{cveId/cvss/minimumSafeVersion/riskLevel/description/evidence}/summary/computedAt; 2 indexes)
  - `convex/cveVersionScanIntel.ts` — 5 entrypoints: `recordCveScan`, `triggerCveScanForRepository`, `getLatestCveScan`, `getCveScanHistory` (lean, no findings), `getCveSummaryByTenant` (surfaces `topCveId`/`topCvss` = highest-CVSS CVE across all repos)
  - `sbom.ts` — fire-and-forget `recordCveScan` after malicious scan (WS-43 block)
  - `http.ts` — `GET /api/sbom/cve-scan?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `cveVersionScanIntel` + `lib/cveVersionScanner` registered
  - `index.tsx` — `RepositoryCveScanPanel`: risk pill + totalVulnerable/criticalCount/highCount/mediumCount pills; top-5 findings each showing CVE ID pill + CVSS score + "v{installed} → fix in v{safe}" annotation; suppressed when clean; wired after `RepositoryMaliciousScanPanel`
  - Verified: 50/50 tests, 0 TS errors

## Session 39 additions
- [x] WS-42: Malicious Package Detection — three-layer static typosquat and malicious package detector
  - `convex/lib/maliciousPackageDetection.ts` — pure library: `POPULAR_NPM_PACKAGES` (~80 top-100 npm packages), `KNOWN_MALICIOUS_NPM_PACKAGES` (15 confirmed: crossenv/discordio/mongose/electorn/coffe-script/babelcli/event-streem/sqlite.js/lodahs/nodemailer-js/node-opencv2/htmlparser/base64js/discord-rpc2/axios2), `SQUATTING_SCOPES` (7 scopes), `TYPOSQUAT_EDIT_DISTANCE=1`; `levenshteinDistance` (standard DP), `findClosestPopularPackage` (length-guarded), `containsHomoglyphSubstitution` (l/1, o/0 flanked by letters), `isNumericSuffixVariant` (strips scope, checks popular+digits), `isScopeSquat` (@npm/@node/etc + popular bare name); `checkMaliciousPackage` (Signal 1: known_malicious npm-only; Signal 2: typosquat unscoped npm-only; Signal 3: patterns all-ecosystems, fires only when 0 prior signals); `computeMaliciousReport` (ecosystem-lowercased dedup, critical-first sort)
  - `convex/lib/maliciousPackageDetection.test.ts` — 55 tests: `levenshteinDistance` ×6, `findClosestPopularPackage` ×5, `containsHomoglyphSubstitution` ×5, `isNumericSuffixVariant` ×5, `isScopeSquat` ×5, `checkMaliciousPackage` ×13 (clean/known_malicious-critical/known_malicious-high/non-npm-exclusion/typosquat/scoped-exclusion/pypi-exclusion/numeric-suffix/scope-squat/homoglyph/output-shape), `computeMaliciousReport` ×10, `configuration constants` ×6; 55/55 ✓
  - `schema.ts` — `maliciousPackageScanResults` table (tenantId/repositoryId/totalSuspicious/criticalCount/highCount/mediumCount/lowCount/overallRisk/findings[]{similarTo nullable}/summary/computedAt; 2 indexes)
  - `convex/maliciousPackageIntel.ts` — 5 entrypoints: `recordMaliciousScan`, `triggerMaliciousScanForRepository`, `getLatestMaliciousScan`, `getMaliciousScanHistory`, `getMaliciousSummaryByTenant` (mostRecentConfirmed surfaces top known_malicious finding)
  - `sbom.ts` — fire-and-forget `recordMaliciousScan` after confusion scan (WS-42 block)
  - `http.ts` — `GET /api/sbom/malicious-scan?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `maliciousPackageIntel` + `lib/maliciousPackageDetection` registered
  - `index.tsx` — `RepositoryMaliciousScanPanel`: risk pill + count pills; top-5 findings each showing per-signal badges + "Resembles: <pkg>" tooltip; suppressed when clean; wired after `RepositoryConfusionScanPanel`
  - Verified: 55/55 tests, 0 TS errors

## Session 38 additions
- [x] WS-41: Dependency Confusion Attack Detector — purely static heuristic detection of Alex Birsan-style confusion attacks
  - `convex/lib/confusionAttackDetection.ts` — pure library (zero Convex deps): `KNOWN_PUBLIC_NPM_SCOPES` (~60 scopes), `INTERNAL_NAME_PATTERNS` (12 regexes), `EXTREME_VERSION_THRESHOLD=9000`, `HIGH_VERSION_THRESHOLD=99`, `MEDIUM_VERSION_THRESHOLD=49`; `parseNpmScope`, `isKnownPublicNpmScope`, `parseMajorVersion`, `looksLikeInternalPackage`, `checkConfusionAttack` (3 signals: extreme_version/high_version_unknown_scope/high_version_internal_name), `computeConfusionReport` (ecosystem-lowercased dedup); fixed `buildTitle` unused param warning → `_riskLevel`
  - `convex/lib/confusionAttackDetection.test.ts` — 54 tests: `parseNpmScope` ×6, `isKnownPublicNpmScope` ×6, `parseMajorVersion` ×6, `looksLikeInternalPackage` ×6, `checkConfusionAttack` ×15 (null cases, all 3 signals, risk-level thresholds, output shape), `computeConfusionReport` ×10 (clean/critical/dedup/case-insensitive-dedup/escalation/high-only/summary/empty/multi-finding), `configuration constants` ×5; 54/54 ✓
  - `schema.ts` — `confusionAttackScanResults` table (tenantId/repositoryId/totalSuspicious/criticalCount/highCount/mediumCount/lowCount/overallRisk/findings[]/summary/computedAt; indexes: `by_repository_and_computed_at`, `by_tenant_and_computed_at`)
  - `convex/confusionAttackIntel.ts` — 5 entrypoints: `recordConfusionScan` (internalMutation: load snapshot, load ≤500 components, run report, insert capped-50 findings, prune to 30 rows/repo), `triggerConfusionScanForRepository` (mutation), `getLatestConfusionScan` (query), `getConfusionScanHistory` (lean query, no findings), `getConfusionSummaryByTenant` (query: criticalRepos/highRepos/mediumRepos/cleanRepos/totalSuspiciousPackages/mostRecentFlag)
  - `sbom.ts` — fire-and-forget `recordConfusionScan` after attestation wiring (WS-41 block with comment)
  - `http.ts` — `GET /api/sbom/confusion-scan?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `_generated/api.d.ts` — `confusionAttackIntel` + `lib/confusionAttackDetection` registered
  - `index.tsx` — `RepositoryConfusionScanPanel` (risk pill, suspicious count, criticalCount/highCount/mediumCount pills, top-5 findings with mono package name + riskLevel pill + title, summary text; suppressed when overallRisk==='none'); wired after `RepositoryAttestationPanel`
  - Verified: 54/54 tests, 0 TS errors

## Session 37 additions
- [x] WS-40: SBOM Attestation — SHA-256 content fingerprinting + tenant-scoped attestation hash; status lifecycle unverified/valid/tampered
  - `convex/lib/sbomAttestation.ts` — pure library (zero deps): `sha256Hex` (pure-JS FIPS 180-4 SHA-256, `>>> 0` unsigned arithmetic throughout, Uint32Array schedule), `ATTESTATION_VERSION = 1`, `SbomComponent`/`AttestationRecord`/`VerificationResult` types, `canonicalizeSbomComponents` (ecosystem:name@version, case-lowered, deduped, sorted, `sentinel-sbom-v1\n` prefix), `computeContentHash`, `computeAttestationHash` (contentHash:tenantSlug:snapshotId:capturedAt), `generateSbomAttestation`, `verifyAttestation`
  - `convex/lib/sbomAttestation.test.ts` — 35 tests: `sha256Hex` ×7 (empty string + "abc" known-answer, length/regex, determinism, multi-block, unicode, different inputs), `canonicalizeSbomComponents` ×7 (sentinel prefix, order-independence, version sensitivity, deduplication, case-insensitivity, adding component, empty list), `computeContentHash` ×5, `computeAttestationHash` ×4, `generateSbomAttestation` ×5, `verifyAttestation` ×7 (valid + tampered on version/removal/addition/wrong-tenant, verifiedAt timestamp, order-independence); ⚠️ test file originally had wrong "abc" SHA-256 expected value (fabricated constant) — fixed to match all reference tools (openssl/Python/Node.js/sha256sum): `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
  - `schema.ts` — `sbomAttestationRecords` table (tenantId/repositoryId/snapshotId/contentHash/attestationHash/componentCount/capturedAt/attestedAt/attestationVersion/status/lastVerifiedAt?; indexes: `by_snapshot`, `by_repository_and_attested_at`, `by_tenant_and_attested_at`)
  - `convex/sbomAttestationIntel.ts` — 6 entrypoints: `recordSbomAttestation` (internalMutation: guard against duplicate per-snapshot, load components, generate, persist as 'unverified'), `verifySnapshotAttestation` (internalMutation: reload components, re-verify, patch status + lastVerifiedAt), `triggerAttestationForRepository` (mutation), `getLatestAttestation` (query), `getAttestationBySnapshotId` (query), `getAttestationSummaryByTenant` (query: valid/tampered/unverified counts + mostRecentTampered)
  - `sbom.ts` — fire-and-forget `recordSbomAttestation` after abandonment scan wiring
  - `http.ts` — `GET /api/sbom/attestation?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `_generated/api.d.ts` — `sbomAttestationIntel` + `lib/sbomAttestation` registered
  - `index.tsx` — `RepositoryAttestationPanel` with status pill (✓ valid/⚠️ tampered/⏳ unverified), componentCount + version pills, content hash + attestation hash hex display, tampered warning message, lastVerifiedAt timestamp; wired after `RepositoryAbandonmentPanel`
  - Verified: 1861/1861 tests passing, tsc clean, biome clean, build 168 kB

## Session 36 additions
- [x] WS-39: Open-Source Package Abandonment Detector — static 27-entry abandonment DB (5 reason types: supply_chain_compromised/archived/officially_deprecated/superseded/unmaintained), risk levels critical→low, version-prefix matching, fired on SBOM ingest after EOL scan
  - `convex/lib/abandonmentDetection.ts` — pure library: `ABANDONED_DATABASE`, `versionMatchesPrefix`, `lookupAbandonedRecord`, `checkPackageAbandonment`, `classifyOverallRisk`, `computeAbandonmentReport`
  - `convex/lib/abandonmentDetection.test.ts` — 46 tests: versionMatchesPrefix ×6, lookupAbandonedRecord ×12, checkPackageAbandonment ×8, classifyOverallRisk ×5, computeAbandonmentReport ×11, DB integrity ×5
  - `schema.ts` — `abandonmentScanResults` table (tenantId/repositoryId/criticalCount/highCount/mediumCount/lowCount/totalAbandoned/overallRisk/findings[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at`)
  - `convex/abandonmentScanIntel.ts` — 5 entrypoints: `recordAbandonmentScan` (internalMutation), `triggerAbandonmentScanForRepository` (mutation), `getLatestAbandonmentScan` (query), `getAbandonmentScanHistory` (lean, no findings), `getAbandonmentSummaryByTenant` (criticalRepos/highRepos/mediumRepos/lowRepos/cleanRepos/totalCriticalPackages/totalHighPackages/totalAbandonedPackages)
  - `sbom.ts` — fire-and-forget `recordAbandonmentScan` after EOL scan wiring
  - `http.ts` — `GET /api/abandonment/scan?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `abandonmentScanIntel` + `lib/abandonmentDetection` registered
  - `index.tsx` — `RepositoryAbandonmentPanel` with ☠️🚫📁🔄🕸️ reason icons, risk-level pills, replacedBy hints
  - Verified: 1826/1826 tests passing, tsc clean, biome clean, build 166 kB

## Session 35 additions
- [x] WS-38: Dependency & Runtime End-of-Life (EOL) Detection — static EOL database with version-prefix matching, fired on SBOM ingest
  - `convex/lib/eolDetection.ts` — pure library: `NEAR_EOL_WINDOW_MS` (90-day constant); `EOL_DATABASE` (33 entries: Node.js 10/12/14/16, Python 2.7/3.6/3.7/3.8, Ruby 2.7/3.0, PHP 7.4/8.0/8.1, .NET 5/6/7, Django 1/2.2/3.2, Flask 1, Rails 5/6.0/6.1, Spring Boot 2.5/2.6, Log4j 1, Angular 12/13/14, request/node-uuid/core-js-2/jQuery-1/2); `versionMatchesPrefix` (segment-safe: '14'→'14.21.3', NOT '141.0'); `parseVersionMajorMinor`; `classifyEolStatus` (end_of_life/near_eol/supported/unknown); `lookupEolEntry` (specificity-preferring sort); `checkComponentEol` (null for supported/unknown, EolFinding with title+description otherwise); `computeEolReport` (dedupes by ecosystem:name:version, three-way null split supported vs unknown, overallStatus critical/warning/ok, summary)
  - `convex/lib/eolDetection.test.ts` — 46 tests: versionMatchesPrefix ×6, parseVersionMajorMinor ×4, classifyEolStatus ×7, lookupEolEntry ×9, checkComponentEol ×8, computeEolReport ×9, DB integrity ×3
  - `schema.ts` — `eolDetectionResults` table (tenantId/repositoryId/eolCount/nearEolCount/supportedCount/unknownCount/overallStatus/findings[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at`)
  - `convex/eolDetectionIntel.ts` — `recordEolScan` internalMutation; `triggerEolScanForRepository` public mutation; `getLatestEolScan` + `getEolScanHistory` + `getEolSummaryByTenant` queries
  - `convex/sbom.ts` — fire-and-forget `recordEolScan` as final step after SBOM quality scoring
  - `convex/http.ts` — `GET /api/eol/scan?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `convex/_generated/api.d.ts` — `eolDetectionIntel` + `"lib/eolDetection"` registered
  - `src/routes/index.tsx` — `RepositoryEolPanel` wired after `RepositoryCryptoWeaknessPanel`
  - 1780/1780 tests, tsc clean, biome clean, build clean (162.80 kB)

## Session 31 additions
- [x] WS-33: Infrastructure as Code (IaC) Security Scanner — static misconfiguration detection for Terraform, Kubernetes, Dockerfile, and Docker Compose
  - `convex/lib/iacSecurity.ts` — pure library: `detectFileType` (`.tf`→terraform, `docker-compose*`→compose, `Dockerfile*`→dockerfile, `.yaml/.yml`→kubernetes, `.json`→cloudformation); 20 rules across 4 file types with pattern/negated flags; `scanIacFile(filename, content)` → `IacScanResult`; `combineIacResults(results[])` → `IacScanSummary`
  - Rule coverage: Terraform (TF_SG_OPEN_INGRESS/critical, TF_S3_PUBLIC_ACL/high, TF_RDS_PUBLIC/critical, TF_IAM_WILDCARD_ACTION/high, TF_IAM_WILDCARD_RESOURCE/high, TF_HTTP_LISTENER/medium); Kubernetes (K8S_PRIVILEGED_CONTAINER/critical, K8S_HOST_NETWORK/high, K8S_HOST_PID/high, K8S_LATEST_IMAGE_TAG/medium, K8S_ALLOW_PRIVILEGE_ESCALATION/high, K8S_RUN_AS_ROOT/high); Dockerfile (DOCKER_ROOT_USER/high negated, DOCKER_ADD_COMMAND/medium, DOCKER_LATEST_TAG/medium, DOCKER_SENSITIVE_ENV/high, DOCKER_CURL_BASH_PIPE/high); Compose (COMPOSE_PRIVILEGED/critical, COMPOSE_HOST_NETWORK/high, COMPOSE_SENSITIVE_ENV/medium)
  - `convex/lib/iacSecurity.test.ts` — 46 tests: detectFileType ×12, Terraform rules ×7, Kubernetes rules ×7, Dockerfile rules ×8, Compose rules ×4, unknown type ×1, combineIacResults ×7
  - `schema.ts` — `iacScanResults` table (totalFiles, totalFindings, criticalCount/highCount/mediumCount/lowCount, overallRisk, fileResults[], summary, computedAt; two indexes)
  - `convex/iacScanIntel.ts` — `recordIacScan` internalMutation; `triggerIacScanForRepository` public mutation; `getLatestIacScan` public query; `getIacScanHistory` lean query; `getIacScanSummaryByTenant` query
  - `convex/events.ts` — fire-and-forget `recordIacScan` filtering `.tf`, `.yaml`, `.yml`, `Dockerfile`, `docker-compose` files from changedFiles on every push
  - `iacScanIntel` + `lib/iacSecurity` registered in `_generated/api.d.ts`
  - `RepositoryIacScanPanel` dashboard component — overall risk pill + finding counts + per-file rows with fileType badge + filename + inline findings (severity + title); wired per-repository after `RepositorySbomQualityPanel`
  - 1583 tests (57 Convex files pass, +46), tsc clean, biome clean, build clean (149.07 kB)

## Session 30 additions
- [x] WS-32: SBOM Quality & Completeness Scoring — 5-axis quality grade for every SBOM snapshot
  - `convex/lib/sbomQuality.ts` — pure library: `isExactVersion` (no range specifiers, rejects `^`/`~`/`>=`/`*`/`latest`/`any`); `computeFreshnessScore` (linear decay: 100 at day 0 → 0 at day 90+); `countLayersPopulated` (out of 6: direct/transitive/build/container/runtime/AI model); `computeSbomQuality(snapshot, components, now?)` → `SbomQualityResult` (overallScore, grade, 5 sub-scores, raw stats, summary)
  - Sub-score weights: completeness 25% (min(100, components×5)), version-pinning 25%, license-resolution 20%, freshness 15%, layer-coverage 15%
  - Grade thresholds: excellent ≥80, good ≥60, fair ≥40, poor <40
  - Empty SBOM → version-pinning=0 and license-resolution=0 (no vacuous 100%; avoids misleadingly high grades)
  - `convex/lib/sbomQuality.test.ts` — 42 tests: isExactVersion ×12, computeFreshnessScore ×5, countLayersPopulated ×4, computeSbomQuality ×21
  - `schema.ts` — `sbomQualitySnapshots` table (overallScore, grade, 5 sub-scores, exactVersionCount, versionPinningRate, licensedCount, licenseResolutionRate, daysSinceCapture, layersPopulated, summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)
  - `convex/sbomQualityIntel.ts` — `computeAndStoreSbomQuality` internalMutation; `triggerSbomQualityForRepository` public mutation (Promise<void> breaks type cycle); `getSbomQualityForRepository` public query; `getSbomQualityHistory` lean query; `getSbomQualitySummaryByTenant` tenant-wide aggregation
  - `convex/sbom.ts` — fire-and-forget `computeAndStoreSbomQuality` wired after license compliance
  - `sbomQualityIntel` + `lib/sbomQuality` registered in `_generated/api.d.ts`
  - `RepositorySbomQualityPanel` dashboard component — grade pill + overall score pill + layers-populated pill + 5 sub-score cards in a responsive grid; hides until first result; wired per-repository after `RepositoryLicenseCompliancePanel`
  - 1537 tests (56 Convex test files pass, +42 new), tsc clean, biome clean, build clean (145.70 kB)

## Session 29 additions
- [x] WS-31: Dependency License Compliance Engine — SPDX classification + static package DB + policy-weighted scoring for SBOM components
  - `convex/lib/licenseCompliance.ts` — pure library: `classifyLicense(spdx)` (6 categories: permissive, weak_copyleft, strong_copyleft, network_copyleft, proprietary, unknown; SPDX OR/AND expression parsing; case-insensitive; substring heuristics for AGPL/affero and GPL/LGPL natural-language strings); 200+ entry static DB across npm/pypi/cargo/go; `lookupStaticLicense(name, ecosystem)`; `assessComponentLicense(component, policy)` (static DB > provided license > unknown); `DEFAULT_COMMERCIAL_POLICY` (permissive→allowed, weak_copyleft→warn, strong_copyleft→blocked, network_copyleft→blocked, proprietary→blocked, unknown→warn); `computeLicenseCompliance(components, policy)` (score=max(0,100-blocked×20-warn×5), overallLevel compliant/caution/non_compliant, violations[], summary)
  - `convex/lib/licenseCompliance.test.ts` — 44 tests: classifyLicense ×18, lookupStaticLicense ×8, assessComponentLicense ×8, computeLicenseCompliance ×10
  - `schema.ts` — `licenseComplianceSnapshots` table (blockedCount, warnCount, allowedCount, unknownCount, complianceScore, overallLevel, violations[], summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)
  - `convex/licenseComplianceIntel.ts` — `refreshLicenseCompliance` internalMutation (loads latest sbom snapshot + up to 500 components, runs compliance, stores result, prunes to 30 per repo); `refreshLicenseComplianceForRepository` public mutation; `getLatestLicenseCompliance` public query; `getLicenseComplianceHistory` lean query; `getLicenseComplianceSummaryByTenant` tenant-wide aggregation query
  - `convex/sbom.ts` — fire-and-forget `refreshLicenseCompliance` wired after SBOM ingest
  - `licenseComplianceIntel` + `lib/licenseCompliance` registered in `_generated/api.d.ts`
  - `RepositoryLicenseCompliancePanel` dashboard component — overall level pill, score/100 pill with color tier, component count, blocked/warn/unknown pills, violation rows (name + ecosystem + resolved license + category); hides until first result; wired per-repository after `RepositorySecretScanPanel`
  - 1495/1495 tests, tsc clean, biome clean, build clean

## Session 28 additions
- [x] WS-30: Hardcoded Credential & Secret Detection Engine — pattern + entropy scanning for leaked secrets in push events
  - `convex/lib/secretDetection.ts` — pure library: 19 regex detectors across 10 credential families (AWS Access Key ID, AWS secret assignment, GCP service account JSON, Azure Storage connection string, OpenAI key, Anthropic key, HuggingFace token, GitHub PAT/OAuth/Actions tokens, GitLab PAT, Stripe live/test keys, SendGrid API key, Slack bot token, RSA/EC/SSH/PGP private keys, PostgreSQL/MongoDB connection strings with credentials, hardcoded password assignment, generic API key assignment); Shannon entropy analysis (≥ 4.5 bits/char) on quoted literals as high-entropy_string catch-all; placeholder filter (${...}, <...>, YOUR_..., EXAMPLE_..., changeme, all-same-char, xxxx..., dummy/fake/mock/test prefixes); UUID + SHA-1/256 hex exclusion from entropy scanner; test-file hint tagging; `scanForSecrets(content, filename?)`, `combineResults(results[])`, `isLikelyPlaceholder`, `redactMatch`, `shannonEntropy`, `isTestFile`
  - `convex/lib/secretDetection.test.ts` — 61 tests: isLikelyPlaceholder ×9, redactMatch ×4, shannonEntropy ×5, isTestFile ×6, AWS ×3, GitHub token ×3, private key ×2, OpenAI ×2, Stripe ×2, DB URL ×3, hardcoded password ×2, Slack ×1, SendGrid ×1, test-file hint ×2, placeholder exclusion ×3, entropy ×3, redactedMatch content ×1, clean content ×2, summary ×2, combineResults ×3, integration ×2
  - `schema.ts` — `secretScanResults` table (findings array, criticalCount/highCount/mediumCount, scannedItems, branch, commitSha; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)
  - `convex/secretDetectionIntel.ts` — `recordSecretScan` internalMutation (combines scan results, inserts row, prunes to 50 per repo); `triggerSecretScanForRepository` public mutation (on-demand); `getLatestSecretScan` public query; `getSecretScanHistory` lean query; `getSecretScanSummaryByTenant` query (affectedRepoCount, tenant-wide critical/high/medium totals)
  - `convex/events.ts` — fire-and-forget `recordSecretScan` in `ingestGithubPushForRepository` scanning changed file paths on every new push (no GitHub API call needed)
  - `secretDetectionIntel` + `lib/secretDetection` registered in `_generated/api.d.ts`
  - `RepositorySecretScanPanel` dashboard component — clean/detected pill, severity breakdown pills, scanned-items count, finding rows with severity badge + description + test-context hint + redacted match; hides until first scan; wired per-repository after `RepositoryTrafficAnomalyPanel`
  - 1451/1451 tests, tsc clean, biome clean, build clean (138.67 kB index bundle)

## Session 27 additions
- [x] WS-29: Production Traffic Anomaly Detection (spec §10 Phase 4) — agent-less HTTP access log monitoring
  - `convex/lib/trafficAnomaly.ts` — pure library: `detectErrorSpike` (error rate vs baseline threshold), `detectPathEnumeration` (>20 unique numeric IDs → IDOR), `detectSuspiciousUserAgent` (14 attack-tool signatures: sqlmap, nikto, nuclei, gobuster, etc.), `detectLatencyOutliers` (p95/p50 ≥10× → blind injection), `detectInjectionAttempts` (9 injection regex patterns across SQL/XSS/path-traversal/template/LFI/command injection), `detectRequestFlood` (>5× baseline volume, scanning vs flood classification); `computeTrafficAnomaly` (combinatorial scoring min(100, Σ confidence×weight), 4-level classification: normal/suspicious/anomalous/critical, finding candidate generation)
  - `convex/lib/trafficAnomaly.test.ts` — 40 tests covering all 6 detectors + integration
  - `schema.ts` — `trafficAnomalySnapshots` table (anomalyScore, level, patterns/findingCandidates arrays, stats object, summary; by_repository_and_computed_at + by_tenant_and_computed_at indexes)
  - `convex/trafficAnomalyIntel.ts` — `ingestTrafficEvents` public mutation (batch capped at 5000 events, computes anomaly, stores snapshot, creates synthetic ingestionEvent+workflowRun+findings when anomalyScore ≥ 50); `getLatestTrafficAnomaly` public query; `getTrafficAnomalyHistory` lean query
  - `convex/http.ts` — `POST /api/traffic/events?tenantSlug=&repositoryFullName=` (API-key-guarded, JSON array body)
  - `trafficAnomalyIntel` + `lib/trafficAnomaly` registered in `_generated/api.d.ts`
  - `RepositoryTrafficAnomalyPanel` dashboard component — level+score pill, request stats, detected pattern rows with type+details, finding candidate severity pills; self-hides until first ingestion
  - Wired per-repository after `RepositoryCloudBlastRadiusPanel`
  - 1390/1390 tests, tsc clean, biome clean, build clean (135.77 kB index bundle)

## Session 26 additions
- [x] WS-28: Gamification Layer (spec §3.7.4) — sprint leaderboards for attack surface reduction
  - `convex/lib/gamification.ts` — pure library: `selectWindowSnapshots` (boundary-inclusive window logic), `computeRepositoryLeaderboard` (scoreDelta ranking, gold/silver/bronze badges, merged-PR count per repo), `computeEngineerLeaderboard` (login grouping, multi-repo attribution), `computeGamification` (full sprint report, totalScoreDelta/totalPrsMerged aggregates, human-readable summary)
  - `convex/lib/gamification.test.ts` — 34 tests covering all functions and edge cases (empty inputs, boundary snapshots, tie-breaking, badge assignment, PR filtering, window exclusion)
  - `schema.ts` — `gamificationSnapshots` table (repositoryLeaderboard/engineerLeaderboard arrays, mostImprovedRepository, totalScoreDelta/totalPrsMerged, summary, computedAt; by_tenant_and_computed_at index); `mergedBy` optional field added to `prProposals`
  - `convex/gamificationIntel.ts` — `refreshGamification` internalMutation (loads attack surface snapshots + PR proposals for tenant, runs computeGamification, inserts snapshot, prunes to 20 rows); `refreshAllTenantsGamification` zero-arg cron target (fans out to all active tenants); `refreshGamificationForTenant` public mutation; `getLatestGamification` public query; `getGamificationHistory` lean history query; `recordPrMergedBy` public mutation (wires GitHub PR-merge webhook to populate mergedBy)
  - `convex/crons.ts` — `gamification sprint refresh` cron every Monday 08:00 UTC (before Slack/Teams digests)
  - `gamificationIntel` + `lib/gamification` registered in `_generated/api.d.ts`
  - `TenantGamificationPanel` dashboard component — repo leaderboard rows with badge emoji + score + delta + trend + PR count pills; engineer contributor pills when mergedBy data exists; self-hides until first snapshot
  - Wired into right-column `space-y-4` section after `TenantVendorTrustPanel`
  - 1350/1350 tests, tsc clean, biome clean, build clean (132.92 kB index bundle)

## Session 25 additions
- [x] WS-27 dashboard surface — `TenantVendorTrustPanel`
  - `convex/vendorTrust.ts` — `listVendorsBySlug` public query (slug→tenantId resolver, returns vendors + latest risk snapshot, bounded at 100)
  - `src/routes/index.tsx` — `TenantVendorTrustPanel`: active count pill, critical/high/revoke/review breakdown pills, top-5 at-risk vendor rows (name, category, score, recommendation, scope-creep/breach-signal badges); self-hides when empty
  - Wired into right-column `space-y-4` section after `TenantCrossRepoPanel`
  - 1280/1280 tests, tsc clean, biome clean

## Session 24 additions
- [x] WS-27: Vendor Trust & OAuth Risk — complete Convex module for SaaS/OAuth vendor risk management
  - `connectedVendors` schema table — stable inventory of every OAuth/SaaS integration per tenant
  - `vendorRiskSnapshots` schema table — append-only audit log of every risk assessment with full scope snapshot for diffing
  - `convex/vendorTrust.ts` — production-ready module: `registerVendor`, `updateVendorStatus`, `updateVendorScopes` (inventory mutations); `listVendors` (returns vendors with latest risk snapshot, dashboard-ready); `getVendorRiskHistory`, `listLatestRiskByTenant` (audit trail + feed queries); `sweepVendorRisk` (per-tenant internalAction); `assessVendorRisk` (on-demand single-vendor assessment); `sweepAllTenantsVendorRisk` (zero-arg internalMutation cron target, fans out per active tenant)
  - 7-rule scoring model: Context AI → Vercel clone → 100/critical/revoke_immediately; admin+env_vars/clean record → 67/high/review_scopes; 40 scopes/no critical data → 40/medium/monitor; stale read-only+dark web mention → 42/medium/monitor (compound rule)
  - `convex/crons.ts` — daily `vendor risk sweep` cron at 01:00 UTC → `sweepAllTenantsVendorRisk`
  - `_generated/api.d.ts` — `vendorTrust` registered

## Session 21 additions
- [x] VS Code Extension — Phase 4 IDE Integration (spec §10 Phase 4, WS-24)
  - `apps/vscode-extension/` — extension manifest, 8 settings, 5 commands, activationEvents for all manifest types
  - `sentinelClient.ts`, `findingStore.ts`, `statusBarItem.ts`, `diagnosticsProvider.ts`, `codeLensProvider.ts`, `findingsPanel.ts`, `commands.ts`, `extension.ts`
  - `findPackageLine()` in codeLensProvider.ts left as user contribution
  - 47/47 tests passing (4 files: codeLens, sentinelClient, findingStore, config)

## Next Up

- [x] Implement `findPackageLine()` in `apps/vscode-extension/src/codeLensProvider.ts` — per-format manifest line resolver for 8 formats
- [x] WS-25 Agentic Workflow Security Scanner (spec §10 Phase 4) — 7 vuln classes across LangChain/CrewAI/AutoGen/LlamaIndex/Vercel AI SDK; 33 Python tests; FastAPI endpoint `POST /analyze/agentic-workflows`; Convex `agenticWorkflowIntel.ts`; `RepositoryAgenticWorkflowPanel` dashboard component; agent-core upgraded to v0.3.0
- [x] WS-26 LLM-Native Application Security Certification (spec §10 Phase 4) — 7-domain certification synthesising all existing signals (prompt_injection, supply_chain_integrity, agentic_pipeline_safety, exploit_validation, regulatory_compliance, attack_surface, dependency_trust); `computeCertificationResult()` + `computeCertificationTier()` pure lib (49 vitest tests, 1280 total); `llmCertificationReports` schema table; `llmCertificationIntel.ts` Convex entrypoints (refreshCertification internalMutation, refreshCertificationForRepository public mutation, getLatestCertificationReport + getCertificationHistory + getTenantCertificationSummary queries); `RepositoryCertificationPanel` at top of each repo card; api.d.ts updated
- [x] WS-38: Dependency & Runtime EOL Detection — static database + version-prefix matching + SBOM-ingest trigger
- [x] WS-39: Open-Source Package Abandonment Detector — 27-entry static DB, 5 reason types, SBOM-ingest trigger, per-repo panel
- [ ] Set `GITHUB_WEBHOOK_SECRET` in Convex and exercise the first live webhook delivery
- [ ] Set `GITHUB_TOKEN` in Convex and run the first live advisory sync
- [ ] Activate HTTP auth: `npx convex env set SENTINEL_API_KEY <value>`
- [ ] Set `SANDBOX_MANAGER_URL` in Convex env once sandbox-manager is deployed
- [ ] Set `OPENAI_API_KEY` in Convex and run `initializePatternLibrary` (one-time pattern library seed)
- [ ] Set `SLACK_WEBHOOK_URL`, `GITLAB_WEBHOOK_TOKEN`, `PAGERDUTY_INTEGRATION_KEY`
- [ ] Run `npx convex dev` to regenerate `_generated/api.d.ts`

## Candidate workstreams (WS-40+)
- [x] WS-39: Open-Source Package Abandonment Detector ✅ (Session 36)
- [x] WS-40: Software Bill of Materials (SBOM) Attestation ✅ (Session 37)
- [x] WS-41: Dependency Confusion Attack Detector ✅ (Session 38)
- [x] WS-42: Malicious Package Detection ✅ (Session 39)
- [ ] WS-42: Malicious Package Detection — heuristic signals for typosquatting beyond edit distance: install scripts, network calls from postinstall, suspicious author emails, recently transferred ownership
- [x] WS-43: Known CVE Version Range Scanner ✅ (Session 40)
- [x] WS-44: Supply Chain Posture Score ✅ (Session 41)
- [x] WS-45: Container Image Security Analyzer ✅ (Session 42)
- [x] WS-46: Compliance Attestation Report Generator ✅ (Session 43)
- [x] WS-47: Compliance Gap Remediation Planner ✅ (Session 44)
- [x] WS-48: License Compliance & Risk Scanner ✅ (Session 44)
- [x] WS-49: Repository Security Health Score ✅ (Session 44)
- [x] WS-50: Dependency Update Recommendation Engine ✅ (Session 44)
- [x] WS-51: Security Event Timeline ✅ (Session 45)

## Session 45 additions
- [x] WS-51: Security Event Timeline — chronological audit log merging 10 source tables into a unified security incident view
  - `convex/lib/securityTimeline.ts` — pure library: 14 event types (`finding_created`, `finding_escalated`, `finding_triaged`, `gate_blocked`, `gate_approved`, `gate_overridden`, `pr_opened`, `pr_merged`, `sla_breached`, `risk_accepted`, `risk_revoked`, `red_agent_win`, `auto_remediation_dispatched`, `secret_detected`); `TimelineEntry` shape; `buildSecurityTimeline(input, limit=50)` — maps 10 source arrays to entries, merges, sorts newest-first, slices to min(limit,100); filtering rules (red_wins only, dispatchedCount>0 only, criticalCount+highCount>0 only); dual-event emission from single prProposals/riskAcceptances records; `countTimelineEventsByType` → `TimelineTypeCounts`
  - `convex/lib/securityTimeline.test.ts` — 38 tests: empty inputs, each event type, sorting, limit cap, ID uniqueness, filtering, unknown severity → undefined; 38/38 ✓ first try
  - `convex/securityTimelineIntel.ts` — shared `loadTimelineData(ctx: QueryCtx, repositoryId)` via `Promise.all` across 10 tables with correct index per table; `getSecurityTimelineForRepository` (slug-based public query); `getSecurityTimelineBySlug` (HTTP API alias); `getTimelineEventCountsByType` (summary pill counts)
  - `http.ts` — `GET /api/security/timeline?tenantSlug=&repositoryFullName=&limit=50` (API-key-guarded, returns `{ timeline, count }`)
  - `_generated/api.d.ts` — `securityTimelineIntel` + `lib/securityTimeline` registered
  - `index.tsx` — `RepositorySecurityTimelinePanel`: `TIMELINE_EVENT_ICON` map (14 types → emoji), `TIMELINE_SEVERITY_TONE`, `formatRelativeTime`; summary pills (finding_created/gate_blocked/sla_breached counts); vertical timeline list with connector line, icon, title, detail, severity pill, relative timestamp; self-hides when empty; wired after `RepositoryDependencyUpdatePanel`
  - Verified: 2615/2615 tests, 0 TS errors, biome clean, build clean

## Session 44 additions
- [x] WS-47: Compliance Gap Remediation Planner — maps WS-46 control gaps to step-by-step remediation playbooks with root-cause-deduplicated effort estimates
  - `convex/lib/complianceRemediationPlanner.ts` — pure library: `REMEDIATION_CATALOG` (22 entries, one per WS-46 control); `CONTROL_ROOT_CAUSE` map (22 controlIds → 9 root cause strings: `secret_exposure`, `iac_misconfiguration`, `crypto_weakness`, `eol_or_cve`, `sbom_integrity`, `cicd_security`, `supply_chain_risk`, `container_risk`); `PlaybookStep` / `RemediationPlaybookEntry` / `RemediationAction` / `ComplianceRemediationPlan` types; `computeRemediationPlan`: filters unknown controlIds, sorts by severity (critical→high→medium→low), deduplicates `estimatedTotalDays` via `Map<rootCause, maxDays>` then sum; `automatableActions` = actions with ≥1 automatable step
  - Catalog entries per framework: SOC2 (CC6.1 rotate credentials / CC6.6 fix IaC misconfigs / CC6.7 replace weak crypto / CC7.1 patch CVE+EOL / CC7.2 re-attest / CC8.1 harden CI/CD / CC9.2 remove malicious+confused deps); GDPR (Art.25 harden containers / Art.32 upgrade crypto+SBOM / Art.33-34 patch EOL+CVE for GDPR breach); PCI-DSS (Req.6.2 CVE patch / Req.6.3 EOL upgrade+cardholder doc / Req.6.5 restore valid attestation / Req.11.3 triage high-risk CVEs); HIPAA (§164.312 a(1) rotate ePHI secrets / a(2)(iv) replace weak crypto for ePHI / c(1) restore SBOM integrity / e(2)(ii) upgrade ePHI transport crypto); NIS2 (Art.21(2)(e) remove malicious packages / (h) update containers / (i) replace deprecated crypto / (j) remove secrets+secure CI/CD)
  - `convex/lib/complianceRemediationPlanner.test.ts` — 79 tests: REMEDIATION_CATALOG integrity ×9, clean input ×5, per-control action checks (CC6.1/CC6.7/CC7.1/CC7.2/CC8.1/Art.25/Art.21(2)(e)/§164.312(a)(1)/Req.6.3), unknown controlId ×2, sorting ×4, aggregate counts ×4, `estimatedTotalDays` root-cause dedup ×5, summary text ×5, all 22 controls produce valid action ×22; 79/79 ✓
  - `schema.ts` — `complianceRemediationSnapshots` table (tenantId/repositoryId/actions[]{controlId/controlName/framework/gapSeverity/title/steps[]{order/instruction/category/automatable}/effort/estimatedDays/automatable/requiresPolicyDoc/evidenceNeeded[]}/totalActions/criticalActions/highActions/mediumActions/lowActions/automatableActions/requiresPolicyDocCount/estimatedTotalDays/summary/computedAt; 2 indexes)
  - `convex/complianceRemediationIntel.ts` — 5 entrypoints: `recordComplianceRemediationPlan` (internalMutation: reads latest `complianceAttestationResults` → flattens `controlGaps` across all frameworks → `computeRemediationPlan` → insert → prune to 30/repo; bails gracefully if no attestation found); `triggerComplianceRemediationPlanForRepository`; `getLatestComplianceRemediationPlan`; `getComplianceRemediationPlanHistory` (lean — strips `steps` per action); `getComplianceRemediationPlanSummaryByTenant` (totalActions/totalCriticalActions/totalAutomatableActions/totalEstimatedDays + mostCriticalRepositoryId/mostCriticalActions)
  - `sbom.ts` — fire-and-forget `recordComplianceRemediationPlan` with `runAfter(7000)` delay (after WS-46 at 5 s)
  - `http.ts` — `GET /api/compliance/remediation-plan?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `complianceRemediationIntel` + `lib/complianceRemediationPlanner` registered
  - `index.tsx` — `RepositoryRemediationPlanPanel`: critical/high/automatable count pills + `~Nd effort` pill; top-5 actions list (title + controlId + gapSeverity pill + effort pill); policy doc indicator; `+N more actions` footer; self-hides when `totalActions === 0`; wired after `RepositoryCompliancePanel`
  - Verified: 79/79 tests, 0 TS errors

- [x] WS-49: Repository Security Health Score — master capstone synthesis layer reading 8+ scanner tables into a single weighted 0–100 health score
  - `convex/lib/repositoryHealthScore.ts` — pure library: 7 weighted categories (`supply_chain` 25%, `vulnerability_management` 20%, `code_security` 15%, `compliance` 15%, `container_security` 10%, `license_risk` 10%, `sbom_quality` 5%); `CATEGORY_WEIGHTS`, `CATEGORY_LABELS`, `scoreToGrade` (A≥90/B≥75/C≥60/D≥40/F<40); per-category penalty models with capped deductions (e.g. CVE critical -20 cap -60, secret critical -20 cap -60, compliance non_compliant base 20); `clamp(0,100)`; `detectTrend` (improving/declining/stable/new, ±5 threshold); `buildSummary`; `computeRepositoryHealthScore(inputs: HealthScannerInputs) → RepositoryHealthReport`
  - Scanner inputs: `supplyChainScore`/`supplyChainRisk` (WS-44), `cveCriticalCount`/`cveHighCount` (WS-43), `eolCriticalCount` (WS-38), `abandonmentCriticalCount` (WS-39), `cryptoCriticalCount`/`cryptoHighCount` (WS-37), `secretCriticalCount`/`secretHighCount` (WS-30), `iacCriticalCount` (WS-33), `cicdCriticalCount` (WS-35), `complianceOverallStatus`/`complianceCriticalGaps`/`complianceHighGaps` (WS-46), `containerCriticalCount`/`containerHighCount` (WS-45), `licenseCriticalCount`/`licenseHighCount` (WS-48), `sbomQualityScore`/`sbomQualityGrade` (WS-32), `previousOverallScore` (trend)
  - `convex/lib/repositoryHealthScore.test.ts` — 105 tests: CATEGORY_WEIGHTS integrity ×5, CATEGORY_LABELS ×1, scoreToGrade thresholds ×15, clean inputs ×8, supply chain ×6, vulnerability management ×10, code security ×8, compliance ×6, container security ×4, license risk ×4, SBOM quality ×7, weighted average ×4, trend detection ×7, top risks ×4, summary ×6, null/undefined handling ×3, per-category grades ×2, edge cases ×5; 105/105 ✓
  - `schema.ts` — `repositoryHealthScoreResults` table (tenantId/repositoryId/overallScore/overallGrade/categories[]{category/label/score/weight/grade/signals[]}/trend/topRisks[]/summary/computedAt; 2 indexes)
  - `convex/repositoryHealthIntel.ts` — 5 entrypoints: `recordRepositoryHealthScore` (internalMutation: reads latest from `supplyChainPostureScores` + `cveVersionScanResults` + `eolDetectionResults` + `abandonmentScanResults` + `cryptoWeaknessResults` + `secretScanResults` + `iacScanResults` + `cicdScanResults` + `complianceAttestationResults` + `containerImageScanResults` + `licenseComplianceScanResults` + `sbomQualitySnapshots` via `Promise.all` → builds `HealthScannerInputs` with previous score → `computeRepositoryHealthScore` → insert → prune to 30/repo); `triggerRepositoryHealthScoreForRepository`; `getLatestRepositoryHealthScore`; `getRepositoryHealthScoreHistory` (lean — strips signals, trims topRisks to 3); `getRepositoryHealthScoreSummaryByTenant` (avgScore/gradeDistribution/worstRepositoryId/worstScore/worstGrade/trendCounts)
  - `sbom.ts` — fire-and-forget `recordRepositoryHealthScore` with `runAfter(9000)` delay (after WS-47 at 7 s)
  - `http.ts` — `GET /api/repository/health-score?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `repositoryHealthIntel` + `lib/repositoryHealthScore` registered
  - `index.tsx` — `RepositoryHealthScorePanel`: 4xl score/100 + Grade pill + trend pill; 7 category mini bars (color-coded green≥90/yellow≥60/red<60); top-3 risk bullet points; self-hides when grade A + stable/new + no risks; wired after `RepositoryRemediationPlanPanel`
  - Verified: 105/105 tests, 0 TS errors

- [x] WS-50: Dependency Update Recommendation Engine — reads CVE/EOL/abandonment findings to produce concrete "upgrade X v1.2.3 → v1.4.0" recommendations
  - `convex/lib/dependencyUpdateRecommendation.ts` — pure library: `parseSemver` (handles v-prefix, pre-release, Maven .RELEASE/.SNAPSHOT, 1-3 segment versions); `classifyEffort` (patch/minor/major from semver comparison, unparseable defaults major); `isMajorBump`; `isReplacementPackage` heuristic (digit-only → version, letters → package name); `ABANDONMENT_LABEL` map; deduplication by `ecosystem::name` case-insensitive key; `RecommendationBuilder` accumulator with Set<UpdateReason>; `computeUpdateRecommendations(input: DependencyUpdateInput) → UpdateRecommendationResult`; sorting: urgency desc → effort asc → alphabetical
  - Input types: `CveFinding` (packageName/ecosystem/version/cveId/cvss/minimumSafeVersion/riskLevel), `EolFinding` (eolStatus/replacedBy), `AbandonmentFinding` (reason/riskLevel/replacedBy)
  - Output: `UpdateRecommendation` (ecosystem/packageName/currentVersion/recommendedVersion/urgency/effort/breakingChangeRisk/reasons[]/details[]/cveIds[]/replacementPackage)
  - `convex/lib/dependencyUpdateRecommendation.test.ts` — 68 tests: parseSemver ×11, classifyEffort ×6, isMajorBump ×4, empty input ×3, CVE findings ×6, EOL findings ×5, abandonment findings ×4, deduplication ×3, sorting ×3, aggregate counts ×6, summary ×5, edge cases ×6, realistic mixed scenario ×6; 68/68 ✓
  - `schema.ts` — `dependencyUpdateRecommendations` table (recommendations[]{ecosystem/packageName/currentVersion/recommendedVersion/urgency/effort/breakingChangeRisk/reasons[]/details[]/cveIds[]/replacementPackage}/criticalCount/highCount/mediumCount/lowCount/totalRecommendations/patchCount/breakingCount/summary/computedAt; 2 indexes)
  - `convex/dependencyUpdateIntel.ts` — 5 entrypoints: `recordDependencyUpdateRecommendations` (internalMutation: reads latest from `cveVersionScanResults` + `eolDetectionResults` + `abandonmentScanResults` → maps findings to typed inputs → `computeUpdateRecommendations` → insert capped at 50 → prune to 30/repo); `triggerDependencyUpdatesForRepository`; `getLatestDependencyUpdateRecommendations`; `getDependencyUpdateHistory` (lean — strips details/cveIds); `getDependencyUpdateSummaryByTenant` (totalRecommendations/totalCritical/totalHigh/totalPatch/totalBreaking + worstRepositoryId/worstRecommendationCount)
  - `sbom.ts` — fire-and-forget `recordDependencyUpdateRecommendations` with `runAfter(11000)` delay (completing cascade: 0s→5s→7s→9s→11s)
  - `http.ts` — `GET /api/sbom/update-recommendations?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `dependencyUpdateIntel` + `lib/dependencyUpdateRecommendation` registered
  - `index.tsx` — `RepositoryDependencyUpdatePanel`: critical/high/patch-level/breaking count pills; top-5 recommendations list (packageName + currentVersion→recommendedVersion + migrate-to indicator + urgency pill + effort pill); `+N more updates` footer; self-hides when `totalRecommendations === 0`; wired after `RepositoryHealthScorePanel`
  - Verified: 68/68 tests, 0 TS errors

## Session 43 additions
- [x] WS-46: Compliance Attestation Report Generator — multi-framework regulatory compliance mapping across SOC2/GDPR/PCI-DSS/HIPAA/NIS2
  - `convex/lib/complianceAttestationReport.ts` — pure library: `COMPLIANCE_FRAMEWORKS` (soc2/gdpr/pci_dss/hipaa/nis2); `GAP_PENALTIES` (critical=20/high=12/medium=6/low=3); `COMPLIANT_SCORE_THRESHOLD = 75`; `FRAMEWORK_LABELS`; 22 control-check functions across 5 frameworks; `computeComplianceAttestation` → `ComplianceAttestationResult` with 5 `FrameworkAttestation` objects; status: `non_compliant` if criticalGaps>0, `at_risk` if highGaps>0 OR score<75, else `compliant`; `buildFrameworkSummary` / `buildOverallSummary` helpers
  - Controls: SOC2 CC6.1 (secrets), CC6.6 (IaC), CC6.7 (crypto), CC7.1 (CVE+EOL), CC7.2 (attestation), CC8.1 (CI/CD), CC9.2 (malicious+confusion+abandonment); GDPR Art.25 (container), Art.32 (crypto+SBOM grade), Art.33-34 (EOL+CVE); PCI-DSS Req.6.2 (CVE), 6.3 (EOL), 6.5 (attestation), 11.3 (CVE high); HIPAA §164.312 a(1) (secrets), a(2)(iv) (crypto), c(1) (attestation tampered), e(2)(ii) (crypto high); NIS2 Art.21(2)(e) (malicious), (h) (container), (i) (crypto), (j) (secrets+CI/CD)
  - `convex/lib/complianceAttestationReport.test.ts` — 73 tests: constants ×6, clean baseline ×7, SOC2 controls ×16, GDPR ×4, PCI-DSS ×4, HIPAA ×4, NIS2 ×5, score ×3, status derivation ×4, overallStatus ×3, fullyCompliantCount ×2, gap aggregation ×3, summary text ×3, framework labels ×5, edge cases ×4; 73/73 ✓
  - `schema.ts` — `complianceAttestationResults` table (tenantId/repositoryId/frameworks[]{framework/label/status/score/criticalGaps/highGaps/controlGaps[]{controlId/controlName/gapSeverity/description}/summary}/overallStatus/criticalGapCount/highGapCount/fullyCompliantCount/summary/computedAt; 2 indexes)
  - `convex/complianceAttestationIntel.ts` — 5 entrypoints: `recordComplianceAttestation` (internalMutation: reads 12 scanner tables via `Promise.all` → builds `ComplianceAttestationInput` → `computeComplianceAttestation` → insert → prune to 30/repo); `triggerComplianceAttestationForRepository`; `getLatestComplianceAttestation`; `getComplianceAttestationHistory` (lean — strips `controlGaps` per framework); `getComplianceAttestationSummaryByTenant` (nonCompliantRepos/atRiskRepos/compliantRepos + totalCriticalGaps/totalHighGaps + worstRepositoryId/worstOverallStatus)
  - `sbom.ts` — fire-and-forget `recordComplianceAttestation` with `runAfter(5000)` delay (after container image scan, WS-46 block)
  - `http.ts` — `GET /api/compliance/attestation?tenantSlug=&repositoryFullName=`
  - `_generated/api.d.ts` — `complianceAttestationIntel` + `lib/complianceAttestationReport` registered
  - `index.tsx` — `RepositoryCompliancePanel`: overall status pill + critical/high gap count pills + `N/5 compliant` pill; per-framework rows (label + score + status pill + top-2 controlIds); self-hides when `overallStatus==='compliant' && criticalGapCount===0 && highGapCount===0`; wired after `RepositoryContainerImagePanel`
  - Verified: 73/73 tests, 0 TS errors

## Session 7 additions
- [x] Tier 3 breach feeds — `tier3BreachFeeds.ts` (paste site, HaveIBeenPwned, dark web scaffold)
  - Paste site monitoring (Pastebin RSS + credential pattern detection)
  - HaveIBeenPwned domain breach check (HIBP API v3 with per-breach detail fetch)
  - Dark web mention ingestion scaffold (`ingestDarkWebMention` mutation for operator/third-party feeds)
  - `normalizePasteSiteMention`, `normalizeHibpDomainBreach`, `normalizeDarkWebMention` + 14 tests
  - Schema extended: paste_site, credential_dump, dark_web_mention source types
- [x] Zero-day anomaly detection (spec §3.1.3) — `convex/lib/zeroDayAnomaly.ts` + 21 tests
  - Centroid-based semantic drift detector: `computeCentroid`, `cosineDistance`, `scoreAnomaly`, `scoreAnomalyAdaptive`
  - Adaptive thresholds for high-velocity repos (adjusts sensitivity to prevent alert fatigue)
  - Wired into `semanticFingerprintIntel.analyzeCodeChange` — scores every push vs 15-push rolling baseline
  - `anomalyLevel` + `anomalyScore` fields added to `codeContextEmbeddings` schema
- [x] GitHub Enterprise Server support — `convex/lib/githubClient.ts`
  - `resolveGitHubConfig()` reads `GHES_BASE_URL` / `GHES_API_URL` env vars
  - `githubRequest()` and `githubHeaders()` unified client
  - `createGhesAdvisory()` for GHES 3.7+ private vulnerability reporting
  - `breachIngest.ts` updated to use client (API URLs now respect GHES config)
- [x] MSSP white-label API (spec §10.3) — `convex/mssp.ts`
  - `POST /api/mssp/tenants`, `GET /api/mssp/tenants`, `GET /api/mssp/tenant/summary`, `DELETE /api/mssp/tenant`, `GET /api/mssp/dashboard`
  - `requireMsspApiKey()` guard (MSSP_API_KEY env var, separate from SENTINEL_API_KEY)
  - Cross-tenant risk aggregation in `getCrossTenantDashboard`
  - `MSSP_BRAND_NAME` white-label override
- [x] LLM call chain detection (spec §3.4.2) — `services/agent-core/analyzers/llm_callchain.py`
  - Python AST + JS/TS regex analysis for 14 LLM frameworks (OpenAI, Anthropic, LangChain, Vercel AI SDK, LlamaIndex, Google GenAI, etc.)
  - 4-tier input classification: DIRECT_USER_INPUT → critical, INDIRECT_INPUT → high, UNKNOWN → medium, STATIC → low
  - `POST /analyze/llm-callchains` FastAPI endpoint
  - 24 agent-core Python tests total (12 new for LLM callchain)

## Session 6 additions
- [x] Tier 2 breach feeds — 4 new sources (GitHub Issues security labels, HackerOne API, oss-security RSS, Packet Storm RSS)
  - `tier2BreachFeeds.ts` — 4 sync actions + `tier2ParseRssItems` + `tier2GuessEcosystem` helpers
  - `convex/lib/breachFeeds.ts` — 4 new normalizers (22 tests for all 8 normalizers)
  - Schema + events.ts `sourceType` extended with: github_issues, hackerone, oss_security, packet_storm
- [x] Real attack surface analysis — `services/agent-core/` static code analysis (spec §3.7)
  - `analyzers/import_graph.py` — import graph builder for JS/TS + Python AST; detects unused/test-only/single-use packages + unreachable files; 12 tests
  - `app.py` — upgraded to v0.2.0 with `POST /analyze/attack-surface` FastAPI endpoint
  - `attackSurfaceIntel.ts` — `runStaticAttackSurfaceAnalysis` internalAction + `storeStaticAnalysisFindings` mutation; calls agent-core via `AGENT_CORE_URL` env var
- [x] Azure DevOps webhook — `convex/azureDevOpsWebhooks.ts`
  - Basic auth verification (ADO uses Authorization: Basic unlike GitHub/Bitbucket HMAC)
  - `git.push` → `recordAdoPushEvent` (idempotent), `git.pullrequest.merged` → `handlePrMerged`
  - `POST /webhooks/azure-devops` HTTP route
  - SCM coverage now complete: GitHub ✅ GitLab ✅ Bitbucket ✅ Azure DevOps ✅

## Session 5 additions (session-level summary moved here)
- [x] Blue Agent detection rules + 22 tests + `GET /api/detection-rules` endpoint
- [x] Post-Fix Validation Loop — PR merge → sandbox re-validation → resolve or regression alert
- [x] Linear GraphQL integration — `createLinearIssue`, `completeLinearIssue`
- [x] Bitbucket Cloud webhook — HMAC-SHA256, repo:push, pullrequest:fulfilled

## Session 8 additions
- [x] CircleCI webhook integration — `convex/circleciWebhooks.ts` (20 tests; closes WS-05 completely)
  - HMAC-SHA256 via `circleci-signature: v1=<hex>`; `parseCircleCiSlug()` for gh/bb/gl slug formats
  - `POST /webhooks/circleci` HTTP route; fail-open in local dev
- [x] AI/ML Model Supply Chain Monitoring — spec §3.5 (30 tests)
  - `convex/lib/modelSupplyChain.ts` — pickle RCE, remote weights, unpinned ML deps, known CVEs, typosquats
  - `modelSupplyChainScans` schema table + `modelSupplyChainIntel.ts` Convex entrypoints
  - Fire-and-forget wired into `sbom.ingestRepositoryInventory`
  - `RepositoryModelSupplyChainPanel` dashboard component
- [x] SOC 2 Automated Evidence Collection — spec §10.1 (31 tests)
  - `convex/lib/complianceEvidence.ts` — 5-framework control catalogue (SOC 2/GDPR/HIPAA/PCI-DSS/NIS2)
  - `complianceEvidenceSnapshots` schema table + `complianceEvidenceIntel.ts` Convex entrypoints
  - `GET /api/compliance/evidence` HTTP endpoint; fire-and-forget wired into `events.ts`
  - `RepositoryComplianceEvidencePanel` dashboard component

## Session 10 additions
- [x] Buildkite webhook integration — `convex/buildkiteWebhooks.ts` (32 tests; closes §4.6.2 CI coverage)
  - Shared-secret X-Buildkite-Token; build.finished passed/failed → scan; blocked/canceled → ignore
  - `POST /webhooks/buildkite` HTTP route; `BUILDKITE_WEBHOOK_TOKEN` env var
- [x] Prometheus metrics endpoint — `convex/lib/prometheusMetrics.ts` + `GET /metrics` HTTP route (spec §4.6.5)
  - 31 tests; 7 metric families; text/plain exposition format v0.0.4
  - `PROMETHEUS_DEFAULT_TENANT`, `PROMETHEUS_SCRAPE_TOKEN` env vars
- [x] Datadog custom metrics — `convex/lib/datadogPayload.ts` + `convex/datadog.ts` + 15-min cron (spec §4.6.5)
  - 17 tests on pure payload library; Datadog API v2; `DD_API_KEY`, `DD_SITE`, `DD_ENV` env vars
- [x] `convex/observabilityIntel.ts` — cross-table metrics assembly query for Prometheus + Datadog
- [x] GitHub Issues ticketing — `convex/githubIssues.ts` + `convex/lib/githubIssuePayload.ts` (spec §4.6.4)
  - 23 tests on pure payload lib; reuses GITHUB_TOKEN; "ghissue:{number}:{html_url}" ref format
- [x] Shortcut ticketing — `convex/shortcut.ts` (spec §4.6.4; completes 4-system ticketing surface)
  - `SHORTCUT_API_TOKEN`, `SHORTCUT_WORKFLOW_STATE_ID` env vars; bug story type; severity→estimate 1–8

## Session 11 additions
- [x] Microsoft Teams integration — `convex/teams.ts` + `convex/lib/teamsCards.ts`
  - 3 Adaptive Card alert types: finding_validated, gate_blocked, honeypot_triggered
  - `sendTeamsAlert`, `recordTeamsDelivery`, `sendWeeklyTeamsDigest`; Monday 09:15 UTC digest cron
  - `TEAMS_WEBHOOK_URL`, `TEAMS_MIN_SEVERITY` env vars; 29 pure unit tests
  - Fire-and-forget wired: events.ts (finding_validated), gateEnforcement.ts (gate_blocked), honeypotIntel.ts (honeypot_triggered)
- [x] Opsgenie integration — `convex/opsgenie.ts` + `convex/lib/opsgeniePayload.ts`
  - Deterministic alias dedup; critical→P1/high→P2/medium→P3/low→P4 mapping
  - `sendOpsgenieAlert`, `pageOnConfirmedExploit`, `pageOnHoneypotTrigger`, `resolveOpsgenieAlert`
  - `OPSGENIE_API_KEY`, `OPSGENIE_TEAM_ID`, `OPSGENIE_SEVERITY_THRESHOLD` env vars; 24 pure unit tests
  - Fire-and-forget wired into events.ts, gateEnforcement.ts, honeypotIntel.ts; registered in `_generated/api.d.ts`
- [x] Full LLM sandbox testing — closes spec §3.9 / §3.4.2 (execute payloads against live AI endpoints)
  - `services/sandbox-manager/src/sentinel_sandbox/exploits/llm_injection.py` — `LlmInjectionModule`
  - 8 payloads × 6 AI endpoint paths × 3 body formats = 144 attempts per finding
  - Canary-based detection: unique canary phrases embedded in payloads → binary indicator match
  - Payloads: canary_direct, canary_role_switch, system_prompt_leak, system_prompt_leak_indirect, jailbreak_dan, jailbreak_override, tool_result_injection, rag_context_injection
  - Body formats: OpenAI-compatible (`messages`), simple (`message`), generic (`prompt`/`input`)
  - Endpoint paths: /v1/chat/completions, /api/chat, /api/generate, /chat, /api/ask, /api/complete
  - `models.py` — `LLM_INJECTION = "llm_injection"` added to `ExploitCategory`
  - `executor.py` — `LlmInjectionModule()` registered in `_MODULES`; `DEFINITIVE` set extended with LLM canaries
  - 33 tests passing; `test_module_is_registered_in_executor` + `test_executor_routes_prompt_injection_to_llm_module` integration tests

## Session 12 additions
- [x] Multi-cloud blast radius — closes spec §3.12 (AWS IAM + GCP + Azure resource graph)
  - `convex/lib/cloudBlastRadius.ts` — pure library: `computeCloudBlastRadius` infers cloud resource exposure from SBOM package names alone — no cloud API needed
  - 30 SDK→resource mappings (boto3/aws-sdk/@aws-sdk/*, @google-cloud/*, firebase-admin, @azure/*, azure-*)
  - Resource sensitivity scoring: IAM/identity (100), secrets/KMS (95), DBs (80–85), storage (75), compute (65–70), messaging (55–65)
  - Score formula: max_sensitivity + multi-provider +10 + IAM +15 + secrets +10 + data +5, clamped 0–100
  - Risk tiers: critical (≥80), severe (≥60), moderate (≥35), minimal (<35)
  - Risk flags: `iamEscalationRisk`, `dataExfiltrationRisk`, `secretsAccessRisk`, `lateralMovementRisk`
  - 27 tests passing (empty, IAM escalation, secrets, boto3 comprehensive, GCP, Azure, multi-cloud, lateral movement, criticalResourceCount, score cap, risk tier boundaries, prefix detection, summary content)
  - `convex/cloudBlastRadiusIntel.ts` — `computeAndStoreCloudBlastRadius` internalMutation, `getCloudBlastRadius` + `getCloudBlastRadiusBySlug` public queries
  - `schema.ts` — `cloudBlastRadiusSnapshots` table with by_repository_and_computed_at index
  - Fire-and-forget wired into `blastRadiusIntel.computeAndStoreBlastRadius` (triggers cloud analysis after every regular blast radius computation)
  - `RepositoryCloudBlastRadiusPanel` dashboard component: hides when no cloud SDK detected; shows tier/score/provider pills + risk flag pills + top-3 resources by sensitivity
  - Registered in `_generated/api.d.ts` (`cloudBlastRadiusIntel`, `lib/cloudBlastRadius`)
  - 946/946 tests passing; tsc clean; biome clean; build clean (96.67 kB index bundle)

## Session 20 additions
- [x] Autonomous Remediation Dispatch — spec §3.18 — closes the WS-21 priority queue → WS-11 proposeFix loop with a concurrency-capped, opt-in dispatch engine
  - `convex/lib/autoRemediation.ts` — pure library (zero Convex imports): `AutoRemediationPolicy` type, `DEFAULT_AUTO_REMEDIATION_POLICY` (enabled=false, tierThreshold='p0', maxConcurrentPrs=3, allowedSeverities=['critical','high']), `isTierEligible` (p0/p0_p1 thresholds), `selectRemediationCandidates` (5 skip reasons: disabled/already_has_pr/below_tier/below_severity/concurrency_cap; slotsRemaining = max(0, max-current))
  - `convex/lib/autoRemediation.test.ts` — 30 tests: isTierEligible×8, selectRemediationCandidates×22 (disabled policy, empty queue, already_has_pr, tier filtering, severity filtering, concurrency cap with currentOpenPrCount deduction, ordering, combined conditions)
  - `schema.ts` — `autoRemediationRuns` table: repositoryId/tenantId/candidateCount/dispatchedCount/skippedAlreadyHasPr/skippedBelowTier/skippedBelowSeverity/skippedConcurrencyCap/dispatchedFindingIds[]/computedAt; indexes: by_repository_and_computed_at, by_tenant_and_computed_at
  - `convex/autoRemediationIntel.ts` — `triggerAutoRemediationForRepository` internalMutation (builds priority queue inline using remediationPriority lib; loads open+draft PRs for concurrency cap + existingPrFindingIds set; selectRemediationCandidates; schedules `api.prGeneration.proposeFix` fire-and-forget for each eligible finding; inserts audit row); `runAllAutoRemediationDispatches` internalMutation (cron target, fans out to all repos); `getAutoRemediationHistoryForRepository` query; `getAutoRemediationSummaryBySlug` query (slug-based, for HTTP handler)
  - `convex/crons.ts` — `auto remediation dispatch` daily at 02:00 UTC → `runAllAutoRemediationDispatches`
  - `convex/http.ts` — `GET /api/remediation/auto-runs?tenantSlug=&repositoryFullName=` (API-key-guarded; 404 when repo not found)
  - `convex/_generated/api.d.ts` — `autoRemediationIntel` + `lib/autoRemediation` registered
  - `src/routes/index.tsx` — `RepositoryAutoRemediationPanel` per-repository component: dispatched/candidate/skip-reason pills; recent run list with dispatch count + timestamp; wired after `RepositoryEscalationPanel`
  - All checks green: 1231/1231 tests (49 files), tsc clean, biome clean

## Session 19 additions
- [x] Finding Severity Escalation Engine — spec §3.17 — makes severity dynamic by synthesizing blast radius, exploit availability (CISA KEV), cross-repo spread, and SLA breach into automatic severity upgrades
  - `convex/lib/escalationPolicy.ts` — pure library (created previous session): `getSeverityRank`, `escalateSeverityForTrigger` (+1/run, monotone), `assessEscalation` (5 triggers, max-wins multi-trigger, informational/critical excluded); `DEFAULT_ESCALATION_POLICY = { blastRadiusCriticalThreshold:80, blastRadiusHighThreshold:60, crossRepoSpreadThreshold:3 }`
  - `convex/lib/escalationPolicy.test.ts` — 66 tests: getSeverityRank×6, escalateSeverityForTrigger×15 (all 5 triggers, ceiling boundaries), assessEscalation×40 (boundary conditions, all triggers, multi-trigger, rationale content, custom policy)
  - `schema.ts` — `severityEscalationEvents` table: findingId/repositoryId/tenantId/previousSeverity/newSeverity/triggers[]/rationale[]/computedAt; indexes: by_finding, by_repository_and_computed_at, by_tenant_and_computed_at
  - `convex/escalationIntel.ts` — `checkAndEscalateFinding` internalMutation (loads blast radius/exploit/cross-repo/SLA signals, runs assessEscalation, atomically patches severity + inserts audit row); `runEscalationSweepForRepository` internalMutation; `runAllEscalationSweeps` internalMutation (cron target); `getEscalationHistoryForFinding` query; `getEscalationSummaryForRepository` + `getEscalationSummaryBySlug` queries
  - `convex/lib/webhookDispatcher.ts` — 12th event type `finding.severity_escalated` + `FindingSeverityEscalatedData` type; ALL_WEBHOOK_EVENT_TYPES updated (12/12)
  - `convex/crons.ts` — `severity escalation sweep` every 4 hours → `runAllEscalationSweeps`
  - `convex/http.ts` — `GET /api/findings/escalations?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `convex/blastRadiusIntel.ts` — fire-and-forget `checkAndEscalateFinding` after every blast radius snapshot stored
  - `convex/crossRepoIntel.ts` — added `internal` import + fire-and-forget `checkAndEscalateFinding` after every cross-repo upsert
  - `convex/_generated/api.d.ts` — `escalationIntel` + `lib/escalationPolicy` registered
  - `src/routes/index.tsx` — `RepositoryEscalationPanel` per-repository component: total escalations pill, unique findings pill, per-trigger count pills, top-5 recent events with prev→new severity arrows + trigger pills + first rationale string; wired after `RepositoryRemediationQueuePanel`
  - All checks green: 1201/1201 tests (48 files), tsc clean, biome clean

## Session 18 additions
- [x] Automated Remediation Priority Queue — spec §3.16 — composite P0/P1/P2/P3 scoring for every repository's active findings
  - `convex/lib/remediationPriority.ts` — pure library (zero Convex imports): additive score model (SLA breach +40, approaching +25, exploit +20, validation +15, blast radius tiered +5/+10/+15, severity tiered +2/+6/+10; clamped 100); `computeRemediationScore`, `classifyPriorityTier`, `prioritizeRemediationQueue` (sort desc + createdAt tiebreak), `computeQueueSummary`
  - `convex/lib/remediationPriority.test.ts` — 30 tests: score signals×17, tier boundaries×4, queue sorting×6, summary×3
  - `convex/remediationQueueIntel.ts` — `getRemediationQueueForRepository` + `getRemediationQueueBySlug` queries; active risk acceptances excluded; blast radius Map pattern (desc snapshots, first = most recent); no new schema table
  - `convex/http.ts` — `GET /api/remediation/queue?tenantSlug=&repositoryFullName=[&limit=25]` (API-key-guarded, limit capped at 100)
  - `convex/_generated/api.d.ts` — `remediationQueueIntel` + `lib/remediationPriority` registered
  - `src/routes/index.tsx` — `RepositoryRemediationQueuePanel` per-repository component: P0/P1/P2/P3 tier count pills, avg score pill, top-5 findings with tier+severity+score badges + rationale text; wired after `RepositoryRiskAcceptancePanel`
  - All checks green: 1135/1135 tests (47 files), tsc clean, biome clean

## Session 17 additions
- [x] Cross-Repository Impact Detection — spec §3.2.1 — lateral package exposure across tenant repositories
  - `convex/lib/crossRepoImpact.ts` — pure library (zero Convex imports): `normalizeForCrossRepo` (strip @scope/, unify separators), `matchesPackage` (normalized name + ecosystem; 'unknown' ecosystem skips check), `assessRepositoryImpact` (direct/transitive counts, deduped versions), `computeCrossRepoImpact` (tenant-wide spread analysis + summary text)
  - `convex/lib/crossRepoImpact.test.ts` — 26 tests: normalizeForCrossRepo×5, matchesPackage×7, assessRepositoryImpact×6, computeCrossRepoImpact×8
  - `schema.ts` — `crossRepoImpactEvents` table: packageName/normalizedPackageName/ecosystem/severity/sourceFindingId/sourceRepositoryId/tenantId/totalRepositories/affectedRepositoryCount/affectedRepositoryIds/affectedRepositoryNames/impacts[]/summary/computedAt; indexes: by_source_finding, by_tenant_and_computed_at, by_tenant_and_normalized_package (upsert guard)
  - `convex/crossRepoIntel.ts` — `computeAndStoreCrossRepoImpact` internalMutation (loads all tenant repos, excludes source repo, loads each latest SBOM snapshot, upserts result); `getCrossRepoImpact` + `getTenantCrossRepoSummary` + `getCrossRepoImpactBySlug` + `getTenantCrossRepoSummaryBySlug` queries
  - `convex/events.ts` — fire-and-forget `computeAndStoreCrossRepoImpact` after compliance evidence refresh (final step in ingestCanonicalDisclosure, only when a finding was created)
  - `convex/http.ts` — `GET /api/findings/cross-repo-impact?tenantSlug=&packageName=` (API-key-guarded)
  - `convex/_generated/api.d.ts` — `crossRepoIntel` + `lib/crossRepoImpact` registered
  - `src/routes/index.tsx` — `TenantCrossRepoPanel` global dashboard component (packages tracked, spread count, repo exposure slots, per-package severity+ecosystem+spread pills + repo name list); wired as first item in right column; `implementationTrack` updated
  - All checks green: 1105/1105 tests (46 files), tsc clean, biome clean

## Session 16 additions
- [x] Risk Acceptance Lifecycle Engine — spec §4.3 — governed risk-accept workflow with temporary/permanent levels, auto-expiry, Slack notifications, HTTP API, dashboard panel
  - `convex/lib/riskAcceptance.ts` — pure library: `AcceptanceLevel`/`AcceptanceStatus`/`AcceptanceSummary` types, `isExpired` (null=never, boundary-inclusive), `isExpiringSoon` (configurable window, false when already expired), `formatExpiryText` (permanent/expired/today/tomorrow/Nd), `computeExpiresAt`, `computeAcceptanceSummary` (counts by level/expiringSoon/alreadyExpired, excludes revoked/expired status)
  - `convex/lib/riskAcceptance.test.ts` — 26 tests: isExpired×5, isExpiringSoon×6, formatExpiryText×6, computeExpiresAt×2, computeAcceptanceSummary×7
  - `schema.ts` — `riskAcceptances` table: `findingId`/`repositoryId`/`tenantId`/`justification`/`approver`/`level`/`expiresAt`/`status`/`revokedAt`/`revokedBy`/`createdAt`; indexes: `by_finding`, `by_repository_and_created_at`, `by_tenant_and_created_at`, `by_status`
  - `convex/riskAcceptanceIntel.ts` — `createRiskAcceptance` mutation (revokes existing active, computes expiresAt, patches finding to accepted_risk); `revokeRiskAcceptance` mutation (patches to revoked, reopens finding); `checkExpiredAcceptances` internalMutation (loads by_status=active, transitions expired ones, re-opens findings, schedules Slack); `getRiskAcceptancesForRepository`/`getExpiringAcceptances`/`getAcceptanceSummaryForRepository`/`getRiskAcceptancesBySlug`/`getActiveAcceptancesForTenant` queries
  - `convex/slack.ts` — `sendAcceptanceExpiryNotification` internalAction: expiry Block Kit message with justification + approver context
  - `convex/crons.ts` — hourly `risk acceptance expiry check` cron
  - `convex/http.ts` — `POST /api/findings/risk-accept` (create), `DELETE /api/findings/risk-accept` (revoke), `GET /api/findings/risk-acceptances` (list+summary)
  - `convex/_generated/api.d.ts` — `riskAcceptanceIntel` + `lib/riskAcceptance` registered
  - `src/routes/index.tsx` — `RepositoryRiskAcceptancePanel` component: active count pill, expiring-soon badge, truncated justification list for near-term expirations; wired after `RepositorySlaPanel`
  - All checks green: 1079/1079 tests (45 files), tsc clean, biome clean, build clean (105.41 kB)

## Session 15 additions
- [x] SLA Enforcement Engine — spec §3.13.3 — time-to-remediate accountability with per-severity thresholds, breach detection, MTTR, Slack notifications, hourly cron, HTTP endpoint, dashboard panel
  - `convex/lib/slaPolicy.ts` — pure library (zero Convex imports): `SlaPolicy`/`SlaFindingAssessment`/`SlaSummary` types, `DEFAULT_SLA_POLICY` (critical 24h, high 72h, medium 168h, low 720h), `getSlaThresholdHours`, `computeSlaDeadline`, `assessSlaFinding` (not_applicable / within_sla / approaching_sla / breached_sla), `computeSlaSummary` (complianceRate + MTTR)
  - `convex/lib/slaPolicy.test.ts` — 32 tests: threshold mapping, deadline computation, all SLA status transitions, inactive/informational exemptions, computeSlaSummary edge cases including MTTR
  - `schema.ts` — `slaBreachEvents` table: `findingId`/`repositoryId`/`tenantId`/`severity`/`title`/`slaThresholdHours`/`openedAt`/`breachedAt`/`notifiedAt`/`notificationChannels`; indexes: `by_finding`, `by_repository_and_breached_at`, `by_tenant_and_breached_at`
  - `convex/slaIntel.ts` — `checkSlaBreaches` internalMutation (loads open+pr_opened findings, deduped by_finding check, inserts breach events, schedules Slack notification); `checkAllSlaBreaches` internalMutation (fans out to all repos via scheduler); `getSlaStatusForRepository` query; `getSlaBreachHistory` query; `getSlaComplianceReport` query; `getSlaStatusBySlug` query (used by HTTP handler); `triggerSlaCheckForRepository` public mutation
  - `convex/slack.ts` — `sendSlaBreachNotification` internalAction: SLA breach Block Kit message with emoji + hoursOverdue text; always fires regardless of SLACK_MIN_SEVERITY
  - `convex/crons.ts` — hourly `sla breach check` cron calling `checkAllSlaBreaches`
  - `convex/http.ts` — `GET /api/sla/status?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `convex/_generated/api.d.ts` — `slaIntel` + `lib/slaPolicy` registered
  - `src/routes/index.tsx` — `RepositorySlaPanel` component: compliance rate pill (green/amber/red), breach count badge, approaching count badge, MTTR pill, status line; wired after `RepositoryLearningPanel`
  - All checks green: 1053/1053 tests (44 files), tsc clean, biome clean, build clean

## Session 14 additions
- [x] Analyst Feedback Loop — `false_positive` + `ignored` finding statuses, triage event log, HTTP PATCH/GET triage API, learning loop integration, dashboard FP visibility
  - `convex/schema.ts` — `findingStatus` union extended: `v.literal('false_positive')`, `v.literal('ignored')`
  - `findingTriageEvents` table: `findingId`, `repositoryId`, `tenantId`, `action`, `note`, `analyst`, `createdAt`; indexes: `by_finding`, `by_repository_and_created_at`, `by_tenant_and_created_at`
  - `convex/lib/findingTriage.ts` — pure library (zero Convex imports): `TriageAction` union (5 actions), `TriageEvent`/`TriageSummary` types, `triageActionToStatus` (action→status map; `add_note` returns null), `computeTriageSummary` (last-action-wins semantics, note collection, FP count), `analystFpRate` (repo-level FP rate 0–1), `analystConfidenceMultiplier` (1.0 − fpRate×0.75, clamped)
  - `convex/lib/findingTriage.test.ts` — 25 tests: `triageActionToStatus`×5, empty log, single events×3, last-action-wins×4, notes×4, `analystFpRate`×4, `analystConfidenceMultiplier`×5
  - `convex/findingTriage.ts` — public mutations: `applyTriageAction` (unified), `markFalsePositive`, `reopenFinding`, `addTriageNote`; public queries: `getTriageHistory` (events + summary), `getFalsePositiveSummary` (per-repo FP counts + breakdown); `loadTriageEventsForLearningLoop` internalQuery
  - `convex/findings.ts` — local `findingStatus` validator updated to include `false_positive`, `ignored`
  - `convex/learningProfileIntel.ts` — `validationStatus` override: `f.status === 'false_positive' ? 'unexploitable' : f.validationStatus`
  - `convex/lib/gatePolicy.ts` — `FindingStatus` type extended with `'false_positive' | 'ignored'`
  - `convex/lib/complianceEvidence.ts` — `EvidenceFinding.status` type extended with `'false_positive' | 'ignored'`
  - `convex/http.ts` — `validStatuses` updated; `PATCH /api/findings/triage` + `GET /api/findings/triage` HTTP routes (API-key-guarded)
  - `convex/_generated/api.d.ts` — `findingTriage` + `lib/findingTriage` registered
  - `src/routes/index.tsx` — `RepositoryLearningPanel` gains `repositoryId` prop + FP count pill via `getFalsePositiveSummary`
  - All checks green: 1021/1021 tests, tsc clean, biome clean, build clean

## Session 13 additions
- [x] Tier 3 Threat Intelligence — CISA KEV + Telegram Bot webhook — closes all "Later" roadmap items
  - `convex/lib/cisaKev.ts` — pure library: `parseCisaKevResponse`, `matchCisaKevToCveList`, `cisaKevToSeverity`, `buildCisaKevSummary`; 26 tests
  - `convex/lib/telegramIntel.ts` — pure library: CVE regex extraction (deduplicated, uppercase), credential pattern detection (GitHub PAT / AWS / OpenAI / api_key), ransomware keyword detection (LockBit, BlackCat, Clop, etc.), package@version mentions, `parseTelegramPost`, `scoreMessageThreatLevel`; 24 tests
  - `convex/tier3Intel.ts` — "use node" module: `syncCisaKevCatalog` internalAction (fetches CISA_KEV_URL, cross-refs 500 breach disclosures, patches `exploitAvailable=true` on matches), `handleTelegramUpdate` internalAction (parses Telegram Bot API update, stores non-trivial signals), 4 internal mutations (`recordCisaKevSync`, `markDisclosuresExploited`, `recordTier3Signal`, `getBreachDisclosuresForKevMatch`), 3 public queries (`getLatestCisaKevSnapshot`, `getRecentTier3Signals`, `getHighPrioritySignals`), `triggerCisaKevSync` public mutation
  - `schema.ts` — `cisaKevSnapshots` table (by_synced_at index), `tier3ThreatSignals` table (by_captured_at + by_threat_level_and_captured_at indexes); `breachDisclosures.sourceType` extended with `cisa_kev` and `telegram`
  - `crons.ts` — CISA KEV daily sync cron at 03:00 UTC
  - `http.ts` — 3 new routes: `POST /webhooks/telegram` (secret-token guard), `GET /api/threat-intel/cisa-kev` (API-key-guarded), `POST /api/threat-intel/cisa-kev/sync` (API-key-guarded); routes use `api.tier3Intel.X` (not `internal`) for public query/mutation functions
  - `_generated/api.d.ts` — `tier3Intel`, `lib/cisaKev`, `lib/telegramIntel` registered
  - `ThreatIntelPanel` dashboard component: global (no per-repo args); shows CISA KEV snapshot stats (totalEntries, ransomwareRelated, matchedFindingCount, matched CVE pills, hasHighPriorityEntries) + last 5 high-priority Telegram signals with threatLevel/source/credential/ransomware pills and CVE tags
  - Wired into right-column `space-y-4` section after "Breach watchlist" article
  - 996/996 tests passing; tsc clean; biome clean; build clean (100.89 kB index bundle)

## Later

- [x] Tier 3 Telegram/underground forum monitoring (requires Tor-capable agent)
- [x] AI model provenance HF API enrichment (weights hash verification via Hugging Face model card metadata)
  - `convex/lib/huggingFaceEnrichment.ts` — pure parser (no network): `isHuggingFaceComponent`, `extractHFModelId`, `parseHFApiResponse`; handles license (cardData → tag fallback), model card detection (README.md in siblings), training datasets (cardData.datasets ∪ dataset: tags, deduplicated), gating (bool/auto/manual), commitSha, pipelineTag, lastModified; 35 tests
  - `convex/modelProvenanceIntel.ts` — `enrichModelProvenanceFromHF` internalAction (identifies HF candidates, fetches HF API in BATCH_SIZE=5 parallel batches, per-model error isolation, merges enriched fields into ModelComponentInput[], calls scanModelProvenance, persists via `persistEnrichedModelProvenance`); `persistEnrichedModelProvenance` internalMutation; `getLatestSnapshotForRepo` + `getSnapshotComponents` internalQuery helpers
  - Two-phase wiring in `sbom.ts`: fast baseline (`refreshModelProvenance`) fires immediately; `enrichModelProvenanceFromHF` fires concurrently and its enriched scan supersedes the baseline once HF fetches complete
  - Config: `HUGGINGFACE_API_TOKEN` env var (optional — public models work without auth)
- [x] Splunk/Elastic SIEM export for Blue Agent detection rules (spec §4.6.5)
  - `convex/lib/siemExport.ts` — pure payload builders: `buildSplunkHecBody` (newline-delimited JSON event objects for HEC batching), `buildElasticBulkBody` (NDJSON action+document pairs with deterministic `_id`, mandatory trailing newline), `isValidSiemUrl`; 29 tests
  - `convex/siemIntel.ts` — `pushToSiem` internalAction (fetches latest `detectionRuleSnapshot`, pushes Splunk + Elastic independently; Elastic `_bulk` partial-error detection via `json.errors`; per-destination fault isolation); `recordSiemPush` internalMutation (30-row retention); `triggerSiemPushForRepository` public mutation; `getLatestSiemPush` + `getSiemPushHistory` public queries
  - `schema.ts` — `siemPushLogs` table with `splunkStatus`/`elasticStatus` union validators, two indexes
  - Fire-and-forget wired into `blueAgentIntel.generateAndStoreDetectionRules` after each rule snapshot
  - `POST /api/siem/push` HTTP endpoint (API-key-guarded, schedules push for a repository)
  - `RepositorySiemPanel` dashboard component (hides when both destinations skipped, shows ok/error pills + error text + timestamp)
  - Config: `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SPLUNK_HEC_INDEX`, `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX`
- [x] Jenkins CI integration (spec §4.6.2 — last remaining CI/CD provider)
  - `convex/jenkinsWebhooks.ts` (Notification Plugin shape; FINALIZED + SUCCESS/FAILURE → scan; QUEUED/STARTED/COMPLETED ignored; ABORTED/UNSTABLE ignored)
  - Auth: `X-Jenkins-Token` shared secret (approach B — Buildkite-style), constant-time XOR-accumulator compare, fail-open when `JENKINS_WEBHOOK_TOKEN` unset
  - `parseRepoUrlFromJenkins` + `normaliseJenkinsBranch` pure helpers; `recordJenkinsEvent` idempotent via `jenkins-build-<repo>-<sha>-<buildNumber>` dedupeKey
  - `POST /webhooks/jenkins` HTTP route
  - 29 tests (URL parsing, branch refspec normalisation, token compare contract, phase/status routing table)
  - `jenkinsWebhooks` registered in `_generated/api.d.ts`; next `convex dev` regenerates automatically

## Session 34 additions
- [x] WS-36: Community Rule/Fingerprint Contribution Marketplace — spec §10 Phase 4 network-effect moat
  - `convex/lib/communityFingerprint.ts` — pure library: `computeContributionScore` (netScore = upvotes−downvotes−reports×2, upvoteRatio, approvalEligible); `isApprovalEligible` (skips already-approved/rejected, checks score threshold + report cap); `deriveStatus` (pending→under_review when reportCount ≥ REPORT_REVIEW_THRESHOLD, preserves operator decisions); `validateContribution` (title 5–120ch, description 20–2000ch, patternText 10–5000ch, vulnClass in set of 19); `summarizeMarketplaceStats` (counts by status/type/vulnClass/severity for approved only); `rankContributions` (sort by netScore desc, createdAt tiebreak, non-mutating)
  - `convex/lib/communityFingerprint.test.ts` — 34 tests covering all 6 functions
  - `convex/communityMarketplace.ts` — Convex entrypoints: `submitContribution` public mutation (validates then inserts); `voteOnContribution` public mutation (idempotent vote switch, self-vote guard, by_voter_and_contribution dedup); `reportContribution` public mutation (one-report-per-tenant, auto-transitions to under_review at threshold); `approveContribution` + `rejectContribution` internalMutations; `listContributions` public query (type+status+vulnClass filters, net-score ranked, cap 200); `getContributionDetail` public query; `getMarketplaceStats` public query; `getTopContributors` public query (approved count per tenant); `getApprovedByVulnClass` public query (detection library seed)
  - `schema.ts` — `communityContributions` table (contributorTenantId/type/title/description/vulnClass/severity/patternText/status/upvoteCount/downvoteCount/reportCount/createdAt/approvedAt/reviewNote; `by_status_and_created_at` + `by_type_and_status` + `by_contributor_tenant` indexes); `contributionVotes` table (contributionId/voterTenantId/voteType/createdAt; `by_contribution` + `by_voter_and_contribution` indexes)
  - `convex/http.ts` — `POST /api/marketplace/contributions`, `GET /api/marketplace/contributions`, `POST /api/marketplace/contributions/vote`, `GET /api/marketplace/stats` (all API-key-guarded)
  - `convex/_generated/api.d.ts` — `communityMarketplace` + `"lib/communityFingerprint"` registered
  - `CommunityMarketplacePanel` dashboard component — approved/fingerprint/rule/pending/under-review count pills, top-5 approved contributions with type+vulnClass+severity+upvote pills; wired in right-column after `TenantGamificationPanel`

- [x] WS-37: Cryptography Weakness Detector — static detection of broken/deprecated crypto in source code
  - `convex/lib/cryptoWeakness.ts` — pure library: `detectSourceFileType` (py/js+ts+jsx+tsx+mjs+cjs/java/go/rb/cs/php/rs); 16 rules across 8 file types covering: CRYPTO_MD5_USAGE/high, CRYPTO_SHA1_USAGE/medium, CRYPTO_DES_USAGE/critical, CRYPTO_RC4_USAGE/critical, CRYPTO_BLOWFISH_USAGE/high, CRYPTO_ECB_MODE/high, CRYPTO_CBC_NO_MAC/medium, CRYPTO_WEAK_RANDOM/high (security-context proximity), CRYPTO_SEEDED_PRNG/high, CRYPTO_WEAK_PASSWORD_HASH/critical (md5/sha1 near password), CRYPTO_RSA_WEAK_KEY/high (512/768/1024/1280/1536-bit), CRYPTO_NO_CERT_VERIFY/critical, CRYPTO_INSECURE_TLS_VERSION/critical (SSLv2/3/TLSv1.0/1.1), CRYPTO_NULL_CIPHER/critical, CRYPTO_BASE64_AS_ENCRYPTION/medium, CRYPTO_HARDCODED_ZERO_IV/high; `scanFileForCryptoWeakness(filename, content)` → `CryptoScanResult`; `combineCryptoResults(results[])` → `CryptoScanSummary`
  - `convex/lib/cryptoWeakness.test.ts` — 61 tests: detectSourceFileType ×12, plus tests for all 16 rules, unknown file type, combineCryptoResults ×7
  - `schema.ts` — `cryptoWeaknessResults` table (tenantId/repositoryId/branch/commitSha/totalFiles/totalFindings/criticalCount/highCount/mediumCount/lowCount/overallRisk/fileResults[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)
  - `convex/cryptoWeaknessIntel.ts` — `recordCryptoWeaknessScan` internalMutation (scans up to 10 files, cap 10 findings/file, inserts result, prunes to 50 per repo); `triggerCryptoWeaknessScanForRepository` public mutation; `getLatestCryptoWeaknessScan` public query; `getCryptoWeaknessScanHistory` lean query; `getCryptoWeaknessSummaryByTenant` query
  - `convex/events.ts` — fire-and-forget `recordCryptoWeaknessScan` filtering `.py|.js|.ts|.jsx|.tsx|.mjs|.cjs|.java|.go|.rb|.cs|.php|.rs` from changedFiles on every push
  - `convex/http.ts` — `GET /api/crypto/weaknesses?tenantSlug=&repositoryFullName=` (API-key-guarded)
  - `convex/_generated/api.d.ts` — `cryptoWeaknessIntel` + `"lib/cryptoWeakness"` registered
  - `RepositoryCryptoWeaknessPanel` dashboard component — overall risk pill + totalFindings + severity pills + files-scanned pill + per-file rows (fileType badge + filename + inline finding list up to 3 per file with severity + title); wired after `RepositoryCicdScanPanel`
  - 1734/1734 tests (60 files pass), tsc clean, biome clean, build clean (159.68 kB)

## Session 33 additions
- [x] WS-35: CI/CD Pipeline Security Scanner — static misconfiguration detection for GitHub Actions, GitLab CI, CircleCI, and Bitbucket Pipelines
  - `convex/lib/cicdSecurity.ts` — pure library: `detectCicdFileType` (`.github/workflows/`→github_actions, `.gitlab-ci.yml`→gitlab_ci, `.circleci/config.yml`→circleci, `bitbucket-pipelines.yml`→bitbucket_pipelines); 17 rules across 4 platforms + 2 cross-platform rules; `scanCicdFile(filename, content)` → `CicdScanResult`; `combineCicdResults(results[])` → `CicdScanSummary`
  - Rule coverage: GitHub Actions (GHACTIONS_SCRIPT_INJECTION/critical, GHACTIONS_PULL_REQUEST_TARGET/high, GHACTIONS_UNPINNED_ACTION/medium, GHACTIONS_EXCESSIVE_PERMISSIONS/high, GHACTIONS_SECRETS_IN_LOGGING/medium, GHACTIONS_SELF_HOSTED_RUNNER/medium); GitLab CI (GITLAB_DIND_PRIVILEGED/critical, GITLAB_CURL_BASH_PIPE/high, GITLAB_ARTIFACT_NO_EXPIRY/low, GITLAB_UNVERIFIED_IMAGE/medium); CircleCI (CIRCLE_CURL_BASH_PIPE/high, CIRCLE_MACHINE_LATEST_IMAGE/medium, CIRCLE_SSH_NO_FINGERPRINT/medium); Bitbucket (BB_PRIVILEGED_PIPELINE/critical, BB_CURL_BASH_PIPE/high); Cross-platform (CI_INLINE_SECRET/high, CI_MISSING_TIMEOUT/low)
  - `convex/lib/cicdSecurity.test.ts` — 48 tests: detectCicdFileType ×12, GitHub Actions rules ×9, GitLab CI rules ×5, CircleCI rules ×4, Bitbucket rules ×2, cross-platform ×5, unknown type ×1, combineCicdResults ×7
  - `schema.ts` — `cicdScanResults` table (totalFiles, totalFindings, criticalCount/highCount/mediumCount/lowCount, overallRisk, fileResults[], summary, computedAt; two indexes)
  - `convex/cicdScanIntel.ts` — `recordCicdScan` internalMutation; `triggerCicdScanForRepository` public mutation; `getLatestCicdScan` public query; `getCicdScanHistory` lean query; `getCicdScanSummaryByTenant` query
  - `convex/events.ts` — fire-and-forget `recordCicdScan` filtering CI/CD file paths from changedFiles on every push
  - `cicdScanIntel` + `lib/cicdSecurity` registered in `_generated/api.d.ts`
  - `RepositoryCicdScanPanel` dashboard component wired after `RepositoryIacScanPanel`
  - 1673 tests (59 files pass, +48 new), tsc clean, biome clean, build clean (156.50 kB)

## Session 32 additions
- [x] WS-34: EPSS Score Integration — FIRST.org exploitation-probability enrichment for breach disclosures
  - `convex/lib/epssEnrichment.ts` — pure library: `classifyEpssRisk` (critical ≥0.5 / high ≥0.2 / medium ≥0.05 / low <0.05), `parseEpssApiResponse` (FIRST.org v3 JSON; lenient, clamped scores, uppercase CVE IDs), `extractCveIds` (sourceRef + aliases, deduplicated), `buildEpssEnrichmentMap`, `enrichDisclosureWithEpss` (case-insensitive, first-match), `buildEpssSummary` (enrichedCount, 4 risk tiers, avgScore, top-10 CVEs sorted desc)
  - `convex/lib/epssEnrichment.test.ts` — 42 tests: classifyEpssRisk ×10, parseEpssApiResponse ×9, extractCveIds ×6, buildEpssEnrichmentMap ×4, enrichDisclosureWithEpss ×6, buildEpssSummary ×7
  - `schema.ts` — `epssScore: v.optional(v.number())` + `epssPercentile: v.optional(v.number())` added to `breachDisclosures`; new `epssSnapshots` table (syncedAt/queriedCveCount/enrichedCount/criticalRiskCount/highRiskCount/mediumRiskCount/lowRiskCount/avgScore/topCves[]/summary; `by_synced_at` index)
  - `convex/epssIntel.ts` — "use node" module: `syncEpssScores` internalAction (loads 500 disclosures, extracts CVE IDs, batches 100/request to FIRST.org API, patches disclosures, persists snapshot); `getRecentDisclosuresForEpss` internalQuery; `patchDisclosureEpss` internalMutation (batch-patch, ID cast); `recordEpssSync` internalMutation (prunes to 30 rows); `getLatestEpssSnapshot` public query; `getEpssEnrichedDisclosures` public query (scored, sorted desc, cap 200); `triggerEpssSync` public mutation
  - `convex/http.ts` — `GET /api/threat-intel/epss` + `POST /api/threat-intel/epss/sync` (both API-key-guarded)
  - `convex/crons.ts` — daily `sync epss scores` cron at 04:00 UTC (after CISA KEV at 03:00)
  - `convex/_generated/api.d.ts` — `epssIntel` + `"lib/epssEnrichment"` registered
  - `src/routes/index.tsx` — `EpssThreatIntelPanel` global dashboard component: sync stats pills (queriedCveCount/enrichedCount/critical+high risk counts/avg probability), topCves rows (risk level pill + CVE ID + exploit-probability pill + percentile pill + package·ecosystem label); self-hides until first sync; wired after `ThreatIntelPanel`
  - Bonus: pre-existing unused `scanned` variable removed from `convex/lib/iacSecurity.ts` (tsc clean)
  - 1625/1625 tests (58 Convex files pass, +42 new), tsc clean, biome clean, build clean (153.00 kB index bundle)

## Rule

- `CURRENT_CONTEXT.md` is the first file to read at the start of every run.
- Keep this file limited to the near-term build queue only.
- When a task becomes active, move it here from the tracker.
- When the active context changes, update `CURRENT_CONTEXT.md`.
- When a workstream or milestone changes, update `PROJECT_TRACKER.md`.
- When scope or build order changes, update `IMPLEMENTATION_SPLIT.md` first.
