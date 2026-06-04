# CyberZen Master Development Backlog

> Exhaustive, hyper-detailed TODO list derived from `/tmp/cyberzen-analysis.md`.
> Every item carries: **Priority** (P0–P3), **Effort** (S/M/L/XL), **Depends on**, and **Files**.
> Effort key: S = 1–2 days, M = 3–5 days, L = 1–2 weeks, XL = 2–4 weeks.

---

# SECTION 1 — CRITICAL: Surface Existing Backend Work (Highest ROI)

> Rationale: ~95 of ~150 Convex top-level modules have no `api.*` reference from `apps/web/src/`. These have 8,600+ passing tests but no human can see them through the app. This section is the single highest-leverage area of the entire backlog.

## 1.1 — Tenant Executive Report (WS-97) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Depends on**: nothing (backend complete)
- **Backend hookup**: `api.executiveReportIntel.getTenantExecutiveReport`
- **Route to create**: `/executive-report` → `apps/web/src/routes/executive-report.tsx`
- **Sidebar entry**: add to `apps/web/src/components/Sidebar.tsx` under "Reports" group with `BarChart3` icon
- **Components to create**:
  - `apps/web/src/components/panels/TenantExecutiveReportPanel.tsx` — top-level KPI tiles (open critical, MTTR, gate block rate, exploit-validated count, SLA breach count)
  - `apps/web/src/components/panels/ExecutiveTrendChart.tsx` — 30/60/90-day trend lines (sparkline-style, hand-rolled SVG, no chart lib unless `recharts` is added)
  - `apps/web/src/components/panels/ExecutiveRepoLeaderboard.tsx` — top 10 worst/best repos
- **UI shows**: KPI tile grid, trend chart, top-N repos table, "share/export" button (PDF + CSV — see §6.20)
- **Props interface**:
  ```ts
  interface TenantExecutiveReportPanelProps {
    report: NonNullable<FunctionReturnType<typeof api.executiveReportIntel.getTenantExecutiveReport>>;
  }
  ```

## 1.2 — Maturity Assessment (CMMI 5-level) (WS-99) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.maturityAssessmentIntel.getLatestMaturityAssessment`
- **Route to create**: `/maturity` → `apps/web/src/routes/maturity.tsx`
- **Sidebar entry**: under "Reports"
- **Components to create**:
  - `apps/web/src/components/panels/RepositoryMaturityPanel.tsx` — per-repo CMMI level
  - `apps/web/src/components/panels/TenantMaturityRadar.tsx` — radar chart across 5 levels
  - `apps/web/src/components/panels/MaturityProgressionTimeline.tsx` — historic level changes
- **UI shows**: current CMMI level (1–5) per repo, dimensions breakdown, gaps to next level, recommended next-action list

## 1.3 — Business Impact (WS-100) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.businessImpactIntel.getBusinessImpactForRepository`
- **Route to add to**: `apps/web/src/routes/repositories.tsx` (panel within `/repositories`) AND new dedicated `/business-impact` summary route at `apps/web/src/routes/business-impact.tsx`
- **Components to create**:
  - `apps/web/src/components/panels/RepositoryBusinessImpactPanel.tsx` — 5-dimension card (financial, regulatory, brand, operational, customer)
  - `apps/web/src/components/panels/TenantBusinessImpactSummary.tsx` — tenant-wide rollup
- **UI shows**: 5 radial gauges per repo, comparison table across repos, "top exposure" callouts

## 1.4 — Cross-Repo Lateral Exposure (WS-20) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.crossRepoIntel.getCrossRepoImpactForTenant`
- **Route to add to**: `apps/web/src/routes/findings.tsx` (new tab "Cross-Repo") AND new dedicated route `/cross-repo` → `apps/web/src/routes/cross-repo.tsx`
- **Components to create**:
  - `apps/web/src/components/panels/TenantCrossRepoPanel.tsx` — repo-x-finding heat-map matrix
  - `apps/web/src/components/panels/CrossRepoFindingDetail.tsx` — drill-down per shared CVE/package
- **UI shows**: matrix grid (rows = repos, cols = shared advisory IDs), click cell → opens drawer with shared dependency chain

## 1.5 — Zero-Day Anomaly Detection (WS-98) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.zeroDayDetectionIntel.getLatestZeroDayDetection`
- **Route to add to**: `apps/web/src/routes/findings.tsx` (new filter chip "Zero-day") AND new dedicated `/zero-day` route at `apps/web/src/routes/zero-day.tsx`
- **Components to create**:
  - `apps/web/src/components/panels/RepositoryZeroDayDetectionPanel.tsx` — novel-pattern findings list with confidence score
  - `apps/web/src/components/panels/ZeroDaySignalGraph.tsx` — anomaly score over time
- **UI shows**: anomaly-flagged code/dep changes, novelty score, "investigate" CTA, link to triage

## 1.6 — Cloud Blast Radius (WS-14 extension) ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.cloudBlastRadiusIntel.getLatestCloudBlastRadius`
- **Route to add to**: `apps/web/src/routes/repositories.tsx` (as `RepositoryCloudBlastRadiusPanel`) — already partially built but cloud variant missing
- **Components to create**:
  - `apps/web/src/components/panels/RepositoryCloudBlastRadiusPanel.tsx` — AWS/GCP/Azure resource fan-out graph
- **UI shows**: cloud resource graph (S3 buckets, IAM roles, secrets reachable), reachable PII tags, blast-radius weight

## 1.7 — Compliance Evidence Collection ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.complianceEvidenceIntel.getEvidencePackageForRepository`
- **Route to add to**: `apps/web/src/routes/compliance.tsx` (new tab "Evidence")
- **Components to create**:
  - `apps/web/src/components/panels/ComplianceEvidencePanel.tsx` — evidence bundle list with framework filter (SOC2/PCI/HIPAA/GDPR/NIS2)
  - `apps/web/src/components/panels/EvidenceArtifactCard.tsx` — single artifact row with download CTA
- **UI shows**: control-ID-keyed evidence list, status (collected / missing / stale), bulk export button

## 1.8 — LLM Certification ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.llmCertificationIntel.getLatestCertificationForRepository`
- **Route to add to**: `apps/web/src/routes/agents.tsx` (new tab "LLM Certification")
- **Components to create**:
  - `apps/web/src/components/panels/LlmCertificationPanel.tsx` — cert status per LLM-using path
  - `apps/web/src/components/panels/LlmCertificationHistory.tsx` — historical cert outcomes
- **UI shows**: certified/uncertified/pending status, last-cert timestamp, failure reasons, re-cert button

## 1.9 — Model Provenance ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: §4.2 (`computeProvenanceScore` impl)
- **Backend hookup**: `api.modelProvenanceIntel.getLatestProvenanceForRepository`
- **Route to add to**: `apps/web/src/routes/agents.tsx` (new tab "Model Provenance")
- **Components to create**:
  - `apps/web/src/components/panels/ModelProvenancePanel.tsx` — model→hash→source chain
  - `apps/web/src/components/panels/ModelProvenanceChainViewer.tsx` — DAG-style visualization
- **UI shows**: model lineage (training data → fine-tune → deploy), signature verification status, provenance score

## 1.10 — Model Supply Chain ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.modelSupplyChainIntel.getLatestModelSupplyChain`
- **Route to add to**: `apps/web/src/routes/supply-chain.tsx` (new tab "Model SC")
- **Components to create**:
  - `apps/web/src/components/panels/ModelSupplyChainPanel.tsx` — HF/registry pull list, signature status
- **UI shows**: model registry pulls, signed/unsigned, integrity hash matches, vulnerable model version alerts

## 1.11 — Observability Intel ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Depends on**: nothing
- **Backend hookup**: `api.observabilityIntel.getLatestObservabilityIntel`
- **Route to add to**: `apps/web/src/routes/integrations.tsx` (new tab "Observability")
- **Components to create**:
  - `apps/web/src/components/panels/ObservabilityIntelPanel.tsx` — Datadog/NewRelic/Grafana push status
- **UI shows**: outbound push history, failed pushes, ack latency

## 1.12 — SIEM Intel ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Depends on**: nothing
- **Backend hookup**: `api.siemIntel.getLatestSiemPushHistory`
- **Route to add to**: `apps/web/src/routes/integrations.tsx` (new tab "SIEM")
- **Components to create**:
  - `apps/web/src/components/panels/SiemIntelPanel.tsx` — Splunk/Elastic push log + replay button
- **UI shows**: push attempts, success/fail, payload preview, retry CTA

## 1.13 — Security Posture (aggregate) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.securityPosture.getSecurityPostureReport`
- **Route**: `/posture` → `apps/web/src/routes/posture.tsx` ✅
- **Components**:
  - `apps/web/src/components/panels/SecurityPostureSummaryPanel.tsx` ✅ — SVG arc gauge (0–100), posture level pill, priority actions
  - `apps/web/src/components/panels/PosturePillarBreakdown.tsx` ✅ — horizontal bars per pillar (findings, attack surface, regulatory, red/blue, learning)
- **Sidebar**: `apps/web/src/components/Sidebar.tsx` — Security Posture entry under Reports ✅
- **UI shows**: posture gauge, pillar bars, "biggest drag on score" list ✅

## 1.14 — PR Generation History (WS-11) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.prGeneration.listGeneratedPrsForRepository`
- **Route to add to**: `apps/web/src/routes/remediation.tsx` (new tab "Auto-PRs")
- **Components to create**:
  - `apps/web/src/components/panels/AutoPrFeedPanel.tsx` — PR list with diff preview
  - `apps/web/src/components/panels/AutoPrDetailDrawer.tsx` — full reasoning chain, sandbox validation status, merge/close CTAs
- **UI shows**: PR list (status, target repo, branch, reasoning summary), drill-down with reasoning, link out to GitHub

## 1.15 — Post-Fix Validation ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing (preferably ship together with 1.14)
- **Backend hookup**: `api.postFixValidation.listValidationRunsForRepository`
- **Route to add to**: `apps/web/src/routes/remediation.tsx` (new tab "Validation")
- **Components to create**:
  - `apps/web/src/components/panels/PostFixValidationPanel.tsx` — validation runs
  - `apps/web/src/components/panels/PostFixValidationDetail.tsx` — pre/post diff, regression flags
- **UI shows**: validation status per fix, regression detection, sandbox URL link

## 1.16 — Sandbox Exploit Validation (WS-09, the README hero claim) ✅ COMPLETED
- **Priority**: P0
- **Effort**: L
- **Depends on**: nothing
- **Backend hookup**: `api.sandboxValidation.listExploitValidationRuns`
- **Route**: `/exploit-validation` → `apps/web/src/routes/exploit-validation.tsx`
- **Sidebar entry**: under "Security" — FlaskConical icon
- **Components created**:
  - `apps/web/src/components/panels/ExploitValidationPanel.tsx` — list of validation runs with PoC status
  - `apps/web/src/components/panels/ExploitPoCViewer.tsx` — read-only code box showing PoC curl/python payload
  - `apps/web/src/components/panels/ExploitReproRecording.tsx` — HTTP repro script display, asciinema-style playback placeholder
- **UI shows**: PoC code, HTTP repro script, asciinema recording placeholder, validation verdict, run metadata

## 1.17 — Gate Enforcement Details ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.gateEnforcement.listGateDecisionsForRepository`, `api.gateEnforcement.getGateDecisionDetail`
- **Route to add to**: `apps/web/src/routes/ci-cd.tsx` (new tab "Gate Decisions")
- **Components to create**:
  - `apps/web/src/components/panels/GateDecisionListPanel.tsx` — gate decisions feed
  - `apps/web/src/components/panels/GateDecisionDetailDrawer.tsx` — full policy trace, override history, replay
- **UI shows**: decisions feed (pass/block/override), policy trace, override-justification log

## 1.18 — Drift Posture Aggregate Page ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.driftPostureIntel.getLatestDriftPosture`
- **Route to create**: `/drift-posture` → `apps/web/src/routes/drift-posture.tsx`
- **Sidebar entry**: under "Posture"
- **Components to create**:
  - `apps/web/src/components/panels/RepositoryDriftPosturePanel.tsx` — aggregate panel (40 scanner roll-up)
  - `apps/web/src/components/panels/DriftPostureScannerGrid.tsx` — grid of 40 scanner tiles
- **UI shows**: aggregate drift score, top contributors, link-out to each scanner detail

## 1.19 — The 40 Individual Drift Detector Panels ✅ COMPLETED
> Each: P1, S (4–6h once template exists), depends on §1.18 template, file pattern is identical.

Template (replace `Xxx` for each):
- **Component**: `apps/web/src/components/panels/RepositoryXxxDriftPanel.tsx`
- **Backend hookup**: `api.xxxDriftIntel.getLatestXxxDriftForRepository`
- **Embedded into**: `apps/web/src/routes/drift-posture.tsx` via tabs or accordion
- **Props**: `{ repositoryId: Id<"repositories"> }`
- **UI shows**: rule-level pass/fail table, count of misconfig, "evidence" expandables

The 40 panels to build:
1. `RepositoryAiMlSecurityDriftPanel` — `api.aiMlSecurityDriftIntel.*`
2. `RepositoryApiSecurityDriftPanel` — `api.apiSecurityDriftIntel.*`
3. `RepositoryArtifactRegistryDriftPanel` — `api.artifactRegistryDriftIntel.*`
4. `RepositoryBackupDrSecurityDriftPanel` — `api.backupDrSecurityDriftIntel.*`
5. `RepositoryCertPkiDriftPanel` — `api.certPkiDriftIntel.*`
6. `RepositoryCfgMgmtSecurityDriftPanel` — `api.cfgMgmtSecurityDriftIntel.*`
7. `RepositoryCicdPipelineSecurityDriftPanel` — `api.cicdPipelineSecurityDriftIntel.*`
8. `RepositoryCloudSecurityDriftPanel` — `api.cloudSecurityDriftIntel.*`
9. `RepositoryContainerHardeningDriftPanel` — `api.containerHardeningDriftIntel.*`
10. `RepositoryDataPipelineDriftPanel` — `api.dataPipelineDriftIntel.*`
11. `RepositoryDepMgrSecurityDriftPanel` — `api.depMgrSecurityDriftIntel.*`
12. `RepositoryDevSecToolsDriftPanel` — `api.devSecToolsDriftIntel.*`
13. `RepositoryDnsSecurityDriftPanel` — `api.dnsSecurityDriftIntel.*`
14. `RepositoryEmailSecurityDriftPanel` — `api.emailSecurityDriftIntel.*`
15. `RepositoryEndpointSecurityDriftPanel` — `api.endpointSecurityDriftIntel.*`
16. `RepositoryIdentityAccessDriftPanel` — `api.identityAccessDriftIntel.*`
17. `RepositoryIotEmbeddedSecurityDriftPanel` — `api.iotEmbeddedSecurityDriftIntel.*`
18. `RepositoryK8sAdmissionDriftPanel` — `api.k8sAdmissionDriftIntel.*`
19. `RepositoryMessagingSecurityDriftPanel` — `api.messagingSecurityDriftIntel.*`
20. `RepositoryMlAiPlatformDriftPanel` — `api.mlAiPlatformDriftIntel.*`
21. `RepositoryMobileAppSecurityDriftPanel` — `api.mobileAppSecurityDriftIntel.*`
22. `RepositoryNetworkFirewallDriftPanel` — `api.networkFirewallDriftIntel.*`
23. `RepositoryNetworkMonitoringDriftPanel` — `api.networkMonitoringDriftIntel.*`
24. `RepositoryObservabilitySecurityDriftPanel` — `api.observabilitySecurityDriftIntel.*`
25. `RepositoryOsSecurityHardeningDriftPanel` — `api.osSecurityHardeningDriftIntel.*`
26. `RepositoryRuntimeSecurityDriftPanel` — `api.runtimeSecurityDriftIntel.*`
27. `RepositorySecretMgmtDriftPanel` — `api.secretMgmtDriftIntel.*`
28. `RepositorySecurityConfigDriftPanel` — `api.securityConfigDriftIntel.*`
29. `RepositoryServerlessFaasDriftPanel` — `api.serverlessFaasDriftIntel.*`
30. `RepositoryServiceMeshSecurityDriftPanel` — `api.serviceMeshSecurityDriftIntel.*`
31. `RepositorySiemSecurityDriftPanel` — `api.siemSecurityDriftIntel.*`
32. `RepositorySsoProviderDriftPanel` — `api.ssoProviderDriftIntel.*`
33. `RepositoryStorageDataSecurityDriftPanel` — `api.storageDataSecurityDriftIntel.*`
34. `RepositorySupplyChainAttestationDriftPanel` — `api.supplyChainAttestationDriftIntel.*`
35. `RepositoryVirtualizationSecurityDriftPanel` — `api.virtualizationSecurityDriftIntel.*`
36. `RepositoryVoipSecurityDriftPanel` — `api.voipSecurityDriftIntel.*`
37. `RepositoryVpnRemoteAccessDriftPanel` — `api.vpnRemoteAccessDriftIntel.*`
38. `RepositoryWebServerSecurityDriftPanel` — `api.webServerSecurityDriftIntel.*`
39. `RepositoryWirelessRadiusDriftPanel` — `api.wirelessRadiusDriftIntel.*`
40. `RepositoryDatabaseSecurityDriftPanel` — `api.databaseSecurityDriftIntel.*` (already partially shown in `compliance.tsx` — extract into its own panel)

## 1.20 — Security Timeline Page ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Depends on**: nothing
- **Backend hookup**: `api.securityTimelineIntel.getTimelineForRepository`
- **Route to create**: `/timeline` → `apps/web/src/routes/timeline.tsx`
- **Components to create**:
  - `apps/web/src/components/panels/SecurityTimelinePanel.tsx` — chronological event stream with filter chips (finding, gate, fix, escalation)
- **UI shows**: timeline with collapsible event nodes, repo/time filters, jump-to-event deep links

---

# SECTION 2 — FRONTEND REFACTORING: Modularize Long Routes

> Goal: shrink each long route to <150 lines that wires panels imported from `apps/web/src/components/panels/`. Bridges tracker-claim ↔ code-reality gap.

## 2.1 — `repositories.tsx` extraction (10 queries → 10+ panels) ✅ COMPLETED
- **Priority**: P0
- **Effort**: L
- ✅ COMPLETED [2026-05-16]
- **Depends on**: nothing
- **Parent route after refactor**: `apps/web/src/routes/repositories.tsx` (orchestrator only)
- **Panels to extract**:
  1. `RepositoryListPanel` — `apps/web/src/components/panels/RepositoryListPanel.tsx` — props `{ repos: Repo[] }`
  2. `RepositoryTrustScorePanel` — `.../RepositoryTrustScorePanel.tsx` — props `{ repositoryId, score }`
  3. `RepositoryBlastRadiusPanel` — `.../RepositoryBlastRadiusPanel.tsx`
  4. `RepositoryAttackSurfacePanel` — `.../RepositoryAttackSurfacePanel.tsx`
  5. `RepositorySlaPanel` — `.../RepositorySlaPanel.tsx`
  6. `RepositoryRemediationQueuePanel` — `.../RepositoryRemediationQueuePanel.tsx`
  7. `RepositoryHealthScorePanel` — `.../RepositoryHealthScorePanel.tsx`
  8. `RepositoryLearningPanel` — `.../RepositoryLearningPanel.tsx`
  9. `RepositoryHoneypotPanel` — `.../RepositoryHoneypotPanel.tsx`
  10. `RepositoryRiskAcceptancePanel` — `.../RepositoryRiskAcceptancePanel.tsx`
- Each panel takes typed props from a Convex query return type via `FunctionReturnType`.

## 2.2 — `compliance.tsx` extraction (9 queries → 9 panels) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Panels extracted** (all in `apps/web/src/components/panels/`):
  1. `RegulatoryDriftPanel.tsx` ✅ — SOC2/GDPR/HIPAA/PCI/NIS2 status
  2. `ComplianceAttestationPanel.tsx` ✅
  3. `ComplianceRemediationPanel.tsx` ✅
  4. `LicenseCompliancePanel.tsx` ✅ (merged licenseCompliance + licenseScan)
  5. ~~`LicenseScanPanel.tsx`~~ — merged into LicenseCompliancePanel
  6. `SecurityDebtPanel.tsx` ✅
  7. `RepositoryDatabaseSecurityDriftPanel.tsx` ✅ (already exists from §1.19 #40)
  8. `SensitiveFileScanPanel.tsx` ✅
  9. ~~`ComplianceFrameworkSelector.tsx`~~ — not needed as standalone (tab-bar kept inline)

## 2.3 — `supply-chain.tsx` extraction (11 queries → 11 panels) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: M
- **Panels** (in `apps/web/src/components/panels/`):
  1. `SupplyChainPosturePanel.tsx` ✅
  2. `PromptInjectionRecentScansPanel.tsx` ✅
  3. `PromptInjectionSupplyChainPanel.tsx` ✅
  4. `RepositoryConfusionScanPanel.tsx` ✅
  5. `RepositoryMaliciousScanPanel.tsx` ✅
  6. `RepositoryAbandonmentPanel.tsx` ✅
  7. `RepositoryEolPanel.tsx` ✅
  8. `RepositoryCryptoWeaknessPanel.tsx` ✅
  9. `TrafficAnomalyPanel.tsx` ✅
  10. `SecretDetectionPanel.tsx` ✅
  11. `SupplyChainOverviewHeader.tsx` ✅ — shared header tiles

## 2.4 — `ci-cd.tsx` extraction (10 queries → 10 panels) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- ✅ COMPLETED [2026-05-16]
- **Panels**:
  1. `RepositoryCicdScanPanel.tsx` ✅
  2. `BranchProtectionPanel.tsx` ✅
  3. `BuildConfigPanel.tsx` ✅
  4. `CommitMessagePanel.tsx` ✅
  5. `GitIntegrityPanel.tsx` ✅
  6. `HighRiskChangePanel.tsx` ✅
  7. `DepLockPanel.tsx` ✅
  8. `TestCoverageGapPanel.tsx` ✅
  9. `RepositoryIacScanPanel.tsx` ✅
  10. `GateDecisionListPanel.tsx` ✅ (also created in §1.17)

## 2.5 — `findings.tsx` extraction ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- ✅ COMPLETED [2026-05-16]
- **Panels extracted** (all in `apps/web/src/components/panels/`):
  1. `FindingsTablePanel.tsx` ✅ — list with severity/repo/state filters + renderDetail callback
  2. `FindingDetailDrawer.tsx` ✅ — drawer for selected finding (includes BlastRadius + Triage + RemediationEntry)
  3. `BlastRadiusPanel.tsx` ✅ — selected finding's blast radius
  4. `FindingTriageActionBar.tsx` ✅ — FP mutation CTA (extensible for accept-risk / snooze / override)
  5. `FindingsSeverityFilterChips.tsx` ✅ — severity filter chip group with counts
  6. `FindingsExportBar.tsx` — CSV/PDF export buttons (see §6.20) — deferred
  7. `FindingZeroDayChip.tsx` — flag for zero-day-detected items (see §1.5) — deferred

## 2.6 — `agents.tsx` extraction (7 queries → 7 panels) ✅ DONE
- **Priority**: P1
- **Effort**: M
- **Status**: Completed — extracted 4 inline panels from `RepoAgentIntelligence`
- **Panels**:
  1. `RedBlueAdversarialPanel.tsx` ✅
  2. `RedAgentEscalationPanel.tsx` — deferred (data merged into RedBlueAdversarialPanel)
  3. `AgentMemoryPanel.tsx` ✅
  4. `LearningProfilePanel.tsx` ✅
  5. `RepositoryAgenticWorkflowPanel.tsx` — deferred (stays inline for now)
  6. `SemanticFingerprintPanel.tsx` ✅
  7. `BlueAgentDefensePanel.tsx` — deferred (data merged into RedBlueAdversarialPanel)

## 2.7 — `breach-intel.tsx` extraction ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- ✅ COMPLETED [2026-05-16]
- **Panels**:
  1. `BreachIntelFeedPanel.tsx` ✅ — disclosure watchlist with severity/match status pills
  2. `EpssThreatIntelPanel.tsx` ✅ — EPSS snapshot with tracked CVEs + top CVE list
  3. `Tier3SignalsPanel.tsx` ✅ — Tier-3 intel signals with threat level pills
  4. `BreachIntelSearchBar.tsx` — deferred (not yet needed)

## 2.8 — Shared panel infrastructure ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- ✅ COMPLETED [2026-05-16]
- **Depends on**: starting any of §2.1–2.7
- **Files created**:
  - `apps/web/src/components/panels/SharedPanelComponents.tsx` ✅ — exports `PanelSkeleton`, `EmptyState`, `PanelContainer`
  - `PanelSkeleton` ✅ — loading placeholder with configurable count/rows
  - `EmptyState` ✅ — "no data" placeholder with icon + message
  - `PanelContainer` ✅ — shared frame with title, subtitle, actions slot

---

# SECTION 3 — Wire Missing Mutations & Actions

> Today only 4 mutations are wired (`acceptWorkspaceInvite`, `createWorkspaceInvite`, `provisionWorkspace`, `markFalsePositive`). Zero `useAction` calls. Below: every backend mutation/action that needs a UI trigger.

## 3.1 — Risk Acceptance create/revoke ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: S
- **Backend**: `api.riskAcceptanceIntel.createRiskAcceptance`, `api.riskAcceptanceIntel.revokeRiskAcceptance`
- **Route**: `apps/web/src/routes/findings.tsx` + `repositories.tsx`
- **UI element**: "Accept Risk" button → modal with justification, expiry-date picker, approver field. "Revoke" button in `RepositoryRiskAcceptancePanel`.
- **Component**: `apps/web/src/components/modals/AcceptRiskModal.tsx` ✅
- **Workflow**: user → "Accept Risk" → modal → mutation fires → list refreshes. ✅

## 3.2 — Gate Decision Override ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **Backend**: `api.gateEnforcement.overrideGateDecision`
- **Route**: `apps/web/src/routes/ci-cd.tsx` (Gate Decisions tab)
- **UI element**: "Override" button in `GateDecisionDetailDrawer` → confirm modal with justification textarea
- **Component**: `apps/web/src/components/modals/GateOverrideModal.tsx`

## 3.3 — Finding Snooze ✅ DONE
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.findingTriage.snoozeFinding` — implemented in `apps/web/convex/findingTriage.ts`
- **Route**: `apps/web/src/routes/findings.tsx`
- **UI element**: "Snooze" button in `FindingTriageActionBar` → modal with 1d/7d/30d duration picker + optional reason textarea
- **Component**: `apps/web/src/components/modals/SnoozeFindingModal.tsx`

## 3.4 — Force re-run scans ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.events.dispatchScannerForRepository` (action — wrap existing fire-and-forget in events.ts)
- **Route**: `apps/web/src/routes/repositories.tsx`
- **UI element**: "Re-scan" button per scanner per repo
- **Component**: `apps/web/src/components/RescanButton.tsx`

## 3.5 — SLA Policy Editor ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Backend**: `api.slaIntel.upsertSlaPolicy`
- **Route**: new `/settings/sla` → `apps/web/src/routes/settings/sla.tsx`
- **UI element**: per-severity hours-to-resolve form
- **Component**: `apps/web/src/components/settings/SlaPolicyForm.tsx`

## 3.6 — Community contribution accept/reject ✅ COMPLETED
- **Priority**: P2
- **Effort**: S
- **Backend**: `api.communityMarketplace.acceptContribution`, `api.communityMarketplace.rejectContribution`
- **Route**: `apps/web/src/routes/integrations.tsx`
- **UI element**: accept/reject buttons next to each community contribution
- **Component**: `apps/web/src/components/panels/CommunityMarketplacePanel.tsx` (already exists but needs CTAs)

## 3.7 — Tenant member management ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Backend**: `api.workspaceAuth.inviteMember`, `api.workspaceAuth.removeMember`, `api.workspaceAuth.changeRole` (some may need backend addition — see §4)
- **Route**: new `/settings/team` → `apps/web/src/routes/settings/team.tsx`
- **UI element**: member list table, "Invite" button, role dropdown
- **Component**: `apps/web/src/components/settings/MemberListTable.tsx`, `InviteMemberModal.tsx`

## 3.8 — Advisory sync trigger ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.advisorySync.runManualSync` (action)
- **Route**: `apps/web/src/routes/breach-intel.tsx`
- **UI element**: "Sync Now" button in `BreachIntelFeedPanel`
- **Workflow**: click → action fires → loading state → toast on completion

## 3.9 — Auto-remediation dispatch ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.autoRemediationIntel.dispatchRemediation`
- **Route**: `apps/web/src/routes/remediation.tsx`
- **UI element**: "Dispatch" button per remediation row
- **Modal**: confirm with summary of changes

## 3.10 — PR generation trigger ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.prGeneration.generatePrForFinding`
- **Route**: `apps/web/src/routes/findings.tsx`
- **UI element**: "Generate PR" button on individual finding
- **Workflow**: click → action → progress indicator → link to created PR

## 3.11 — Sandbox validation manual trigger ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.sandboxValidation.runValidationForFinding`
- **Route**: `apps/web/src/routes/exploit-validation.tsx`
- **UI element**: "Re-validate" button per validation row

✅ COMPLETED [2026-05-16] — `RevalidateButton` component in `ExploitValidationPanel.tsx` with loading spinner, success/error states, and `useMutation(api.sandboxValidation.runValidationForFinding)`.

## 3.12 — Honeypot deploy/teardown ✅ COMPLETED
- **Priority**: P2
- **Effort**: S
- **Backend**: `api.honeypotIntel.deployHoneypot`, `api.honeypotIntel.tearDownHoneypot`
- **Route**: `apps/web/src/routes/repositories.tsx`
- **UI element**: deploy/teardown CTAs in `RepositoryHoneypotPanel`

✅ COMPLETED [2026-05-16] — `HoneypotCtaButtons` component in `repositories.tsx` with Deploy (`signal-button`) and Teardown (`signal-button secondary-button`) using `useMutation`, loading spinners, and feedback messages.

## 3.13 — Workspace settings updates ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Backend**: `api.workspaceAuth.updateWorkspaceSettings`
- **Route**: new `/settings/general` → `apps/web/src/routes/settings/general.tsx`
- **UI element**: workspace name, default policy, deployment-mode dropdown

## 3.14 — Repository disconnect/reconnect ✅ COMPLETED
- **Priority**: P2
- **Effort**: S
- **Backend**: `api.repositories.disconnect`, `api.repositories.reconnect` (add if missing)
- **Route**: `apps/web/src/routes/repositories.tsx`
- **UI element**: per-repo dropdown menu

---

# SECTION 4 — Fix Unimplemented Functions

## 4.1 — `computeVendorRiskScore` (vendor risk) ✅ COMPLETED
- **Priority**: P0
✅ COMPLETED [2026-05-16]
- **Effort**: S
- **File**: `apps/web/convex/vendorTrust.ts:20`
- **Current state**: `TODO: Implement computeVendorRiskScore below (5–10 lines of logic).`
- **What it should do**: Aggregate OAuth scope sensitivity + breach-history weight + advisory volume + last-update recency into a 0–100 risk score for each vendor record.
- **Implementation approach**:
  1. Input: `{ scopes: string[]; breachCount: number; advisoryCount: number; lastUpdated: number; }`
  2. Sensitive-scope set: `repo`, `write:packages`, `admin:org`, `delete_repo`, `workflow` → weight 25 each (capped 50)
  3. breachCount weight = `Math.min(breachCount * 10, 30)`
  4. advisoryCount weight = `Math.min(advisoryCount * 2, 20)`
  5. staleness (now − lastUpdated > 180d) → +10
  6. Return `Math.min(score, 100)`
  7. Add unit tests in `apps/web/convex/lib/vendorTrust.test.ts` covering: empty scopes, all sensitive scopes, max breach, stale vendor.

## 4.2 — `computeProvenanceScore` (model provenance) ✅ COMPLETED
- **Priority**: P1
✅ COMPLETED [2026-05-16]
- **Effort**: S
- **File**: `apps/web/convex/lib/modelProvenance.ts:310`
- **Current state**: `TODO: Implement the provenance score calculation.`
- **What it should do**: Score 0–100 reflecting completeness of model lineage (signed source, training data manifest, fine-tune attestation, deployment hash match).
- **Implementation approach**:
  1. Input: `ProvenanceChain` with fields `{ sourceSignature, trainingDataManifest, fineTuneAttestation, deploymentHashMatch, sbomPresent }`
  2. Each present → +20 (5 components × 20 = 100)
  3. If `deploymentHashMatch === false` → cap score at 50
  4. Add tests in `lib/modelProvenance.test.ts`.

## 4.3 — `computeEolReport` (EOL detection) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **File**: `apps/web/convex/lib/eolDetection.ts:571`
- **Current state**: ✅ COMPLETED — function fully implemented, TODO comment removed, 46 tests passing
- **What it does**: Walk dependency tree, look up each `(ecosystem, name, version)` against `EOL_DATABASE` (33 entries including Node 10/12/14/16, Python 2.7/3.6/3.7/3.8, etc.). Returns `{ findings, eolCount, nearEolCount, supportedCount, unknownCount, overallStatus, summary }`. Deduplicates by `ecosystem:name:version`.
- **Tests**: `apps/web/convex/lib/eolDetection.test.ts` — 46 tests all passing

## 4.4 — `repositoryScore` (trust score) ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **File**: `apps/web/convex/lib/trustScore.ts:168`
- **Current state**: ✅ COMPLETED — new `repositoryScore()` function added with weighted-average formula; `aggregateTrustScore()` also has Strategy B. 19 tests passing.
- **Formula**: `health×0.25 + posture×0.20 + findingDensityScore(100−min(critical×5+high×2+medium,100))×0.20 + slaScore(100−min(slaBreachRate×100,100))×0.20 + learningConfidence×0.15`. Rounded to int, clamped 0–100.
- **Tests**: `apps/web/convex/lib/trustScore.test.ts` — 19 tests all passing

## 4.5 — User-contribution predicate hooks (non-blocking but underfire detectors) ✅ COMPLETED
- **Priority**: P2
✅ COMPLETED [2026-05-16]
- **Effort**: S each
- **Files** (all 6 predicates implemented with comprehensive positive/negative tests):
  1. `apps/web/convex/lib/apiSecurityDrift.ts:246` — `isGraphQLSecurityConfig` — matches graphql-shield, graphql-auth, apollo+security qualifier, security dir context ✅
  2. `apps/web/convex/lib/apiSecurityDrift.ts:246` — same function handles both GraphQL config patterns (merged into one predicate) ✅
  3. `apps/web/convex/lib/databaseSecurityDrift.ts:337` — `isDatabaseMigrationSecurityFile` — matches migration dirs + security keywords in basename/parent ✅
  4. `apps/web/convex/lib/containerHardeningDrift.ts:294` — `isKubeExternalSecretConfig` — matches ExternalSecret, SecretStore, SealedSecret, vault-agent patterns ✅
  5. `apps/web/convex/lib/cloudSecurityDrift.ts:330` — `isAuditLoggingConfig` — matches CloudTrail, Stackdriver, Azure activity-log, audit-log, siem-config identifiers ✅
  6. `apps/web/convex/lib/testCoverageGap.ts:222` — `isSecurityMiddlewareSource` — matches middleware+security keyword conjunction (auth/csrf/helmet/rate-limit) ✅
- **Tests**: 566 tests passing across 5 test files covering all 6 predicates with positive and negative examples.

---

# SECTION 5 — Integrations Page: Replace Static Data with Live Data

## 5.1 — New schema tables ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **File**: `apps/web/convex/schema.ts` — add tables:
  ```ts
  integrationCatalog: defineTable({
    slug: v.string(),
    label: v.string(),
    category: v.union(v.literal("vcs"), v.literal("ci"), v.literal("chat"), v.literal("paging"), v.literal("ticket"), v.literal("siem"), v.literal("obs")),
    envVarName: v.string(),
    description: v.string(),
    webhookPathTemplate: v.optional(v.string()),
    docsUrl: v.optional(v.string()),
  }).index("by_slug", ["slug"]),

  integrationStatus: defineTable({
    tenantId: v.id("tenants"),
    integrationSlug: v.string(),
    configured: v.boolean(),
    lastSuccessAt: v.optional(v.number()),
    lastErrorAt: v.optional(v.number()),
    lastErrorMessage: v.optional(v.string()),
    health: v.union(v.literal("healthy"), v.literal("degraded"), v.literal("offline")),
  })
    .index("by_tenant", ["tenantId"])
    .index("by_tenant_slug", ["tenantId", "integrationSlug"]),
  ```

## 5.2 — Seed catalog ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **File**: `apps/web/convex/seed.ts` — extend to insert the existing hardcoded list from `integrations.tsx:66-115` into `integrationCatalog`.

## 5.3 — New Convex queries ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **Files**:
  - `apps/web/convex/integrations.ts` (new) — exports:
    - `listIntegrationCatalog` — public query
    - `listIntegrationStatusForTenant` — workspace-scoped
    - `recomputeIntegrationStatus` (internal mutation, called from cron)

## 5.4 — Refactor `integrations.tsx` ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **File**: `apps/web/src/routes/integrations.tsx`
- **Changes**:
  - Remove hardcoded `WEBHOOK_INTEGRATIONS` (L66-115)
  - Remove hardcoded `INTEGRATION_STATUS` (L280-323)
  - Replace with `useQuery(api.integrations.listIntegrationCatalog)` and `useQuery(api.integrations.listIntegrationStatusForTenant)`

## 5.5 — Recompute status cron ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **File**: `apps/web/convex/crons.ts` — add cron that runs `recomputeIntegrationStatus` every 5 min (reads env vars + last-success timestamps from notifier modules).

---

# SECTION 6 — New Features (Gaps vs Competitors)

## 6.1 — User Management / RBAC ✅ COMPLETED
- **Priority**: P0
- **Effort**: L
- **Depends on**: §3.7
- **Schema additions** (`apps/web/convex/schema.ts`):
  - `roles` table: `{ tenantId, name, permissions: string[] }` ✅
  - `permissionGrants` table: `{ tenantId, userId, roleId }` ✅
- **Backend** (`apps/web/convex/rbac.ts` new): ✅
  - `listRoles`, `createRole`, `updateRole`, `deleteRole` ✅
  - `assignRoleToUser`, `removeRoleFromUser` ✅
  - Audit log entries for all mutations ✅
- **Frontend**: ✅
  - Route `/settings/roles` → `apps/web/src/routes/settings/roles.tsx` ✅
  - Components: `RoleListTable`, `RoleEditorDrawer` (inline) ✅
- **Sidebar**: Roles entry under System group ✅

## 6.2 — Notification Center + Alert Preferences ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Schema**: `notifications` (id, userId, tenantId, type, payload, readAt, createdAt), `notificationPreferences` (userId, channel, type, enabled)
- **Backend**: `apps/web/convex/notifications.ts` — list/mark-read/mark-all-read; cron to enqueue from findings/gate events
- **Frontend**:
  - `apps/web/src/components/NotificationBell.tsx` in `Header.tsx`
  - `apps/web/src/components/NotificationDrawer.tsx`
  - Route `/settings/notifications` → preferences form

## 6.3 — Custom Dashboard Builder / Widget System ✅ COMPLETED
- **Priority**: P2
- **Effort**: XL
- ✅ COMPLETED [2026-05-16]
- **Schema**: `dashboards` (id, userId, tenantId, name, layout JSON, isDefault, createdAt, updatedAt) ✅
- **Backend**: `apps/web/convex/dashboards.ts` ✅ — listDashboards, getDashboard, createDashboard, updateDashboard, deleteDashboard
- **Frontend**:
  - Route `/dashboards` → `apps/web/src/routes/dashboards/index.tsx` ✅ — dashboard list + create
  - Route `/dashboards/$id` → `apps/web/src/routes/dashboards/$id.tsx` ✅ — render dashboard with widget grid
  - WidgetCatalog preview, CreateDashboardButton modal, DashboardCard list ✅
- **Sidebar**: Dashboard Builder entry under Overview group ✅

## 6.4 — API Key Management UI ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Schema**: `apiKeys` (id, tenantId, name, hashedSecret, prefix, scopes: string[], lastUsedAt, expiresAt, revokedAt) ✅
- **Backend**: `apps/web/convex/apiKeys.ts` — `create/list/rotate/revoke` ✅
- **Frontend**: ✅
  - Route `/settings/api-keys` → `apps/web/src/routes/settings/api-keys.tsx` ✅
  - `ApiKeyList` with status pills, rotate/revoke buttons ✅
  - `CreateApiKeyModal` with scope selector, expiry picker ✅
  - `SecretRevealModal` with one-time-display warning + copy button ✅
- **Sidebar**: API Keys entry under System group ✅

## 6.5 — Audit Log Viewer ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- **Schema**: `auditLog` (tenantId, actorUserId, action, resourceType, resourceId, payload, at, ip, ua) ✅
- **Backend**: `apps/web/convex/auditLog.ts` — `listForTenant` query with action/resourceType/actor/date filters ✅
  - Audit log entries appended by rbac.ts and apiKeys.ts mutations ✅
- **Frontend**: ✅
  - Route `/audit-log` → `apps/web/src/routes/audit-log.tsx` ✅
  - `AuditLogTable` with color-coded action pills, expandable payload details ✅
  - `AuditLogFilters` with action, resource type, and search filters ✅
- **Sidebar**: Audit Log entry under Security group ✅

## 6.6 — Webhook Configuration UI ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
- **Schema**: `outgoingWebhooks` (id, tenantId, url, secret, eventTypes: string[], enabled, lastDeliveryAt, failureCount)
- **Backend**: `apps/web/convex/outgoingWebhooks.ts` — CRUD + test-fire action
- **Frontend**:
  - Route `/settings/webhooks` → `apps/web/src/routes/settings/webhooks.tsx`
  - `WebhookListTable.tsx`, `WebhookEditorDrawer.tsx`, `WebhookTestFireButton.tsx`, `WebhookDeliveryHistoryDrawer.tsx`

## 6.7 — Scan Scheduling + On-Demand Triggers ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Schema**: `scanSchedules` (id, tenantId, scannerSlug, cronExpression, enabled, repositoryIds, lastRunAt, description) ✅
- **Backend**: `apps/web/convex/scanScheduling.ts` — `listSchedules`, `getSchedule`, `createSchedule`, `updateSchedule`, `deleteSchedule`, `runScanNow` ✅
- **Frontend**: ✅
  - Route `/settings/scans` → `apps/web/src/routes/settings/scans.tsx` ✅
  - `ScanScheduleTable` with scanner, cron, status, run-now button ✅
  - `ScanScheduleEditor` drawer with scanner dropdown, cron input, description ✅
  - `RunNowButton` with loading state ✅
- **Sidebar**: Scan Schedules entry under System group ✅

## 6.8 — Finding Suppression Rules Engine ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Schema**: `suppressionRules` (id, tenantId, pattern, scope, scopeValue, justification, expiresAt, createdById, enabled) ✅
- **Backend**: `apps/web/convex/suppressionRules.ts` — `listRules`, `createRule`, `updateRule`, `deleteRule` ✅
- **Frontend**: ✅
  - Route `/settings/suppression` → `apps/web/src/routes/settings/suppression.tsx` ✅
  - `SuppressionRuleList` with pattern, scope, expiry, status columns ✅
  - `SuppressionRuleEditor` drawer with pattern, scope selector, justification, expiry ✅
  - `RuleMatchPreview` inline with scope pills ✅
- **Sidebar**: Suppression Rules entry under System group ✅

## 6.9 — Custom Policy Builder ✅ COMPLETED
- **Priority**: P1
- **Effort**: L
✅ COMPLETED [2026-05-16]
- **Schema**: `customPolicies` (id, tenantId, name, description, dsl, enabled, createdAt, updatedAt) ✅
- **Backend**: `apps/web/convex/customPolicies.ts` — `listPolicies`, `getPolicy`, `createPolicy`, `updatePolicy`, `deletePolicy` ✅
- **Frontend**: ✅
  - Route `/settings/policies` → `apps/web/src/routes/settings/policies.tsx` ✅
  - `PolicyListTable` with name, DSL preview, status columns ✅
  - `PolicyEditor` drawer with name, DSL textarea, condition templates ✅
  - `PolicySimulator` inline with template condition buttons ✅
- **Sidebar**: Policy Builder entry under System group ✅

## 6.10 — Repository Connection Wizard (GitHub App Install Flow) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Route**: `/connect/github` → `apps/web/src/routes/connect/github.tsx` ✅
- **Multi-step wizard**: ✅
  - Step 1: Install App — permissions overview + install CTA ✅
  - Step 2: Select Repositories — filterable repo list with multi-select ✅
  - Step 3: Initial Scan — confirm selection + trigger scan ✅
  - Step 4: Complete — summary with nav links ✅
- **Progress indicator**: 4-step breadcrumb with done/active/pending states ✅
- **Sidebar**: Connect GitHub entry under Repositories group ✅

## 6.11 — Invite System with Role Assignment ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **Depends on**: §3.7 + §6.1
✅ COMPLETED [2026-05-16]
- **Schema**: extend `workspaceInvites` with `assignedRoleId` ✅
- **Frontend**: extend `InviteMemberModal.tsx` with role dropdown ✅ — fetches roles from `api.rbac.listRoles`

## 6.12 — Billing / Subscription Management ✅ COMPLETED
- **Priority**: P1
- **Effort**: L
- **Depends on**: §8 (monetization plan)
✅ COMPLETED [2026-05-16]
- **Schema**: `subscriptions`, `invoices`, `usageRecords` ✅ — all defined in schema.ts
- **Backend**: `apps/web/convex/billing.ts` ✅ — `listPlans`, `currentPlanForTenant`, `listInvoicesForTenant`, `currentUsageForTenant`
- **Frontend**: ✅
  - Route `/settings/billing` → `apps/web/src/routes/settings/billing.tsx` ✅
  - `BillingSummaryCard` ✅ — current plan, status pill, usage meters
  - `PlanComparisonTable` ✅ — feature cards for Free/Team/Enterprise
  - `InvoiceList` ✅ — invoice history with download links
- **Seed**: 3 plans (Free $0, Team $49, Enterprise $199) ✅ — added to `seed.ts`

## 6.13 — Public API Documentation ✅ COMPLETED
- **Priority**: P2
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Route**: `/docs/api` → `apps/web/src/routes/docs/api.tsx` ✅
- **Components**: ✅
  - `ApiEndpointList` ✅ — filterable, expandable endpoint catalog
  - `ApiEndpointDetail` ✅ — method badge, path, auth, status codes, request/response examples
  - `ApiTryItPanel` ✅ — curl command generator
- **Endpoints**: 18 documented endpoints covering findings, repositories, compliance, SBOM, security posture, blast radius, adversarial, and webhooks ✅
- **Approach**: Static OpenAPI-style docs derived from `convex/http.ts` route table ✅

## 6.14 — Settings Hub Pages ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Route**: `/settings` → `apps/web/src/routes/settings/index.tsx` (settings landing)
- **Sub-routes** (all under `apps/web/src/routes/settings/`):
  - `general.tsx` (§3.13)
  - `team.tsx` (§3.7)
  - `roles.tsx` (§6.1)
  - `api-keys.tsx` (§6.4)
  - `webhooks.tsx` (§6.6)
  - `scans.tsx` (§6.7)
  - `suppression.tsx` (§6.8)
  - `notifications.tsx` (§6.2)
  - `sla.tsx` (§3.5)
  - `billing.tsx` (§6.12)
  - `audit-log.tsx` (§6.5 — could live at `/audit-log` instead)
  - `integrations.tsx` (link out to existing route)

## 6.15 — Search + Global Command Palette ✅ COMPLETED
- **Priority**: P1
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Backend**: `apps/web/convex/search.ts` — universal search query over findings, repos, advisories
- **Frontend**:
  - `apps/web/src/components/CommandPalette.tsx` — Cmd/Ctrl-K trigger
  - Index categories: navigate to route, run scanner, find repo, find finding, recent activity
  - Integrate into `__root.tsx`

## 6.16 — Keyboard Shortcuts ✅ COMPLETED
- **Priority**: P2
- **Effort**: S
✅ COMPLETED [2026-05-16]
- **Files**:
  - `apps/web/src/lib/shortcuts.ts` — registry
  - `apps/web/src/components/ShortcutsModal.tsx` — `?` to show
  - Wire common ops: g+r repos, g+f findings, g+c compliance, /, esc, etc.

## 6.17 — Dark/Light Theme Refinements ✅ COMPLETED [2026-05-16]
- **Priority**: P2
- **Effort**: S
✅ COMPLETED [2026-05-16]
- **Files**:
  - `apps/web/src/components/ThemeToggle.tsx` — audited; already supports light/dark/auto cycling with `data-theme` attribute
  - `apps/web/src/styles.css` — added dark-mode focus ring, shimmer, overlay, and card-shadow refinements

## 6.18 — Mobile-Responsive Audit ✅ COMPLETED [2026-05-16]
- **Priority**: P2
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Approach**: Responsive breakpoint CSS for tables (card layout on <md), sidebar mobile drawer, stat/repo grid stacking
- **Files touched**: `apps/web/src/styles.css` (mobile table cards, stacked grids, compact padding), `Sidebar.tsx` (mobile toggle with aria-expanded/controls)

## 6.19 — Accessibility (a11y) Audit ✅ COMPLETED [2026-05-16]
- **Priority**: P1
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Approach**: Created shared focus helpers, ARIA labels on sidebar/modal/drawers, skip-link, reduced-motion, focus-visible
- **Files**:
  - `apps/web/src/lib/a11y.ts` — trapFocus, stashFocus, autoFocusFirst, announceToScreenReader, onEscapeKey, rovingTabIndex
  - `Sidebar.tsx` — skip-link, role="navigation", aria-expanded, aria-controls
  - `styles.css` — skip-link styles, reduced-motion media query, focus-visible dark mode

## 6.20 — Error Boundaries + Loading States ✅ COMPLETED
- **Priority**: P0
- **Effort**: S
- **Files**:
  - `apps/web/src/components/RouteErrorBoundary.tsx` — wraps each route
  - `apps/web/src/components/SectionErrorBoundary.tsx` — wraps each panel
  - Wire into `apps/web/src/routes/__root.tsx` and per-route via TanStack Router `errorComponent`

## 6.21 — Real-Time Toast Notifications ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- **Depends on**: §6.2
- **Files**:
  - `apps/web/src/components/Toaster.tsx`
  - Subscribe to Convex notifications query; show toast for new critical findings, gate failures, exploit confirmations
  - Mount in `__root.tsx`

## 6.22 — Export / Report Generation (PDF + CSV) ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Backend**: `apps/web/convex/exports.ts` ✅
  - `exportFindingsCsv` action ✅ — CSV with severity/status filters
  - `exportExecReportPdf` action ✅ — structured HTML report with KPIs and tables
  - `exportComplianceEvidencePdf` action ✅ — framework evidence report
- **Frontend**: ✅
  - `apps/web/src/components/ExportMenu.tsx` ✅ — reusable dropdown with CSV/PDF options
  - Wired into: `findings.tsx` ✅, `executive-report.tsx` ✅, `compliance.tsx` ✅

## 6.23 — Data Retention + Archival Policies ✅ COMPLETED [2026-05-16]
- **Priority**: P2
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Schema**: `retentionPolicies` (tenantId, dataType, retentionDays, action, enabled) — added to schema.ts
- **Backend**: `apps/web/convex/retention.ts` — list/create/update/delete + `runDailyArchive` internal action + `_runDailyArchiveForAll` internal mutation
- **Cron**: `crons.ts` — daily at 05:00 UTC runs `internal.retention.runDailyArchive`
- **Frontend**: `apps/web/src/routes/settings/retention.tsx` — policy list with toggle/delete, create form with data-type selector

## 6.24 — On-Call Rotation + Escalation UI ✅ COMPLETED [2026-05-16]
- **Priority**: P2
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **Schema**: `onCallSchedules` (rotation members, cadence, timezone) + `escalationPolicies` (steps with delay/target/channels) — added to schema.ts
- **Backend**: `apps/web/convex/onCall.ts` — full CRUD for schedules and escalation policies with tenant auth
- **Frontend**: `apps/web/src/routes/settings/on-call.tsx` — calendar-like weekly rotation grid, schedule list with member badges, escalation policy management

## 6.25 — Integration Marketplace ✅ COMPLETED
- **Priority**: P2
- **Effort**: L
- **Builds on**: §5
- ✅ COMPLETED [2026-05-16]
- **Frontend**:
  - Route `/marketplace` → `apps/web/src/routes/marketplace.tsx` ✅
  - Marketplace catalog grid with category filter ✅
  - IntegrationCard with install buttons, vote/flag CTAs ✅
  - InstallFlowModal for configuration ✅
- **Sidebar**: Marketplace entry under System group ✅

## 6.26 — SSO / SAML Configuration ✅ COMPLETED
- **Priority**: P0 (Enterprise)
- **Effort**: L
- ✅ COMPLETED [2026-05-16]
- **Schema**: `ssoConfigs` (SAML/OIDC fields per tenant) ✅, `ssoTestLogins` ✅
- **Backend**: `apps/web/convex/sso.ts` ✅ — listSsoConfigs, createSsoConfig, updateSsoConfig, deleteSsoConfig, getAcsUrl
- **Frontend**: `apps/web/src/routes/settings/sso.tsx` ✅
  - IdP metadata upload (SAML XML, OIDC endpoints) ✅
  - ACS URL display with copy button ✅
  - Test login button with status display ✅
  - Config list with enable/disable toggle ✅

## 6.27 — 2FA Enforcement ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
- ✅ COMPLETED [2026-05-16]
- **Schema**: `twoFactorEnrollments` (userId, tenantId, secretEncrypted, verified, enforced, backupCodesEncrypted) ✅
- **Backend**: `apps/web/convex/twoFactor.ts` ✅
  - getTwoFactorStatus, startEnrollment (returns otpauth URI + backup codes) ✅
  - verifyEnrollment, verifyTwoFactor, disableTwoFactor ✅
  - getTenantTwoFactorPolicy (admin view of enforcement) ✅
- **Frontend**: `apps/web/src/routes/settings/two-factor.tsx` ✅
  - QR code enrollment via otpauth URI ✅
  - TOTP code verification input ✅
  - Disable 2FA with confirmation ✅
  - Tenant-wide 2FA policy display for admins ✅

## 6.28 — API Rate Limiting Visibility ✅ COMPLETED
- **Priority**: P2
- **Effort**: S
- ✅ COMPLETED [2026-05-16]
- **Schema**: `apiUsageRecords` (apiKeyId, tenantId, windowStart, requestCount, blockedCount, period) ✅
- **Backend**: `apps/web/convex/apiKeys.ts` ✅ — getApiKeyUsage query with per-key hourly/daily counters
- **Frontend**: `ApiUsagePanel` in `/settings/api-keys` ✅
  - Per-key request volume display (req/hr, req/day) ✅
  - Rate limit progress bar with color-coded thresholds ✅
  - Blocked request count alerts ✅

## 6.29 — Health Check / Status Page ✅ COMPLETED
- **Priority**: P1
- **Effort**: S
- ✅ COMPLETED [2026-05-16]
- **Schema**: `serviceHealthChecks`, `incidentReports` ✅
- **Backend**: `apps/web/convex/health.ts` ✅
  - getServiceHealth — public query (no auth), 7 core services ✅
  - getIncidentHistory — public query with expandable incidents ✅
  - getOverallStatus — lightweight query for status badges ✅
  - recordHealthCheck, createIncident, updateIncident — internal mutations ✅
- **Frontend**: Public route `/status` → `apps/web/src/routes/status.tsx` (no auth) ✅
  - `OverallStatusBanner` ✅ — color-coded status with active incident count
  - `ServiceHealthRow` ✅ — per-service status with latency and status pill
  - `IncidentHistoryList` ✅ — expandable incident rows with severity, timeline
- **Sidebar**: Status entry under System group ✅

---

# SECTION 7 — Technical Debt & Platform Health

## 7.1 — Split `dashboard.overview` mega-query ✅ COMPLETED
- **Priority**: P0
- **Effort**: M
✅ COMPLETED [2026-05-16]
- **File**: `apps/web/convex/dashboard.ts`
- **Approach**:
  - Extracted per-section queries: `dashboard.kpiStats`, `dashboard.recentFindings`, `dashboard.repoSummaries`, `dashboard.workflowEvents`, `dashboard.gateDecisions`, `dashboard.escalations`
  - Each route subscribes to only what it needs
  - Audit re-renders with Convex query devtools
- **Files modified**: `dashboard.ts` (6 new focused queries replacing 1 mega-query)
- **Note**: Existing routes still reference `api.dashboard.overview` — migration to individual queries can be done incrementally per route

## 7.2 — Add Per-Route Error Boundaries ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: S
- See §6.20.
- **Note**: Wired `errorComponent: RouteErrorBoundary` into all 46 route files (45 child routes + already present on `__root.tsx`). Updated `RouteErrorBoundary` to accept TanStack Router's `{ error, reset }` props in addition to the `children` wrapper mode so the same component works for both invocations.

## 7.3 — PostHog Event Taxonomy ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: S
- **Done**: `apps/web/src/lib/analytics.ts` exports a typed `track<E extends EventName>(name, props)` wrapper around `posthog.capture` with per-event prop schemas. Wired call sites: `finding.triaged` + `finding.accepted_risk` in `FindingTriageActionBar.tsx`/`AcceptRiskModal.tsx`, `gate.overridden` in `GateOverrideModal.tsx`, `scan.triggered` in `RescanButton.tsx` + `connect/github.tsx`, `pr.generated` in `remediation.tsx` (dispatchRemediation), `repo.connected` in `connect/github.tsx`, `member.invited` in `InviteMemberModal.tsx`, `export.run` (csv + pdf scopes) in `ExportMenu.tsx`.

## 7.4 — Reconcile `PROJECT_TRACKER.md` with Reality ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: S
- **File**: `PROJECT_TRACKER.md`
- **Action**:
  - Split each `[done]` entry into `backend [done]` vs `panel [done|missing]`
  - Add explicit "UI surface" column
  - Mark the 40 drift panels as `panel [missing]` until §1.19 is shipped
  - Reconcile the panel-component list referenced in tracker but absent from `apps/web/src/components/`

## 7.5 — Auth Review (Convex Auth 0.0.92 pre-1.0) ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: S
- **Approach**: audit `apps/web/convex/auth.ts` + `auth.config.ts`; review GA roadmap; document upgrade path; verify session refresh & 2FA story
- **Output**: `docs/decisions/auth-readiness.md`

## 7.6 — Long File Refactor with Line Counts ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: bundled with §2
- **Files (likely line counts to verify with `wc -l`)**:
  - `apps/web/src/routes/repositories.tsx`
  - `apps/web/src/routes/compliance.tsx`
  - `apps/web/src/routes/supply-chain.tsx`
  - `apps/web/src/routes/ci-cd.tsx`
  - `apps/web/src/routes/findings.tsx`
  - `apps/web/src/routes/agents.tsx`
  - `apps/web/src/routes/breach-intel.tsx`
  - `apps/web/src/routes/integrations.tsx`
  - `apps/web/convex/dashboard.ts` (787 lines, see §7.1)
  - `apps/web/convex/schema.ts` (4,715 lines — investigate splitting into per-domain `schema/*.ts` re-exports)

## 7.7 — Frontend Test Coverage ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: M
- **Current**: backend has 8,603 passing tests; `apps/web/src/` has ~zero
- **Add**:
  - `apps/web/src/**/*.test.tsx` covering each panel rendering with mock data
  - Set up `@testing-library/react` test harness if missing
  - Cover: `__root.tsx` workspace gating, `findings.tsx` triage flow, `repositories.tsx` panel rendering, `onboarding.tsx` form validation

## 7.8 — Convex Performance Audit ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: M
- **Approach**: run the `convex-performance-audit` skill against `apps/web/convex/`
- **Target areas**: `dashboard.overview` (split per §7.1), top-10 hot queries by read amplification, OCC conflict candidates
- **Output**: action list in `docs/decisions/perf-audit.md`

## 7.9 — SEO + Meta Tags ✅ COMPLETED [2026-05-17]
- **Priority**: P3
- **Effort**: S
- **Files**:
  - `apps/web/src/routes/__root.tsx` — add per-route meta via TanStack Start head
  - `apps/web/public/robots.txt`, `apps/web/public/sitemap.xml`
  - Public routes only: `/`, `/about`, `/status`, `/docs/api`

## 7.10 — Bundle Size Optimization ✅ COMPLETED [2026-05-17]
- **Priority**: P2
- **Effort**: S
- **Approach**:
  - Run `vite build --report` (or rollup-plugin-visualizer)
  - Lazy-import heavy panels (e.g., exploit recording viewer)
  - Audit `lucide-react` imports — switch to per-icon `import { X } from 'lucide-react'` if not already
- **Files**: `apps/web/vite.config.ts`, route-level lazy imports

---

# SECTION 8 — Monetization & Packaging

## 8.1 — Tiered Pricing Implementation ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: M
- **Schema**: `plans` (slug, name, monthlyPrice, repoLimit, seatLimit, featureFlags: string[])
- **Backend**: `apps/web/convex/plans.ts` — `listPlans`, `currentPlanForTenant`
- **Seed**: Free / Team / Enterprise per analysis §5.2
- **Frontend**: `apps/web/src/routes/pricing.tsx` (public), `apps/web/src/routes/settings/billing.tsx` (auth)
- **Done**: Added `plans` table to `schema.ts` indexed by slug; `convex/plans.ts` with `listPlans`, `currentPlanForTenant`, `getPlanBySlug`; seeded Free/Team/Enterprise tiers in `seed.ts`; created public `/pricing` route with comparison cards; extended `/settings/billing` with `CurrentTierCard` from new `plans` table + upgrade CTA.

## 8.2 — Feature Flag System ✅ COMPLETED [2026-05-17]
- **Priority**: P0
- **Effort**: S
- **Depends on**: §8.1
- **Schema**: derived from plan.featureFlags
- **Backend**: `apps/web/convex/featureFlags.ts` — `isEnabledForTenant(slug)`
- **Frontend**: `apps/web/src/lib/featureFlags.ts` — `useFeatureFlag(slug)` hook
- **Wire**: gate Enterprise-only routes (SSO, on-prem) in `Sidebar.tsx`
- **Done**: `featureFlags.ts` query reads tenant → subscription → plan.featureFlags. Hook `useFeatureFlag(slug)` returns boolean | undefined. Sidebar items now support `featureFlag` field with `SidebarItem` wrapper that redirects locked Enterprise routes (SSO, deployment, MSSP) to `/pricing` with a `Lock` icon.

## 8.3 — Usage Metering ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: M
- **Schema**: `usageRecords` (tenantId, metric, value, at) — already in `schema.ts` with `by_tenant`, `by_tenant_and_metric`, `by_tenant_and_period` indexes
- **Backend**: `apps/web/convex/usage.ts` — `incrementUsage` (internalMutation), `getUsageForTenant` (query returning aggregated usage by metric), `dailyAggregate` (internalAction that rolls raw records into per-day aggregates), `aggregateTenantUsage` helper (collapses raw window into one summary row and deletes originals)
- **Cron**: `usage daily aggregate` at `0 0 * * *` UTC in `crons.ts`
- **Metrics**: `repos_connected`, `scans_run`, `prs_generated`, `sandboxes_started`, `api_calls`

## 8.4 — Stripe Integration ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: L
- **Files**:
  - `apps/web/convex/stripeWebhook.ts` — `handleStripeWebhook` httpAction with HMAC-SHA256 `Stripe-Signature` verification (5-min tolerance); internal mutations `applySubscriptionEvent`, `markSubscriptionCanceled`, `applyInvoicePaid`; handles `customer.subscription.created/updated/deleted` and `invoice.paid`
  - `apps/web/convex/checkout.ts` — `createCheckoutSession` action; POSTs to Stripe `/checkout/sessions` via form-encoded fetch; falls back to mock URL when `STRIPE_SECRET_KEY` is unset; uses `STRIPE_PRICE_<SLUG>` env override or inline `price_data` derived from the plans table
  - `apps/web/convex/billingPortal.ts` — `createPortalSession` action + `getTenantStripeCustomer` internalQuery; falls back to mock URL when no Stripe customer or key
  - `apps/web/convex/http.ts` — registers `POST /api/stripe/webhook`
- **Frontend**: `UpgradeButton.tsx` already calls `api.checkout.createCheckoutSession` and redirects to `result.url`
- **Env required (production)**: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `APP_URL`, optional per-plan `STRIPE_PRICE_FREE`/`_TEAM`/`_ENTERPRISE`

## 8.5 — MSSP Partner Portal ✅ COMPLETED [2026-05-17]
- **Priority**: P2
- **Effort**: L
- **Backend**: extended `apps/web/convex/mssp.ts` with public queries `listManagedTenants` (status/usage/findings/plan/health per tenant), `getBillingRollup` (per-plan revenue rollup + recent invoices), `getWhiteLabelSettings` (env-sourced brand config); added `setManagedTenantStatus` mutation
- **Frontend**: `apps/web/src/routes/mssp.tsx` with three tabs — Managed Tenants (sortable table + pause/resume actions), Billing Rollup (StatCards + per-plan revenue + recent invoices), White Label (form printing `npx convex env set` commands)
- **Sidebar**: `/mssp` entry already gated behind `mssp_portal` feature flag under the System group

## 8.6 — On-Prem Deployment Mode Toggle ✅ COMPLETED [2026-05-17]
- **Priority**: P2
- **Effort**: M
- **Schema**: `tenants.deploymentMode` already exists per analysis §5.2
- **Backend**: `apps/web/convex/deploymentMode.ts` — switch + validation
- **Frontend**: `apps/web/src/routes/settings/deployment.tsx`
- **Affects**: Some integrations disabled / different defaults in on-prem mode

## 8.7 — Compliance Attestation as Paid Add-on ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: S
- **Depends on**: §8.2
- **Approach**: gate `complianceAttestationIntel` queries behind feature flag `compliance_attestation`
- **Frontend**: upsell card in `/compliance` for non-Enterprise tenants

---

# SECTION 9 — Orphaned Routes & Cleanup

## 9.1 — `/about` page decision ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: S
- **Done**: rewrote `apps/web/src/routes/about.tsx` as public marketing landing (hero + CTA, 6-feature grid, scan→analyze→remediate CSS/SVG flow diagram, social proof stats, 3 testimonials, footer with Sign Up / API docs / Status links). Added `PUBLIC_ROUTES` allowlist in `__root.tsx` so `/about` renders without auth or workspace context.
- **File**: `apps/web/src/routes/about.tsx`
- **Options**:
  - (a) Make it real: turn into public marketing landing — feature highlights, architecture, link to `/docs/api`, link to `/status`
  - (b) Remove: delete the file and reference from any sidebar/menu
- **Recommended**: (a) but as a public landing — add to `apps/web/src/components/Sidebar.tsx` only if signed-in, otherwise public-accessible without workspace context

## 9.2 — Dead-code Cleanup ✅ COMPLETED [2026-05-17]
- **Priority**: P2
- **Effort**: S
- **Done**: scanned `apps/web/src/lib/utils.ts` exports against grep across `apps/web/src/`. Removed `formatLayerLabel` (zero call sites outside its own definition). All other `*Tone` helpers and `formatTimestamp`/`formatDate` confirmed referenced. `apps/web/src/lib/a11y.ts` is documented infrastructure for §6.19 modal/drawer accessibility — kept intentionally even though no current call sites. Convex backend modules: every top-level `*Intel.ts` and `*.ts` resolves via the generated `api.*` namespace from dashboard slices in `apps/web/src/`; internal libs (`lib/eventRouter.ts`, `lib/sessionAuth.ts`, `lib/githubClient.ts`) are used by handlers via relative import. Full automated unused-exports sweep (ts-prune / knip) is deferred until those tools are added to devDependencies.
- **Approach**:
  - Run `bunx knip` or equivalent against `apps/web/`
  - Remove unused exports in `apps/web/convex/*.ts` flagged as never referenced (after confirming via grep — NOT including internal-only modules called from `http.ts`/`crons.ts`)

## 9.3 — Stale TODO Comment Cleanup (backend) ✅ COMPLETED [2026-05-17]
- **Priority**: P3
- **Effort**: S
- **Done**: removed/converted resolved TODOs across the §4 implementation files. `convex/lib/complianceEvidence.ts:110` TODO converted to a configuration note (audit-tunable threshold). `convex/vendorTrust.ts` stripped two now-stale `MASTER_TODO.md §4.1` spec pointers (algorithm is documented inline). `convex/lib/modelProvenance.ts` stripped two `Spec: MASTER_TODO.md §4.2` pointers in computeProvenanceScore. `eolDetectionIntel.ts`, `trustScoreIntel.ts`, and `complianceEvidenceIntel.ts` had no stale TODOs. Verified by `grep -rn "MASTER_TODO" apps/web/convex/` returning empty.
- **Files** (after §4 is done):
  - Remove resolved TODO comments from §4.1–4.5 once functions are implemented
  - `apps/web/convex/lib/complianceEvidence.ts:110` — resolve or convert to a real ticket

---

# SECTION 10 — Stub Services to Build

## 10.1 — `services/breach-intel/` (Python) ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: XL
- **Current**: README only
- **Scope**:
  - Replicate the work `apps/web/convex/breachIngest.ts` does in Convex actions, into a dedicated Python service for higher-throughput dark-web/Telegram ingest
  - HTTP API endpoints for the Convex app to call as an action target
  - Files to create:
    - `services/breach-intel/src/main.py`
    - `services/breach-intel/src/ingestors/telegram.py`
    - `services/breach-intel/src/ingestors/darkweb.py`
    - `services/breach-intel/src/ingestors/cisa_kev.py`
    - `services/breach-intel/src/ingestors/osv.py`
    - `services/breach-intel/src/correlator.py`
    - `services/breach-intel/src/http_server.py` (FastAPI)
    - `services/breach-intel/tests/`
    - `services/breach-intel/Dockerfile`
    - `services/breach-intel/pyproject.toml`
- **Convex side**: wire `apps/web/convex/breachIngest.ts` to call into this service via action

## 10.2 — `services/event-gateway/` (Go) ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: XL
- **Current**: README only
- **Scope**: high-throughput webhook intake → fan-out to Convex
- **Files**:
  - `services/event-gateway/cmd/gateway/main.go`
  - `services/event-gateway/internal/handlers/{github,gitlab,bitbucket,azureDevOps,jenkins,circleci,buildkite}.go`
  - `services/event-gateway/internal/forwarder/convex.go`
  - `services/event-gateway/internal/auth/hmac.go`
  - `services/event-gateway/internal/queue/buffer.go`
  - `services/event-gateway/Dockerfile`
  - `services/event-gateway/go.mod`
- **Convex side**: replace `apps/web/convex/http.ts` webhook ingest routes' first pass with this service (optional — Convex still terminal storage)

## 10.3 — `services/shared/` cross-service contracts ✅ COMPLETED [2026-05-17]
- **Priority**: P1
- **Effort**: M
- **Current**: README only
- **Scope**:
  - Protobuf or JSON-schema definitions for cross-service payloads
  - Files:
    - `services/shared/contracts/finding.proto`
    - `services/shared/contracts/breach-event.proto`
    - `services/shared/contracts/gate-decision.proto`
    - `services/shared/contracts/sbom-snapshot.proto`
    - `services/shared/generated/python/` (codegen output)
    - `services/shared/generated/go/` (codegen output)
    - `services/shared/generated/ts/` (codegen for the Convex side)
    - `services/shared/Makefile` (codegen)
    - `services/shared/README.md` — overview

---

# Cross-cutting / Ordering Notes

- §2.8 (shared panel infrastructure) is a **soft prerequisite** for §1.1–1.20 and all of §2. Build it first.
- §6.20 (error boundaries) and §6.21 (toasts) **should ship in the same week** so new panels (§1) don't white-screen on errors.
- §4 (TODO functions) should be done before §1.9 / §1.6 / §1.3 etc. depend on score outputs.
- §6.1 (RBAC) is a prereq for §3.7, §6.11.
- §8.1 + §8.2 (plans + flags) are prereq for §8.7, §6.12.
- §5 (integrations schema) is independent and can ship in parallel with §1.
- §10.3 (shared contracts) is a prereq for §10.1 and §10.2.

# Recommended P0 Sprint 1 (single 2-week sprint)

The single highest-leverage 2-week sprint that converts the most existing backend value to user-visible product:

1. §2.8 (panel infra)
2. §6.20 (error boundaries)
3. §1.1 (executive report)
4. §1.2 (maturity)
5. §1.3 (business impact)
6. §1.18 (drift posture aggregate)
7. §4.1 (vendor risk score)
8. §4.4 (repository trust score)
9. §5 (integrations live data)
10. §3.1 (risk acceptance UI)

Estimated: ~10 engineer-weeks of work. Outcome: every backend module from §1 that produces tenant-level synthesis becomes visible; the integrations page stops lying about config status; risk acceptance becomes user-driven.
