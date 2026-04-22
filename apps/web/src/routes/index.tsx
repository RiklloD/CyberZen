import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	AlertTriangle,
	Boxes,
	FlaskConical,
	GitMerge,
	ShieldCheck,
	Sparkles,
	Waypoints,
} from "lucide-react";
import { useTransition } from "react";
import { env } from "#/env";
import { api } from "../../convex/_generated/api";
import type { Id } from "../../convex/_generated/dataModel";
import StatusPill from "../components/StatusPill";

export const Route = createFileRoute("/")({ component: HomePage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewFinding = OverviewData["findings"][number];
type OverviewWorkflow = OverviewData["workflows"][number];
type OverviewWorkflowTask = OverviewWorkflow["tasks"][number];
type OverviewCiGateEnforcement = OverviewData["ciGateEnforcement"];
type OverviewGateDecision =
	OverviewCiGateEnforcement["recentDecisions"][number];
type OverviewRepository = OverviewData["repositories"][number];
type OverviewDisclosure = OverviewData["disclosures"][number];
type OverviewAdvisoryAggregator = OverviewData["advisoryAggregator"];
type OverviewAdvisorySyncRun = OverviewAdvisoryAggregator["recentRuns"][number];
type OverviewAdvisorySource =
	OverviewAdvisoryAggregator["sourceCoverage"][number];
type OverviewSemanticFinding =
	OverviewData["semanticFingerprint"]["recentFindings"][number];
type OverviewExploitValidationRun =
	OverviewData["exploitValidation"]["recentRuns"][number];
type OverviewSnapshot = NonNullable<OverviewRepository["latestSnapshot"]>;
type OverviewComparison = NonNullable<OverviewSnapshot["comparison"]>;
type OverviewSnapshotComponent = OverviewSnapshot["previewComponents"][number];
type OverviewVulnerableComponent =
	OverviewSnapshot["vulnerablePreview"][number];
type OverviewUpdatedComponent = OverviewComparison["updatedPreview"][number];
type OverviewDiffComponent = OverviewComparison["addedPreview"][number];

type RecentScansData = FunctionReturnType<
	typeof api.promptIntelligence.recentScans
>;
type RecentScan = RecentScansData[number];
type SupplyChainResult = NonNullable<
	FunctionReturnType<typeof api.promptIntelligence.supplyChainAnalysis>
>;
type FlaggedSupplyChainComponent =
	SupplyChainResult["flaggedComponents"][number];

type BlastRadiusSummary = NonNullable<
	FunctionReturnType<
		typeof api.blastRadiusIntel.blastRadiusSummaryForRepository
	>
>;
type BlastRadiusTopFinding = BlastRadiusSummary["topFindings"][number];

type TrustScoreSummary = NonNullable<
	FunctionReturnType<typeof api.trustScoreIntel.getRepositoryTrustScoreSummary>
>;
type TrustScoreBreakdownEntry = TrustScoreSummary["breakdown"][number];

type AttackSurfaceDashboard = NonNullable<
	FunctionReturnType<typeof api.attackSurfaceIntel.getAttackSurfaceDashboard>
>;
type AttackSurfaceSnapshot = AttackSurfaceDashboard["snapshot"];
type AttackSurfaceHistoryEntry = AttackSurfaceDashboard["history"][number];

const implementationTrack = [
	"Set env vars and exercise first live webhook delivery: GITHUB_WEBHOOK_SECRET, GITHUB_TOKEN, SENTINEL_API_KEY",
	"Run first live CISA KEV sync and verify exploitAvailable patches flow into breach watchlist",
	"Confirm analyst triage loop: mark a finding false_positive via PATCH /api/findings/triage and watch learning profile confidence multiplier drop on next refresh",
	"Connect TELEGRAM_WEBHOOK_SECRET and point a threat-intel Telegram channel at POST /webhooks/telegram",
	"SLA enforcement is live: hourly cron checks active findings; GET /api/sla/status returns compliance rate and MTTR per repository",
	"Cross-repo impact detection is live: every supply-chain disclosure now scans all tenant repositories for lateral package exposure; GET /api/findings/cross-repo-impact returns per-package spread data",
	"Automated remediation priority queue is live: every repository now has a composite-scored P0/P1/P2/P3 queue merging SLA breach, exploit availability, blast radius, and validation outcome; GET /api/remediation/queue",
];

const loadingSkeletonIds = [
	"skeleton-a",
	"skeleton-b",
	"skeleton-c",
	"skeleton-d",
	"skeleton-e",
	"skeleton-f",
];

function formatTimestamp(timestamp?: number) {
	if (!timestamp) {
		return "Not yet";
	}

	return new Intl.DateTimeFormat("en-CH", {
		month: "short",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
	}).format(timestamp);
}

function severityTone(severity: string) {
	if (severity === "critical" || severity === "high") {
		return "danger" as const;
	}

	if (severity === "medium") {
		return "warning" as const;
	}

	return "info" as const;
}

function workflowTone(status: string) {
	if (status === "completed") {
		return "success" as const;
	}

	if (status === "failed") {
		return "danger" as const;
	}

	if (status === "running") {
		return "info" as const;
	}

	return "warning" as const;
}

function disclosureTone(status: string) {
	if (status === "matched") {
		return "danger" as const;
	}

	if (status === "version_unknown" || status === "no_snapshot") {
		return "warning" as const;
	}

	if (status === "version_unaffected") {
		return "success" as const;
	}

	return "info" as const;
}

function taskTone(status: string) {
	return workflowTone(status);
}

function syncTone(status: string) {
	if (status === "failed") {
		return "danger" as const;
	}

	if (status === "skipped") {
		return "warning" as const;
	}

	return "success" as const;
}

function validationTone(status?: string) {
	if (status === "validated") {
		return "success" as const;
	}

	if (status === "likely_exploitable") {
		return "warning" as const;
	}

	if (status === "unexploitable") {
		return "info" as const;
	}

	return workflowTone(status || "queued");
}

function componentTone(layer: string, hasKnownVulnerabilities = false) {
	if (hasKnownVulnerabilities) {
		return "danger" as const;
	}

	if (layer === "direct") {
		return "success" as const;
	}

	if (layer === "build") {
		return "warning" as const;
	}

	return "info" as const;
}

function formatLayerLabel(layer: string) {
	if (layer === "ai_model") {
		return "AI model";
	}

	return layer.replace("_", " ");
}

function injectionRiskTone(
	riskLevel: string,
): "success" | "warning" | "danger" | "neutral" {
	if (riskLevel === "confirmed_injection" || riskLevel === "likely_injection") {
		return "danger";
	}
	if (riskLevel === "suspicious") {
		return "warning";
	}
	return "success";
}

function supplyChainRiskTone(
	riskLevel: string,
): "success" | "warning" | "danger" | "neutral" {
	if (riskLevel === "critical" || riskLevel === "high") {
		return "danger";
	}
	if (riskLevel === "medium") {
		return "warning";
	}
	return "success";
}

function blastTierTone(
	riskTier: string,
): "success" | "warning" | "danger" | "neutral" {
	if (riskTier === "critical") return "danger";
	if (riskTier === "high") return "warning";
	if (riskTier === "medium") return "neutral";
	return "success";
}

/**
 * Shows the latest blast radius snapshot for a single finding:
 * risk tier pill, reachable services list, attack path depth,
 * and business impact score.
 */
function FindingBlastRadiusPanel({
	findingId,
}: {
	findingId: OverviewFinding["_id"];
}) {
	const snapshot = useQuery(api.blastRadiusIntel.getBlastRadius, { findingId });

	if (snapshot === undefined || snapshot === null) return null;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Blast radius</p>
				<StatusPill
					label={snapshot.riskTier}
					tone={blastTierTone(snapshot.riskTier)}
				/>
				<StatusPill
					label={`impact ${snapshot.businessImpactScore}`}
					tone="neutral"
				/>
				<StatusPill
					label={`depth ${snapshot.attackPathDepth}`}
					tone="neutral"
				/>
			</div>
			{snapshot.reachableServices.length > 0 ? (
				<div className="mt-2 flex flex-wrap gap-2">
					{snapshot.reachableServices.slice(0, 6).map((svc) => (
						<StatusPill key={svc} label={svc} tone="neutral" />
					))}
					{snapshot.reachableServices.length > 6 ? (
						<StatusPill
							label={`+${snapshot.reachableServices.length - 6} more`}
							tone="neutral"
						/>
					) : null}
				</div>
			) : null}
			{snapshot.exposedDataLayers.length > 0 ? (
				<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
					Layers: {snapshot.exposedDataLayers.join(", ")}
				</p>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{snapshot.summary}
			</p>
		</div>
	);
}

/**
 * Shows the repository-level blast radius aggregate:
 * max risk tier, total unique reachable services, and the top 3 findings
 * by business impact score.
 */
function RepositoryBlastRadiusSummary({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const summary = useQuery(
		api.blastRadiusIntel.blastRadiusSummaryForRepository,
		{ tenantSlug, repositoryFullName },
	);

	if (summary === undefined || summary === null) return null;
	if (
		summary.maxRiskTier === "low" &&
		summary.totalReachableServices.length === 0 &&
		summary.topFindings.length === 0
	) {
		return null;
	}

	return (
		<div className="mb-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface-strong)]/60 p-3">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Blast radius</p>
				<StatusPill
					label={`max risk: ${summary.maxRiskTier}`}
					tone={blastTierTone(summary.maxRiskTier)}
				/>
				{summary.totalReachableServices.length > 0 ? (
					<StatusPill
						label={`${summary.totalReachableServices.length} reachable service${summary.totalReachableServices.length === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
			</div>
			{summary.topFindings.length > 0 ? (
				<div className="mt-2 space-y-1">
					{summary.topFindings.map((f: BlastRadiusTopFinding) => (
						<div
							key={f.findingId}
							className="flex flex-wrap items-center gap-2"
						>
							<StatusPill label={f.riskTier} tone={blastTierTone(f.riskTier)} />
							<StatusPill
								label={`score ${f.businessImpactScore}`}
								tone="neutral"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{f.title}
							</span>
						</div>
					))}
				</div>
			) : null}
		</div>
	);
}

// ── Semantic fingerprinting panel ────────────────────────────────────────────

function RepositorySemanticFingerprintPanel({
	repositoryId,
}: {
	repositoryId: string;
}) {
	const analysis = useQuery(
		api.semanticFingerprintIntel.getLatestCodeAnalysis,
		{
			repositoryId: repositoryId as Id<"repositories">,
		},
	);
	const libraryStatus = useQuery(
		api.semanticFingerprintIntel.getPatternLibraryStatus,
		{},
	);

	if (!analysis && !libraryStatus) return null;

	const notInitialized =
		libraryStatus &&
		!libraryStatus.isInitialized &&
		libraryStatus.totalPatterns === 0;

	if (notInitialized) {
		return (
			<div className="panel-section">
				<h4 className="panel-label">Semantic Fingerprinting</h4>
				<p className="text-xs text-gray-500">
					Pattern library not initialized.{" "}
					<span className="text-amber-400">
						Set OPENAI_API_KEY and run initializePatternLibrary.
					</span>
				</p>
			</div>
		);
	}

	return (
		<div className="panel-section">
			<h4 className="panel-label">Semantic Fingerprinting</h4>
			{libraryStatus && (
				<div className="flex gap-2 mb-2 flex-wrap">
					<StatusPill
						tone={libraryStatus.isInitialized ? "success" : "warning"}
						label={`${libraryStatus.totalPatterns}/${libraryStatus.specPatterns} patterns`}
					/>
					<StatusPill
						tone="info"
						label={`${libraryStatus.bySeverity.critical} critical`}
					/>
				</div>
			)}
			{analysis ? (
				<div className="space-y-1 text-xs">
					<p className="text-gray-400">
						Last:{" "}
						<span className="text-gray-300">
							{analysis.commitSha.slice(0, 7)}
						</span>{" "}
						on <span className="text-gray-300">{analysis.branch}</span>
					</p>
					{analysis.topMatches.length > 0 ? (
						<div className="space-y-1">
							{analysis.topMatches
								.slice(0, 3)
								.map(
									(m: {
										patternId: string;
										vulnClass: string;
										severity: string;
										similarity: number;
										confidence: number;
									}) => (
										<div key={m.patternId} className="flex items-center gap-2">
											<StatusPill
												tone={
													m.severity === "critical"
														? "danger"
														: m.severity === "high"
															? "warning"
															: "neutral"
												}
												label={m.severity}
											/>
											<span className="text-gray-400 truncate">
												{m.vulnClass.replace(/_/g, " ")}
											</span>
											<span className="text-gray-500 ml-auto">
												{(m.similarity * 100).toFixed(0)}%
											</span>
										</div>
									),
								)}
						</div>
					) : (
						<p className="text-green-400">
							No semantic matches above threshold
						</p>
					)}
				</div>
			) : (
				<p className="text-xs text-gray-500">
					No analysis run yet for this repository.
				</p>
			)}
		</div>
	);
}

function RepositoryIntelligencePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scans = useQuery(api.promptIntelligence.recentScans, {
		tenantSlug,
		repositoryFullName,
		limit: 5,
	});
	const supplyChain = useQuery(api.promptIntelligence.supplyChainAnalysis, {
		tenantSlug,
		repositoryFullName,
	});

	// Both queries still loading — render nothing rather than a blank panel.
	if (scans === undefined && supplyChain === undefined) return null;

	const hasInjectionData = scans !== undefined && scans.length > 0;
	const hasSupplyChainData = supplyChain !== undefined && supplyChain !== null;

	if (!hasInjectionData && !hasSupplyChainData) return null;

	return (
		<div className="mt-3 space-y-3">
			{/* ── Supply chain analysis ── */}
			{hasSupplyChainData ? (
				<div className="rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
					<div className="flex flex-wrap items-center gap-2">
						<p className="tiny-label">Supply chain</p>
						<StatusPill
							label={supplyChain.riskLevel}
							tone={supplyChainRiskTone(supplyChain.riskLevel)}
						/>
						<StatusPill
							label={`score ${supplyChain.overallRiskScore.toFixed(0)}`}
							tone="neutral"
						/>
						{supplyChain.typosquatCandidates.length > 0 ? (
							<StatusPill
								label={`${supplyChain.typosquatCandidates.length} typosquat candidate${supplyChain.typosquatCandidates.length === 1 ? "" : "s"}`}
								tone="danger"
							/>
						) : null}
					</div>
					<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
						{supplyChain.summary}
					</p>
					{supplyChain.flaggedComponents.length > 0 ? (
						<div className="mt-3 space-y-2">
							{supplyChain.flaggedComponents
								.slice(0, 3)
								.map((component: FlaggedSupplyChainComponent) => (
									<div
										key={`${component.name}-${component.version}`}
										className="flex flex-wrap items-center gap-2"
									>
										<StatusPill
											label={`${component.name}@${component.version}`}
											tone={supplyChainRiskTone(component.riskLevel)}
										/>
										<StatusPill
											label={component.isDirect ? "direct" : "transitive"}
											tone="neutral"
										/>
										<span className="text-xs text-[var(--sea-ink-soft)]">
											{component.summary}
										</span>
									</div>
								))}
						</div>
					) : null}
				</div>
			) : null}

			{/* ── Recent prompt injection scans ── */}
			{hasInjectionData ? (
				<div className="rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
					<div className="flex flex-wrap items-center gap-2">
						<p className="tiny-label">Injection scans</p>
						<StatusPill label={`${scans.length} recent`} tone="neutral" />
						{scans.some(
							(s: RecentScan) =>
								s.riskLevel === "confirmed_injection" ||
								s.riskLevel === "likely_injection",
						) ? (
							<StatusPill label="injection detected" tone="danger" />
						) : scans.some((s: RecentScan) => s.riskLevel === "suspicious") ? (
							<StatusPill label="suspicious content" tone="warning" />
						) : (
							<StatusPill label="all clear" tone="success" />
						)}
					</div>
					<div className="mt-3 space-y-2">
						{scans.map((scan: RecentScan) => (
							<div key={scan._id} className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={scan.riskLevel.replace("_", " ")}
									tone={injectionRiskTone(scan.riskLevel)}
								/>
								<StatusPill label={scan.contentRef} tone="neutral" />
								<StatusPill
									label={`score ${scan.score}`}
									tone={
										scan.score > 50
											? "danger"
											: scan.score > 20
												? "warning"
												: "success"
									}
								/>
								{scan.categories.length > 0 ? (
									<span className="text-xs text-[var(--sea-ink-soft)]">
										{scan.categories.join(", ")}
									</span>
								) : null}
							</div>
						))}
					</div>
				</div>
			) : null}
		</div>
	);
}

/**
 * Shows the per-repository memory snapshot: dominant severity, false-positive
 * rate, and the top 2 recurring vulnerability classes.
 */
function RepositoryMemoryPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const memory = useQuery(api.agentMemory.getRepositoryMemory, {
		tenantSlug,
		repositoryFullName,
	});

	if (memory === undefined || memory === null) return null;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Agent memory</p>
				<StatusPill
					label={memory.dominantSeverity}
					tone={severityTone(memory.dominantSeverity)}
				/>
				<StatusPill
					label={`FP ${Math.round(memory.falsePositiveRate * 100)}%`}
					tone={memory.falsePositiveRate > 0.3 ? "warning" : "neutral"}
				/>
				<StatusPill
					label={`${memory.totalFindingsAnalyzed} analyzed`}
					tone="neutral"
				/>
			</div>
			{memory.recurringVulnClasses.length > 0 ? (
				<div className="mt-2 space-y-1">
					{memory.recurringVulnClasses.slice(0, 2).map((vc) => (
						<div
							key={vc.vulnClass}
							className="flex flex-wrap items-center gap-2"
						>
							<StatusPill
								label={vc.vulnClass.replaceAll("_", " ")}
								tone="info"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{vc.count}× / avg severity{" "}
								{(vc.avgSeverityWeight * 100).toFixed(0)}%
							</span>
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{memory.summary}
			</p>
		</div>
	);
}

/**
 * Shows the per-repository adversarial round summary:
 * win/loss/draw record, averages, latest strategy, and exploit chains.
 */
function AdversarialRoundPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const summary = useQuery(api.redBlueIntel.adversarialSummaryForRepository, {
		tenantSlug,
		repositoryFullName,
	});
	const redAgentFindingCount = useQuery(
		api.redAgentEscalation.getRedAgentFindingCount,
		{ tenantSlug, repositoryFullName },
	);

	if (summary === undefined || summary === null) return null;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Red/Blue rounds</p>
				<StatusPill
					label={`${summary.totalRounds} round${summary.totalRounds === 1 ? "" : "s"}`}
					tone="neutral"
				/>
				{summary.redWins > 0 ? (
					<StatusPill label={`red ${summary.redWins}W`} tone="danger" />
				) : null}
				{summary.blueWins > 0 ? (
					<StatusPill label={`blue ${summary.blueWins}W`} tone="success" />
				) : null}
				{summary.draws > 0 ? (
					<StatusPill label={`${summary.draws} draw`} tone="neutral" />
				) : null}
				{redAgentFindingCount != null && redAgentFindingCount > 0 ? (
					<StatusPill
						label={`${redAgentFindingCount} escalated finding${redAgentFindingCount === 1 ? "" : "s"}`}
						tone="warning"
					/>
				) : null}
			</div>
			<div className="mt-2 flex flex-wrap gap-2">
				<StatusPill
					label={`coverage ${summary.avgAttackSurfaceCoverage}%`}
					tone={summary.avgAttackSurfaceCoverage > 60 ? "warning" : "neutral"}
				/>
				<StatusPill
					label={`detection ${summary.avgBlueDetectionScore}%`}
					tone={summary.avgBlueDetectionScore > 70 ? "success" : "neutral"}
				/>
			</div>
			{summary.latestRound ? (
				<div className="mt-2 space-y-1">
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Latest: {summary.latestRound.redStrategySummary}
					</p>
					{summary.latestRound.exploitChains.length > 0 ? (
						<div className="mt-1 space-y-1">
							{summary.latestRound.exploitChains.map((chain, i) => (
								<p
									// biome-ignore lint/suspicious/noArrayIndexKey: exploit chains have no stable id
									key={i}
									className="text-xs text-[var(--sea-ink-soft)]"
								>
									→ {chain}
								</p>
							))}
						</div>
					) : null}
				</div>
			) : null}
		</div>
	);
}

function attackSurfaceTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 70) return "success";
	if (score >= 40) return "warning";
	if (score > 0) return "danger";
	return "neutral";
}

function trendTone(
	trend: AttackSurfaceSnapshot["trend"],
): "success" | "warning" | "neutral" {
	if (trend === "improving") return "success";
	if (trend === "degrading") return "warning";
	return "neutral";
}

function RepositoryAttackSurfacePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const data = useQuery(api.attackSurfaceIntel.getAttackSurfaceDashboard, {
		tenantSlug,
		repositoryFullName,
	});

	if (data === undefined || data === null) return null;

	const { snapshot, history } = data;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Attack surface</p>
				<StatusPill
					label={`score ${snapshot.score}`}
					tone={attackSurfaceTone(snapshot.score)}
				/>
				<StatusPill label={snapshot.trend} tone={trendTone(snapshot.trend)} />
				<StatusPill
					label={`${snapshot.resolvedFindings}/${snapshot.totalFindings} resolved`}
					tone="neutral"
				/>
			</div>

			{snapshot.openCriticalCount > 0 || snapshot.openHighCount > 0 ? (
				<div className="mt-2 flex flex-wrap gap-2">
					{snapshot.openCriticalCount > 0 ? (
						<StatusPill
							label={`${snapshot.openCriticalCount} open critical`}
							tone="danger"
						/>
					) : null}
					{snapshot.openHighCount > 0 ? (
						<StatusPill
							label={`${snapshot.openHighCount} open high`}
							tone="warning"
						/>
					) : null}
					{snapshot.activeMitigationCount > 0 ? (
						<StatusPill
							label={`${snapshot.activeMitigationCount} PR active`}
							tone="info"
						/>
					) : null}
				</div>
			) : null}

			{history.length > 1 ? (
				<div className="mt-3">
					<p className="mb-1 text-xs text-[var(--sea-ink-soft)]">
						Score history ({history.length} snapshots)
					</p>
					<div className="flex h-8 items-end gap-[2px]">
						{history.map((point: AttackSurfaceHistoryEntry, i: number) => (
							<div
								// biome-ignore lint/suspicious/noArrayIndexKey: history points have no stable id
								key={i}
								className="flex-1 rounded-[2px] bg-[var(--sea-ink-soft)]/30"
								style={{ height: `${Math.max(4, point.score)}%` }}
								title={`Score ${point.score} — ${new Date(point.computedAt).toLocaleDateString()}`}
							/>
						))}
					</div>
				</div>
			) : null}

			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{snapshot.summary}
			</p>
		</div>
	);
}

function driftLevelTone(
	level: string,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "non_compliant") return "danger";
	if (level === "at_risk") return "warning";
	if (level === "drifting") return "warning";
	return "success";
}

function frameworkScoreTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 80) return "success";
	if (score >= 60) return "warning";
	return "danger";
}

/**
 * Shows the per-repository regulatory drift snapshot: overall drift level,
 * per-framework compliance scores, and open gap counts.
 */
function RepositoryRegulatoryDriftPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const snapshot = useQuery(api.regulatoryDriftIntel.getLatestRegulatoryDrift, {
		tenantSlug,
		repositoryFullName,
	});

	if (snapshot === undefined || snapshot === null) return null;

	const frameworkScores = [
		{ key: "soc2", label: "SOC 2", score: snapshot.soc2Score },
		{ key: "gdpr", label: "GDPR", score: snapshot.gdprScore },
		{ key: "hipaa", label: "HIPAA", score: snapshot.hipaaScore },
		{ key: "pci_dss", label: "PCI-DSS", score: snapshot.pciDssScore },
		{ key: "nis2", label: "NIS2", score: snapshot.nis2Score },
	];

	// Only surface frameworks below perfect to keep the panel compact.
	const driftingFrameworks = frameworkScores.filter((f) => f.score < 100);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Regulatory drift</p>
				<StatusPill
					label={snapshot.overallDriftLevel.replace("_", " ")}
					tone={driftLevelTone(snapshot.overallDriftLevel)}
				/>
				{snapshot.openGapCount > 0 ? (
					<StatusPill
						label={`${snapshot.openGapCount} open gap${snapshot.openGapCount === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
				{snapshot.criticalGapCount > 0 ? (
					<StatusPill
						label={`${snapshot.criticalGapCount} critical`}
						tone="danger"
					/>
				) : null}
			</div>
			{driftingFrameworks.length > 0 ? (
				<div className="mt-2 flex flex-wrap gap-2">
					{driftingFrameworks.map((f) => (
						<StatusPill
							key={f.key}
							label={`${f.label} ${f.score}`}
							tone={frameworkScoreTone(f.score)}
						/>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{snapshot.summary}
			</p>
		</div>
	);
}

// ─── Honeypot attractiveness tone helper ──────────────────────────────────────

function honeypotScoreTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 85) return "danger";
	if (score >= 70) return "warning";
	return "neutral";
}

/**
 * Shows the per-repository honeypot plan: proposal counts by kind and the
 * top canary placements ranked by attractiveness score.
 */
function RepositoryHoneypotPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const snapshot = useQuery(api.honeypotIntel.getLatestHoneypotPlan, {
		tenantSlug,
		repositoryFullName,
	});

	if (snapshot === undefined || snapshot === null) return null;

	// Show the top 3 proposals by attractiveness.
	const topProposals = snapshot.proposals.slice(0, 3);

	const kindLabel: Record<string, string> = {
		endpoint: "endpoint",
		database_field: "DB field",
		file: "file",
		token: "token",
	};

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Honeypot plan</p>
				<StatusPill
					label={`${snapshot.totalProposals} proposal${snapshot.totalProposals === 1 ? "" : "s"}`}
					tone="neutral"
				/>
				{snapshot.endpointCount > 0 ? (
					<StatusPill
						label={`${snapshot.endpointCount} endpoint${snapshot.endpointCount === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
				{snapshot.databaseFieldCount > 0 ? (
					<StatusPill
						label={`${snapshot.databaseFieldCount} DB field${snapshot.databaseFieldCount === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
				{snapshot.fileCount > 0 ? (
					<StatusPill
						label={`${snapshot.fileCount} file${snapshot.fileCount === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
				{snapshot.tokenCount > 0 ? (
					<StatusPill
						label={`${snapshot.tokenCount} token${snapshot.tokenCount === 1 ? "" : "s"}`}
						tone="neutral"
					/>
				) : null}
			</div>
			{topProposals.length > 0 ? (
				<div className="mt-2 space-y-1">
					{topProposals.map((p) => (
						<div key={p.path} className="flex flex-wrap items-center gap-2">
							<StatusPill label={kindLabel[p.kind] ?? p.kind} tone="neutral" />
							<StatusPill
								label={`score ${p.attractivenessScore}`}
								tone={honeypotScoreTone(p.attractivenessScore)}
							/>
							<span className="font-mono text-xs text-[var(--sea-ink-soft)]">
								{p.path}
							</span>
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{snapshot.summary}
			</p>
		</div>
	);
}

// ─── Learning profile tone helpers ───────────────────────────────────────────

function learningTrendTone(
	trend: string,
): "success" | "warning" | "danger" | "neutral" {
	if (trend === "improving") return "success";
	if (trend === "degrading") return "danger";
	return "neutral";
}

function maturityTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 70) return "success";
	if (score >= 35) return "warning";
	return "neutral";
}

function multiplierTone(
	m: number,
): "success" | "warning" | "danger" | "neutral" {
	if (m >= 1.5) return "danger"; // recurring pattern — high attention
	return "neutral";
}

/**
 * Shows the per-repository learning profile: vuln class patterns, exploit
 * paths retained from red-agent wins, attack surface trend, and learning
 * maturity score.
 */
function RepositoryLearningPanel({
	tenantSlug,
	repositoryFullName,
	repositoryId,
}: {
	tenantSlug: string;
	repositoryFullName: string;
	repositoryId: Id<"repositories">;
}) {
	const profile = useQuery(api.learningProfileIntel.getLatestLearningProfile, {
		tenantSlug,
		repositoryFullName,
	});
	const fpSummary = useQuery(api.findingTriage.getFalsePositiveSummary, {
		repositoryId,
	});

	if (profile === undefined || profile === null) return null;

	// Top 3 vuln class patterns by confirmedCount.
	const topPatterns = profile.vulnClassPatterns.slice(0, 3);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Learning profile</p>
				<StatusPill
					label={`maturity ${profile.adaptedConfidenceScore}/100`}
					tone={maturityTone(profile.adaptedConfidenceScore)}
				/>
				<StatusPill
					label={`surface ${profile.attackSurfaceTrend}`}
					tone={learningTrendTone(profile.attackSurfaceTrend)}
				/>
				{profile.recurringCount > 0 ? (
					<StatusPill
						label={`${profile.recurringCount} recurring`}
						tone="warning"
					/>
				) : null}
				{profile.suppressedCount > 0 ? (
					<StatusPill
						label={`${profile.suppressedCount} suppressed`}
						tone="neutral"
					/>
				) : null}
				{profile.successfulExploitPaths.length > 0 ? (
					<StatusPill
						label={`${profile.successfulExploitPaths.length} exploit path${profile.successfulExploitPaths.length === 1 ? "" : "s"}`}
						tone="danger"
					/>
				) : null}
				{fpSummary && fpSummary.totalFalsePositives > 0 ? (
					<StatusPill
						label={`${fpSummary.totalFalsePositives} analyst FP`}
						tone="neutral"
					/>
				) : null}
			</div>
			{topPatterns.length > 0 ? (
				<div className="mt-2 space-y-1">
					{topPatterns.map((p) => (
						<div
							key={p.vulnClass}
							className="flex flex-wrap items-center gap-2"
						>
							<StatusPill
								label={p.vulnClass.replaceAll("_", " ")}
								tone={multiplierTone(p.confidenceMultiplier)}
							/>
							<StatusPill
								label={`×${p.confidenceMultiplier} confidence`}
								tone={multiplierTone(p.confidenceMultiplier)}
							/>
							{p.isRecurring ? (
								<span className="text-xs text-[var(--sea-ink-soft)]">
									recurring
								</span>
							) : null}
							{p.isSuppressed ? (
								<span className="text-xs text-[var(--sea-ink-soft)]">
									suppressed
								</span>
							) : null}
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{profile.summary}
			</p>
		</div>
	);
}

// ─── Risk Acceptance Panel ───────────────────────────────────────────────────

/**
 * Shows active risk acceptances for a repository: how many are active,
 * which are expiring soon, and the justification + expiry for near-term ones.
 * Hidden when no active acceptances exist.
 */
function RepositoryRiskAcceptancePanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const summary = useQuery(
		api.riskAcceptanceIntel.getAcceptanceSummaryForRepository,
		{ repositoryId },
	);
	const expiring = useQuery(api.riskAcceptanceIntel.getExpiringAcceptances, {
		repositoryId,
	});

	if (summary === undefined || summary === null) return null;
	if (summary.totalActive === 0) return null;

	const nowMs = Date.now();

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Risk acceptances</p>
				<StatusPill label={`${summary.totalActive} active`} tone="neutral" />
				{summary.expiringSoon > 0 ? (
					<StatusPill
						label={`${summary.expiringSoon} expiring soon`}
						tone="warning"
					/>
				) : null}
				{summary.permanent > 0 ? (
					<StatusPill label={`${summary.permanent} permanent`} tone="neutral" />
				) : null}
			</div>
			{expiring && expiring.length > 0 ? (
				<div className="mt-2 space-y-1">
					{expiring.slice(0, 3).map((a) => (
						<div key={a._id} className="flex flex-wrap items-center gap-2">
							<StatusPill
								label={
									a.expiresAt != null
										? (() => {
												const remaining = a.expiresAt - nowMs;
												const days = Math.floor(remaining / (24 * 3_600_000));
												return days === 0
													? "expires today"
													: days === 1
														? "expires tomorrow"
														: `expires in ${days}d`;
											})()
										: "permanent"
								}
								tone="warning"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{a.justification.slice(0, 60)}
								{a.justification.length > 60 ? "…" : ""}
							</span>
						</div>
					))}
				</div>
			) : null}
		</div>
	);
}

// ─── SLA Enforcement Panel ───────────────────────────────────────────────────

function slaComplianceTone(
	rate: number,
): "success" | "warning" | "danger" | "neutral" {
	if (rate >= 0.9) return "success";
	if (rate >= 0.7) return "warning";
	return "danger";
}

/**
 * Shows per-repository SLA health: compliance rate, breach count, approaching
 * count, and mean time-to-remediate.  Hidden when no active findings exist.
 */
function RepositorySlaPanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const data = useQuery(api.slaIntel.getSlaStatusForRepository, {
		repositoryId,
	});

	if (data === undefined) return null;
	// Hide when no findings are tracked (no open findings with SLA thresholds)
	if (data.summary.totalTracked === 0 && data.summary.breachedSla === 0)
		return null;

	const { summary } = data;
	const compliancePct = Math.round(summary.complianceRate * 100);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">SLA enforcement</p>
				<StatusPill
					label={`${compliancePct}% compliant`}
					tone={slaComplianceTone(summary.complianceRate)}
				/>
				{summary.breachedSla > 0 ? (
					<StatusPill label={`${summary.breachedSla} breached`} tone="danger" />
				) : null}
				{summary.approachingSla > 0 ? (
					<StatusPill
						label={`${summary.approachingSla} approaching`}
						tone="warning"
					/>
				) : null}
				{summary.mttrHours !== null ? (
					<StatusPill
						label={`MTTR ${Math.round(summary.mttrHours)}h`}
						tone="neutral"
					/>
				) : null}
			</div>
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{summary.withinSla} within · {summary.approachingSla} approaching ·{" "}
				{summary.breachedSla} breached of {summary.totalTracked} active
				{summary.mttrHours !== null
					? ` · MTTR ${Math.round(summary.mttrHours)}h`
					: ""}
			</p>
		</div>
	);
}

// ─── Remediation Priority Queue Panel (per-repository) ───────────────────────

function priorityTierTone(
	tier: string,
): "success" | "warning" | "danger" | "neutral" {
	if (tier === "p0") return "danger";
	if (tier === "p1") return "warning";
	if (tier === "p2") return "info" as "neutral"; // closest tone
	return "neutral";
}

/**
 * Shows the automated remediation priority queue for a single repository:
 * P0/P1/P2/P3 tier counts, average composite score, and the top-ranked
 * findings with rationale strings so operators know *why* each finding ranked
 * where it did.  Hidden when the queue is empty.
 */
function RepositoryRemediationQueuePanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const data = useQuery(
		api.remediationQueueIntel.getRemediationQueueForRepository,
		{ repositoryId },
	);

	if (data === undefined) return null;
	if (data.summary.totalCandidates === 0) return null;

	const { queue, summary } = data;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Remediation queue</p>
				{summary.p0Count > 0 ? (
					<StatusPill label={`P0 ×${summary.p0Count}`} tone="danger" />
				) : null}
				{summary.p1Count > 0 ? (
					<StatusPill label={`P1 ×${summary.p1Count}`} tone="warning" />
				) : null}
				{summary.p2Count > 0 ? (
					<StatusPill label={`P2 ×${summary.p2Count}`} tone="neutral" />
				) : null}
				{summary.p3Count > 0 ? (
					<StatusPill label={`P3 ×${summary.p3Count}`} tone="neutral" />
				) : null}
				<StatusPill
					label={`avg score ${summary.averageScore}`}
					tone="neutral"
				/>
				<StatusPill label={`${summary.totalCandidates} active`} tone="info" />
			</div>
			{queue.length > 0 ? (
				<div className="mt-3 space-y-3">
					{queue.slice(0, 5).map((finding) => (
						<div
							key={finding.findingId}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)] p-3"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={finding.priorityTier.toUpperCase()}
									tone={priorityTierTone(finding.priorityTier)}
								/>
								<StatusPill
									label={finding.severity}
									tone={severityTone(finding.severity)}
								/>
								<StatusPill
									label={`score ${finding.priorityScore}`}
									tone="neutral"
								/>
							</div>
							<p className="mt-2 text-sm font-medium text-[var(--sea-ink)] line-clamp-1">
								{finding.title}
							</p>
							{finding.priorityRationale.length > 0 ? (
								<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
									{finding.priorityRationale.join(" · ")}
								</p>
							) : null}
						</div>
					))}
				</div>
			) : null}
		</div>
	);
}

// ─── Severity Escalation Panel ────────────────────────────────────────────────

/**
 * Shows the automatic severity escalation activity for a single repository.
 * Displays total escalations, per-trigger counts, and the 10 most recent
 * upgrade events so operators can see which intelligence signals are driving
 * severity changes.  Hidden when no escalations have occurred.
 */
function RepositoryEscalationPanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const data = useQuery(api.escalationIntel.getEscalationSummaryForRepository, {
		repositoryId,
	});

	if (data === undefined) return null;
	if (data.totalEscalations === 0) return null;

	const {
		triggerCounts,
		recentEvents,
		totalEscalations,
		uniqueFindingsEscalated,
	} = data;

	const triggerLabels: Record<string, string> = {
		exploit_available: "Exploit",
		blast_radius_critical: "Blast ≥80",
		blast_radius_high: "Blast ≥60",
		cross_repo_spread: "Cross-repo",
		sla_breach: "SLA breach",
	};

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Severity escalations</p>
				<StatusPill label={`${totalEscalations} upgrades`} tone="warning" />
				<StatusPill
					label={`${uniqueFindingsEscalated} findings`}
					tone="neutral"
				/>
				{Object.entries(triggerCounts).map(([trigger, count]) =>
					count > 0 ? (
						<StatusPill
							key={trigger}
							label={`${triggerLabels[trigger] ?? trigger} ×${count}`}
							tone="neutral"
						/>
					) : null,
				)}
			</div>
			{recentEvents.length > 0 ? (
				<div className="mt-3 space-y-2">
					{recentEvents.slice(0, 5).map((ev) => (
						<div
							key={`${ev.findingId}-${ev.computedAt}`}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)] p-3"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={ev.previousSeverity}
									tone={severityTone(ev.previousSeverity)}
								/>
								<span className="text-xs text-[var(--sea-ink-soft)]">→</span>
								<StatusPill
									label={ev.newSeverity}
									tone={severityTone(ev.newSeverity)}
								/>
								{ev.triggers.map((t: string) => (
									<StatusPill
										key={t}
										label={triggerLabels[t] ?? t}
										tone="neutral"
									/>
								))}
							</div>
							{ev.rationale.length > 0 ? (
								<p className="mt-1 text-xs text-[var(--sea-ink-soft)] line-clamp-2">
									{ev.rationale[0]}
								</p>
							) : null}
						</div>
					))}
				</div>
			) : null}
		</div>
	);
}

// ─── Autonomous Remediation Panel ────────────────────────────────────────────

/**
 * Shows auto-remediation dispatch activity for a single repository.
 * Displays total PRs dispatched, candidate count, and per-skip-reason counts
 * so operators can see whether the policy is surfacing findings or gating
 * them.  Hidden when no dispatch runs have been recorded (policy disabled or
 * not yet triggered).
 */
function RepositoryAutoRemediationPanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const data = useQuery(
		api.autoRemediationIntel.getAutoRemediationHistoryForRepository,
		{ repositoryId },
	);

	if (data === undefined) return null;
	if (data.length === 0) return null;

	// Aggregate across all recorded runs for the headline numbers.
	const totalDispatched = data.reduce((sum, r) => sum + r.dispatchedCount, 0);
	const totalCandidates = data.reduce((sum, r) => sum + r.candidateCount, 0);
	const totalAlreadyHasPr = data.reduce(
		(sum, r) => sum + r.skippedAlreadyHasPr,
		0,
	);
	const totalBelowTier = data.reduce((sum, r) => sum + r.skippedBelowTier, 0);
	const totalBelowSeverity = data.reduce(
		(sum, r) => sum + r.skippedBelowSeverity,
		0,
	);
	const totalConcurrencyCap = data.reduce(
		(sum, r) => sum + r.skippedConcurrencyCap,
		0,
	);

	// Show the 5 most recent runs (data is already newest-first).
	const recentRuns = data.slice(0, 5);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Auto-remediation</p>
				{totalDispatched > 0 ? (
					<StatusPill label={`${totalDispatched} dispatched`} tone="success" />
				) : null}
				<StatusPill label={`${totalCandidates} candidates`} tone="neutral" />
				{totalAlreadyHasPr > 0 ? (
					<StatusPill label={`${totalAlreadyHasPr} has-PR`} tone="neutral" />
				) : null}
				{totalBelowTier > 0 ? (
					<StatusPill label={`${totalBelowTier} below-tier`} tone="neutral" />
				) : null}
				{totalBelowSeverity > 0 ? (
					<StatusPill
						label={`${totalBelowSeverity} below-sev`}
						tone="neutral"
					/>
				) : null}
				{totalConcurrencyCap > 0 ? (
					<StatusPill
						label={`${totalConcurrencyCap} cap-limited`}
						tone="warning"
					/>
				) : null}
			</div>
			{recentRuns.length > 0 ? (
				<div className="mt-3 space-y-2">
					{recentRuns.map((run) => (
						<div
							key={run.computedAt}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)] p-3"
						>
							<div className="flex flex-wrap items-center gap-2">
								{run.dispatchedCount > 0 ? (
									<StatusPill
										label={`${run.dispatchedCount} dispatched`}
										tone="success"
									/>
								) : (
									<StatusPill label="0 dispatched" tone="neutral" />
								)}
								<StatusPill
									label={`${run.candidateCount} candidates`}
									tone="neutral"
								/>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
								{new Date(run.computedAt).toLocaleString()}
							</p>
						</div>
					))}
				</div>
			) : null}
		</div>
	);
}

// ─── Agentic Workflow Security Panel ─────────────────────────────────────────

/** Per-repository panel — surfaces agentic pipeline security findings. */
function RepositoryAgenticWorkflowPanel({
	repositoryId,
}: {
	repositoryId: Id<"repositories">;
}) {
	const scan = useQuery(api.agenticWorkflowIntel.getLatestAgenticScan, {
		repositoryId,
	});

	if (scan === undefined) return null;
	if (!scan) return null;
	if (scan.criticalCount + scan.highCount + scan.mediumCount === 0) return null;

	const vulnClassLabel = (cls: string) =>
		cls.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

	const severityTone = (sev: string) => {
		if (sev === "critical") return "danger" as const;
		if (sev === "high") return "warning" as const;
		return "neutral" as const;
	};

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Agentic security</p>
				{scan.criticalCount > 0 ? (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				) : null}
				{scan.highCount > 0 ? (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				) : null}
				{scan.mediumCount > 0 ? (
					<StatusPill label={`${scan.mediumCount} medium`} tone="neutral" />
				) : null}
				{scan.frameworksDetected.length > 0 ? (
					<StatusPill
						label={scan.frameworksDetected.join(", ")}
						tone="neutral"
					/>
				) : null}
			</div>
			<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">{scan.summary}</p>
			{scan.findings.length > 0 ? (
				<div className="mt-3 space-y-2">
					{scan.findings.slice(0, 4).map((f) => (
						<div
							key={`${f.file}-${f.line}-${f.vulnClass}`}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)] p-3"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={f.severity.toUpperCase()}
									tone={severityTone(f.severity)}
								/>
								<StatusPill
									label={vulnClassLabel(f.vulnClass)}
									tone="neutral"
								/>
								<StatusPill label={f.framework} tone="neutral" />
							</div>
							<p className="mt-1 text-xs font-medium text-[var(--sea-ink)]">
								{f.evidence}
							</p>
							<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
								{f.file}:{f.line}
							</p>
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				Scanned {scan.totalFilesScanned} files ·{" "}
				{new Date(scan.computedAt).toLocaleString()}
			</p>
		</div>
	);
}

// ─── Vendor Trust Panel (tenant-level) ───────────────────────────────────────

const RISK_LEVEL_TONE: Record<
	string,
	"danger" | "warning" | "info" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "success",
	trusted: "success",
};

const RECOMMENDATION_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral"
> = {
	revoke_immediately: "danger",
	review_scopes: "warning",
	monitor: "info",
	no_action: "neutral",
};

const RECOMMENDATION_LABEL: Record<string, string> = {
	revoke_immediately: "revoke",
	review_scopes: "review scopes",
	monitor: "monitor",
	no_action: "ok",
};

const CATEGORY_LABEL: Record<string, string> = {
	ai_tool: "AI tool",
	observability: "observability",
	auth_provider: "auth",
	database: "database",
	ci_cd: "CI/CD",
	communication: "comms",
	security: "security",
	other: "other",
};

/**
 * Global panel — surfaces connected OAuth/SaaS vendor risk across the tenant.
 * Hidden until at least one vendor is registered.
 */
function TenantVendorTrustPanel({ tenantSlug }: { tenantSlug: string }) {
	const vendors = useQuery(api.vendorTrust.listVendorsBySlug, { tenantSlug });

	if (vendors === undefined || vendors === null || vendors.length === 0)
		return null;

	const activeVendors = vendors.filter((v) => v.status === "active");

	// Aggregate risk-level counts across vendors with a latest snapshot
	const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, trusted: 0 };
	const recCounts = {
		revoke_immediately: 0,
		review_scopes: 0,
		monitor: 0,
		no_action: 0,
	};
	for (const v of vendors) {
		if (!v.latestRisk) continue;
		riskCounts[v.latestRisk.riskLevel as keyof typeof riskCounts] =
			(riskCounts[v.latestRisk.riskLevel as keyof typeof riskCounts] ?? 0) + 1;
		recCounts[v.latestRisk.recommendation as keyof typeof recCounts] =
			(recCounts[v.latestRisk.recommendation as keyof typeof recCounts] ?? 0) +
			1;
	}

	// Top vendors to surface: critical → high → by score desc
	const atRisk = vendors
		.filter((v) => v.latestRisk && v.latestRisk.riskScore >= 40)
		.sort(
			(a, b) => (b.latestRisk?.riskScore ?? 0) - (a.latestRisk?.riskScore ?? 0),
		)
		.slice(0, 5);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Vendor trust</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				OAuth and SaaS integrations assessed for supply-chain risk.
			</h2>

			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`${activeVendors.length} active vendor${activeVendors.length === 1 ? "" : "s"}`}
					tone="info"
				/>
				{riskCounts.critical > 0 && (
					<StatusPill label={`${riskCounts.critical} critical`} tone="danger" />
				)}
				{riskCounts.high > 0 && (
					<StatusPill label={`${riskCounts.high} high`} tone="warning" />
				)}
				{recCounts.revoke_immediately > 0 && (
					<StatusPill
						label={`${recCounts.revoke_immediately} revoke`}
						tone="danger"
					/>
				)}
				{recCounts.review_scopes > 0 && (
					<StatusPill
						label={`${recCounts.review_scopes} review`}
						tone="warning"
					/>
				)}
			</div>

			{atRisk.length > 0 && (
				<div className="mt-4 space-y-2">
					{atRisk.map((vendor) => (
						<div
							key={vendor._id}
							className="flex flex-wrap items-center gap-2 rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 px-3 py-2"
						>
							<span className="text-sm font-medium text-[var(--sea-ink)]">
								{vendor.name}
							</span>
							<StatusPill
								label={CATEGORY_LABEL[vendor.category] ?? vendor.category}
								tone="neutral"
							/>
							{vendor.latestRisk && (
								<>
									<StatusPill
										label={`score ${vendor.latestRisk.riskScore}`}
										tone={
											RISK_LEVEL_TONE[vendor.latestRisk.riskLevel] ?? "info"
										}
									/>
									<StatusPill
										label={
											RECOMMENDATION_LABEL[vendor.latestRisk.recommendation] ??
											vendor.latestRisk.recommendation
										}
										tone={
											RECOMMENDATION_TONE[vendor.latestRisk.recommendation] ??
											"neutral"
										}
									/>
									{vendor.latestRisk.scopeCreepDetected && (
										<StatusPill label="scope creep" tone="warning" />
									)}
									{vendor.latestRisk.breachDetected && (
										<StatusPill label="breach signal" tone="danger" />
									)}
								</>
							)}
						</div>
					))}
				</div>
			)}
		</article>
	);
}

// ─── Traffic Anomaly Panel (per-repository) ───────────────────────────────────

/**
 * Per-repository production traffic anomaly panel.
 *
 * Shows the latest anomaly assessment from HTTP access log ingestion —
 * anomaly score, level, detected patterns, and finding candidates.
 *
 * Hidden until the first traffic batch has been ingested via
 * POST /api/traffic/events.
 *
 * Spec §10 Phase 4 — Production Traffic Anomaly Detection / WS-29.
 */
function RepositoryTrafficAnomalyPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const snapshot = useQuery(api.trafficAnomalyIntel.getLatestTrafficAnomaly, {
		tenantSlug,
		repositoryFullName,
	});

	if (snapshot === undefined || snapshot === null) return null;

	const LEVEL_TONE: Record<
		string,
		"danger" | "warning" | "info" | "success" | "neutral"
	> = {
		critical: "danger",
		anomalous: "warning",
		suspicious: "info",
		normal: "success",
	};

	const LEVEL_EMOJI: Record<string, string> = {
		critical: "🚨",
		anomalous: "⚠️",
		suspicious: "🔍",
		normal: "✓",
	};

	const SEVERITY_TONE: Record<
		string,
		"danger" | "warning" | "info" | "neutral"
	> = {
		critical: "danger",
		high: "warning",
		medium: "info",
		low: "neutral",
	};

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Traffic analysis</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Production HTTP traffic anomaly detection — no code access required.
			</h2>

			{/* Top-level status */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`${LEVEL_EMOJI[snapshot.level] ?? ""} ${snapshot.level} · score ${snapshot.anomalyScore}`}
					tone={LEVEL_TONE[snapshot.level] ?? "neutral"}
				/>
				<StatusPill
					label={`${snapshot.stats.totalRequests} requests`}
					tone="info"
				/>
				{snapshot.stats.errorRate > 0 && (
					<StatusPill
						label={`${(snapshot.stats.errorRate * 100).toFixed(0)}% errors`}
						tone={
							snapshot.stats.errorRate >= 0.3
								? "danger"
								: snapshot.stats.errorRate >= 0.1
									? "warning"
									: "neutral"
						}
					/>
				)}
				<StatusPill
					label={`${snapshot.stats.uniquePaths} unique paths`}
					tone="neutral"
				/>
			</div>

			{/* Detected patterns */}
			{snapshot.patterns.length > 0 && (
				<div className="mt-4 space-y-1">
					{snapshot.patterns.slice(0, 4).map((pattern) => (
						<div
							key={pattern.type}
							className="rounded-lg bg-[var(--foam-wash)] px-4 py-2 text-sm"
						>
							<span className="font-medium text-[var(--sea-ink)]">
								{pattern.type.replace(/_/g, " ")}
							</span>
							<span className="ml-2 text-[var(--salt-mist)]">
								{pattern.details}
							</span>
						</div>
					))}
				</div>
			)}

			{/* Finding candidates */}
			{snapshot.findingCandidates.length > 0 && (
				<div className="mt-3 flex flex-wrap gap-2">
					{snapshot.findingCandidates.map((c) => (
						<StatusPill
							key={c.vulnClass}
							label={`${c.vulnClass.replace(/_/g, " ")} · ${c.severity}`}
							tone={SEVERITY_TONE[c.severity] ?? "neutral"}
						/>
					))}
				</div>
			)}

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{snapshot.summary}</p>
		</article>
	);
}

// ─── Secret Scan Panel (per-repository) ──────────────────────────────────────

/**
 * Shows the latest secret / hardcoded-credential scan result for a repository.
 *
 * Detects: AWS/GCP/Azure keys, OpenAI/Anthropic API keys, GitHub tokens,
 * Stripe keys, private keys, database URLs with credentials, hardcoded
 * passwords, and high-entropy string literals.
 *
 * Hidden until the first scan result exists (on every push, file paths are
 * scanned automatically via fire-and-forget from the push webhook handler).
 *
 * Spec §3 / WS-30 — Hardcoded Credential & Secret Detection Engine.
 */
function RepositorySecretScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.secretDetectionIntel.getLatestSecretScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const SEV_TONE: Record<string, "danger" | "warning" | "info" | "neutral"> = {
		critical: "danger",
		high: "warning",
		medium: "info",
	};

	const overallTone =
		scan.criticalCount > 0
			? ("danger" as const)
			: scan.highCount > 0
				? ("warning" as const)
				: scan.totalFound > 0
					? ("info" as const)
					: ("success" as const);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Secret detection</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Hardcoded credential scan
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={
						scan.totalFound === 0
							? "✓ clean"
							: `${scan.totalFound} secret(s) detected`
					}
					tone={overallTone}
				/>
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
				<StatusPill
					label={`${scan.scannedItems} item(s) scanned`}
					tone="neutral"
				/>
			</div>

			{/* Finding rows */}
			{scan.findings.length > 0 && (
				<div className="mt-4 space-y-1">
					{scan.findings.slice(0, 5).map((finding) => (
						<div
							key={`${finding.category}-${finding.redactedMatch}`}
							className="rounded-lg bg-[var(--foam-wash)] px-4 py-2 text-sm"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={finding.severity}
									tone={SEV_TONE[finding.severity] ?? "neutral"}
								/>
								<span className="font-medium text-[var(--sea-ink)]">
									{finding.description}
								</span>
								{finding.isTestFileHint && (
									<StatusPill label="test context" tone="neutral" />
								)}
							</div>
							<p className="mt-1 font-mono text-xs text-[var(--salt-mist)]">
								{finding.redactedMatch}
							</p>
						</div>
					))}
					{scan.findings.length > 5 && (
						<p className="text-xs text-[var(--salt-mist)]">
							+ {scan.findings.length - 5} more finding(s)
						</p>
					)}
				</div>
			)}

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{scan.summary}</p>
		</article>
	);
}

// ─── License Compliance Panel (per-repository) ───────────────────────────────

/**
 * Shows the latest dependency license compliance evaluation for a repository.
 *
 * Displays the compliance score (0–100), overall level, per-category counts,
 * and up to 5 blocked/warned component violations with their resolved license.
 *
 * Hidden until the first compliance snapshot has been computed.
 *
 * Spec §3 / WS-31 — Dependency License Compliance Engine.
 */
function RepositoryLicenseCompliancePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const result = useQuery(
		api.licenseComplianceIntel.getLatestLicenseCompliance,
		{
			tenantSlug,
			repositoryFullName,
		},
	);

	if (result === undefined || result === null) return null;

	const LEVEL_TONE: Record<
		"compliant" | "caution" | "non_compliant",
		"success" | "warning" | "danger"
	> = {
		compliant: "success",
		caution: "warning",
		non_compliant: "danger",
	};

	const LEVEL_LABEL: Record<"compliant" | "caution" | "non_compliant", string> =
		{
			compliant: "✓ compliant",
			caution: "caution",
			non_compliant: "non-compliant",
		};

	const overallLevel = result.overallLevel as
		| "compliant"
		| "caution"
		| "non_compliant";
	const overallTone = LEVEL_TONE[overallLevel] ?? "neutral";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">License compliance</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Dependency license evaluation
			</h2>

			{/* Summary pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={LEVEL_LABEL[overallLevel] ?? result.overallLevel}
					tone={overallTone}
				/>
				<StatusPill
					label={`score ${result.complianceScore}/100`}
					tone={
						result.complianceScore >= 80
							? "success"
							: result.complianceScore >= 50
								? "warning"
								: "danger"
					}
				/>
				<StatusPill
					label={`${result.totalComponents} components`}
					tone="neutral"
				/>
				{result.blockedCount > 0 && (
					<StatusPill label={`${result.blockedCount} blocked`} tone="danger" />
				)}
				{result.warnCount > 0 && (
					<StatusPill label={`${result.warnCount} warnings`} tone="warning" />
				)}
				{result.unknownCount > 0 && (
					<StatusPill label={`${result.unknownCount} unknown`} tone="neutral" />
				)}
			</div>

			{/* Violation rows */}
			{result.violations.length > 0 && (
				<div className="mt-4 space-y-1">
					{result.violations.slice(0, 5).map((v) => (
						<div
							key={`${v.name}-${v.ecosystem}`}
							className="rounded-lg bg-[var(--foam-wash)] px-4 py-2 text-sm"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={v.outcome === "blocked" ? "blocked" : "warn"}
									tone={v.outcome === "blocked" ? "danger" : "warning"}
								/>
								<span className="font-medium text-[var(--sea-ink)]">
									{v.name}
								</span>
								<span className="text-[var(--salt-mist)]">({v.ecosystem})</span>
							</div>
							<p className="mt-1 text-xs text-[var(--salt-mist)]">
								{v.resolvedLicense ?? "unknown license"} · {v.category}
							</p>
						</div>
					))}
					{result.violations.length > 5 && (
						<p className="text-xs text-[var(--salt-mist)]">
							+ {result.violations.length - 5} more violation(s)
						</p>
					)}
				</div>
			)}

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{result.summary}</p>
		</article>
	);
}

// ─── License Scan Panel (per-repository) — WS-48 ────────────────────────────

const LICENSE_RISK_TONE: Record<
	string,
	"danger" | "warning" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "neutral",
	low: "neutral",
	none: "success",
};

const LICENSE_TYPE_LABEL: Record<string, string> = {
	strong_copyleft: "Strong copyleft",
	weak_copyleft: "Weak copyleft",
	proprietary: "Proprietary",
	unknown: "Unknown",
	permissive: "Permissive",
};

function RepositoryLicenseScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.licenseScanIntel.getLatestLicenseComplianceScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;
	// Self-hide when no risky licenses found
	if (
		scan.criticalCount === 0 &&
		scan.highCount === 0 &&
		scan.mediumCount === 0 &&
		scan.lowCount === 0
	)
		return null;

	const topFindings = scan.findings.slice(0, 5);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">License risk</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				SPDX license scan
			</h2>

			{/* Summary pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`overall ${scan.overallRisk}`}
					tone={LICENSE_RISK_TONE[scan.overallRisk] ?? "neutral"}
				/>
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.unknownLicenseCount > 0 && (
					<StatusPill
						label={`${scan.unknownLicenseCount} unknown`}
						tone="neutral"
					/>
				)}
				<StatusPill label={`${scan.totalScanned} scanned`} tone="neutral" />
			</div>

			{/* Per-package findings */}
			<ul className="mt-4 space-y-2">
				{topFindings.map((f) => (
					<li
						key={`${f.packageName}-${f.ecosystem}-${f.spdxId}`}
						className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
					>
						<div className="flex items-start justify-between gap-2">
							<div className="min-w-0">
								<p className="text-sm font-semibold text-[var(--sea-ink)] leading-snug">
									{f.packageName}
									<span className="ml-1.5 font-normal text-[var(--sea-ink)]/50 text-xs">
										{f.version}
									</span>
								</p>
								<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60">
									{f.spdxId} ·{" "}
									{LICENSE_TYPE_LABEL[f.licenseType] ?? f.licenseType}
								</p>
							</div>
							<StatusPill
								label={f.riskLevel}
								tone={LICENSE_RISK_TONE[f.riskLevel] ?? "neutral"}
							/>
						</div>
					</li>
				))}
				{scan.findings.length > 5 && (
					<li className="px-3 text-xs text-[var(--sea-ink)]/40">
						+{scan.findings.length - 5} more finding
						{scan.findings.length - 5 > 1 ? "s" : ""}
					</li>
				)}
			</ul>

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{scan.summary}</p>
		</article>
	);
}

// ─── SBOM Quality Panel (per-repository) ─────────────────────────────────────

/**
 * Shows the latest SBOM quality evaluation for a repository.
 *
 * Five sub-scores: completeness (25%), version-pinning discipline (25%),
 * license resolution rate (20%), snapshot freshness (15%), and layer coverage
 * (15%) compose into a single 0–100 grade.
 *
 * Hidden until the first quality snapshot has been computed.
 *
 * Spec §3 / WS-32 — SBOM Quality & Completeness Scoring.
 */
function RepositorySbomQualityPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const quality = useQuery(api.sbomQualityIntel.getSbomQualityForRepository, {
		tenantSlug,
		repositoryFullName,
	});

	if (quality === undefined || quality === null) return null;

	const GRADE_TONE: Record<
		"excellent" | "good" | "fair" | "poor",
		"success" | "info" | "warning" | "danger"
	> = {
		excellent: "success",
		good: "info",
		fair: "warning",
		poor: "danger",
	};

	const grade = quality.grade as "excellent" | "good" | "fair" | "poor";
	const gradeTone = GRADE_TONE[grade] ?? "neutral";

	function subScoreTone(score: number): "success" | "warning" | "danger" {
		return score >= 80 ? "success" : score >= 50 ? "warning" : "danger";
	}

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">SBOM quality</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Completeness &amp; hygiene score
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={grade} tone={gradeTone} />
				<StatusPill
					label={`${quality.overallScore}/100`}
					tone={subScoreTone(quality.overallScore)}
				/>
				<StatusPill
					label={`${quality.totalComponents} components`}
					tone="neutral"
				/>
				<StatusPill
					label={`${quality.layersPopulated}/6 layers`}
					tone={quality.layersPopulated >= 4 ? "success" : "warning"}
				/>
			</div>

			{/* Sub-score breakdown */}
			<div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
				<div className="rounded-lg bg-[var(--foam-wash)] px-3 py-2 text-sm">
					<p className="text-xs text-[var(--salt-mist)]">Completeness</p>
					<StatusPill
						label={`${quality.completenessScore}/100`}
						tone={subScoreTone(quality.completenessScore)}
					/>
				</div>
				<div className="rounded-lg bg-[var(--foam-wash)] px-3 py-2 text-sm">
					<p className="text-xs text-[var(--salt-mist)]">Version pinning</p>
					<StatusPill
						label={`${quality.versionPinningScore}/100`}
						tone={subScoreTone(quality.versionPinningScore)}
					/>
				</div>
				<div className="rounded-lg bg-[var(--foam-wash)] px-3 py-2 text-sm">
					<p className="text-xs text-[var(--salt-mist)]">License resolution</p>
					<StatusPill
						label={`${quality.licenseResolutionScore}/100`}
						tone={subScoreTone(quality.licenseResolutionScore)}
					/>
				</div>
				<div className="rounded-lg bg-[var(--foam-wash)] px-3 py-2 text-sm">
					<p className="text-xs text-[var(--salt-mist)]">Freshness</p>
					<StatusPill
						label={`${quality.freshnessScore}/100`}
						tone={subScoreTone(quality.freshnessScore)}
					/>
				</div>
				<div className="rounded-lg bg-[var(--foam-wash)] px-3 py-2 text-sm">
					<p className="text-xs text-[var(--salt-mist)]">Layer coverage</p>
					<StatusPill
						label={`${quality.layerCoverageScore}/100`}
						tone={subScoreTone(quality.layerCoverageScore)}
					/>
				</div>
			</div>

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{quality.summary}</p>
		</article>
	);
}

// ─── IaC Security Panel (per-repository) ─────────────────────────────────────

/**
 * Shows the latest Infrastructure as Code (IaC) security scan for a repository.
 *
 * Displays overall risk level, finding counts by severity, and per-file
 * misconfiguration rows covering Terraform, Kubernetes, Dockerfile, and
 * Docker Compose files.
 *
 * Hidden until the first scan result exists.
 *
 * Spec §3 / WS-33 — IaC Security Scanner.
 */
function RepositoryIacScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.iacScanIntel.getLatestIacScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const RISK_TONE: Record<
		"critical" | "high" | "medium" | "low" | "none",
		"danger" | "warning" | "info" | "neutral" | "success"
	> = {
		critical: "danger",
		high: "warning",
		medium: "info",
		low: "neutral",
		none: "success",
	};

	const overallRisk = scan.overallRisk as
		| "critical"
		| "high"
		| "medium"
		| "low"
		| "none";
	const riskTone = RISK_TONE[overallRisk] ?? "neutral";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">IaC security</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Infrastructure misconfiguration scan
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={overallRisk === "none" ? "✓ clean" : overallRisk}
					tone={riskTone}
				/>
				<StatusPill
					label={`${scan.totalFindings} finding${scan.totalFindings === 1 ? "" : "s"}`}
					tone={scan.totalFindings === 0 ? "success" : "neutral"}
				/>
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
				<StatusPill
					label={`${scan.totalFiles} file${scan.totalFiles === 1 ? "" : "s"} scanned`}
					tone="neutral"
				/>
			</div>

			{/* Per-file findings */}
			{scan.fileResults.filter((fr) => fr.findings.length > 0).length > 0 && (
				<div className="mt-4 space-y-2">
					{scan.fileResults
						.filter((fr) => fr.findings.length > 0)
						.slice(0, 4)
						.map((fr) => (
							<div
								key={fr.filename}
								className="rounded-lg bg-[var(--foam-wash)] px-4 py-2 text-sm"
							>
								<div className="flex flex-wrap items-center gap-2">
									<StatusPill label={fr.fileType} tone="neutral" />
									<span className="font-mono text-xs text-[var(--sea-ink)]">
										{fr.filename.split("/").pop()}
									</span>
								</div>
								<div className="mt-1 space-y-1">
									{fr.findings.slice(0, 3).map((f) => (
										<p
											key={f.ruleId}
											className="text-xs text-[var(--salt-mist)]"
										>
											<span
												className={
													f.severity === "critical"
														? "font-semibold text-red-600"
														: f.severity === "high"
															? "font-semibold text-orange-500"
															: "font-medium"
												}
											>
												[{f.severity.toUpperCase()}]
											</span>{" "}
											{f.title}
										</p>
									))}
									{fr.findings.length > 3 && (
										<p className="text-xs text-[var(--salt-mist)]">
											+ {fr.findings.length - 3} more
										</p>
									)}
								</div>
							</div>
						))}
				</div>
			)}

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{scan.summary}</p>
		</article>
	);
}

// ─── CI/CD Pipeline Security Panel ───────────────────────────────────────────

/**
 * Per-repository CI/CD pipeline misconfiguration scan results.
 *
 * Displays the overall risk level, finding severity counts, and per-file
 * finding rows for GitHub Actions, GitLab CI, CircleCI, and Bitbucket Pipelines.
 *
 * Hidden until the first scan has been recorded so fresh repositories are
 * not cluttered with empty panels.
 */
function RepositoryCicdScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.cicdScanIntel.getLatestCicdScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const RISK_TONE: Record<
		"critical" | "high" | "medium" | "low" | "none",
		"danger" | "warning" | "info" | "neutral" | "success"
	> = {
		critical: "danger",
		high: "warning",
		medium: "info",
		low: "neutral",
		none: "success",
	};

	const PLATFORM_LABEL: Record<string, string> = {
		github_actions: "GH Actions",
		gitlab_ci: "GitLab CI",
		circleci: "CircleCI",
		bitbucket_pipelines: "Bitbucket",
		unknown: "unknown",
	};

	const overallRisk = scan.overallRisk as
		| "critical"
		| "high"
		| "medium"
		| "low"
		| "none";
	const riskTone = RISK_TONE[overallRisk] ?? "neutral";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">CI/CD security</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Pipeline misconfiguration scan
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={overallRisk === "none" ? "✓ clean" : overallRisk}
					tone={riskTone}
				/>
				<StatusPill
					label={`${scan.totalFindings} finding${scan.totalFindings === 1 ? "" : "s"}`}
					tone={scan.totalFindings === 0 ? "success" : "neutral"}
				/>
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
				<StatusPill
					label={`${scan.totalFiles} file${scan.totalFiles === 1 ? "" : "s"} scanned`}
					tone="neutral"
				/>
			</div>

			{/* Per-file findings */}
			{scan.fileResults.filter((fr) => fr.findings.length > 0).length > 0 && (
				<div className="mt-4 space-y-2">
					{scan.fileResults
						.filter((fr) => fr.findings.length > 0)
						.slice(0, 4)
						.map((fr) => (
							<div
								key={fr.filename}
								className="rounded-lg bg-[var(--foam-wash)] px-4 py-2 text-sm"
							>
								<div className="flex flex-wrap items-center gap-2">
									<StatusPill
										label={PLATFORM_LABEL[fr.fileType] ?? fr.fileType}
										tone="neutral"
									/>
									<span className="font-mono text-xs text-[var(--sea-ink)]">
										{fr.filename.split("/").pop()}
									</span>
								</div>
								{fr.findings.slice(0, 3).map((f) => (
									<p
										key={f.ruleId}
										className="mt-1 text-xs text-[var(--salt-mist)]"
									>
										<span
											className={`mr-1 font-semibold ${
												f.severity === "critical"
													? "text-red-600"
													: f.severity === "high"
														? "text-orange-500"
														: f.severity === "medium"
															? "text-yellow-600"
															: "text-slate-500"
											}`}
										>
											[{f.severity}]
										</span>{" "}
										{f.title}
									</p>
								))}
								{fr.findings.length > 3 && (
									<p className="text-xs text-[var(--salt-mist)]">
										+ {fr.findings.length - 3} more
									</p>
								)}
							</div>
						))}
				</div>
			)}

			<p className="mt-3 text-sm text-[var(--salt-mist)]">{scan.summary}</p>
		</article>
	);
}

// ─── Gamification Panel (tenant-level) ───────────────────────────────────────

/**
 * Global sprint leaderboard for attack surface reduction.
 *
 * Shows the top repositories ranked by score improvement over the last 14 days,
 * the engineer leaderboard (when mergedBy data exists), and tenant-wide totals.
 *
 * Hidden until the first gamification snapshot has been computed so it does
 * not add noise to fresh deployments.
 *
 * Spec §3.7.4 — Gamification Layer / WS-28.
 */
function TenantGamificationPanel({ tenantSlug }: { tenantSlug: string }) {
	const snapshot = useQuery(api.gamificationIntel.getLatestGamification, {
		tenantSlug,
	});

	if (snapshot === undefined || snapshot === null) return null;
	if (snapshot.repositoryLeaderboard.length === 0) return null;

	const BADGE_EMOJI: Record<string, string> = {
		gold: "🥇",
		silver: "🥈",
		bronze: "🥉",
	};

	const TREND_TONE: Record<
		string,
		"success" | "warning" | "danger" | "neutral"
	> = {
		improving: "success",
		stable: "neutral",
		degrading: "danger",
	};

	const topRepos = snapshot.repositoryLeaderboard.slice(0, 5);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Sprint leaderboard</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Teams competing on attack surface reduction over the last{" "}
				{snapshot.windowDays} days.
			</h2>

			{/* Tenant-wide totals */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`${snapshot.repositoryLeaderboard.length} repos tracked`}
					tone="info"
				/>
				{snapshot.totalScoreDelta > 0 && (
					<StatusPill
						label={`+${snapshot.totalScoreDelta.toFixed(1)} pts total`}
						tone="success"
					/>
				)}
				{snapshot.totalScoreDelta < 0 && (
					<StatusPill
						label={`${snapshot.totalScoreDelta.toFixed(1)} pts total`}
						tone="danger"
					/>
				)}
				{snapshot.totalPrsMerged > 0 && (
					<StatusPill
						label={`${snapshot.totalPrsMerged} security PR${snapshot.totalPrsMerged === 1 ? "" : "s"} merged`}
						tone="success"
					/>
				)}
			</div>

			{/* Repository leaderboard */}
			<div className="mt-4 space-y-2">
				{topRepos.map((entry) => (
					<div
						key={entry.repositoryId}
						className="flex items-center justify-between gap-2 rounded-xl bg-[var(--foam-wash)] px-4 py-2"
					>
						<div className="flex min-w-0 items-center gap-2">
							<span className="text-lg">
								{entry.badge ? BADGE_EMOJI[entry.badge] : `#${entry.rank}`}
							</span>
							<span className="truncate font-mono text-sm text-[var(--sea-ink)]">
								{entry.repositoryName}
							</span>
						</div>
						<div className="flex shrink-0 items-center gap-1">
							<StatusPill label={`score ${entry.currentScore}`} tone="info" />
							{entry.scoreDelta > 0 && (
								<StatusPill
									label={`+${entry.scoreDelta.toFixed(1)}`}
									tone="success"
								/>
							)}
							{entry.scoreDelta < 0 && (
								<StatusPill label={entry.scoreDelta.toFixed(1)} tone="danger" />
							)}
							<StatusPill
								label={entry.trend}
								tone={TREND_TONE[entry.trend] ?? "neutral"}
							/>
							{entry.mergedPrCount > 0 && (
								<StatusPill
									label={`${entry.mergedPrCount} PR${entry.mergedPrCount === 1 ? "" : "s"}`}
									tone="success"
								/>
							)}
						</div>
					</div>
				))}
			</div>

			{/* Engineer leaderboard — only shown when mergedBy data is available */}
			{snapshot.engineerLeaderboard.length > 0 && (
				<div className="mt-4">
					<p className="mb-2 text-xs font-medium uppercase tracking-widest text-[var(--salt-mist)]">
						Engineer contributors
					</p>
					<div className="flex flex-wrap gap-2">
						{snapshot.engineerLeaderboard.slice(0, 5).map((eng) => (
							<StatusPill
								key={eng.engineerLogin}
								label={`${eng.engineerLogin} · ${eng.mergedPrCount} PR${eng.mergedPrCount === 1 ? "" : "s"}`}
								tone="info"
							/>
						))}
					</div>
				</div>
			)}

			{/* Summary */}
			<p className="mt-3 text-sm text-[var(--salt-mist)]">{snapshot.summary}</p>
		</article>
	);
}

// ─── Community Marketplace Panel (global) ────────────────────────────────────

/**
 * Global panel — surfaces the community rule/fingerprint contribution
 * marketplace.  Shows aggregate stats (approved/pending counts by type) and
 * the top-5 recently approved contributions ranked by net community score.
 *
 * Hidden until at least one contribution exists so it does not add noise to
 * fresh deployments.
 *
 * Spec §10 Phase 4 — "Public rule/fingerprint contribution marketplace".
 */
// ---------------------------------------------------------------------------
// RepositoryCryptoWeaknessPanel — WS-37
// ---------------------------------------------------------------------------

function RepositoryCryptoWeaknessPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.cryptoWeaknessIntel.getLatestCryptoWeaknessScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const RISK_TONE: Record<
		"critical" | "high" | "medium" | "low" | "none",
		"danger" | "warning" | "info" | "neutral" | "success"
	> = {
		critical: "danger",
		high: "warning",
		medium: "info",
		low: "neutral",
		none: "success",
	};

	const overallRisk = scan.overallRisk as
		| "critical"
		| "high"
		| "medium"
		| "low"
		| "none";
	const riskTone = RISK_TONE[overallRisk] ?? "neutral";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Cryptography hygiene</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Crypto weakness scan
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={overallRisk === "none" ? "✓ clean" : overallRisk}
					tone={riskTone}
				/>
				<StatusPill
					label={`${scan.totalFindings} finding${scan.totalFindings === 1 ? "" : "s"}`}
					tone={scan.totalFindings === 0 ? "success" : "neutral"}
				/>
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
				<StatusPill
					label={`${scan.totalFiles} file${scan.totalFiles === 1 ? "" : "s"} scanned`}
					tone="neutral"
				/>
			</div>

			{/* Per-file findings */}
			{scan.fileResults.filter((fr) => fr.findings.length > 0).length > 0 && (
				<div className="mt-4 space-y-2">
					{scan.fileResults
						.filter((fr) => fr.findings.length > 0)
						.slice(0, 4)
						.map((fr) => (
							<div
								key={fr.filename}
								className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
							>
								<div className="mb-1 flex flex-wrap items-center gap-2">
									<StatusPill
										label={fr.fileType === "unknown" ? "src" : fr.fileType}
										tone="neutral"
									/>
									<span className="min-w-0 flex-1 truncate font-mono text-xs text-[var(--sea-ink)]/70">
										{fr.filename}
									</span>
								</div>
								<div className="space-y-1">
									{fr.findings.slice(0, 3).map((f) => (
										<div
											key={f.ruleId}
											className="flex flex-wrap items-start gap-2"
										>
											<StatusPill
												label={f.severity}
												tone={
													RISK_TONE[f.severity as keyof typeof RISK_TONE] ??
													"neutral"
												}
											/>
											<span className="min-w-0 flex-1 text-xs text-[var(--sea-ink)]/80">
												{f.title}
											</span>
										</div>
									))}
								</div>
							</div>
						))}
				</div>
			)}

			{scan.summary && (
				<p className="mt-3 text-sm text-[var(--sea-ink)]/60">{scan.summary}</p>
			)}
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryEolPanel — WS-38
// ---------------------------------------------------------------------------

function RepositoryEolPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.eolDetectionIntel.getLatestEolScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const STATUS_TONE: Record<
		"critical" | "warning" | "ok",
		"danger" | "warning" | "success"
	> = {
		critical: "danger",
		warning: "warning",
		ok: "success",
	};

	const EOL_STATUS_TONE: Record<string, "danger" | "warning"> = {
		end_of_life: "danger",
		near_eol: "warning",
	};

	const CATEGORY_ICON: Record<string, string> = {
		runtime: "⚙️",
		framework: "🏗️",
		package: "📦",
	};

	const statusTone =
		STATUS_TONE[scan.overallStatus as "critical" | "warning" | "ok"] ??
		"neutral";
	const statusLabel =
		scan.overallStatus === "critical"
			? `${scan.eolCount} end-of-life`
			: scan.overallStatus === "warning"
				? `${scan.nearEolCount} near EOL`
				: "✓ all supported";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Lifecycle risk</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				End-of-life detection
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={statusLabel} tone={statusTone} />
				{scan.eolCount > 0 && (
					<StatusPill label={`${scan.eolCount} EOL`} tone="danger" />
				)}
				{scan.nearEolCount > 0 && (
					<StatusPill label={`${scan.nearEolCount} near-EOL`} tone="warning" />
				)}
				{scan.unknownCount > 0 && (
					<StatusPill label={`${scan.unknownCount} untracked`} tone="neutral" />
				)}
			</div>

			{/* Per-finding rows */}
			{scan.findings.length > 0 && (
				<div className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<div
							key={`${f.packageName}-${f.version}`}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="mb-1 flex flex-wrap items-center gap-2">
								<span className="text-xs">
									{CATEGORY_ICON[f.category] ?? "📦"}
								</span>
								<StatusPill
									label={f.eolStatus === "end_of_life" ? "EOL" : "near EOL"}
									tone={EOL_STATUS_TONE[f.eolStatus] ?? "warning"}
								/>
								<span className="text-sm font-medium text-[var(--sea-ink)]">
									{f.packageName}
								</span>
								<span className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-xs text-[var(--sea-ink)]/70">
									{f.version}
								</span>
							</div>
							<p className="text-xs text-[var(--sea-ink)]/70">{f.title}</p>
							{f.replacedBy && (
								<p className="mt-0.5 text-xs text-[var(--sea-ink)]/50">
									→ {f.replacedBy}
								</p>
							)}
						</div>
					))}
				</div>
			)}

			{scan.summary && (
				<p className="mt-3 text-sm text-[var(--sea-ink)]/60">{scan.summary}</p>
			)}
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryAbandonmentPanel — WS-39
// ---------------------------------------------------------------------------

function RepositoryAbandonmentPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.abandonmentScanIntel.getLatestAbandonmentScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;

	const RISK_TONE: Record<
		"critical" | "high" | "medium" | "low" | "none",
		"danger" | "warning" | "neutral" | "success"
	> = {
		critical: "danger",
		high: "warning",
		medium: "warning",
		low: "neutral",
		none: "success",
	};

	const REASON_ICON: Record<string, string> = {
		supply_chain_compromised: "☠️",
		officially_deprecated: "🚫",
		archived: "📁",
		superseded: "🔄",
		unmaintained: "🕸️",
	};

	const overallRisk = scan.overallRisk as
		| "critical"
		| "high"
		| "medium"
		| "low"
		| "none";
	const riskTone = RISK_TONE[overallRisk] ?? "neutral";
	const riskLabel =
		scan.totalAbandoned === 0
			? "✓ no abandoned packages"
			: `${scan.totalAbandoned} abandoned`;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain risk</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Abandonment detection
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={riskLabel} tone={riskTone} />
				{scan.criticalCount > 0 && (
					<StatusPill
						label={`${scan.criticalCount} compromised`}
						tone="danger"
					/>
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high-risk`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} deprecated`} tone="warning" />
				)}
				{scan.lowCount > 0 && (
					<StatusPill label={`${scan.lowCount} superseded`} tone="neutral" />
				)}
			</div>

			{/* Per-finding rows */}
			{scan.findings.length > 0 && (
				<div className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<div
							key={`${f.packageName}-${f.version}`}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="mb-1 flex flex-wrap items-center gap-2">
								<span className="text-xs">{REASON_ICON[f.reason] ?? "⚠️"}</span>
								<StatusPill
									label={f.riskLevel}
									tone={
										RISK_TONE[
											f.riskLevel as
												| "critical"
												| "high"
												| "medium"
												| "low"
												| "none"
										] ?? "neutral"
									}
								/>
								<span className="text-sm font-medium text-[var(--sea-ink)]">
									{f.packageName}
								</span>
								<span className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-xs text-[var(--sea-ink)]/70">
									{f.version}
								</span>
							</div>
							<p className="text-xs text-[var(--sea-ink)]/70">{f.title}</p>
							{f.replacedBy && (
								<p className="mt-0.5 text-xs text-[var(--sea-ink)]/50">
									→ {f.replacedBy}
								</p>
							)}
						</div>
					))}
				</div>
			)}

			{scan.summary && (
				<p className="mt-3 text-sm text-[var(--sea-ink)]/60">{scan.summary}</p>
			)}
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryAttestationPanel — WS-40
// ---------------------------------------------------------------------------

function RepositoryAttestationPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const attestation = useQuery(api.sbomAttestationIntel.getLatestAttestation, {
		tenantSlug,
		repositoryFullName,
	});

	if (attestation === undefined || attestation === null) return null;

	const STATUS_TONE: Record<
		"valid" | "tampered" | "unverified",
		"success" | "danger" | "neutral"
	> = {
		valid: "success",
		tampered: "danger",
		unverified: "neutral",
	};

	const STATUS_ICON: Record<string, string> = {
		valid: "✓",
		tampered: "⚠️",
		unverified: "⏳",
	};

	const status = attestation.status as "valid" | "tampered" | "unverified";
	const tone = STATUS_TONE[status] ?? "neutral";
	const statusLabel = `${STATUS_ICON[status] ?? ""} ${status}`;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Integrity</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				SBOM attestation
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={statusLabel} tone={tone} />
				<StatusPill
					label={`${attestation.componentCount} components`}
					tone="neutral"
				/>
				<StatusPill
					label={`v${attestation.attestationVersion}`}
					tone="neutral"
				/>
			</div>

			{/* Hash display */}
			<div className="mt-4 space-y-2">
				<div className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3">
					<p className="mb-1 text-xs font-medium text-[var(--sea-ink)]/60">
						Content hash
					</p>
					<p className="break-all font-mono text-xs text-[var(--sea-ink)]/80">
						{attestation.contentHash}
					</p>
				</div>
				<div className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3">
					<p className="mb-1 text-xs font-medium text-[var(--sea-ink)]/60">
						Attestation hash
					</p>
					<p className="break-all font-mono text-xs text-[var(--sea-ink)]/80">
						{attestation.attestationHash}
					</p>
				</div>
			</div>

			{status === "tampered" && (
				<p className="mt-3 text-sm font-medium text-red-500">
					Component list differs from attested state — possible tampering
					detected.
				</p>
			)}

			{attestation.lastVerifiedAt && (
				<p className="mt-3 text-xs text-[var(--sea-ink)]/50">
					Last verified {new Date(attestation.lastVerifiedAt).toLocaleString()}
				</p>
			)}
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryConfusionScanPanel — WS-41
// ---------------------------------------------------------------------------

const CONFUSION_RISK_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "neutral",
	none: "success",
};

const CONFUSION_RISK_LABEL: Record<string, string> = {
	critical: "🚨 Critical",
	high: "⚠️ High",
	medium: "ℹ️ Medium",
	low: "↓ Low",
	none: "✓ Clean",
};

function RepositoryConfusionScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.confusionAttackIntel.getLatestConfusionScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;
	if (scan.overallRisk === "none") return null;

	const riskTone = CONFUSION_RISK_TONE[scan.overallRisk] ?? "neutral";
	const riskLabel = CONFUSION_RISK_LABEL[scan.overallRisk] ?? scan.overallRisk;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Dependency confusion
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={riskLabel} tone={riskTone} />
				{scan.totalSuspicious > 0 && (
					<StatusPill
						label={`${scan.totalSuspicious} suspicious`}
						tone={riskTone}
					/>
				)}
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
			</div>

			{/* Top findings */}
			{scan.findings.length > 0 && (
				<ul className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<li
							key={f.evidence}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="flex items-center justify-between gap-2">
								<p className="font-mono text-sm font-medium text-[var(--sea-ink)]">
									{f.packageName}
								</p>
								<StatusPill
									label={f.riskLevel}
									tone={CONFUSION_RISK_TONE[f.riskLevel] ?? "neutral"}
								/>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink)]/60">{f.title}</p>
						</li>
					))}
				</ul>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{scan.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryMaliciousScanPanel — WS-42
// ---------------------------------------------------------------------------

const MALICIOUS_RISK_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "neutral",
	none: "success",
};

const SIGNAL_LABEL: Record<string, string> = {
	known_malicious: "confirmed malicious",
	typosquat_near_popular: "typosquat",
	suspicious_name_pattern: "suspicious pattern",
};

function RepositoryMaliciousScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.maliciousPackageIntel.getLatestMaliciousScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;
	if (scan.overallRisk === "none") return null;

	const riskTone = MALICIOUS_RISK_TONE[scan.overallRisk] ?? "neutral";
	const riskLabel =
		scan.overallRisk === "critical"
			? "🚨 Critical"
			: scan.overallRisk === "high"
				? "⚠️ High"
				: scan.overallRisk === "medium"
					? "ℹ️ Medium"
					: "↓ Low";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Malicious packages
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={riskLabel} tone={riskTone} />
				{scan.totalSuspicious > 0 && (
					<StatusPill
						label={`${scan.totalSuspicious} suspicious`}
						tone={riskTone}
					/>
				)}
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} confirmed`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} typosquat`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} pattern`} tone="info" />
				)}
			</div>

			{/* Top findings */}
			{scan.findings.length > 0 && (
				<ul className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<li
							key={f.evidence}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="flex items-center justify-between gap-2">
								<p className="font-mono text-sm font-medium text-[var(--sea-ink)]">
									{f.packageName}
								</p>
								<div className="flex gap-1">
									{f.signals.map((s) => (
										<StatusPill
											key={s}
											label={SIGNAL_LABEL[s] ?? s}
											tone={MALICIOUS_RISK_TONE[f.riskLevel] ?? "neutral"}
										/>
									))}
								</div>
							</div>
							{f.similarTo && (
								<p className="mt-1 text-xs text-[var(--sea-ink)]/60">
									Resembles: <span className="font-mono">{f.similarTo}</span>
								</p>
							)}
						</li>
					))}
				</ul>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{scan.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositorySupplyChainPosturePanel — WS-44
// ---------------------------------------------------------------------------

const POSTURE_RISK_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "neutral",
	clean: "success",
};

const POSTURE_GRADE_COLOR: Record<string, string> = {
	A: "text-[var(--success)]",
	B: "text-[var(--sea-ink)]",
	C: "text-[color:var(--warning,#d97706)]",
	D: "text-[color:var(--warning,#d97706)]",
	F: "text-[color:var(--danger,#dc2626)]",
};

const POSTURE_CATEGORY_LABEL: Record<string, string> = {
	cve: "CVEs",
	malicious: "Malicious",
	confusion: "Confusion",
	abandonment: "Abandoned",
	eol: "EOL",
	attestation: "Attestation",
};

function RepositorySupplyChainPosturePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const posture = useQuery(
		api.supplyChainPostureIntel.getLatestSupplyChainPosture,
		{
			tenantSlug,
			repositoryFullName,
		},
	);

	if (posture === undefined || posture === null) return null;
	if (posture.riskLevel === "clean") return null;

	const riskTone = POSTURE_RISK_TONE[posture.riskLevel] ?? "neutral";
	const gradeColor =
		POSTURE_GRADE_COLOR[posture.grade] ?? "text-[var(--sea-ink)]";

	const riskLabel =
		posture.riskLevel === "critical"
			? "🚨 Critical"
			: posture.riskLevel === "high"
				? "⚠️ High"
				: posture.riskLevel === "medium"
					? "ℹ️ Medium"
					: "↓ Low";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Posture score
			</h2>

			{/* Score + grade row */}
			<div className="mt-4 flex items-end gap-4">
				<span className={`text-6xl font-black leading-none ${gradeColor}`}>
					{posture.grade}
				</span>
				<div className="flex flex-col gap-1 pb-1">
					<span className="text-2xl font-bold text-[var(--sea-ink)]">
						{posture.score}
						<span className="text-sm font-normal text-[var(--sea-ink)]/50">
							/100
						</span>
					</span>
					<StatusPill label={riskLabel} tone={riskTone} />
				</div>
			</div>

			{/* Per-category breakdown pills */}
			{posture.breakdown.length > 0 && (
				<div className="mt-4 flex flex-wrap gap-2">
					{posture.breakdown.map((entry) => (
						<div
							key={entry.category}
							className="flex items-center gap-1.5 rounded-lg border border-[color:var(--line)]/50 bg-[var(--surface)]/50 px-3 py-1.5"
						>
							<span className="text-xs font-medium text-[var(--sea-ink)]/70">
								{POSTURE_CATEGORY_LABEL[entry.category] ?? entry.category}
							</span>
							<span className="text-xs font-bold text-[color:var(--danger,#dc2626)]">
								−{entry.penalty}
							</span>
							<span className="text-xs text-[var(--sea-ink)]/50">
								{entry.detail}
							</span>
						</div>
					))}
				</div>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{posture.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryCveScanPanel — WS-43
// ---------------------------------------------------------------------------

const CVE_RISK_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "neutral",
	none: "success",
};

function RepositoryCveScanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.cveVersionScanIntel.getLatestCveScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;
	if (scan.overallRisk === "none") return null;

	const riskTone = CVE_RISK_TONE[scan.overallRisk] ?? "neutral";
	const riskLabel =
		scan.overallRisk === "critical"
			? "🚨 Critical"
			: scan.overallRisk === "high"
				? "⚠️ High"
				: scan.overallRisk === "medium"
					? "ℹ️ Medium"
					: "↓ Low";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Known CVEs
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={riskLabel} tone={riskTone} />
				{scan.totalVulnerable > 0 && (
					<StatusPill
						label={`${scan.totalVulnerable} vulnerable`}
						tone={riskTone}
					/>
				)}
				{scan.criticalCount > 0 && (
					<StatusPill
						label={`${scan.criticalCount} critical CVE${scan.criticalCount > 1 ? "s" : ""}`}
						tone="danger"
					/>
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
			</div>

			{/* Top findings */}
			{scan.findings.length > 0 && (
				<ul className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<li
							key={f.evidence}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="flex items-center justify-between gap-2">
								<div>
									<p className="font-mono text-sm font-medium text-[var(--sea-ink)]">
										{f.packageName}
									</p>
									<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60">
										v{f.version} → fix in v{f.minimumSafeVersion}
									</p>
								</div>
								<div className="flex flex-col items-end gap-1">
									<StatusPill
										label={f.cveId}
										tone={CVE_RISK_TONE[f.riskLevel] ?? "neutral"}
									/>
									<span className="text-xs text-[var(--sea-ink)]/50">
										CVSS {f.cvss.toFixed(1)}
									</span>
								</div>
							</div>
						</li>
					))}
				</ul>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{scan.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryContainerImagePanel — WS-45
// ---------------------------------------------------------------------------

const CONTAINER_RISK_TONE: Record<
	string,
	"danger" | "warning" | "info" | "neutral" | "success"
> = {
	critical: "danger",
	high: "warning",
	medium: "info",
	low: "neutral",
	none: "success",
};

const CONTAINER_SIGNAL_LABEL: Record<string, string> = {
	eol_base_image: "EOL",
	near_eol: "Near EOL",
	outdated_base: "Outdated",
	no_version_tag: "Unpinned",
	deprecated_image: "Deprecated",
};

function RepositoryContainerImagePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const scan = useQuery(api.containerImageIntel.getLatestContainerImageScan, {
		tenantSlug,
		repositoryFullName,
	});

	if (scan === undefined || scan === null) return null;
	if (scan.overallRisk === "none") return null;

	const riskTone = CONTAINER_RISK_TONE[scan.overallRisk] ?? "neutral";
	const riskLabel =
		scan.overallRisk === "critical"
			? "🚨 Critical"
			: scan.overallRisk === "high"
				? "⚠️ High"
				: scan.overallRisk === "medium"
					? "ℹ️ Medium"
					: "↓ Low";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Supply chain</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Container images
			</h2>

			{/* Summary pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={riskLabel} tone={riskTone} />
				{scan.totalImages > 0 && (
					<StatusPill
						label={`${scan.totalImages} image${scan.totalImages > 1 ? "s" : ""} scanned`}
						tone="neutral"
					/>
				)}
				{scan.criticalCount > 0 && (
					<StatusPill label={`${scan.criticalCount} critical`} tone="danger" />
				)}
				{scan.highCount > 0 && (
					<StatusPill label={`${scan.highCount} high`} tone="warning" />
				)}
				{scan.mediumCount > 0 && (
					<StatusPill label={`${scan.mediumCount} medium`} tone="info" />
				)}
			</div>

			{/* Top findings */}
			{scan.findings.length > 0 && (
				<ul className="mt-4 space-y-2">
					{scan.findings.slice(0, 5).map((f) => (
						<li
							key={f.evidence}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="flex items-center justify-between gap-2">
								<div className="min-w-0">
									<p className="truncate font-mono text-sm font-medium text-[var(--sea-ink)]">
										{f.imageName}
										<span className="text-[var(--sea-ink)]/50">
											:{f.imageVersion}
										</span>
									</p>
									<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60">
										→ {f.recommendedVersion}
										{f.eolDateText && (
											<span className="ml-1 text-[var(--sea-ink)]/40">
												(EOL {f.eolDateText})
											</span>
										)}
									</p>
								</div>
								<div className="shrink-0">
									<StatusPill
										label={CONTAINER_SIGNAL_LABEL[f.signal] ?? f.signal}
										tone={CONTAINER_RISK_TONE[f.riskLevel] ?? "neutral"}
									/>
								</div>
							</div>
						</li>
					))}
				</ul>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{scan.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryCompliancePanel — WS-46
// ---------------------------------------------------------------------------

const COMPLIANCE_STATUS_TONE: Record<
	string,
	"danger" | "warning" | "success" | "neutral"
> = {
	non_compliant: "danger",
	at_risk: "warning",
	compliant: "success",
};

const COMPLIANCE_STATUS_LABEL: Record<string, string> = {
	non_compliant: "Non-compliant",
	at_risk: "At risk",
	compliant: "Compliant",
};

const FRAMEWORK_DISPLAY_ORDER = [
	"soc2",
	"gdpr",
	"pci_dss",
	"hipaa",
	"nis2",
] as const;

function RepositoryCompliancePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const attestation = useQuery(
		api.complianceAttestationIntel.getLatestComplianceAttestation,
		{ tenantSlug, repositoryFullName },
	);

	if (attestation === undefined || attestation === null) return null;
	// Self-hide when all frameworks are compliant and no gaps
	if (
		attestation.overallStatus === "compliant" &&
		attestation.criticalGapCount === 0 &&
		attestation.highGapCount === 0
	)
		return null;

	const overallTone =
		COMPLIANCE_STATUS_TONE[attestation.overallStatus] ?? "neutral";
	const overallLabel =
		attestation.overallStatus === "non_compliant"
			? "🚨 Non-compliant"
			: attestation.overallStatus === "at_risk"
				? "⚠️ At risk"
				: "✓ Compliant";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Compliance</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Regulatory attestation
			</h2>

			{/* Overall status pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={overallLabel} tone={overallTone} />
				{attestation.criticalGapCount > 0 && (
					<StatusPill
						label={`${attestation.criticalGapCount} critical gap${attestation.criticalGapCount > 1 ? "s" : ""}`}
						tone="danger"
					/>
				)}
				{attestation.highGapCount > 0 && (
					<StatusPill
						label={`${attestation.highGapCount} high gap${attestation.highGapCount > 1 ? "s" : ""}`}
						tone="warning"
					/>
				)}
				{attestation.fullyCompliantCount > 0 && (
					<StatusPill
						label={`${attestation.fullyCompliantCount}/5 compliant`}
						tone="success"
					/>
				)}
			</div>

			{/* Per-framework status rows */}
			<ul className="mt-4 space-y-2">
				{FRAMEWORK_DISPLAY_ORDER.map((fw) => {
					const framework = attestation.frameworks.find(
						(f) => f.framework === fw,
					);
					if (!framework) return null;
					// Skip compliant frameworks with no gaps to keep the panel focused
					if (
						framework.status === "compliant" &&
						framework.controlGaps.length === 0
					)
						return null;
					return (
						<li
							key={fw}
							className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
						>
							<div className="flex items-center justify-between gap-2">
								<div className="min-w-0">
									<p className="text-sm font-semibold text-[var(--sea-ink)]">
										{framework.label}
									</p>
									{framework.controlGaps.length > 0 && (
										<p className="mt-0.5 truncate text-xs text-[var(--sea-ink)]/60">
											{framework.controlGaps
												.slice(0, 2)
												.map((g) => g.controlId)
												.join(", ")}
											{framework.controlGaps.length > 2 &&
												` +${framework.controlGaps.length - 2} more`}
										</p>
									)}
								</div>
								<div className="flex shrink-0 items-center gap-1.5">
									<span className="text-xs text-[var(--sea-ink)]/50">
										{framework.score}
									</span>
									<StatusPill
										label={
											COMPLIANCE_STATUS_LABEL[framework.status] ??
											framework.status
										}
										tone={COMPLIANCE_STATUS_TONE[framework.status] ?? "neutral"}
									/>
								</div>
							</div>
						</li>
					);
				})}
			</ul>

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">
				{attestation.summary}
			</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryRemediationPlanPanel — WS-47
// ---------------------------------------------------------------------------

const EFFORT_LABEL: Record<string, string> = {
	low: "Low effort",
	medium: "Medium effort",
	high: "High effort",
};

const EFFORT_TONE: Record<string, "success" | "warning" | "danger"> = {
	low: "success",
	medium: "warning",
	high: "danger",
};

const GAP_SEVERITY_TONE: Record<string, "danger" | "warning" | "neutral"> = {
	critical: "danger",
	high: "warning",
	medium: "neutral",
	low: "neutral",
};

function RepositoryRemediationPlanPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const plan = useQuery(
		api.complianceRemediationIntel.getLatestComplianceRemediationPlan,
		{ tenantSlug, repositoryFullName },
	);

	if (plan === undefined || plan === null) return null;
	// Self-hide when there are no actions required
	if (plan.totalActions === 0) return null;

	// Show top 5 actions (already sorted critical → low)
	const topActions = plan.actions.slice(0, 5);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Compliance</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Remediation plan
			</h2>

			{/* Summary pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				{plan.criticalActions > 0 && (
					<StatusPill
						label={`${plan.criticalActions} critical`}
						tone="danger"
					/>
				)}
				{plan.highActions > 0 && (
					<StatusPill label={`${plan.highActions} high`} tone="warning" />
				)}
				{plan.automatableActions > 0 && (
					<StatusPill
						label={`${plan.automatableActions} automatable`}
						tone="success"
					/>
				)}
				<StatusPill
					label={`~${plan.estimatedTotalDays}d effort`}
					tone="neutral"
				/>
			</div>

			{/* Top priority actions */}
			<ul className="mt-4 space-y-2">
				{topActions.map((action) => (
					<li
						key={action.controlId}
						className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
					>
						<div className="flex items-start justify-between gap-2">
							<div className="min-w-0">
								<p className="text-sm font-semibold text-[var(--sea-ink)] leading-snug">
									{action.title}
								</p>
								<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60">
									{action.controlId}
									{action.requiresPolicyDoc && (
										<span className="ml-1.5 text-[var(--sea-ink)]/40">
											· policy doc required
										</span>
									)}
								</p>
							</div>
							<div className="flex shrink-0 flex-col items-end gap-1">
								<StatusPill
									label={action.gapSeverity}
									tone={GAP_SEVERITY_TONE[action.gapSeverity] ?? "neutral"}
								/>
								<StatusPill
									label={EFFORT_LABEL[action.effort] ?? action.effort}
									tone={EFFORT_TONE[action.effort] ?? "neutral"}
								/>
							</div>
						</div>
					</li>
				))}
				{plan.totalActions > 5 && (
					<li className="px-3 text-xs text-[var(--sea-ink)]/40">
						+{plan.totalActions - 5} more action
						{plan.totalActions - 5 > 1 ? "s" : ""}
					</li>
				)}
			</ul>

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{plan.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryHealthScorePanel — WS-49
// ---------------------------------------------------------------------------

const GRADE_TONE: Record<string, "success" | "warning" | "danger" | "neutral"> =
	{
		A: "success",
		B: "success",
		C: "warning",
		D: "danger",
		F: "danger",
	};

const TREND_ICON: Record<string, string> = {
	improving: "\u2191",
	declining: "\u2193",
	stable: "\u2194",
	new: "\u2022",
};

const TREND_TONE: Record<string, "success" | "warning" | "danger" | "neutral"> =
	{
		improving: "success",
		declining: "danger",
		stable: "neutral",
		new: "neutral",
	};

function RepositoryHealthScorePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const score = useQuery(
		api.repositoryHealthIntel.getLatestRepositoryHealthScore,
		{ tenantSlug, repositoryFullName },
	);

	if (score === undefined || score === null) return null;
	// Self-hide when grade A + stable/new + no risks
	if (
		score.overallGrade === "A" &&
		(score.trend === "stable" || score.trend === "new") &&
		score.topRisks.length === 0
	)
		return null;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Security</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Health score
			</h2>

			{/* Score + grade + trend */}
			<div className="mt-4 flex items-center gap-3">
				<span className="text-4xl font-bold text-[var(--sea-ink)]">
					{score.overallScore}
				</span>
				<span className="text-lg text-[var(--sea-ink)]/50">/100</span>
				<StatusPill
					label={`Grade ${score.overallGrade}`}
					tone={GRADE_TONE[score.overallGrade] ?? "neutral"}
				/>
				<StatusPill
					label={`${TREND_ICON[score.trend] ?? ""} ${score.trend}`}
					tone={TREND_TONE[score.trend] ?? "neutral"}
				/>
			</div>

			{/* Per-category mini bars */}
			<div className="mt-4 space-y-1.5">
				{score.categories.map((cat) => (
					<div key={cat.category} className="flex items-center gap-2">
						<span className="w-[7.5rem] shrink-0 text-xs text-[var(--sea-ink)]/60 truncate">
							{cat.label}
						</span>
						<div className="relative h-2 flex-1 overflow-hidden rounded-full bg-[var(--line)]/30">
							<div
								className="absolute inset-y-0 left-0 rounded-full"
								style={{
									width: `${cat.score}%`,
									backgroundColor:
										cat.score >= 90
											? "var(--tone-success, #22c55e)"
											: cat.score >= 60
												? "var(--tone-warning, #eab308)"
												: "var(--tone-danger, #ef4444)",
								}}
							/>
						</div>
						<span className="w-8 shrink-0 text-right text-xs font-medium text-[var(--sea-ink)]/70">
							{cat.score}
						</span>
					</div>
				))}
			</div>

			{/* Top risks */}
			{score.topRisks.length > 0 && (
				<ul className="mt-3 space-y-1">
					{score.topRisks.slice(0, 3).map((risk) => (
						<li
							key={risk}
							className="text-xs text-[var(--sea-ink)]/60 leading-snug"
						>
							<span className="mr-1 text-[var(--tone-danger)]">&bull;</span>
							{risk}
						</li>
					))}
					{score.topRisks.length > 3 && (
						<li className="px-1 text-xs text-[var(--sea-ink)]/40">
							+{score.topRisks.length - 3} more
						</li>
					)}
				</ul>
			)}

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{score.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositoryDependencyUpdatePanel — WS-50
// ---------------------------------------------------------------------------

const EFFORT_LABEL_UPDATE: Record<string, string> = {
	patch: "Patch",
	minor: "Minor",
	major: "Major",
	replacement: "Replace",
};

const EFFORT_TONE_UPDATE: Record<
	string,
	"success" | "warning" | "danger" | "neutral"
> = {
	patch: "success",
	minor: "neutral",
	major: "warning",
	replacement: "danger",
};

const URGENCY_TONE: Record<string, "danger" | "warning" | "neutral"> = {
	critical: "danger",
	high: "warning",
	medium: "neutral",
	low: "neutral",
};

function RepositoryDependencyUpdatePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const result = useQuery(
		api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations,
		{ tenantSlug, repositoryFullName },
	);

	if (result === undefined || result === null) return null;
	// Self-hide when no recommendations
	if (result.totalRecommendations === 0) return null;

	const topRecs = result.recommendations.slice(0, 5);

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Dependencies</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Update recommendations
			</h2>

			{/* Summary pills */}
			<div className="mt-4 flex flex-wrap gap-2">
				{result.criticalCount > 0 && (
					<StatusPill
						label={`${result.criticalCount} critical`}
						tone="danger"
					/>
				)}
				{result.highCount > 0 && (
					<StatusPill label={`${result.highCount} high`} tone="warning" />
				)}
				{result.patchCount > 0 && (
					<StatusPill
						label={`${result.patchCount} patch-level`}
						tone="success"
					/>
				)}
				{result.breakingCount > 0 && (
					<StatusPill
						label={`${result.breakingCount} breaking`}
						tone="danger"
					/>
				)}
			</div>

			{/* Top recommendations */}
			<ul className="mt-4 space-y-2">
				{topRecs.map((rec) => (
					<li
						key={`${rec.ecosystem}:${rec.packageName}`}
						className="rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 p-3"
					>
						<div className="flex items-start justify-between gap-2">
							<div className="min-w-0">
								<p className="text-sm font-semibold text-[var(--sea-ink)] leading-snug">
									{rec.packageName}
								</p>
								<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60">
									{rec.currentVersion} → {rec.recommendedVersion}
									{rec.replacementPackage && (
										<span className="ml-1.5 text-[var(--sea-ink)]/40">
											· migrate to {rec.replacementPackage}
										</span>
									)}
								</p>
							</div>
							<div className="flex shrink-0 flex-col items-end gap-1">
								<StatusPill
									label={rec.urgency}
									tone={URGENCY_TONE[rec.urgency] ?? "neutral"}
								/>
								<StatusPill
									label={EFFORT_LABEL_UPDATE[rec.effort] ?? rec.effort}
									tone={EFFORT_TONE_UPDATE[rec.effort] ?? "neutral"}
								/>
							</div>
						</div>
					</li>
				))}
				{result.totalRecommendations > 5 && (
					<li className="px-3 text-xs text-[var(--sea-ink)]/40">
						+{result.totalRecommendations - 5} more update
						{result.totalRecommendations - 5 > 1 ? "s" : ""}
					</li>
				)}
			</ul>

			<p className="mt-3 text-xs text-[var(--sea-ink)]/50">{result.summary}</p>
		</article>
	);
}

// ---------------------------------------------------------------------------
// RepositorySecurityDebtPanel — WS-52
// ---------------------------------------------------------------------------

/** Trend label → StatusPill tone */
function debtTrendTone(
	trend: string,
): "success" | "warning" | "danger" | "neutral" {
	if (trend === "improving") return "success";
	if (trend === "stable") return "neutral";
	if (trend === "degrading") return "warning";
	return "danger"; // critical
}

/** 0–100 debt score → tone (inverse of most panels — lower score = worse) */
function debtScoreTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 80) return "success";
	if (score >= 60) return "neutral";
	if (score >= 40) return "warning";
	return "danger";
}

function RepositorySecurityDebtPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const snapshot = useQuery(api.securityDebtIntel.getLatestSecurityDebtBySlug, {
		tenantSlug,
		repositoryFullName,
	});

	if (!snapshot) return null;

	const velocityLabel =
		snapshot.netVelocityPerDay > 0
			? `+${snapshot.netVelocityPerDay}/day`
			: snapshot.netVelocityPerDay < 0
				? `${snapshot.netVelocityPerDay}/day`
				: "0/day";

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">WS-52</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Security debt velocity
			</h2>

			{/* Summary row */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`score ${snapshot.debtScore}/100`}
					tone={debtScoreTone(snapshot.debtScore)}
				/>
				<StatusPill
					label={snapshot.trend}
					tone={debtTrendTone(snapshot.trend)}
				/>
				<StatusPill
					label={`velocity ${velocityLabel}`}
					tone={snapshot.netVelocityPerDay > 1 ? "warning" : "neutral"}
				/>
			</div>

			{/* Backlog summary */}
			<div className="mt-3 flex flex-wrap gap-2">
				{snapshot.openFindings > 0 && (
					<StatusPill label={`${snapshot.openFindings} open`} tone="neutral" />
				)}
				{snapshot.openCritical > 0 && (
					<StatusPill
						label={`${snapshot.openCritical} critical`}
						tone="danger"
					/>
				)}
				{snapshot.openHigh > 0 && (
					<StatusPill label={`${snapshot.openHigh} high`} tone="warning" />
				)}
				{snapshot.overdueFindings > 0 && (
					<StatusPill
						label={`${snapshot.overdueFindings} overdue SLA`}
						tone="danger"
					/>
				)}
			</div>

			{/* Projection */}
			{snapshot.projectedClearanceDays !== null && (
				<p className="mt-3 text-sm text-[var(--sea-ink)]/70">
					Projected clearance:{" "}
					<span className="font-semibold">
						{snapshot.projectedClearanceDays}d
					</span>{" "}
					at current resolution rate
				</p>
			)}

			{/* Window stats */}
			<p className="mt-2 text-xs text-[var(--sea-ink)]/50">
				{snapshot.newFindingsInWindow} new · {snapshot.resolvedFindingsInWindow}{" "}
				resolved in {snapshot.windowDays}d window
			</p>

			{/* Summary text */}
			<p className="mt-3 text-sm text-[var(--sea-ink)]/70">
				{snapshot.summary}
			</p>
		</article>
	);
}

// RepositoryBranchProtectionPanel — WS-53
// ---------------------------------------------------------------------------

/** Risk level → StatusPill tone */
function branchRiskTone(
	level: string,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "none") return "success";
	if (level === "low") return "neutral";
	if (level === "medium") return "warning";
	return "danger"; // high | critical
}

/** Severity → StatusPill tone */
function branchFindingSeverityTone(
	severity: string,
): "success" | "warning" | "danger" | "neutral" {
	if (severity === "critical") return "danger";
	if (severity === "high") return "danger";
	if (severity === "medium") return "warning";
	return "neutral";
}

function RepositoryBranchProtectionPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const result = useQuery(
		api.branchProtectionIntel.getLatestBranchProtectionBySlug,
		{ tenantSlug, repositoryFullName },
	);

	if (!result || result.riskLevel === "none") return null;

	return (
		<article className="rounded-xl border border-[var(--sea-glass)]/20 bg-[var(--deep-sea)]/40 p-4">
			<div className="flex items-center justify-between">
				<h4 className="text-sm font-semibold text-[var(--sea-ink)]">
					Branch Protection
				</h4>
				<span className="text-xs text-[var(--sea-ink)]/40">
					{result.dataSource === "github_api" ? "GitHub API" : "Simulated"}
				</span>
			</div>

			{/* Risk score + level */}
			<div className="mt-2 flex flex-wrap gap-2">
				<StatusPill
					label={`Risk ${result.riskScore}/100`}
					tone={branchRiskTone(result.riskLevel)}
				/>
				<StatusPill
					label={result.riskLevel.toUpperCase()}
					tone={branchRiskTone(result.riskLevel)}
				/>
				{result.criticalCount > 0 && (
					<StatusPill
						label={`${result.criticalCount} critical`}
						tone="danger"
					/>
				)}
				{result.highCount > 0 && (
					<StatusPill label={`${result.highCount} high`} tone="danger" />
				)}
				{result.mediumCount > 0 && (
					<StatusPill label={`${result.mediumCount} medium`} tone="warning" />
				)}
				{result.lowCount > 0 && (
					<StatusPill label={`${result.lowCount} low`} tone="neutral" />
				)}
			</div>

			{/* Top 5 findings */}
			{result.findings.length > 0 && (
				<ul className="mt-3 space-y-2">
					{result.findings.slice(0, 5).map((f) => (
						<li
							key={f.ruleId}
							className="rounded-lg bg-[var(--deep-sea)]/60 px-3 py-2"
						>
							<div className="flex items-center gap-2">
								<StatusPill
									label={f.severity}
									tone={branchFindingSeverityTone(f.severity)}
								/>
								<span className="text-xs font-medium text-[var(--sea-ink)]/80">
									{f.title}
								</span>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink)]/50">
								{f.recommendation}
							</p>
						</li>
					))}
				</ul>
			)}

			{/* Summary */}
			<p className="mt-3 text-sm text-[var(--sea-ink)]/70">{result.summary}</p>
		</article>
	);
}

// RepositorySensitiveFilePanel — WS-54
// ---------------------------------------------------------------------------

function sensitiveFileRiskTone(
	level: string,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "none") return "success";
	if (level === "low") return "neutral";
	if (level === "medium") return "warning";
	return "danger";
}

function sensitiveFileCategoryLabel(cat: string): string {
	const map: Record<string, string> = {
		private_key: "Private Key",
		credentials: "Credentials",
		app_config: "App Config",
		debug: "Debug Artifact",
	};
	return map[cat] ?? cat;
}

function RepositorySensitiveFilePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const result = useQuery(
		api.sensitiveFileIntel.getLatestSensitiveFileScanBySlug,
		{ tenantSlug, repositoryFullName },
	);

	if (!result || result.riskLevel === "none") return null;

	return (
		<article className="rounded-xl border border-[var(--sea-glass)]/20 bg-[var(--deep-sea)]/40 p-4">
			<div className="flex items-center justify-between">
				<h4 className="text-sm font-semibold text-[var(--sea-ink)]">
					Sensitive Files in Commits
				</h4>
				<span className="font-mono text-xs text-[var(--sea-ink)]/40">
					{result.commitSha.slice(0, 7)}@{result.branch}
				</span>
			</div>

			{/* Risk score + severity counts */}
			<div className="mt-2 flex flex-wrap gap-2">
				<StatusPill
					label={`Risk ${result.riskScore}/100`}
					tone={sensitiveFileRiskTone(result.riskLevel)}
				/>
				<StatusPill
					label={result.riskLevel.toUpperCase()}
					tone={sensitiveFileRiskTone(result.riskLevel)}
				/>
				{result.criticalCount > 0 && (
					<StatusPill
						label={`${result.criticalCount} critical`}
						tone="danger"
					/>
				)}
				{result.highCount > 0 && (
					<StatusPill label={`${result.highCount} high`} tone="danger" />
				)}
				{result.mediumCount > 0 && (
					<StatusPill label={`${result.mediumCount} medium`} tone="warning" />
				)}
				{result.lowCount > 0 && (
					<StatusPill label={`${result.lowCount} low`} tone="neutral" />
				)}
			</div>

			{/* Top 5 findings */}
			{result.findings.length > 0 && (
				<ul className="mt-3 space-y-2">
					{result.findings.slice(0, 5).map((f, i) => (
						<li
							// biome-ignore lint/suspicious/noArrayIndexKey: static list
							key={`${f.ruleId}-${i}`}
							className="rounded-lg bg-[var(--deep-sea)]/60 px-3 py-2"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={f.severity}
									tone={sensitiveFileRiskTone(f.severity)}
								/>
								<StatusPill
									label={sensitiveFileCategoryLabel(f.category)}
									tone="neutral"
								/>
								<code className="text-xs text-[var(--sea-ink)]/70">
									{f.matchedPath}
								</code>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink)]/50">
								{f.recommendation}
							</p>
						</li>
					))}
				</ul>
			)}

			{/* Summary */}
			<p className="mt-3 text-sm text-[var(--sea-ink)]/70">{result.summary}</p>
		</article>
	);
}

// RepositoryCommitMessagePanel — WS-55
// ---------------------------------------------------------------------------

function commitMessageRiskTone(
	level: string,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "none") return "success";
	if (level === "low") return "neutral";
	if (level === "medium") return "warning";
	return "danger";
}

function commitMessageRuleLabel(ruleId: string): string {
	const map: Record<string, string> = {
		SECURITY_BYPASS: "Security Bypass",
		REVERT_SECURITY_FIX: "Revert Security Fix",
		FORCE_MERGE_BYPASS: "Force Merge Bypass",
		CVE_ACKNOWLEDGED: "CVE Reference",
		TODO_SECURITY_DEBT: "Security Debt TODO",
		DEBUG_MODE_ENABLED: "Debug Mode",
		EMERGENCY_DEPLOYMENT: "Emergency Deploy",
		SENSITIVE_DATA_REFERENCE: "Sensitive Data",
	};
	return map[ruleId] ?? ruleId;
}

function RepositoryCommitMessagePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const result = useQuery(
		api.commitMessageIntel.getLatestCommitMessageScanBySlug,
		{ tenantSlug, repositoryFullName },
	);

	if (!result || result.riskLevel === "none") return null;

	return (
		<article className="rounded-xl border border-[var(--sea-glass)]/20 bg-[var(--deep-sea)]/40 p-4">
			<div className="flex items-center justify-between">
				<h4 className="text-sm font-semibold text-[var(--sea-ink)]">
					Commit Message Security Signals
				</h4>
				<span className="font-mono text-xs text-[var(--sea-ink)]/40">
					{result.commitSha.slice(0, 7)}@{result.branch}
				</span>
			</div>

			{/* Risk score + severity counts */}
			<div className="mt-2 flex flex-wrap gap-2">
				<StatusPill
					label={`Risk ${result.riskScore}/100`}
					tone={commitMessageRiskTone(result.riskLevel)}
				/>
				<StatusPill
					label={result.riskLevel.toUpperCase()}
					tone={commitMessageRiskTone(result.riskLevel)}
				/>
				{result.criticalCount > 0 && (
					<StatusPill
						label={`${result.criticalCount} critical`}
						tone="danger"
					/>
				)}
				{result.highCount > 0 && (
					<StatusPill label={`${result.highCount} high`} tone="danger" />
				)}
				{result.mediumCount > 0 && (
					<StatusPill label={`${result.mediumCount} medium`} tone="warning" />
				)}
				{result.lowCount > 0 && (
					<StatusPill label={`${result.lowCount} low`} tone="neutral" />
				)}
			</div>

			{/* Top 5 findings */}
			{result.findings.length > 0 && (
				<ul className="mt-3 space-y-2">
					{result.findings.slice(0, 5).map((f, i) => (
						<li
							// biome-ignore lint/suspicious/noArrayIndexKey: static list
							key={`${f.ruleId}-${i}`}
							className="rounded-lg bg-[var(--deep-sea)]/60 px-3 py-2"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={f.severity}
									tone={commitMessageRiskTone(f.severity)}
								/>
								<StatusPill
									label={commitMessageRuleLabel(f.ruleId)}
									tone="neutral"
								/>
								<code className="text-xs text-[var(--sea-ink)]/70">
									{f.matchedMessage}
								</code>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink)]/50">
								{f.recommendation}
							</p>
						</li>
					))}
				</ul>
			)}

			{/* Summary */}
			<p className="mt-3 text-sm text-[var(--sea-ink)]/70">{result.summary}</p>
		</article>
	);
}

// RepositorySecurityTimelinePanel — WS-51
// ---------------------------------------------------------------------------

/** Icon and tone mapping per timeline event type. */
const TIMELINE_EVENT_ICON: Record<string, string> = {
	finding_created: "🔍",
	finding_escalated: "🔺",
	finding_triaged: "🏷️",
	gate_blocked: "🚫",
	gate_approved: "✅",
	gate_overridden: "⚠️",
	pr_opened: "📤",
	pr_merged: "🎉",
	sla_breached: "⏰",
	risk_accepted: "📋",
	risk_revoked: "🔒",
	red_agent_win: "🔴",
	auto_remediation_dispatched: "🤖",
	secret_detected: "🔑",
};

const TIMELINE_SEVERITY_TONE: Record<
	string,
	"danger" | "warning" | "success" | "neutral"
> = {
	critical: "danger",
	high: "warning",
	medium: "info" as "neutral",
	low: "neutral",
};

function formatRelativeTime(timestamp: number): string {
	const diffMs = Date.now() - timestamp;
	const diffMin = Math.floor(diffMs / 60_000);
	if (diffMin < 1) return "just now";
	if (diffMin < 60) return `${diffMin}m ago`;
	const diffHr = Math.floor(diffMin / 60);
	if (diffHr < 24) return `${diffHr}h ago`;
	const diffDay = Math.floor(diffHr / 24);
	return `${diffDay}d ago`;
}

function RepositorySecurityTimelinePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const timeline = useQuery(
		api.securityTimelineIntel.getSecurityTimelineForRepository,
		{ tenantSlug, repositoryFullName, limit: 20 },
	);

	if (timeline === undefined || timeline === null) return null;
	if (timeline.length === 0) return null;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Audit Trail</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Security event timeline
			</h2>

			{/* Summary pill */}
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={`${timeline.length} events`} tone="neutral" />
				{timeline.some((e) => e.eventType === "gate_blocked") && (
					<StatusPill label="gate blocked" tone="danger" />
				)}
				{timeline.some((e) => e.eventType === "sla_breached") && (
					<StatusPill label="SLA breach" tone="warning" />
				)}
				{timeline.some((e) => e.eventType === "red_agent_win") && (
					<StatusPill label="red agent win" tone="danger" />
				)}
				{timeline.some((e) => e.eventType === "secret_detected") && (
					<StatusPill label="secrets exposed" tone="danger" />
				)}
			</div>

			{/* Event list */}
			<ol className="mt-4 space-y-0">
				{timeline.map((event, idx) => (
					<li key={event.id} className="flex items-start gap-3">
						{/* Timeline vertical line */}
						<div className="flex flex-col items-center">
							<span className="text-base" aria-hidden>
								{TIMELINE_EVENT_ICON[event.eventType] ?? "•"}
							</span>
							{idx < timeline.length - 1 && (
								<div className="mt-1 h-full min-h-[1.5rem] w-px bg-[color:var(--line)]/40" />
							)}
						</div>

						{/* Event content */}
						<div className="min-w-0 flex-1 pb-4">
							<div className="flex items-start justify-between gap-2">
								<div className="min-w-0">
									<p className="text-sm font-semibold text-[var(--sea-ink)] leading-snug">
										{event.title}
									</p>
									{event.detail && (
										<p className="mt-0.5 text-xs text-[var(--sea-ink)]/60 leading-snug">
											{event.detail}
										</p>
									)}
								</div>
								<div className="flex shrink-0 flex-col items-end gap-1">
									{event.severity && (
										<StatusPill
											label={event.severity}
											tone={TIMELINE_SEVERITY_TONE[event.severity] ?? "neutral"}
										/>
									)}
									<span className="text-[10px] text-[var(--sea-ink)]/40 whitespace-nowrap">
										{formatRelativeTime(event.timestamp)}
									</span>
								</div>
							</div>
						</div>
					</li>
				))}
			</ol>
		</article>
	);
}

// ---------------------------------------------------------------------------
// CommunityMarketplacePanel — WS-36
// ---------------------------------------------------------------------------

function CommunityMarketplacePanel() {
	const stats = useQuery(api.communityMarketplace.getMarketplaceStats, {});
	const topApproved = useQuery(api.communityMarketplace.listContributions, {
		status: "approved",
		limit: 5,
	});

	if (stats === undefined || stats === null) return null;
	if (stats.totalContributions === 0) return null;

	const SEVERITY_TONE: Record<
		string,
		"danger" | "warning" | "info" | "neutral"
	> = {
		critical: "danger",
		high: "warning",
		medium: "info",
		low: "neutral",
		informational: "neutral",
	};

	const TYPE_LABEL: Record<string, string> = {
		fingerprint: "fingerprint",
		detection_rule: "rule",
	};

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Community marketplace</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Operator-contributed fingerprints and detection rules enrich the
				platform for everyone.
			</h2>

			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill label={`${stats.approvedCount} approved`} tone="success" />
				<StatusPill
					label={`${stats.fingerprintCount} fingerprints`}
					tone="info"
				/>
				<StatusPill label={`${stats.detectionRuleCount} rules`} tone="info" />
				{stats.pendingCount > 0 && (
					<StatusPill
						label={`${stats.pendingCount} pending review`}
						tone="neutral"
					/>
				)}
				{stats.underReviewCount > 0 && (
					<StatusPill
						label={`${stats.underReviewCount} under review`}
						tone="warning"
					/>
				)}
			</div>

			{topApproved && topApproved.length > 0 && (
				<div className="mt-4 space-y-2">
					{topApproved.map((c) => (
						<div
							key={`${c.createdAt}-${c.title}`}
							className="flex flex-wrap items-center gap-2 rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 px-3 py-2"
						>
							<span className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--sea-ink)]">
								{c.title}
							</span>
							<StatusPill label={TYPE_LABEL[c.type] ?? c.type} tone="neutral" />
							<StatusPill label={c.vulnClass.replace(/_/g, " ")} tone="info" />
							<StatusPill
								label={c.severity}
								tone={SEVERITY_TONE[c.severity] ?? "neutral"}
							/>
							<StatusPill label={`▲ ${c.upvoteCount}`} tone="success" />
						</div>
					))}
				</div>
			)}
		</article>
	);
}

// ─── Cross-Repository Impact Panel (tenant-level) ────────────────────────────

/**
 * Global panel — surfaces packages that are present in more than one
 * monitored repository so operators can triage lateral exposure quickly.
 * Hidden until at least one disclosure has triggered a cross-repo scan.
 */
function TenantCrossRepoPanel({ tenantSlug }: { tenantSlug: string }) {
	const data = useQuery(api.crossRepoIntel.getTenantCrossRepoSummaryBySlug, {
		tenantSlug,
	});

	// Loading or no cross-repo data yet
	if (data === undefined || data === null) return null;
	if (data.totalPackagesTracked === 0) return null;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Cross-repository impact</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				Package disclosures with lateral exposure across repositories.
			</h2>
			<div className="mt-4 flex flex-wrap gap-2">
				<StatusPill
					label={`${data.totalPackagesTracked} package${data.totalPackagesTracked === 1 ? "" : "s"} tracked`}
					tone="info"
				/>
				{data.packagesWithSpread > 0 ? (
					<StatusPill
						label={`${data.packagesWithSpread} spread across repos`}
						tone="danger"
					/>
				) : (
					<StatusPill label="no lateral spread detected" tone="success" />
				)}
				{data.totalAffectedRepoSlots > 0 ? (
					<StatusPill
						label={`${data.totalAffectedRepoSlots} repo exposure${data.totalAffectedRepoSlots === 1 ? "" : "s"}`}
						tone="warning"
					/>
				) : null}
			</div>
			{data.events.length > 0 ? (
				<div className="mt-5 space-y-4">
					{data.events.slice(0, 8).map((event) => (
						<div key={event._id} className="signal-row">
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={event.severity}
									tone={severityTone(event.severity)}
								/>
								<StatusPill label={event.ecosystem} tone="neutral" />
								{event.affectedRepositoryCount > 0 ? (
									<StatusPill
										label={`${event.affectedRepositoryCount} other repo${event.affectedRepositoryCount === 1 ? "" : "s"}`}
										tone="danger"
									/>
								) : (
									<StatusPill label="source repo only" tone="success" />
								)}
							</div>
							<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
								{event.packageName}
							</h3>
							<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
								{event.summary}
							</p>
							{event.affectedRepositoryNames.length > 0 ? (
								<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
									Also in:{" "}
									{event.affectedRepositoryNames.slice(0, 5).join(", ")}
									{event.affectedRepositoryNames.length > 5
										? ` +${event.affectedRepositoryNames.length - 5} more`
										: ""}
								</p>
							) : null}
						</div>
					))}
				</div>
			) : null}
		</article>
	);
}

// ─── AI/ML Model Supply Chain Panel ──────────────────────────────────────────

function modelRiskTone(
	level: "low" | "medium" | "high" | "critical" | undefined,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "critical") return "danger";
	if (level === "high") return "danger";
	if (level === "medium") return "warning";
	if (level === "low") return "success";
	return "neutral";
}

/**
 * Shows the per-repository AI/ML model supply chain risk: detected frameworks,
 * pickle serialisation risk, unpinned versions, and flagged components.
 */
function RepositoryModelSupplyChainPanel({
	repositoryId,
}: {
	repositoryId: string;
}) {
	const scan = useQuery(api.modelSupplyChainIntel.getLatestModelScan, {
		repositoryId:
			repositoryId as import("convex/values").GenericId<"repositories">,
	});

	if (scan === undefined || scan === null) return null;

	// Only show if ML packages were detected
	if (scan.mlFrameworkCount === 0 && scan.flaggedComponentCount === 0)
		return null;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">ML supply chain</p>
				<StatusPill
					label={`${scan.mlFrameworkCount} ML framework${scan.mlFrameworkCount === 1 ? "" : "s"}`}
					tone="neutral"
				/>
				<StatusPill
					label={`risk ${scan.riskLevel}`}
					tone={modelRiskTone(scan.riskLevel)}
				/>
				{scan.hasPickleRisk ? (
					<StatusPill label="pickle RCE risk" tone="danger" />
				) : null}
				{scan.hasUnpinnedFramework ? (
					<StatusPill label="unpinned ML dep" tone="warning" />
				) : null}
				{scan.vulnerableFrameworkCount > 0 ? (
					<StatusPill
						label={`${scan.vulnerableFrameworkCount} CVE${scan.vulnerableFrameworkCount === 1 ? "" : "s"}`}
						tone="danger"
					/>
				) : null}
			</div>
			{scan.flaggedComponents.length > 0 ? (
				<div className="mt-2 space-y-1">
					{scan.flaggedComponents.slice(0, 3).map((c) => (
						<div key={c.name} className="flex flex-wrap items-center gap-2">
							<StatusPill
								label={`${c.name}@${c.version}`}
								tone={modelRiskTone(c.riskLevel)}
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{c.topSignalKind.replaceAll("_", " ")}
							</span>
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">{scan.summary}</p>
		</div>
	);
}

// ─── Model Provenance Panel ───────────────────────────────────────────────────

function provenanceRiskTone(
	level: string | undefined,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "verified") return "success";
	if (level === "acceptable") return "neutral";
	if (level === "unverified") return "warning";
	if (level === "risky") return "danger";
	return "neutral";
}

/**
 * Shows per-repository AI model provenance health: source registry verification,
 * license compliance, weights hash coverage, and per-model risk levels.
 * Only renders when AI model components are detected in the SBOM.
 */
function RepositoryModelProvenancePanel({
	repositoryId,
}: {
	repositoryId: string;
}) {
	const scan = useQuery(api.modelProvenanceIntel.getLatestModelProvenance, {
		repositoryId:
			repositoryId as import("convex/values").GenericId<"repositories">,
	});

	if (scan === undefined || scan === null) return null;
	// Only show when AI models are present
	if (scan.totalModels === 0) return null;

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">AI model provenance</p>
				<StatusPill
					label={`${scan.totalModels} model${scan.totalModels === 1 ? "" : "s"}`}
					tone="neutral"
				/>
				<StatusPill
					label={scan.overallRiskLevel}
					tone={provenanceRiskTone(scan.overallRiskLevel)}
				/>
				<StatusPill
					label={`score ${scan.aggregateScore}/100`}
					tone={
						scan.aggregateScore >= 80
							? "success"
							: scan.aggregateScore >= 60
								? "warning"
								: "danger"
					}
				/>
				{scan.verifiedCount > 0 ? (
					<StatusPill label={`${scan.verifiedCount} verified`} tone="success" />
				) : null}
				{scan.riskyCount > 0 ? (
					<StatusPill label={`${scan.riskyCount} risky`} tone="danger" />
				) : null}
			</div>
			{scan.components.length > 0 ? (
				<div className="mt-2 space-y-1">
					{scan.components.slice(0, 3).map((c) => (
						<div key={c.name} className="flex flex-wrap items-center gap-2">
							<StatusPill
								label={c.name}
								tone={provenanceRiskTone(c.riskLevel)}
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{c.resolvedSource} · {c.resolvedLicense}
							</span>
							{c.topSignalKind ? (
								<span className="text-xs text-[var(--sea-ink-soft)] opacity-70">
									⚠ {c.topSignalKind.replaceAll("_", " ")}
								</span>
							) : null}
						</div>
					))}
				</div>
			) : null}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">{scan.summary}</p>
		</div>
	);
}

// ─── Compliance Evidence Panel ────────────────────────────────────────────────

function evidenceScoreTone(
	score: number | null,
): "success" | "warning" | "danger" | "neutral" {
	if (score === null) return "neutral";
	if (score >= 90) return "success";
	if (score >= 70) return "warning";
	return "danger";
}

/**
 * Shows the per-repository compliance evidence summary across all 5 regulatory
 * frameworks: evidence scores, open gap counts, and last generated timestamp.
 */
function RepositoryComplianceEvidencePanel({
	repositoryId,
}: {
	repositoryId: string;
}) {
	const allEvidence = useQuery(
		api.complianceEvidenceIntel.getAllFrameworkEvidence,
		{
			repositoryId:
				repositoryId as import("convex/values").GenericId<"repositories">,
		},
	);

	if (allEvidence === undefined || allEvidence === null) return null;

	// Only show if at least one framework has been generated
	const hasData = allEvidence.some((fw) => fw.evidenceScore !== null);
	if (!hasData) return null;

	const frameworkLabels: Record<string, string> = {
		soc2: "SOC 2",
		gdpr: "GDPR",
		hipaa: "HIPAA",
		pci_dss: "PCI-DSS",
		nis2: "NIS2",
	};

	const totalOpenGaps = allEvidence.reduce(
		(acc, fw) => acc + (fw.openGapControlCount ?? 0),
		0,
	);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Compliance evidence</p>
				{totalOpenGaps > 0 ? (
					<StatusPill
						label={`${totalOpenGaps} open gap${totalOpenGaps === 1 ? "" : "s"}`}
						tone="warning"
					/>
				) : (
					<StatusPill label="all controls covered" tone="success" />
				)}
			</div>
			<div className="mt-2 flex flex-wrap gap-2">
				{allEvidence.map((fw) =>
					fw.evidenceScore !== null ? (
						<StatusPill
							key={fw.framework}
							label={`${frameworkLabels[fw.framework] ?? fw.framework} ${fw.evidenceScore}/100`}
							tone={evidenceScoreTone(fw.evidenceScore)}
						/>
					) : null,
				)}
			</div>
			{totalOpenGaps > 0 ? (
				<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
					{allEvidence
						.filter((fw) => fw.openGapControlCount > 0)
						.map(
							(fw) =>
								`${frameworkLabels[fw.framework] ?? fw.framework}: ${fw.openGapControlCount} gap${fw.openGapControlCount === 1 ? "" : "s"}`,
						)
						.join(" · ")}
				</p>
			) : null}
		</div>
	);
}

// ─── Trust score tone helpers ────────────────────────────────────────────────

function trustScoreTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 80) return "success";
	if (score >= 60) return "warning";
	if (score > 0) return "danger";
	return "neutral";
}

function trustTierTone(
	tier: string,
): "success" | "warning" | "danger" | "neutral" {
	if (tier === "trusted") return "success";
	if (tier === "acceptable") return "neutral";
	if (tier === "at_risk") return "warning";
	if (tier === "compromised") return "danger";
	return "neutral";
}

/**
 * TrustScoreTierBar — horizontal stacked bar visualising the 4 trust tiers.
 *
 * Each segment's width is proportional to tier.count / totalComponents.
 *
 * Tier colour guide:
 *   trusted     (≥80) → success green   bg-[var(--success)] / #22c55e
 *   acceptable  (60–79) → muted blue   bg-[var(--signal)]  / #3b82f6
 *   at_risk     (30–59) → amber        bg-amber-400         / #fb923c
 *   compromised (<30)  → danger red    bg-[var(--danger)]  / #ef4444
 *
 * Return null when totalComponents is 0 (nothing to display).
 * Keep it compact — the bar lives inside a panel row at most ~24px tall.
 *
 * Trade-offs to consider:
 *   - Show segment labels (count/pct) only when the segment is wide enough?
 *   - Add a `title` tooltip for accessibility / hover detail?
 *   - Fully transparent segments for tiers with count === 0, or skip them?
 */
function TrustScoreTierBar({
	breakdown,
	totalComponents,
}: {
	breakdown: TrustScoreBreakdownEntry[];
	totalComponents: number;
}) {
	if (totalComponents === 0) return null;

	const TIER_COLORS: Record<string, string> = {
		trusted: "bg-[var(--success)]",
		acceptable: "bg-[var(--accent)]",
		at_risk: "bg-[var(--warning)]",
		compromised: "bg-[var(--danger)]",
	};

	const segments = breakdown.filter((e) => e.count > 0);

	return (
		<div className="mt-3 flex h-2 w-full overflow-hidden rounded-full bg-[var(--surface-2)]">
			{segments.map((entry) => (
				<div
					key={entry.tier}
					className={`flex-none ${TIER_COLORS[entry.tier] ?? "bg-[var(--muted)]"}`}
					style={{ width: `${(entry.count / totalComponents) * 100}%` }}
					title={`${entry.label}: ${entry.count}`}
				/>
			))}
		</div>
	);
}

// ── Tone helpers for sandbox outcomes ────────────────────────────────────────

type SandboxOutcome =
	| "exploited"
	| "likely_exploitable"
	| "not_exploitable"
	| "error";
type Tone = "neutral" | "success" | "warning" | "danger" | "info";

function sandboxOutcomeTone(outcome: SandboxOutcome | null | undefined): Tone {
	if (outcome === "exploited") return "danger";
	if (outcome === "likely_exploitable") return "warning";
	if (outcome === "not_exploitable") return "success";
	return "neutral";
}

function sandboxOutcomeLabel(
	outcome: SandboxOutcome | null | undefined,
): string {
	if (outcome === "exploited") return "Confirmed";
	if (outcome === "likely_exploitable") return "Likely";
	if (outcome === "not_exploitable") return "Safe";
	return "Pending";
}

/**
 * Shows real sandbox exploit validation results for a repository:
 * - How many findings have been sandbox-validated
 * - How many were confirmed exploitable (with PoC)
 * - Latest run outcome + winning payload
 */
function RepositorySandboxPanel({ repositoryId }: { repositoryId: string }) {
	const summary = useQuery(
		api.sandboxValidation.getSandboxSummaryForRepository,
		{
			repositoryId: repositoryId as Id<"repositories">,
		},
	);

	if (!summary || summary.totalRuns === 0) return null;

	const latest = summary.latestRun;

	return (
		<div className="panel-section">
			<h4 className="panel-label">Sandbox Validation</h4>
			<div className="flex flex-wrap gap-2 mb-2">
				<StatusPill tone="danger" label={`${summary.exploited} Exploited`} />
				<StatusPill
					tone="warning"
					label={`${summary.likelyExploitable} Likely`}
				/>
				<StatusPill tone="success" label={`${summary.notExploitable} Safe`} />
				{summary.withPoc > 0 && (
					<StatusPill tone="neutral" label={`${summary.withPoc} PoC`} />
				)}
			</div>
			{latest && (
				<div className="text-xs text-gray-400 space-y-1">
					<div className="flex items-center gap-2">
						<span className="text-gray-500">Latest:</span>
						<StatusPill
							tone={sandboxOutcomeTone(latest.outcome as SandboxOutcome | null)}
							label={sandboxOutcomeLabel(
								latest.outcome as SandboxOutcome | null,
							)}
						/>
						<span className="text-gray-500">{latest.sandboxMode}</span>
					</div>
					{latest.winningPayloadLabel && (
						<p className="font-mono text-xs text-amber-400 truncate">
							⚡ {latest.winningPayloadLabel}
						</p>
					)}
					{latest.pocCurl && (
						<p className="text-green-400 text-xs">
							✓ PoC curl command available
						</p>
					)}
					<p className="text-gray-500 leading-snug">{latest.evidenceSummary}</p>
				</div>
			)}
		</div>
	);
}

// ---------------------------------------------------------------------------
// SIEM Push Panel
// ---------------------------------------------------------------------------

type SiemStatus = "ok" | "skipped" | "error";

function siemStatusTone(
	status: SiemStatus,
): "success" | "warning" | "danger" | "neutral" {
	if (status === "ok") return "success";
	if (status === "error") return "danger";
	return "neutral";
}

function siemStatusLabel(
	dest: string,
	status: SiemStatus,
	ruleCount: number,
): string {
	if (status === "skipped") return `${dest} not configured`;
	if (status === "ok") return `${dest} ✓ ${ruleCount} rules`;
	return `${dest} error`;
}

/**
 * Shows the latest SIEM push status for Splunk + Elastic.
 * Hidden when no push has been attempted yet.
 */
function RepositorySiemPanel({ repositoryId }: { repositoryId: string }) {
	const latest = useQuery(api.siemIntel.getLatestSiemPush, {
		repositoryId: repositoryId as Id<"repositories">,
	});

	if (!latest) return null;
	// Hide if both destinations are perpetually skipped (not configured at all)
	if (latest.splunkStatus === "skipped" && latest.elasticStatus === "skipped")
		return null;

	return (
		<div className="panel-section">
			<h4 className="panel-label">SIEM Push</h4>
			<div className="flex flex-wrap gap-2 mb-2">
				<StatusPill
					tone={siemStatusTone(latest.splunkStatus as SiemStatus)}
					label={siemStatusLabel(
						"Splunk",
						latest.splunkStatus as SiemStatus,
						latest.splunkRuleCount,
					)}
				/>
				<StatusPill
					tone={siemStatusTone(latest.elasticStatus as SiemStatus)}
					label={siemStatusLabel(
						"Elastic",
						latest.elasticStatus as SiemStatus,
						latest.elasticRuleCount,
					)}
				/>
			</div>
			{(latest.splunkError || latest.elasticError) && (
				<p className="text-xs text-red-400 truncate">
					{latest.splunkError ?? latest.elasticError}
				</p>
			)}
			<p className="text-xs text-gray-500">
				Last push: {new Date(latest.pushedAt).toLocaleString()}
			</p>
		</div>
	);
}

// ─── Cloud Blast Radius Panel ─────────────────────────────────────────────────

/**
 * Shows the inferred multi-cloud blast radius for a repository, derived from
 * SBOM package names. Hides when no cloud SDK is detected (providers empty).
 */
function RepositoryCloudBlastRadiusPanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const snapshot = useQuery(
		api.cloudBlastRadiusIntel.getCloudBlastRadiusBySlug,
		{ tenantSlug, repositoryFullName },
	);

	if (snapshot === undefined || snapshot === null) return null;
	if (snapshot.providers.length === 0) return null;

	const PROVIDER_LABELS: Record<string, string> = {
		aws: "AWS",
		gcp: "GCP",
		azure: "Azure",
	};

	const topResources = [...snapshot.reachableCloudResources]
		.sort(
			(a: { sensitivityScore: number }, b: { sensitivityScore: number }) =>
				b.sensitivityScore - a.sensitivityScore,
		)
		.slice(0, 3);

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Cloud blast radius</p>
				<StatusPill
					label={snapshot.cloudRiskTier}
					tone={cloudRiskTierTone(snapshot.cloudRiskTier)}
				/>
				<StatusPill
					label={`score ${snapshot.cloudBlastScore}`}
					tone="neutral"
				/>
				{(snapshot.providers as string[]).map((p: string) => (
					<StatusPill key={p} label={PROVIDER_LABELS[p] ?? p} tone="info" />
				))}
			</div>
			<div className="mt-2 flex flex-wrap gap-2">
				{snapshot.iamEscalationRisk ? (
					<StatusPill label="IAM escalation" tone="danger" />
				) : null}
				{snapshot.dataExfiltrationRisk ? (
					<StatusPill label="Data exfil" tone="danger" />
				) : null}
				{snapshot.secretsAccessRisk ? (
					<StatusPill label="Secrets access" tone="warning" />
				) : null}
				{snapshot.lateralMovementRisk ? (
					<StatusPill label="Lateral movement" tone="warning" />
				) : null}
			</div>
			{topResources.length > 0 ? (
				<div className="mt-2 space-y-1">
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Top {topResources.length} resource
						{topResources.length === 1 ? "" : "s"} of{" "}
						{snapshot.reachableCloudResources.length} detected:
					</p>
					<div className="flex flex-wrap gap-2">
						{topResources.map(
							(r: {
								provider: string;
								resourceType: string;
								sensitivityScore: number;
								label: string;
							}) => (
								<StatusPill
									key={`${r.provider}:${r.resourceType}`}
									label={`${PROVIDER_LABELS[r.provider] ?? r.provider} ${r.label}`}
									tone={
										r.sensitivityScore >= 80
											? "danger"
											: r.sensitivityScore >= 60
												? "warning"
												: "neutral"
									}
								/>
							),
						)}
					</div>
				</div>
			) : null}
		</div>
	);
}

function cloudRiskTierTone(
	tier: string,
): "success" | "warning" | "danger" | "neutral" {
	if (tier === "critical") return "danger";
	if (tier === "severe") return "warning";
	if (tier === "moderate") return "neutral";
	return "success";
}

// ─── LLM Certification Panel ─────────────────────────────────────────────────

function certTierTone(
	tier: string | undefined,
): "success" | "warning" | "danger" | "neutral" {
	if (tier === "gold") return "success";
	if (tier === "silver") return "info" as "neutral"; // closest available
	if (tier === "bronze") return "warning";
	return "danger";
}

function certOutcomeTone(
	outcome: string,
): "success" | "warning" | "danger" | "neutral" {
	if (outcome === "pass") return "success";
	if (outcome === "warn") return "warning";
	return "danger";
}

const CERT_TIER_EMOJI: Record<string, string> = {
	gold: "🥇",
	silver: "🥈",
	bronze: "🥉",
	uncertified: "✗",
};

const DOMAIN_LABELS: Record<string, string> = {
	prompt_injection: "Prompt injection",
	supply_chain_integrity: "Supply chain",
	agentic_pipeline_safety: "Agentic pipeline",
	exploit_validation: "Exploit validation",
	regulatory_compliance: "Regulatory",
	attack_surface: "Attack surface",
	dependency_trust: "Dep. trust",
};

/**
 * Shows the LLM-native application security certification tier (Gold / Silver /
 * Bronze / Uncertified) synthesised from all 7 signal domains.  Hidden until
 * the first certification report has been computed.
 */
function RepositoryCertificationPanel({
	repositoryId,
}: {
	repositoryId: string;
}) {
	const report = useQuery(
		api.llmCertificationIntel.getLatestCertificationReport,
		{
			repositoryId:
				repositoryId as import("convex/values").GenericId<"repositories">,
		},
	);

	if (report === undefined || report === null) return null;

	const tierLabel =
		`${CERT_TIER_EMOJI[report.tier] ?? ""} ${report.tier.charAt(0).toUpperCase() + report.tier.slice(1)}`.trim();

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">LLM security certification</p>
				<StatusPill label={tierLabel} tone={certTierTone(report.tier)} />
				<StatusPill
					label={`score ${report.overallScore}/100`}
					tone={
						report.overallScore >= 80
							? "success"
							: report.overallScore >= 55
								? "warning"
								: "danger"
					}
				/>
				{report.passCount > 0 && (
					<StatusPill label={`${report.passCount}/7 pass`} tone="success" />
				)}
				{report.failCount > 0 && (
					<StatusPill label={`${report.failCount} fail`} tone="danger" />
				)}
				{report.warnCount > 0 && (
					<StatusPill label={`${report.warnCount} warn`} tone="warning" />
				)}
			</div>

			{/* Domain breakdown — only show failing or warning domains to keep it compact */}
			{report.domainResults.filter(
				(d: { outcome: string }) => d.outcome !== "pass",
			).length > 0 ? (
				<div className="mt-2 space-y-1">
					{report.domainResults
						.filter((d: { outcome: string }) => d.outcome !== "pass")
						.map(
							(d: {
								domain: string;
								outcome: string;
								score: number;
								rationale: string;
							}) => (
								<div
									key={d.domain}
									className="flex flex-wrap items-start gap-2"
								>
									<StatusPill
										label={DOMAIN_LABELS[d.domain] ?? d.domain}
										tone={certOutcomeTone(d.outcome)}
									/>
									<span className="text-xs text-[var(--sea-ink-soft)] leading-5">
										{d.rationale}
									</span>
								</div>
							),
						)}
				</div>
			) : (
				<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
					All 7 domains passed.
				</p>
			)}

			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{report.summary}
			</p>
		</div>
	);
}

/**
 * Shows the global CISA KEV sync status and recent high-priority Telegram
 * threat signals. Uses no per-repository filtering — surfaces platform-wide
 * threat intel context. Hidden until the first CISA KEV sync has run.
 */
// ---------------------------------------------------------------------------
// WS-34 — EPSS Score Integration panel
// ---------------------------------------------------------------------------

function EpssThreatIntelPanel() {
	const snapshot = useQuery(api.epssIntel.getLatestEpssSnapshot, {});
	const enriched = useQuery(api.epssIntel.getEpssEnrichedDisclosures, {
		limit: 8,
	});

	if (snapshot === undefined && enriched === undefined) return null;

	const EPSS_RISK_TONE: Record<
		string,
		"danger" | "warning" | "neutral" | "info"
	> = {
		critical: "danger",
		high: "warning",
		medium: "neutral",
		low: "info",
	};

	const fmtPct = (n: number) => `${(n * 100).toFixed(1)}%`;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">EPSS score enrichment</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				FIRST.org exploitation-probability scores cross-referenced against
				breach disclosures. Daily sync at 04:00 UTC.
			</h2>

			{/* Sync summary */}
			{snapshot ? (
				<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
					<p className="tiny-label">Latest sync</p>
					<div className="mt-3 flex flex-wrap gap-2">
						<StatusPill
							label={`${snapshot.queriedCveCount} CVEs queried`}
							tone="info"
						/>
						<StatusPill
							label={`${snapshot.enrichedCount} enriched`}
							tone={snapshot.enrichedCount > 0 ? "success" : "neutral"}
						/>
						{snapshot.criticalRiskCount > 0 ? (
							<StatusPill
								label={`${snapshot.criticalRiskCount} critical-risk`}
								tone="danger"
							/>
						) : null}
						{snapshot.highRiskCount > 0 ? (
							<StatusPill
								label={`${snapshot.highRiskCount} high-risk`}
								tone="warning"
							/>
						) : null}
						{snapshot.enrichedCount > 0 ? (
							<StatusPill
								label={`avg ${fmtPct(snapshot.avgScore)} probability`}
								tone={snapshot.avgScore >= 0.2 ? "warning" : "neutral"}
							/>
						) : null}
					</div>
					<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
						{snapshot.summary}
					</p>
				</div>
			) : (
				<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No EPSS sync has run yet. The daily cron runs at 04:00 UTC, or
						trigger one manually via{" "}
						<code className="text-xs">POST /api/threat-intel/epss/sync</code>.
					</p>
				</div>
			)}

			{/* Top scored CVEs */}
			{enriched && enriched.length > 0 ? (
				<div className="mt-4 space-y-2">
					<p className="tiny-label">Top EPSS-scored CVEs</p>
					{enriched.map((item) => (
						<div
							key={String(item._id)}
							className="flex flex-wrap items-center gap-2 rounded-xl border border-[color:var(--line)]/50 bg-[var(--surface)]/50 px-3 py-2"
						>
							<StatusPill
								label={item.epssRiskLevel}
								tone={EPSS_RISK_TONE[item.epssRiskLevel] ?? "neutral"}
							/>
							<span className="font-mono text-xs font-medium text-[var(--sea-ink)]">
								{item.sourceRef}
							</span>
							<StatusPill
								label={`${fmtPct(item.epssScore)} exploit prob.`}
								tone={EPSS_RISK_TONE[item.epssRiskLevel] ?? "neutral"}
							/>
							<StatusPill
								label={`p${Math.round(item.epssPercentile * 100)}`}
								tone="info"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{item.packageName} · {item.ecosystem}
							</span>
						</div>
					))}
				</div>
			) : snapshot ? (
				<p className="mt-4 text-sm text-[var(--sea-ink-soft)]">
					No CVEs have been enriched with EPSS scores yet in the current
					disclosure set.
				</p>
			) : null}
		</article>
	);
}

function ThreatIntelPanel() {
	const snapshot = useQuery(api.tier3Intel.getLatestCisaKevSnapshot, {});
	const signals = useQuery(api.tier3Intel.getHighPrioritySignals, {});

	// While both are loading, render nothing (avoid layout flicker)
	if (snapshot === undefined && signals === undefined) return null;

	const THREAT_TONE: Record<string, "danger" | "warning" | "neutral" | "info"> =
		{
			critical: "danger",
			high: "warning",
			medium: "neutral",
			low: "info",
		};

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<p className="island-kicker mb-2">Tier 3 threat intelligence</p>
			<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
				CISA KEV catalog cross-referenced against open findings. Telegram
				channel signals scored and stored.
			</h2>

			{/* CISA KEV snapshot */}
			{snapshot ? (
				<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
					<p className="tiny-label">CISA KEV — last sync</p>
					<div className="mt-3 flex flex-wrap gap-2">
						<StatusPill
							label={`${snapshot.totalEntries} CVEs in catalog`}
							tone="info"
						/>
						<StatusPill
							label={`${snapshot.ransomwareRelated} ransomware-related`}
							tone={snapshot.ransomwareRelated > 0 ? "danger" : "neutral"}
						/>
						<StatusPill
							label={`${snapshot.matchedFindingCount} findings matched`}
							tone={snapshot.matchedFindingCount > 0 ? "danger" : "success"}
						/>
						{snapshot.hasHighPriorityEntries ? (
							<StatusPill label="high-priority entries" tone="warning" />
						) : null}
					</div>
					{snapshot.matchedCveIds.length > 0 ? (
						<div className="mt-3 flex flex-wrap gap-2">
							{(snapshot.matchedCveIds as string[]).slice(0, 6).map((cve) => (
								<StatusPill key={cve} label={cve} tone="danger" />
							))}
							{snapshot.matchedCveIds.length > 6 ? (
								<StatusPill
									label={`+${snapshot.matchedCveIds.length - 6} more`}
									tone="neutral"
								/>
							) : null}
						</div>
					) : (
						<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
							No open findings matched CISA KEV entries in the last sync.
						</p>
					)}
				</div>
			) : (
				<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No CISA KEV sync has run yet. The daily cron runs at 03:00 UTC, or
						trigger one manually via{" "}
						<code className="text-xs">
							POST /api/threat-intel/cisa-kev/sync
						</code>
						.
					</p>
				</div>
			)}

			{/* High-priority Telegram signals */}
			{signals && signals.length > 0 ? (
				<div className="mt-4 space-y-3">
					<p className="tiny-label">Recent high-priority signals</p>
					{signals
						.slice(0, 5)
						.map(
							(sig: {
								_id: string;
								threatLevel: string;
								source: string;
								cveIds: string[];
								hasCredentialPattern: boolean;
								hasRansomwareKeywords: boolean;
								capturedAt: number;
								text: string;
							}) => (
								<div key={sig._id} className="signal-row">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={sig.threatLevel}
											tone={THREAT_TONE[sig.threatLevel] ?? "neutral"}
										/>
										<StatusPill label={sig.source} tone="neutral" />
										{sig.hasCredentialPattern ? (
											<StatusPill label="credential leak" tone="danger" />
										) : null}
										{sig.hasRansomwareKeywords ? (
											<StatusPill label="ransomware" tone="danger" />
										) : null}
										{(sig.cveIds as string[]).slice(0, 3).map((cve) => (
											<StatusPill key={cve} label={cve} tone="warning" />
										))}
									</div>
									<p className="mt-2 line-clamp-2 text-sm text-[var(--sea-ink-soft)]">
										{sig.text}
									</p>
									<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
										{formatTimestamp(sig.capturedAt)}
									</p>
								</div>
							),
						)}
				</div>
			) : (
				<p className="mt-4 text-sm text-[var(--sea-ink-soft)]">
					No high-priority threat signals captured yet.
				</p>
			)}
		</article>
	);
}

/**
 * Shows the per-repository dependency trust score summary:
 * repository composite score, direct/transitive scores, vulnerable and
 * untrusted counts, and a 4-tier distribution bar.
 */
function RepositoryTrustScorePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const summary = useQuery(api.trustScoreIntel.getRepositoryTrustScoreSummary, {
		tenantSlug,
		repositoryFullName,
	});

	if (summary === undefined || summary === null) return null;

	const compromisedEntry = summary.breakdown.find(
		(b) => b.tier === "compromised",
	);
	const atRiskEntry = summary.breakdown.find((b) => b.tier === "at_risk");

	return (
		<div className="mt-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Trust scores</p>
				<StatusPill
					label={`repo ${summary.repositoryScore}/100`}
					tone={trustScoreTone(summary.repositoryScore)}
				/>
				{compromisedEntry && compromisedEntry.count > 0 ? (
					<StatusPill
						label={`${compromisedEntry.count} compromised`}
						tone="danger"
					/>
				) : null}
				{atRiskEntry && atRiskEntry.count > 0 ? (
					<StatusPill label={`${atRiskEntry.count} at risk`} tone="warning" />
				) : null}
				{summary.vulnerableCount > 0 ? (
					<StatusPill
						label={`${summary.vulnerableCount} CVE-tagged`}
						tone="danger"
					/>
				) : null}
			</div>
			<div className="mt-2 flex flex-wrap gap-2">
				<StatusPill
					label={`direct ${summary.directDepScore}`}
					tone={trustScoreTone(summary.directDepScore)}
				/>
				<StatusPill
					label={`transitive ${summary.transitiveDepScore}`}
					tone={trustScoreTone(summary.transitiveDepScore)}
				/>
				{summary.untrustedCount > 0 ? (
					<StatusPill
						label={`${summary.untrustedCount} untrusted`}
						tone="warning"
					/>
				) : null}
			</div>
			{/* Tier breakdown — text pills as fallback until TrustScoreTierBar is wired */}
			{summary.totalComponents > 0 ? (
				<div className="mt-2 flex flex-wrap gap-1">
					{summary.breakdown
						.filter((entry) => entry.count > 0)
						.map((entry) => (
							<StatusPill
								key={entry.tier}
								label={`${entry.count} ${entry.tier.replace("_", " ")}`}
								tone={trustTierTone(entry.tier)}
							/>
						))}
				</div>
			) : null}
			<TrustScoreTierBar
				breakdown={summary.breakdown}
				totalComponents={summary.totalComponents}
			/>
		</div>
	);
}

// ─── Security posture tone helpers ───────────────────────────────────────────

function postureLevelTone(
	level: string,
): "success" | "warning" | "danger" | "neutral" {
	if (level === "critical") return "danger";
	if (level === "at_risk") return "warning";
	if (level === "fair") return "warning";
	if (level === "good") return "success";
	return "success"; // excellent
}

function postureScoreTone(
	score: number,
): "success" | "warning" | "danger" | "neutral" {
	if (score >= 80) return "success";
	if (score >= 50) return "warning";
	return "danger";
}

/**
 * Shows the unified security posture score for a repository — the leading
 * summary card an operator sees before drilling into detail panels.
 */
function RepositoryPosturePanel({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const report = useQuery(api.securityPosture.getSecurityPostureReport, {
		tenantSlug,
		repositoryFullName,
	});

	if (report === undefined || report === null) return null;

	return (
		<div className="mb-3 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-4">
			<div className="flex flex-wrap items-center gap-2">
				<p className="tiny-label">Security posture</p>
				<StatusPill
					label={`${report.overallScore}/100`}
					tone={postureScoreTone(report.overallScore)}
				/>
				<StatusPill
					label={report.postureLevel.replace("_", " ")}
					tone={postureLevelTone(report.postureLevel)}
				/>
			</div>
			{report.topActions.length > 0 ? (
				<ul className="mt-2 space-y-0.5">
					{report.topActions.map((action) => (
						<li
							key={action}
							className="text-xs text-[var(--sea-ink-soft)] before:mr-1.5 before:content-['→']"
						>
							{action}
						</li>
					))}
				</ul>
			) : null}
		</div>
	);
}

// ---------------------------------------------------------------------------
// WebhookSettingsPanel — outbound event delivery overview
// ---------------------------------------------------------------------------

function deliveryTone(success: boolean): "info" | "danger" {
	return success ? "info" : "danger";
}

function endpointCountTone(count: number): "info" | "neutral" {
	return count > 0 ? "info" : "neutral";
}

function eventTypeTone(
	eventType: string,
): "info" | "warning" | "danger" | "neutral" {
	if (eventType.startsWith("gate.")) return "warning";
	if (eventType.startsWith("regulatory.")) return "warning";
	if (eventType.startsWith("attack_surface.")) return "danger";
	if (eventType.startsWith("finding.validated")) return "info";
	return "info";
}

function WebhookSettingsPanel({ tenantSlug }: { tenantSlug: string }) {
	const endpoints = useQuery(api.webhooks.listEndpoints, { tenantSlug });
	const deliveries = useQuery(api.webhooks.listRecentDeliveries, {
		tenantSlug,
		limit: 10,
	});

	if (endpoints === undefined) return null;

	return (
		<article className="panel rounded-[1.75rem] p-6">
			<div className="flex flex-wrap items-center justify-between gap-2">
				<div>
					<p className="island-kicker mb-2">Outbound webhooks</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Sentinel delivers signed event payloads to your SIEM, Slack, or
						PagerDuty as findings and gate decisions are made.
					</h2>
				</div>
				<StatusPill
					label={`${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}`}
					tone={endpointCountTone(endpoints.length)}
				/>
			</div>

			{endpoints.length === 0 ? (
				<div className="mt-5 rounded-xl border border-dashed border-[color:var(--line)] p-4">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No endpoints registered. Register via the REST API:
					</p>
					<pre className="mt-2 overflow-x-auto rounded bg-[var(--surface)] p-3 text-xs text-[var(--sea-ink)]">
						{`POST /api/webhooks\n{ "tenantSlug": "${tenantSlug}", "url": "https://…", "secret": "…", "events": [] }`}
					</pre>
				</div>
			) : (
				<div className="mt-5 space-y-2">
					{endpoints.map((ep) => (
						<div
							key={ep._id}
							className="rounded-xl border border-[color:var(--line)]/70 bg-[var(--surface)]/60 p-3"
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={ep.active ? "active" : "inactive"}
									tone={ep.active ? "success" : "neutral"}
								/>
								<span className="break-all text-xs font-mono text-[var(--sea-ink)]">
									{ep.url}
								</span>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
								{ep.events.length === 0 ? "All events" : ep.events.join(" · ")}
								{ep.lastDeliveryAt != null
									? ` · Last delivery: ${formatTimestamp(ep.lastDeliveryAt)}`
									: ""}
							</p>
						</div>
					))}
				</div>
			)}

			{deliveries && deliveries.length > 0 ? (
				<div className="mt-5">
					<p className="tiny-label mb-2">Recent deliveries</p>
					<div className="space-y-1">
						{deliveries.map((d) => (
							<div
								key={d._id}
								className="flex flex-wrap items-center gap-2 rounded-lg px-2 py-1"
							>
								<StatusPill
									label={d.success ? "ok" : "fail"}
									tone={deliveryTone(d.success)}
								/>
								<StatusPill
									label={d.eventType}
									tone={eventTypeTone(d.eventType)}
								/>
								{d.statusCode != null ? (
									<span className="text-xs text-[var(--sea-ink-soft)]">
										HTTP {d.statusCode}
									</span>
								) : null}
								<span className="text-xs text-[var(--sea-ink-soft)]">
									{d.durationMs}ms
								</span>
								<span className="ml-auto text-xs text-[var(--sea-ink-soft)]">
									{formatTimestamp(d.attemptedAt)}
								</span>
							</div>
						))}
					</div>
				</div>
			) : null}
		</article>
	);
}

function SetupState() {
	return (
		<main className="page-wrap px-4 pb-14 pt-10">
			<section className="hero-panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<p className="island-kicker mb-4">Configuration needed</p>
				<h1 className="display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
					The Sentinel control plane is scaffolded and ready. Convex just needs
					to be connected.
				</h1>
				<p className="mt-5 max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
					Run <code>bunx --bun convex init</code>, set
					<code> VITE_CONVEX_URL</code> and <code>CONVEX_DEPLOYMENT</code> in
					<code> .env.local</code>, then reload this page.
				</p>
				<div className="mt-8 flex flex-wrap gap-3">
					<Link to="/about" className="signal-button secondary-button">
						Review architecture decisions
					</Link>
					<a
						href="https://docs.convex.dev/quickstart/tanstack-start"
						target="_blank"
						rel="noreferrer"
						className="signal-button"
					>
						Open Convex quickstart
					</a>
				</div>
			</section>
		</main>
	);
}

function HomePage() {
	if (!env.VITE_CONVEX_URL) {
		return <SetupState />;
	}

	return <ConfiguredDashboard />;
}

function ConfiguredDashboard() {
	const overview = useQuery(api.dashboard.overview, {
		tenantSlug: "atlas-fintech",
	});
	const seedBaseline = useMutation(api.seed.seedBaseline);
	const ingestGithubPush = useMutation(api.events.ingestGithubPush);
	const simulateLatestWorkflowStep = useMutation(
		api.events.simulateLatestWorkflowStep,
	);
	const runLatestSemanticFingerprint = useMutation(
		api.events.runLatestSemanticFingerprint,
	);
	const runLatestExploitValidation = useMutation(
		api.events.runLatestExploitValidation,
	);
	const runLatestGateEvaluation = useMutation(
		api.events.runLatestGateEvaluation,
	);
	const runAdversarialRound = useMutation(
		api.redBlueIntel.runAdversarialRoundForRepository,
	);
	const [isPending, startTransition] = useTransition();

	async function handleSeed() {
		await seedBaseline({});
	}

	function queueSamplePush() {
		startTransition(() => {
			void ingestGithubPush({
				tenantSlug: "atlas-fintech",
				repositoryFullName: "atlas-fintech/payments-api",
				branch: "main",
				commitSha: `manual-${Date.now().toString(36)}`,
				changedFiles: [
					"services/auth/jwt.py",
					"services/sbom/parser.py",
					"infra/github/workflows/scan.yml",
				],
			});
		});
	}

	function advanceWorkflow() {
		startTransition(() => {
			void simulateLatestWorkflowStep({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	function runSemanticFingerprint() {
		startTransition(() => {
			void runLatestSemanticFingerprint({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	function runExploitValidation() {
		startTransition(() => {
			void runLatestExploitValidation({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	function runGateEvaluation() {
		startTransition(() => {
			void runLatestGateEvaluation({ tenantSlug: "atlas-fintech" });
		});
	}

	function runAdversarialRoundForFirstRepo() {
		if (!overview || !overview.repositories[0]) return;
		startTransition(() => {
			void runAdversarialRound({
				tenantSlug: "atlas-fintech",
				repositoryFullName: overview.repositories[0].fullName,
			});
		});
	}

	if (overview === null) {
		return (
			<main className="page-wrap px-4 pb-14 pt-10">
				<section className="hero-panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
					<p className="island-kicker mb-4">First-run workspace</p>
					<h1 className="display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
						The app is wired. Seed the baseline Sentinel tenant to start shaping
						the runtime around real data.
					</h1>
					<p className="mt-5 max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
						This creates a tenant, repositories, workflow history, SBOM
						inventory, breach disclosures, findings, and gate decisions that
						match the Phase 1 path from the spec.
					</p>
					<div className="mt-8 flex flex-wrap gap-3">
						<button
							type="button"
							onClick={handleSeed}
							className="signal-button"
						>
							Seed baseline workspace
						</button>
						<Link to="/about" className="signal-button secondary-button">
							See the architecture rationale
						</Link>
					</div>
				</section>
			</main>
		);
	}

	if (overview === undefined) {
		return (
			<main className="page-wrap px-4 pb-14 pt-10">
				<section className="panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
					<p className="island-kicker mb-4">Loading control plane</p>
					<div className="grid gap-4 md:grid-cols-3">
						{loadingSkeletonIds.map((skeletonId) => (
							<div
								key={skeletonId}
								className="loading-panel h-28 rounded-3xl"
							/>
						))}
					</div>
				</section>
			</main>
		);
	}

	return (
		<main className="page-wrap px-4 pb-14 pt-10">
			<section className="hero-panel rise-in relative overflow-hidden rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<div className="halo halo-left" />
				<div className="halo halo-right" />
				<div className="flex flex-wrap items-start justify-between gap-5">
					<div className="max-w-3xl">
						<p className="island-kicker mb-3">Sentinel Phase 0 foundation</p>
						<h1 className="display-title mb-5 max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
							Build the cyber-intelligence spine first, then layer autonomy on
							top.
						</h1>
						<p className="max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
							This dashboard is already anchored to the real domain model:
							events, workflow runs, SBOM snapshots, breach disclosures,
							findings, and gate decisions. That gives us a trustworthy place to
							plug GitHub, Python agents, and later sandbox execution into.
						</p>
					</div>
					<div className="panel-grid min-w-[280px] flex-1 rounded-[1.5rem] p-5">
						<div className="flex items-center justify-between">
							<span className="tiny-label">Tenant</span>
							<StatusPill label={overview.tenant.currentPhase} tone="info" />
						</div>
						<div className="mt-2 text-2xl font-semibold text-[var(--sea-ink)]">
							{overview.tenant.name}
						</div>
						<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
							Deployment: {overview.tenant.deploymentMode.replace("_", " ")}
						</p>
						<div className="mt-4 flex flex-wrap gap-2">
							<button
								type="button"
								onClick={handleSeed}
								className="signal-button secondary-button"
							>
								Re-check baseline
							</button>
							<button
								type="button"
								onClick={queueSamplePush}
								className="signal-button"
								disabled={isPending}
							>
								Queue sample push
							</button>
							<button
								type="button"
								onClick={advanceWorkflow}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Advance active workflow
							</button>
							<button
								type="button"
								onClick={runSemanticFingerprint}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run semantic fingerprint
							</button>
							<button
								type="button"
								onClick={runExploitValidation}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run exploit validation
							</button>
							<button
								type="button"
								onClick={runGateEvaluation}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run gate evaluation
							</button>
							<button
								type="button"
								onClick={runAdversarialRoundForFirstRepo}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run adversarial round
							</button>
						</div>
					</div>
				</div>
			</section>

			<section className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
				{[
					{
						label: "Open findings",
						value: overview.stats.openFindings,
						hint: "Current unresolved risk",
						icon: AlertTriangle,
					},
					{
						label: "Critical or high",
						value: overview.stats.criticalFindings,
						hint: "Potential merge blockers",
						icon: ShieldCheck,
					},
					{
						label: "Active workflows",
						value: overview.stats.activeWorkflows,
						hint: "Queued or running scans",
						icon: Waypoints,
					},
					{
						label: "SBOM components",
						value: overview.stats.sbomComponents,
						hint: "Latest known inventory size",
						icon: Boxes,
					},
					{
						label: "Validated findings",
						value: overview.stats.validatedFindings,
						hint: "Exploit-first confirmed",
						icon: Sparkles,
					},
				].map(({ label, value, hint, icon: Icon }, index) => (
					<article
						key={label}
						className="panel rise-in rounded-[1.35rem] p-5"
						style={{ animationDelay: `${index * 70 + 80}ms` }}
					>
						<div className="flex items-center justify-between">
							<span className="tiny-label">{label}</span>
							<span className="metric-icon">
								<Icon size={16} />
							</span>
						</div>
						<div className="mt-4 text-4xl font-semibold text-[var(--sea-ink)]">
							{value}
						</div>
						<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">{hint}</p>
					</article>
				))}
			</section>

			<section className="mt-8 grid gap-4 xl:grid-cols-[1.3fr_1fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<div className="flex items-center justify-between gap-3">
						<div>
							<p className="island-kicker mb-2">Open finding queue</p>
							<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
								Only the evidence-backed problems should survive to this layer.
							</h2>
						</div>
						<StatusPill
							label={`${overview.findings.length} visible`}
							tone="warning"
						/>
					</div>
					<div className="mt-5 space-y-4">
						{overview.findings.map((finding: OverviewFinding) => (
							<div key={finding._id} className="signal-row">
								<div className="flex flex-wrap items-center gap-2">
									<StatusPill
										label={finding.severity}
										tone={severityTone(finding.severity)}
									/>
									<StatusPill label={finding.source} tone="info" />
									<StatusPill
										label={finding.validationStatus}
										tone={
											finding.validationStatus === "validated"
												? "success"
												: "warning"
										}
									/>
								</div>
								<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
									{finding.title}
								</h3>
								<div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-[var(--sea-ink-soft)]">
									<span>Status: {finding.status.replace("_", " ")}</span>
									<span>
										Confidence: {Math.round(finding.confidence * 100)}%
									</span>
									<span>Raised: {formatTimestamp(finding.createdAt)}</span>
								</div>
								<FindingBlastRadiusPanel findingId={finding._id} />
							</div>
						))}
					</div>
				</article>

				<div className="space-y-4">
					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Workflow spine</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Recent runs
								</h2>
							</div>
							<StatusPill label="event driven" tone="info" />
						</div>
						<div className="mt-5 space-y-4">
							{overview.workflows.map((workflow: OverviewWorkflow) => (
								<div key={workflow._id} className="signal-row">
									<div className="flex items-center justify-between gap-4">
										<div className="text-lg font-semibold text-[var(--sea-ink)]">
											{workflow.workflowType.replace("_", " ")}
										</div>
										<StatusPill
											label={workflow.status}
											tone={workflowTone(workflow.status)}
										/>
									</div>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{workflow.summary}
									</p>
									<div className="mt-3 flex flex-wrap gap-4 text-sm text-[var(--sea-ink-soft)]">
										<span>Priority: {workflow.priority}</span>
										<span>
											Progress: {workflow.completedTaskCount}/
											{workflow.totalTaskCount}
										</span>
										<span>
											Stage:{" "}
											{workflow.currentStage
												? workflow.currentStage.replace("_", " ")
												: "Not started"}
										</span>
										<span>Started: {formatTimestamp(workflow.startedAt)}</span>
										<span>Ended: {formatTimestamp(workflow.completedAt)}</span>
									</div>
									<div className="mt-4 flex flex-wrap gap-2">
										{workflow.tasks.map((task: OverviewWorkflowTask) => (
											<StatusPill
												key={task._id}
												label={`${task.order + 1}. ${task.stage}`}
												tone={taskTone(task.status)}
											/>
										))}
									</div>
								</div>
							))}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">CI/CD gate enforcement</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Policy-driven blocking now records auditable decisions for
									each finding.
								</h2>
							</div>
							<GitMerge className="text-[var(--signal)]" size={18} />
						</div>
						<div className="mt-4 flex flex-wrap gap-2">
							<StatusPill
								label={`${overview.ciGateEnforcement.blockedCount} blocked`}
								tone={
									overview.ciGateEnforcement.blockedCount > 0
										? "danger"
										: "success"
								}
							/>
							<StatusPill
								label={`${overview.ciGateEnforcement.approvedCount} approved`}
								tone="success"
							/>
							{overview.ciGateEnforcement.overrideCount > 0 ? (
								<StatusPill
									label={`${overview.ciGateEnforcement.overrideCount} overridden`}
									tone="warning"
								/>
							) : null}
							<StatusPill label="local-first MVP" tone="neutral" />
						</div>
						<div className="mt-5 space-y-4">
							{overview.ciGateEnforcement.recentDecisions.length > 0 ? (
								overview.ciGateEnforcement.recentDecisions.map(
									(decision: OverviewGateDecision) => (
										<div key={decision._id} className="signal-row">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={decision.decision}
													tone={
														decision.decision === "blocked"
															? "danger"
															: decision.decision === "approved"
																? "success"
																: "warning"
													}
												/>
												<StatusPill
													label={decision.stage.replace("_", " ")}
													tone="neutral"
												/>
												<StatusPill
													label={decision.actorId.replace(/_/g, " ")}
													tone="info"
												/>
											</div>
											<h3 className="mt-3 text-base font-semibold text-[var(--sea-ink)]">
												{decision.findingTitle}
											</h3>
											<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
												{decision.repositoryName} /{" "}
												{formatTimestamp(decision.createdAt)}
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												{decision.justification ?? "No justification recorded."}
											</p>
											{decision.expiresAt ? (
												<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
													Expires: {formatTimestamp(decision.expiresAt)}
												</p>
											) : null}
										</div>
									),
								)
							) : (
								<div className="signal-row">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										No gate decisions recorded yet. Queue a sample push, run
										semantic fingerprinting and exploit validation, then trigger
										a gate evaluation to see policy-driven blocking in action.
									</p>
								</div>
							)}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Semantic fingerprinting</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Changed-code matches now feed the exploit-first pipeline.
								</h2>
							</div>
							<StatusPill
								label={`${overview.semanticFingerprint.openCandidateCount} open`}
								tone={
									overview.semanticFingerprint.openCandidateCount > 0
										? "warning"
										: "success"
								}
							/>
						</div>
						<div className="mt-4 flex flex-wrap gap-2">
							<StatusPill
								label={`pending validation ${overview.semanticFingerprint.pendingValidationCount}`}
								tone="info"
							/>
							<StatusPill label="path-aware MVP" tone="neutral" />
						</div>
						<div className="mt-5 space-y-4">
							{overview.semanticFingerprint.recentFindings.map(
								(finding: OverviewSemanticFinding) => (
									<div key={finding._id} className="signal-row">
										<div className="flex flex-wrap items-center gap-2">
											<StatusPill
												label={finding.severity}
												tone={severityTone(finding.severity)}
											/>
											<StatusPill
												label={finding.validationStatus}
												tone={
													finding.validationStatus === "validated"
														? "success"
														: "warning"
												}
											/>
										</div>
										<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
											{finding.title}
										</h3>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											{finding.repositoryName} /{" "}
											{finding.vulnClass.replaceAll("_", " ")}
										</p>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Confidence {Math.round(finding.confidence * 100)}% /{" "}
											{formatTimestamp(finding.createdAt)}
										</p>
									</div>
								),
							)}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Exploit validation</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Local-first validation runs now classify which candidates stay
									open.
								</h2>
							</div>
							<FlaskConical className="text-[var(--signal)]" size={18} />
						</div>
						<div className="mt-4 flex flex-wrap gap-2">
							<StatusPill
								label={`pending ${overview.exploitValidation.pendingCount}`}
								tone={
									overview.exploitValidation.pendingCount > 0
										? "warning"
										: "success"
								}
							/>
							<StatusPill
								label={`validated ${overview.exploitValidation.validatedCount}`}
								tone="success"
							/>
							<StatusPill
								label={`likely exploitable ${overview.exploitValidation.likelyExploitableCount}`}
								tone="warning"
							/>
						</div>
						<div className="mt-5 space-y-4">
							{overview.exploitValidation.recentRuns.length > 0 ? (
								overview.exploitValidation.recentRuns.map(
									(run: OverviewExploitValidationRun) => (
										<div key={run._id} className="signal-row">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={run.status}
													tone={workflowTone(run.status)}
												/>
												{run.outcome ? (
													<StatusPill
														label={run.outcome.replaceAll("_", " ")}
														tone={validationTone(run.outcome)}
													/>
												) : null}
											</div>
											<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
												{run.findingTitle}
											</h3>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												{run.repositoryName} / confidence{" "}
												{Math.round(run.validationConfidence * 100)}%
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												{run.evidenceSummary}
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												Started {formatTimestamp(run.startedAt)} / finished{" "}
												{formatTimestamp(run.completedAt)}
											</p>
										</div>
									),
								)
							) : (
								<div className="signal-row">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										No validation runs recorded yet. Trigger the local-first
										validation path after queueing a semantic or breach finding.
									</p>
								</div>
							)}
						</div>
					</article>
				</div>
			</section>

			<section className="mt-8 grid gap-4 xl:grid-cols-[1.2fr_1fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<div className="flex items-center justify-between gap-3">
						<div>
							<p className="island-kicker mb-2">Repository inventory</p>
							<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
								The first operator-facing surface is already typed around real
								repos.
							</h2>
						</div>
						{overview.latestSnapshot ? (
							<StatusPill
								label={`SBOM ${overview.latestSnapshot.commitSha}`}
								tone="success"
							/>
						) : null}
					</div>
					<div className="mt-5 grid gap-4 md:grid-cols-2">
						{overview.repositories.map((repository: OverviewRepository) => (
							<div key={repository._id} className="signal-row h-full">
								<RepositoryPosturePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySandboxPanel repositoryId={repository._id} />
								<RepositoryBlastRadiusSummary
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<div className="flex items-center justify-between gap-3">
									<div>
										<h3 className="text-lg font-semibold text-[var(--sea-ink)]">
											{repository.name}
										</h3>
										<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
											{repository.provider} / {repository.primaryLanguage}
										</p>
									</div>
									<StatusPill label={repository.defaultBranch} tone="neutral" />
								</div>
								<div className="mt-4 space-y-2 text-sm text-[var(--sea-ink-soft)]">
									<div>
										Last scan: {formatTimestamp(repository.lastScannedAt)}
									</div>
									<div>Commit: {repository.latestCommitSha || "Unknown"}</div>
								</div>
								{repository.latestSnapshot ? (
									<div className="mt-4 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface-strong)]/70 p-4">
										<div className="flex flex-wrap items-center gap-2">
											<StatusPill
												label={`${repository.latestSnapshot.totalComponents} components`}
												tone="success"
											/>
											<StatusPill
												label={repository.latestSnapshot.commitSha}
												tone="neutral"
											/>
										</div>
										<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
											Captured:{" "}
											{formatTimestamp(repository.latestSnapshot.capturedAt)}
										</p>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Source manifests:{" "}
											{repository.latestSnapshot.sourceFiles.join(", ")}
										</p>
										<div className="mt-3 flex flex-wrap gap-2">
											{[
												{
													layer: "direct",
													count:
														repository.latestSnapshot.directDependencyCount,
												},
												{
													layer: "transitive",
													count:
														repository.latestSnapshot.transitiveDependencyCount,
												},
												{
													layer: "build",
													count: repository.latestSnapshot.buildDependencyCount,
												},
												{
													layer: "container",
													count:
														repository.latestSnapshot.containerDependencyCount,
												},
												{
													layer: "runtime",
													count:
														repository.latestSnapshot.runtimeDependencyCount,
												},
												{
													layer: "ai_model",
													count:
														repository.latestSnapshot.aiModelDependencyCount,
												},
											]
												.filter((entry) => entry.count > 0)
												.map(({ layer, count }) => (
													<StatusPill
														key={`${repository._id}-${layer}`}
														label={`${formatLayerLabel(String(layer))}: ${count}`}
														tone={
															layer === "direct"
																? "success"
																: layer === "build" || layer === "container"
																	? "warning"
																	: "info"
														}
													/>
												))}
											{repository.latestSnapshot.vulnerableComponentCount >
											0 ? (
												<StatusPill
													label={`vulnerable: ${repository.latestSnapshot.vulnerableComponentCount}`}
													tone="danger"
												/>
											) : null}
										</div>
										{repository.latestSnapshot.comparison ? (
											<div className="mt-3 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
												<div className="flex flex-wrap items-center gap-2">
													<StatusPill
														label={`+${repository.latestSnapshot.comparison.addedCount} added`}
														tone="success"
													/>
													<StatusPill
														label={`${repository.latestSnapshot.comparison.updatedCount} updated`}
														tone="warning"
													/>
													<StatusPill
														label={`-${repository.latestSnapshot.comparison.removedCount} removed`}
														tone="danger"
													/>
													{repository.latestSnapshot.comparison
														.vulnerableComponentDelta !== 0 ? (
														<StatusPill
															label={`vuln delta ${repository.latestSnapshot.comparison.vulnerableComponentDelta > 0 ? "+" : ""}${repository.latestSnapshot.comparison.vulnerableComponentDelta}`}
															tone={
																repository.latestSnapshot.comparison
																	.vulnerableComponentDelta > 0
																	? "danger"
																	: "success"
															}
														/>
													) : null}
												</div>
												<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
													Compared with{" "}
													{
														repository.latestSnapshot.comparison
															.previousCommitSha
													}{" "}
													from{" "}
													{formatTimestamp(
														repository.latestSnapshot.comparison
															.previousCapturedAt,
													)}
												</p>
												<div className="mt-3 space-y-2 text-sm text-[var(--sea-ink-soft)]">
													{repository.latestSnapshot.comparison.updatedPreview.map(
														(component: OverviewUpdatedComponent) => (
															<p
																key={`${repository._id}-update-${component.name}-${component.sourceFile}`}
															>
																Updated {component.name} in{" "}
																{component.sourceFile}:{" "}
																{component.previousVersion} to{" "}
																{component.nextVersion}
															</p>
														),
													)}
													{repository.latestSnapshot.comparison.addedPreview.map(
														(component: OverviewDiffComponent) => (
															<p
																key={`${repository._id}-add-${component.name}-${component.version}-${component.sourceFile}`}
															>
																Added {component.name}@{component.version} via{" "}
																{component.sourceFile}
															</p>
														),
													)}
													{repository.latestSnapshot.comparison.removedPreview.map(
														(component: OverviewDiffComponent) => (
															<p
																key={`${repository._id}-remove-${component.name}-${component.version}-${component.sourceFile}`}
															>
																Removed {component.name}@{component.version}{" "}
																from {component.sourceFile}
															</p>
														),
													)}
												</div>
											</div>
										) : null}
										{repository.latestSnapshot.vulnerablePreview.length > 0 ? (
											<div className="mt-3 rounded-2xl border border-[color:var(--danger)]/20 bg-[color:var(--danger)]/6 p-4">
												<div className="flex items-center justify-between gap-3">
													<p className="tiny-label">Vulnerable inventory</p>
													<StatusPill
														label={`${repository.latestSnapshot.vulnerableComponentCount} flagged`}
														tone="danger"
													/>
												</div>
												<div className="mt-3 space-y-2 text-sm text-[var(--sea-ink-soft)]">
													{repository.latestSnapshot.vulnerablePreview.map(
														(component: OverviewVulnerableComponent) => (
															<p
																key={`${repository._id}-vuln-${component.name}-${component.version}-${component.sourceFile}`}
															>
																{component.name}@{component.version} via{" "}
																{component.sourceFile} (
																{formatLayerLabel(component.layer)})
															</p>
														),
													)}
												</div>
											</div>
										) : null}
										<div className="mt-3 flex flex-wrap gap-2">
											{repository.latestSnapshot.previewComponents.map(
												(component: OverviewSnapshotComponent) => (
													<StatusPill
														key={`${repository._id}-${component.name}-${component.version}`}
														label={`${component.name}@${component.version}`}
														tone={componentTone(
															component.layer,
															component.hasKnownVulnerabilities,
														)}
													/>
												),
											)}
										</div>
									</div>
								) : (
									<p className="mt-4 text-sm text-[var(--sea-ink-soft)]">
										No SBOM snapshot imported for this repository yet.
									</p>
								)}
								<RepositoryCertificationPanel repositoryId={repository._id} />
								<RepositoryTrustScorePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySemanticFingerprintPanel
									repositoryId={repository._id}
								/>
								<RepositoryIntelligencePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryMemoryPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<AdversarialRoundPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryAttackSurfacePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryRegulatoryDriftPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryHoneypotPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryLearningPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
									repositoryId={repository._id}
								/>
								<RepositorySlaPanel repositoryId={repository._id} />
								<RepositoryRiskAcceptancePanel repositoryId={repository._id} />
								<RepositoryRemediationQueuePanel
									repositoryId={repository._id}
								/>
								<RepositoryEscalationPanel repositoryId={repository._id} />
								<RepositoryAutoRemediationPanel repositoryId={repository._id} />
								<RepositoryAgenticWorkflowPanel repositoryId={repository._id} />
								<RepositoryModelSupplyChainPanel
									repositoryId={repository._id}
								/>
								<RepositoryModelProvenancePanel repositoryId={repository._id} />
								<RepositoryComplianceEvidencePanel
									repositoryId={repository._id}
								/>
								<RepositorySiemPanel repositoryId={repository._id} />
								<RepositoryCloudBlastRadiusPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryTrafficAnomalyPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySecretScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryLicenseCompliancePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryLicenseScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySbomQualityPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryIacScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryCicdScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryCryptoWeaknessPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryEolPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryAbandonmentPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryAttestationPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryConfusionScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryMaliciousScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryCveScanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySupplyChainPosturePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryContainerImagePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryCompliancePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryRemediationPlanPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryHealthScorePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryDependencyUpdatePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySecurityDebtPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryBranchProtectionPanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySensitiveFilePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositoryCommitMessagePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
								<RepositorySecurityTimelinePanel
									tenantSlug={overview.tenant.slug}
									repositoryFullName={repository.fullName}
								/>
							</div>
						))}
					</div>
				</article>

				<div className="space-y-4">
					<TenantCrossRepoPanel tenantSlug={overview.tenant.slug} />
					<TenantVendorTrustPanel tenantSlug={overview.tenant.slug} />
					<TenantGamificationPanel tenantSlug={overview.tenant.slug} />
					<CommunityMarketplacePanel />

					<article className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Breach intel aggregator</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Feed sync is now observable instead of disappearing behind backend
							actions.
						</h2>
						<div className="mt-5 flex flex-wrap gap-2">
							<StatusPill
								label={`recent disclosures ${overview.advisoryAggregator.recentImportedDisclosures}`}
								tone="info"
							/>
							<StatusPill
								label={`matched ${overview.advisoryAggregator.recentMatchedDisclosures}`}
								tone={
									overview.advisoryAggregator.recentMatchedDisclosures > 0
										? "danger"
										: "success"
								}
							/>
							{overview.advisoryAggregator.lastCompletedAt ? (
								<StatusPill
									label={`last sync ${formatTimestamp(overview.advisoryAggregator.lastCompletedAt)}`}
									tone="success"
								/>
							) : (
								<StatusPill label="no sync history yet" tone="warning" />
							)}
						</div>
						<div className="mt-5 space-y-4">
							{overview.advisoryAggregator.recentRuns.length > 0 ? (
								overview.advisoryAggregator.recentRuns.map(
									(run: OverviewAdvisorySyncRun) => (
										<div key={run._id} className="signal-row">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={run.status}
													tone={syncTone(run.status)}
												/>
												<StatusPill label={run.triggerType} tone="neutral" />
												<StatusPill
													label={`${run.packageCount} packages`}
													tone="info"
												/>
											</div>
											<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
												{run.repositoryName}
											</h3>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												GitHub fetched {run.githubFetched}, imported{" "}
												{run.githubImported}. OSV fetched {run.osvFetched},
												imported {run.osvImported}.
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												Started {formatTimestamp(run.startedAt)} / finished{" "}
												{formatTimestamp(run.completedAt)}
											</p>
											{run.reason ? (
												<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
													{run.reason}
												</p>
											) : null}
										</div>
									),
								)
							) : (
								<div className="signal-row">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										No advisory sync runs have been recorded yet.
									</p>
								</div>
							)}
						</div>
						{overview.advisoryAggregator.sourceCoverage.length > 0 ? (
							<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
								<p className="tiny-label">Recent source coverage</p>
								<div className="mt-3 space-y-3">
									{overview.advisoryAggregator.sourceCoverage.map(
										(source: OverviewAdvisorySource) => (
											<div key={`${source.sourceType}-${source.sourceTier}`}>
												<div className="flex flex-wrap items-center gap-2">
													<StatusPill
														label={source.sourceType.replaceAll("_", " ")}
														tone="neutral"
													/>
													<StatusPill
														label={source.sourceTier.replace("_", " ")}
														tone="info"
													/>
													<StatusPill
														label={`${source.disclosureCount} disclosures`}
														tone="info"
													/>
													<StatusPill
														label={`${source.matchedCount} matched`}
														tone={
															source.matchedCount > 0 ? "danger" : "success"
														}
													/>
												</div>
												<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
													{source.sourceName} / last published{" "}
													{formatTimestamp(source.lastPublishedAt)}
												</p>
											</div>
										),
									)}
								</div>
							</div>
						) : null}
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Breach watchlist</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Feed-normalized disclosure intake is now version aware against
							live inventory.
						</h2>
						<div className="mt-5 space-y-4">
							{overview.disclosures.map((disclosure: OverviewDisclosure) => (
								<div key={disclosure._id} className="signal-row">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={disclosure.sourceType.replaceAll("_", " ")}
											tone="neutral"
										/>
										<StatusPill
											label={disclosure.sourceTier.replace("_", " ")}
											tone="info"
										/>
										<StatusPill
											label={disclosure.severity}
											tone={severityTone(disclosure.severity)}
										/>
										<StatusPill
											label={disclosure.matchStatus.replace("_", " ")}
											tone={disclosureTone(disclosure.matchStatus)}
										/>
										{disclosure.exploitAvailable ? (
											<StatusPill label="exploit available" tone="danger" />
										) : null}
									</div>
									<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
										{disclosure.packageName}
									</h3>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{disclosure.sourceName}
										{disclosure.repositoryName
											? ` / ${disclosure.repositoryName}`
											: ""}
										{" / "}
										{disclosure.sourceRef}
										{" / "}
										{formatTimestamp(disclosure.publishedAt)}
									</p>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{disclosure.matchSummary}
									</p>
									{disclosure.affectedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Affected ranges: {disclosure.affectedVersions.join(" ; ")}
										</p>
									) : null}
									{disclosure.fixVersion ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Fixed in: {disclosure.fixVersion}
										</p>
									) : null}
									{disclosure.affectedMatchedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Affected installed versions:{" "}
											{disclosure.affectedMatchedVersions.join(", ")}
										</p>
									) : disclosure.matchedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Observed installed versions:{" "}
											{disclosure.matchedVersions.join(", ")}
										</p>
									) : null}
								</div>
							))}
						</div>
					</article>

					<ThreatIntelPanel />
					<EpssThreatIntelPanel />
				</div>
			</section>

			<section className="mt-8">
				<WebhookSettingsPanel tenantSlug="atlas-fintech" />
			</section>

			<section className="mt-8 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Build track</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						The next four implementation moves are already constrained by the
						spec and the project tracker.
					</h2>
					<div className="mt-5 grid gap-3">
						{implementationTrack.map((step, index) => (
							<div key={step} className="timeline-step">
								<div className="timeline-index">{index + 1}</div>
								<p className="text-sm text-[var(--sea-ink)]">{step}</p>
							</div>
						))}
					</div>
				</article>

				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Why this shape</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Convex handles the control plane now so Python and Go can specialize
						later instead of carrying the whole platform on day one.
					</h2>
					<div className="mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]">
						<p>
							Convex is the system of record for tenants, workflows, findings,
							SBOM state, and operator UI data.
						</p>
						<p>
							Python remains the path for orchestration, embeddings, scraping,
							and exploit reasoning.
						</p>
						<p>
							Go still fits the event gateway and sandbox manager, but those are
							being staged behind stable contracts instead of guessed into
							existence.
						</p>
					</div>
					<div className="mt-5">
						<Link to="/about" className="signal-button secondary-button">
							Read the full foundation decision log
						</Link>
					</div>
				</article>
			</section>
		</main>
	);
}
