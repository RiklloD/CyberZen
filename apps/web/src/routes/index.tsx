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

type AttackSurfaceDashboard = NonNullable<
	FunctionReturnType<typeof api.attackSurfaceIntel.getAttackSurfaceDashboard>
>;
type AttackSurfaceSnapshot = AttackSurfaceDashboard["snapshot"];
type AttackSurfaceHistoryEntry = AttackSurfaceDashboard["history"][number];

const implementationTrack = [
	"Exercise the first real GitHub webhook delivery against the Convex HTTP endpoint",
	"Run the first live advisory bulk-sync pass against the hosted Convex deployment",
	"Exercise the first live end-to-end repository scan path",
	"Begin the PR Generation MVP once live validation evidence exists",
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
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const profile = useQuery(api.learningProfileIntel.getLatestLearningProfile, {
		tenantSlug,
		repositoryFullName,
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
								/>
							</div>
						))}
					</div>
				</article>

				<div className="space-y-4">
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
