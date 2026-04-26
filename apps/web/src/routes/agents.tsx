import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Bot } from "lucide-react";
import { useState } from "react";
import { api } from "../../convex/_generated/api";
import type { Id } from "../../convex/_generated/dataModel";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	formatTimestamp,
	learningTrendTone,
	maturityTone,
	multiplierTone,
	severityTone,
	validationTone,
} from "../lib/utils";

export const Route = createFileRoute("/agents")({ component: AgentsPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];
type OverviewSemanticFinding = OverviewData["semanticFingerprint"]["recentFindings"][number];
type OverviewExploitRun = OverviewData["exploitValidation"]["recentRuns"][number];

const TENANT = TENANT_SLUG;

function AgentsPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState<"overview" | "repo">("overview");

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
					{["a", "b", "c"].map((k) => (
						<div key={k} className="loading-panel h-32 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { repositories, semanticFingerprint, exploitValidation } = overview;
	const activeRepo =
		selectedRepo
			? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
			: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Bot size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Agents &amp; Learning</h1>
						<p className="page-subtitle">
							Red/Blue adversarial rounds · Semantic fingerprinting · Exploit validation · Learning profiles
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="tab-bar mb-5">
					<button
						type="button"
						className={`tab-btn ${activeTab === "overview" ? "is-active" : ""}`}
						onClick={() => setActiveTab("overview")}
					>
						Global overview
					</button>
					<button
						type="button"
						className={`tab-btn ${activeTab === "repo" ? "is-active" : ""}`}
						onClick={() => setActiveTab("repo")}
					>
						Per-repository
					</button>
				</div>

				{activeTab === "overview" && (
					<div className="space-y-4">
						{/* Semantic fingerprinting */}
						<div>
							<div className="section-header mb-3">
								<h2 className="section-title">Semantic Fingerprinting</h2>
								<StatusPill
									label={`${semanticFingerprint.openCandidateCount} candidates`}
									tone={semanticFingerprint.openCandidateCount > 0 ? "warning" : "success"}
								/>
							</div>

							<div className="card mb-3">
								<div className="flex flex-wrap gap-2 mb-2">
									<StatusPill
										label={`${semanticFingerprint.openCandidateCount} open candidates`}
										tone={semanticFingerprint.openCandidateCount > 0 ? "warning" : "success"}
									/>
									<StatusPill
										label={`${semanticFingerprint.pendingValidationCount} pending validation`}
										tone="neutral"
									/>
								</div>
							</div>

							{semanticFingerprint.recentFindings.length > 0 && (
								<div className="space-y-2">
									{semanticFingerprint.recentFindings.map(
										(finding: OverviewSemanticFinding) => (
											<div key={finding._id} className="card card-sm">
												<div className="flex flex-wrap items-center gap-2">
													<StatusPill
														label={finding.severity}
														tone={severityTone(finding.severity)}
													/>
													<StatusPill label={finding.vulnClass.replace(/_/g, " ")} tone="info" />
													<StatusPill
														label={`${(finding.confidence * 100).toFixed(0)}% confidence`}
														tone="neutral"
													/>
												</div>
												<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
													{finding.repositoryName} · {formatTimestamp(finding.createdAt)}
												</p>
											</div>
										),
									)}
								</div>
							)}
						</div>

						{/* Exploit Validation */}
						<div>
							<div className="section-header mb-3">
								<h2 className="section-title">Exploit Validation</h2>
							</div>
							<div className="space-y-2">
						{exploitValidation.recentRuns.map((run: OverviewExploitRun) => (
								<div key={run._id} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={run.outcome ?? run.status}
											tone={validationTone(run.outcome ?? undefined)}
										/>
										<StatusPill label={run.status} tone="neutral" />
									</div>
									<p className="mt-1 text-xs font-medium text-[var(--sea-ink)]">
										{run.findingTitle}
									</p>
									<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
										{run.repositoryName} · {formatTimestamp(run.startedAt)}
									</p>
									{run.evidenceSummary && (
										<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
											{run.evidenceSummary}
										</p>
									)}
								</div>
							))}
								{exploitValidation.recentRuns.length === 0 && (
									<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
										<p>No exploit validation runs.</p>
									</div>
								)}
							</div>
						</div>
					</div>
				)}

				{activeTab === "repo" && (
					<div>
						{repositories.length > 1 && (
							<div className="tab-bar mb-4">
								{repositories.map((r: OverviewRepository) => (
									<button
										key={r._id}
										type="button"
										className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
										onClick={() => setSelectedRepo(r._id)}
									>
										{r.fullName.split("/").pop()}
									</button>
								))}
							</div>
						)}
						{activeRepo && (
							<RepoAgentIntelligence
								tenantSlug={TENANT}
								repositoryId={activeRepo._id as Id<"repositories">}
								repositoryFullName={activeRepo.fullName}
							/>
						)}
					</div>
				)}
			</div>
		</main>
	);
}

function RepoAgentIntelligence({
	tenantSlug,
	repositoryId,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryId: Id<"repositories">;
	repositoryFullName: string;
}) {
	const adversarialSummary = useQuery(
		api.redBlueIntel.adversarialSummaryForRepository,
		{ tenantSlug, repositoryFullName },
	);
	const redAgentFindingCount = useQuery(
		api.redAgentEscalation.getRedAgentFindingCount,
		{ tenantSlug, repositoryFullName },
	);
	const agentMemory = useQuery(api.agentMemory.getRepositoryMemory, {
		tenantSlug: tenantSlug,
		repositoryFullName: repositoryFullName,
	});
	const learningProfile = useQuery(
		api.learningProfileIntel.getLatestLearningProfile,
		{ tenantSlug, repositoryFullName },
	);
	const agenticScan = useQuery(
		api.agenticWorkflowIntel.getLatestAgenticScan,
		{ repositoryId },
	);
	const semanticAnalysis = useQuery(
		api.semanticFingerprintIntel.getLatestCodeAnalysis,
		{ repositoryId },
	);

	return (
		<div className="grid gap-4 sm:grid-cols-2">
			{/* Red/Blue Adversarial */}
			{adversarialSummary && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Red/Blue Adversarial Rounds</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`${adversarialSummary.totalRounds} rounds`}
							tone="neutral"
						/>
						{adversarialSummary.redWins > 0 && (
							<StatusPill
								label={`Red ${adversarialSummary.redWins}W`}
								tone="danger"
							/>
						)}
						{adversarialSummary.blueWins > 0 && (
							<StatusPill
								label={`Blue ${adversarialSummary.blueWins}W`}
								tone="success"
							/>
						)}
						{adversarialSummary.draws > 0 && (
							<StatusPill
								label={`${adversarialSummary.draws} draws`}
								tone="neutral"
							/>
						)}
						{redAgentFindingCount != null && redAgentFindingCount > 0 && (
							<StatusPill
								label={`${redAgentFindingCount} escalated`}
								tone="warning"
							/>
						)}
					</div>
					<div className="mt-2 flex flex-wrap gap-1.5">
						<StatusPill
							label={`coverage ${adversarialSummary.avgAttackSurfaceCoverage}%`}
							tone={adversarialSummary.avgAttackSurfaceCoverage > 60 ? "warning" : "neutral"}
						/>
						<StatusPill
							label={`detection ${adversarialSummary.avgBlueDetectionScore}%`}
							tone={adversarialSummary.avgBlueDetectionScore > 70 ? "success" : "neutral"}
						/>
					</div>
					{adversarialSummary.latestRound && (
						<>
							<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
								Latest: {adversarialSummary.latestRound.redStrategySummary}
							</p>
							{adversarialSummary.latestRound.exploitChains.slice(0, 3).map((chain, i) => (
								<p
									// biome-ignore lint/suspicious/noArrayIndexKey: exploit chains have no stable id
									key={i}
									className="mt-0.5 text-xs text-[var(--sea-ink-soft)]"
								>
									→ {chain}
								</p>
							))}
						</>
					)}
				</div>
			)}

			{/* Agent Memory */}
			{agentMemory && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Agent Memory</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={agentMemory.dominantSeverity}
							tone={severityTone(agentMemory.dominantSeverity)}
						/>
						<StatusPill
							label={`FP ${Math.round(agentMemory.falsePositiveRate * 100)}%`}
							tone={agentMemory.falsePositiveRate > 0.3 ? "warning" : "neutral"}
						/>
						<StatusPill
							label={`${agentMemory.totalFindingsAnalyzed} analyzed`}
							tone="neutral"
						/>
					</div>
					{agentMemory.recurringVulnClasses.slice(0, 2).map((vc) => (
						<div key={vc.vulnClass} className="mt-1.5 flex flex-wrap gap-1.5">
							<StatusPill
								label={vc.vulnClass.replaceAll("_", " ")}
								tone="info"
							/>
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{vc.count}× · avg severity {(vc.avgSeverityWeight * 100).toFixed(0)}%
							</span>
						</div>
					))}
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">{agentMemory.summary}</p>
				</div>
			)}

			{/* Learning Profile */}
			{learningProfile && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Learning Profile</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`maturity ${learningProfile.adaptedConfidenceScore}/100`}
							tone={maturityTone(learningProfile.adaptedConfidenceScore)}
						/>
						<StatusPill
							label={learningProfile.attackSurfaceTrend}
							tone={learningTrendTone(learningProfile.attackSurfaceTrend)}
						/>
						{learningProfile.recurringCount > 0 && (
							<StatusPill
								label={`${learningProfile.recurringCount} recurring`}
								tone="warning"
							/>
						)}
						{learningProfile.suppressedCount > 0 && (
							<StatusPill
								label={`${learningProfile.suppressedCount} suppressed`}
								tone="neutral"
							/>
						)}
						{learningProfile.successfulExploitPaths.length > 0 && (
							<StatusPill
								label={`${learningProfile.successfulExploitPaths.length} exploit paths`}
								tone="danger"
							/>
						)}
					</div>
					{learningProfile.vulnClassPatterns.slice(0, 3).map((p) => (
						<div key={p.vulnClass} className="mt-1.5 flex flex-wrap gap-1.5">
							<StatusPill
								label={p.vulnClass.replaceAll("_", " ")}
								tone={multiplierTone(p.confidenceMultiplier)}
							/>
							<StatusPill
								label={`×${p.confidenceMultiplier} confidence`}
								tone={multiplierTone(p.confidenceMultiplier)}
							/>
						</div>
					))}
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
						{learningProfile.summary}
					</p>
				</div>
			)}

			{/* Semantic Fingerprint per-repo */}
			{semanticAnalysis && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Semantic Fingerprint (this repo)</p>
					<p className="text-xs text-[var(--sea-ink-soft)] mb-2">
						Commit: <code>{semanticAnalysis.commitSha.slice(0, 7)}</code> on {semanticAnalysis.branch}
					</p>
					{semanticAnalysis.topMatches.slice(0, 5).map((m) => (
						<div key={m.patternId} className="flex flex-wrap items-center gap-1.5 mt-1">
							<StatusPill
								label={m.severity}
								tone={
									m.severity === "critical"
										? "danger"
										: m.severity === "high"
											? "warning"
											: "neutral"
								}
							/>
							<span className="text-xs text-[var(--sea-ink-soft)] truncate">
								{m.vulnClass.replace(/_/g, " ")}
							</span>
							<span className="text-xs text-[var(--sea-ink-soft)] ml-auto">
								{(m.similarity * 100).toFixed(0)}%
							</span>
						</div>
					))}
					{semanticAnalysis.topMatches.length === 0 && (
						<p className="text-xs text-[var(--success)]">
							No semantic matches above threshold
						</p>
					)}
				</div>
			)}

			{/* Agentic Workflow Scan */}
			{agenticScan && (
				<div className="card card-sm col-span-full sm:col-span-1">
					<p className="panel-label mb-2">Agentic Workflow Scan</p>
					<div className="flex flex-wrap gap-1.5">
						{agenticScan.criticalCount > 0 && (
							<StatusPill
								label={`${agenticScan.criticalCount} critical`}
								tone="danger"
							/>
						)}
						{agenticScan.highCount > 0 && (
							<StatusPill
								label={`${agenticScan.highCount} high`}
								tone="warning"
							/>
						)}
					</div>
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">{agenticScan.summary}</p>
				</div>
			)}
		</div>
	);
}
