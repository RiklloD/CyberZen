import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Bot } from "lucide-react";
import { useState } from "react";
import AgentMemoryPanel from "../components/panels/AgentMemoryPanel";
import LearningProfilePanel from "../components/panels/LearningProfilePanel";
import LlmCertificationHistory from "../components/panels/LlmCertificationHistory";
import LlmCertificationPanel from "../components/panels/LlmCertificationPanel";
import ModelProvenanceChainViewer from "../components/panels/ModelProvenanceChainViewer";
import ModelProvenancePanel from "../components/panels/ModelProvenancePanel";
import RedBlueAdversarialPanel from "../components/panels/RedBlueAdversarialPanel";
import SemanticFingerprintPanel from "../components/panels/SemanticFingerprintPanel";
import StatusPill from "../components/StatusPill";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import {
	formatTimestamp,
	severityTone,
	validationTone } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/agents")({ errorComponent: RouteErrorBoundary, component: AgentsPage });

type RecentFindingsData = NonNullable<
	FunctionReturnType<typeof api.dashboard.recentFindings>
>;
type EscalationsData = NonNullable<
	FunctionReturnType<typeof api.dashboard.escalations>
>;
type OverviewRepository =
	NonNullable<FunctionReturnType<typeof api.dashboard.overview>>["repositories"][number];
type OverviewSemanticFinding =
	RecentFindingsData["semanticFingerprint"]["recentFindings"][number];
type OverviewExploitRun =
	EscalationsData["exploitValidation"]["recentRuns"][number];

function AgentsPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const recentFindings = useQuery(api.dashboard.recentFindings, { tenantSlug: TENANT });
	const escalations = useQuery(api.dashboard.escalations, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState<"overview" | "repo" | "certification" | "provenance">("overview");

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

	const { repositories } = overview;
	const semanticFingerprint = recentFindings?.semanticFingerprint;
	const exploitValidation = escalations?.exploitValidation;
	const activeRepo = selectedRepo
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
							Red/Blue adversarial rounds · Semantic fingerprinting · Exploit
							validation · Learning profiles
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
					<button
						type="button"
						className={`tab-btn ${activeTab === "certification" ? "is-active" : ""}`}
						onClick={() => setActiveTab("certification")}
					>
						LLM Certification
					</button>
					<button
						type="button"
						className={`tab-btn ${activeTab === "provenance" ? "is-active" : ""}`}
						onClick={() => setActiveTab("provenance")}
					>
						Model Provenance
					</button>
				</div>

				{activeTab === "overview" && (
					<div className="space-y-4">
						{/* Semantic fingerprinting */}
						<div>
							<div className="section-header mb-3">
								<h2 className="section-title">Semantic Fingerprinting</h2>
								{semanticFingerprint && (
									<StatusPill
										label={`${semanticFingerprint.openCandidateCount} candidates`}
										tone={
											semanticFingerprint.openCandidateCount > 0
												? "warning"
												: "success"
										}
									/>
								)}
							</div>

							{semanticFingerprint ? (
								<div className="card mb-3">
									<div className="flex flex-wrap gap-2 mb-2">
										<StatusPill
											label={`${semanticFingerprint.openCandidateCount} open candidates`}
											tone={
												semanticFingerprint.openCandidateCount > 0
													? "warning"
													: "success"
											}
										/>
										<StatusPill
											label={`${semanticFingerprint.pendingValidationCount} pending validation`}
											tone="neutral"
										/>
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
															<StatusPill
																label={finding.vulnClass.replace(/_/g, " ")}
																tone="info"
															/>
															<StatusPill
																label={`${(finding.confidence * 100).toFixed(0)}% confidence`}
																tone="neutral"
															/>
														</div>
														<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
															{finding.repositoryName} ·{" "}
															{formatTimestamp(finding.createdAt)}
														</p>
													</div>
												),
											)}
										</div>
									)}
								</div>
							) : (
								<div className="card">
									<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
										<p>No semantic fingerprint data available yet.</p>
									</div>
								</div>
							)}
						</div>

						{/* Exploit Validation */}
						<div>
							<div className="section-header mb-3">
								<h2 className="section-title">Exploit Validation</h2>
							</div>
							{exploitValidation ? (
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
							) : (
								<div className="card">
									<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
										<p>No exploit validation data available yet.</p>
									</div>
								</div>
							)}
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

		{activeTab === "certification" && (
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
						<RepoLlmCertificationSection
							repositoryId={activeRepo._id as Id<"repositories">}
						/>
					)}
				</div>
			)}

			{activeTab === "provenance" && (
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
						<RepoModelProvenanceSection
							repositoryId={activeRepo._id as Id<"repositories">}
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
	repositoryFullName }: {
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
		repositoryFullName: repositoryFullName });
	const learningProfile = useQuery(
		api.learningProfileIntel.getLatestLearningProfile,
		{ tenantSlug, repositoryFullName },
	);
	const agenticScan = useQuery(api.agenticWorkflowIntel.getLatestAgenticScan, {
		repositoryId });
	const semanticAnalysis = useQuery(
		api.semanticFingerprintIntel.getLatestCodeAnalysis,
		{ repositoryId },
	);

	return (
		<div className="grid gap-4 sm:grid-cols-2">
			{/* Red/Blue Adversarial */}
			{adversarialSummary && (
				<RedBlueAdversarialPanel
					adversarialSummary={adversarialSummary}
					redAgentFindingCount={redAgentFindingCount}
				/>
			)}

			{/* Agent Memory */}
			{agentMemory && (
				<AgentMemoryPanel memory={agentMemory} />
			)}

			{/* Learning Profile */}
			{learningProfile && (
				<LearningProfilePanel profile={learningProfile} />
			)}

			{/* Semantic Fingerprint per-repo */}
			{semanticAnalysis && (
				<SemanticFingerprintPanel analysis={semanticAnalysis} />
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
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
						{agenticScan.summary}
					</p>
				</div>
			)}
		</div>
	);
}

function RepoLlmCertificationSection({
	repositoryId }: {
	repositoryId: Id<"repositories">;
}) {
	const certReport = useQuery(
		api.llmCertificationIntel.getLatestCertificationReport,
		{ repositoryId },
	);
	const certHistory = useQuery(
		api.llmCertificationIntel.getCertificationHistory,
		{ repositoryId, limit: 20 },
	);

	if (!certReport && certHistory === undefined) {
		return (
			<div className="grid gap-3 sm:grid-cols-2">
				{["a", "b"].map((k) => (
					<div key={k} className="loading-panel h-32 rounded-2xl" />
				))}
			</div>
		);
	}

	return (
		<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
			{/* Left: Certification report */}
			<div>
				{certReport ? (
					<LlmCertificationPanel report={certReport} />
				) : (
					<div className="card">
						<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
							<p className="text-sm text-[var(--sea-ink-soft)]">
								No LLM certification data available for this repository yet.
							</p>
						</div>
					</div>
				)}
			</div>

			{/* Right: History */}
			<div>
				<LlmCertificationHistory history={certHistory ?? []} />
			</div>
		</div>
	);
}

function RepoModelProvenanceSection({
	repositoryId }: {
	repositoryId: Id<"repositories">;
}) {
	const provenanceScan = useQuery(
		api.modelProvenanceIntel.getLatestModelProvenance,
		{ repositoryId },
	);

	if (provenanceScan === undefined) {
		return (
			<div className="grid gap-3 sm:grid-cols-2">
				{["a", "b"].map((k) => (
					<div key={k} className="loading-panel h-32 rounded-2xl" />
				))}
			</div>
		);
	}

	if (!provenanceScan) {
		return (
			<div className="card">
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No model provenance data available for this repository yet.
						Run a provenance scan to analyze AI model supply chain integrity.
					</p>
				</div>
			</div>
		);
	}

	return (
		<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
			{/* Left: Provenance panel */}
			<div>
				<ModelProvenancePanel scan={provenanceScan} />
			</div>

			{/* Right: Chain viewer */}
			<div>
				<ModelProvenanceChainViewer scan={provenanceScan} />
			</div>
		</div>
	);
}