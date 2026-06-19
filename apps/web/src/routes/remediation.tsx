import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
type RemediationQueueItem = NonNullable<FunctionReturnType<typeof api.remediationQueueIntel.getRemediationQueueForRepository>>["queue"][number];
type AutoRemediationRun = NonNullable<FunctionReturnType<typeof api.autoRemediationIntel.getAutoRemediationHistoryForRepository>>[number];
type DepUpdateItem = NonNullable<FunctionReturnType<typeof api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations>>["recommendations"][number];
import { AlertTriangle, Play, Wrench } from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import AutoPrDetailDrawer from "../components/panels/AutoPrDetailDrawer";
import AutoPrFeedPanel from "../components/panels/AutoPrFeedPanel";
import type { PrProposal } from "../components/panels/AutoPrFeedPanel";
import PostFixValidationDetail from "../components/panels/PostFixValidationDetail";
import PostFixValidationPanel from "../components/panels/PostFixValidationPanel";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { track } from "../lib/analytics";
import {
	formatTimestamp,
	priorityTierTone,
	severityTone,
	slaComplianceTone } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/remediation")({
	errorComponent: RouteErrorBoundary,
	component: RemediationPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function RemediationPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-40 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { repositories } = overview;
	const activeRepo = selectedRepo
		? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
		: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Wrench size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Remediation</h1>
						<p className="page-subtitle">
							Automated priority queue · SLA enforcement · Auto-fix history
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
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
					<RepoRemediationView
						tenantSlug={TENANT}
						repositoryId={activeRepo._id as Id<"repositories">}
						repositoryFullName={activeRepo.fullName}
					/>
				)}
			</div>
		</main>
	);
}

function RepoRemediationView({
	tenantSlug,
	repositoryId,
	repositoryFullName }: {
	tenantSlug: string;
	repositoryId: Id<"repositories">;
	repositoryFullName: string;
}) {
	const [activeTab, setActiveTab] = useState<"overview" | "auto-prs" | "validation">("overview");
	const [selectedPr, setSelectedPr] = useState<PrProposal | null>(null);
	const [dispatchTarget, setDispatchTarget] = useState<Id<"repositories"> | null>(null);
	const [selectedValidationRun, setSelectedValidationRun] = useState<NonNullable<
		FunctionReturnType<typeof api.postFixValidation.listValidationRunsForRepository>
	>[number] | null>(null);

	const dispatchRemediationMutation = useMutation(api.autoRemediationIntel.dispatchRemediation);
	const [isDispatchPending, setIsDispatchPending] = useState(false);
	async function dispatchRemediation(args: Parameters<typeof dispatchRemediationMutation>[0]) {
		setIsDispatchPending(true);
		try {
			return await dispatchRemediationMutation(args);
		} finally {
			setIsDispatchPending(false);
		}
	}

	const queue = useQuery(
		api.remediationQueueIntel.getRemediationQueueForRepository,
		{ repositoryId },
	);
	const autoRemediation = useQuery(
		api.autoRemediationIntel.getAutoRemediationHistoryForRepository,
		{ repositoryId },
	);
	const escalation = useQuery(
		api.escalationIntel.getEscalationSummaryForRepository,
		{ repositoryId },
	);
	const sla = useQuery(api.slaIntel.getSlaStatusForRepository, {
		repositoryId });
	const depUpdates = useQuery(
		api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations,
		{ tenantSlug, repositoryFullName },
	);
	const prProposals = useQuery(
		api.prGeneration.listGeneratedPrsForRepository,
		{ repositoryId },
	);
	const validationRuns = useQuery(
		api.postFixValidation.listValidationRunsForRepository,
		{ repositoryId },
	);

	return (
		<div className="space-y-4">
			{/* Tab bar */}
			<div className="tab-bar">
				<button
					type="button"
					className={`tab-btn ${activeTab === "overview" ? "is-active" : ""}`}
					onClick={() => setActiveTab("overview")}
				>
					Overview
				</button>
			<button
				type="button"
				className={`tab-btn ${activeTab === "auto-prs" ? "is-active" : ""}`}
				onClick={() => setActiveTab("auto-prs")}
			>
				Auto-PRs
				{prProposals && prProposals.length > 0 && (
					<span className="ml-1.5 text-[var(--sea-ink-soft)]">
						({prProposals.length})
					</span>
				)}
			</button>
			<button
				type="button"
				className={`tab-btn ${activeTab === "validation" ? "is-active" : ""}`}
				onClick={() => setActiveTab("validation")}
			>
				Validation
				{validationRuns && validationRuns.length > 0 && (
					<span className="ml-1.5 text-[var(--sea-ink-soft)]">
						({validationRuns.length})
					</span>
				)}
			</button>
			</div>

			{/* Tab: Overview (existing content) */}
			{activeTab === "overview" && (
				<div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
			{/* Left: Priority queue */}
			<div>
				{queue && queue.summary.totalCandidates > 0 && (
					<div className="mb-4">
						<div className="section-header mb-3">
							<h2 className="section-title">Priority Queue</h2>
							<StatusPill
								label={`${queue.summary.totalCandidates} items`}
								tone="neutral"
							/>
						</div>

						{/* Tier counts */}
						<div className="flex flex-wrap gap-2 mb-4">
							{queue.summary.p0Count > 0 && (
								<div className="inset-panel flex items-center gap-2">
									<StatusPill label="P0" tone="danger" />
									<span className="text-lg font-bold text-[var(--sea-ink)]">
										{queue.summary.p0Count}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										critical
									</span>
								</div>
							)}
							{queue.summary.p1Count > 0 && (
								<div className="inset-panel flex items-center gap-2">
									<StatusPill label="P1" tone="warning" />
									<span className="text-lg font-bold text-[var(--sea-ink)]">
										{queue.summary.p1Count}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										high
									</span>
								</div>
							)}
							{queue.summary.p2Count > 0 && (
								<div className="inset-panel flex items-center gap-2">
									<StatusPill label="P2" tone="info" />
									<span className="text-lg font-bold text-[var(--sea-ink)]">
										{queue.summary.p2Count}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										medium
									</span>
								</div>
							)}
							{queue.summary.p3Count > 0 && (
								<div className="inset-panel flex items-center gap-2">
									<StatusPill label="P3" tone="neutral" />
									<span className="text-lg font-bold text-[var(--sea-ink)]">
										{queue.summary.p3Count}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										low
									</span>
								</div>
							)}
						</div>

						{/* Queue items */}
						<div className="space-y-2">
							{queue.queue.map((item: RemediationQueueItem) => (
								<div key={item.findingId} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={item.priorityTier.toUpperCase()}
											tone={priorityTierTone(item.priorityTier)}
										/>
										<StatusPill
											label={item.severity}
											tone={severityTone(item.severity)}
										/>
										<StatusPill
											label={`score ${item.priorityScore.toFixed(0)}`}
											tone="neutral"
										/>
									</div>
									<h3 className="mt-1.5 text-sm font-semibold text-[var(--sea-ink)]">
										{item.title}
									</h3>
									{item.priorityRationale.length > 0 && (
										<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
											{item.priorityRationale[0]}
										</p>
									)}
									{item.slaStatus === "breached_sla" && (
										<p className="mt-0.5 text-xs text-[var(--danger)]">
											SLA breached
										</p>
									)}
								</div>
							))}
						</div>
					</div>
				)}

				{/* SLA Enforcement */}
				{sla && sla.summary.totalTracked > 0 && (
					<div className="mb-4">
						<h2 className="section-title mb-3">SLA Enforcement</h2>
						<div className="card card-sm">
							<div className="flex flex-wrap gap-2 mb-2">
								<StatusPill
									label={`${Math.round(sla.summary.complianceRate * 100)}% compliant`}
									tone={slaComplianceTone(sla.summary.complianceRate)}
								/>
								{sla.summary.breachedSla > 0 && (
									<StatusPill
										label={`${sla.summary.breachedSla} breached`}
										tone="danger"
									/>
								)}
								{sla.summary.approachingSla > 0 && (
									<StatusPill
										label={`${sla.summary.approachingSla} approaching`}
										tone="warning"
									/>
								)}
								{sla.summary.mttrHours !== null && (
									<StatusPill
										label={`MTTR ${Math.round(sla.summary.mttrHours)}h`}
										tone="neutral"
									/>
								)}
							</div>
							<p className="text-xs text-[var(--sea-ink-soft)]">
								{sla.summary.withinSla} within · {sla.summary.approachingSla}{" "}
								approaching · {sla.summary.breachedSla} breached of{" "}
								{sla.summary.totalTracked} active
							</p>
						</div>
					</div>
				)}
			</div>

			{/* Right: Auto-remediation + escalation + dependency updates */}
			<div className="space-y-4">
				{/* Auto-remediation history */}
				{autoRemediation && autoRemediation.length > 0 && (
					<div>
						<div className="flex items-center justify-between mb-3">
							<h2 className="section-title">Auto-Remediation History</h2>
							<button
								type="button"
								onClick={() => setDispatchTarget(repositoryId)}
								className="signal-button"
								style={{ padding: "0.4rem 0.75rem", fontSize: "0.75rem" }}
							>
								<Play size={13} className="mr-1" />
								Dispatch Now
							</button>
						</div>
						<div className="space-y-2">
							{autoRemediation.slice(0, 10).map((run: AutoRemediationRun) => (
								<div key={run._id} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={`${run.dispatchedCount} dispatched`}
											tone={run.dispatchedCount > 0 ? "success" : "neutral"}
										/>
										<StatusPill
											label={`${run.candidateCount} candidates`}
											tone="info"
										/>
									</div>
									<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
										Skipped: {run.skippedAlreadyHasPr} with PR ·{" "}
										{run.skippedBelowTier} below tier ·{" "}
										{run.skippedBelowSeverity} below severity
									</p>
									<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
										{formatTimestamp(run.computedAt)}
									</p>
								</div>
							))}
						</div>
					</div>
				)}

				{/* Auto-remediation dispatch (when no history yet) */}
				{(!autoRemediation || autoRemediation.length === 0) && (
					<div>
						<div className="flex items-center justify-between mb-3">
							<h2 className="section-title">Auto-Remediation</h2>
							<button
								type="button"
								onClick={() => setDispatchTarget(repositoryId)}
								className="signal-button"
								style={{ padding: "0.4rem 0.75rem", fontSize: "0.75rem" }}
							>
								<Play size={13} className="mr-1" />
								Dispatch Now
							</button>
						</div>
						<div className="card card-sm">
							<p className="text-xs text-[var(--sea-ink-soft)]">
								No auto-remediation runs yet. Click "Dispatch Now" to trigger
								automated PR generation for eligible findings.
							</p>
						</div>
					</div>
				)}

				{/* Escalation summary */}
				{escalation && (
					<div>
						<h2 className="section-title mb-3">Escalation Summary</h2>
						<div className="card card-sm">
							<div className="flex flex-wrap gap-2 mb-2">
								<StatusPill
									label={`${escalation.totalEscalations} escalated`}
									tone={escalation.totalEscalations > 0 ? "warning" : "success"}
								/>
								{escalation.uniqueFindingsEscalated > 0 && (
									<StatusPill
										label={`${escalation.uniqueFindingsEscalated} unique findings`}
										tone="danger"
									/>
								)}
							</div>
						</div>
					</div>
				)}

				{/* Dependency updates */}
				{depUpdates && depUpdates.recommendations.length > 0 && (
					<div>
						<h2 className="section-title mb-3">
							Dependency Update Recommendations
						</h2>
						<div className="space-y-2">
							{depUpdates.recommendations.slice(0, 8).map((update: DepUpdateItem) => (
								<div
									key={`${update.packageName}-${update.currentVersion}`}
									className="card card-sm"
								>
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={update.urgency}
											tone={
												update.urgency === "critical"
													? "danger"
													: update.urgency === "high"
														? "warning"
														: "neutral"
											}
										/>
										<StatusPill label={update.effort} tone="info" />
									</div>
									<p className="mt-1 text-xs font-mono font-medium text-[var(--sea-ink)]">
										{update.packageName}
									</p>
									<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
										{update.currentVersion} → {update.recommendedVersion}
									</p>
								</div>
							))}
						</div>
					</div>
				)}
			</div>
		</div>
			)}

			{/* Tab: Auto-PRs */}
			{activeTab === "auto-prs" && (
				<div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
					{/* Left: PR feed list */}
					<div>
						{prProposals ? (
							<AutoPrFeedPanel
								proposals={prProposals}
								onSelect={setSelectedPr}
								selectedId={selectedPr?._id ?? null}
								repositoryFullName={repositoryFullName}
							/>
						) : (
							<div className="card">
								<div className="flex items-center gap-2 mb-3">
									<div className="loading-panel h-4 w-24 rounded" />
								</div>
								<div className="space-y-2">
									<div className="loading-panel h-16 rounded-lg" />
									<div className="loading-panel h-16 rounded-lg" />
								</div>
							</div>
						)}
					</div>

					{/* Right: Detail drawer */}
					<div>
						{selectedPr ? (
							<AutoPrDetailDrawer
								proposal={selectedPr}
								onClose={() => setSelectedPr(null)}
							/>
						) : (
							<div className="card">
								<p className="text-xs text-[var(--sea-ink-soft)] italic">
									Select a PR from the list to view its reasoning chain,
									sandbox validation status, and available actions.
								</p>
							</div>
						)}
					</div>
				</div>
			)}

			{/* Tab: Validation */}
			{activeTab === "validation" && (
				<div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
					{/* Left: Validation runs list */}
					<div>
						<PostFixValidationPanel
							runs={validationRuns}
							onSelect={setSelectedValidationRun}
						/>
					</div>

					{/* Right: Detail */}
					<div>
						{selectedValidationRun ? (
							<PostFixValidationDetail run={selectedValidationRun} />
						) : (
							<div className="card">
								<p className="text-xs text-[var(--sea-ink-soft)] italic">
									Select a validation run from the list to view the pre/post
									diff, regression flags, and sandbox details.
								</p>
							</div>
						)}
					</div>
				</div>
		)}

		{/* §3.9 — Dispatch confirm modal */}
		{dispatchTarget && (
			<div
				onClick={(e) => { if (e.target === e.currentTarget) setDispatchTarget(null); }}
				style={{
					position: "fixed",
					inset: 0,
					zIndex: 50,
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					background: "rgba(0, 0, 0, 0.44)",
					backdropFilter: "blur(2px)" }}
			>
				<div
					className="card"
					style={{ width: "min(420px, 92vw)" }}
				>
					<div className="flex items-center gap-2 mb-4">
						<AlertTriangle size={18} className="text-[var(--warning)]" />
						<h2 className="text-sm font-bold text-[var(--sea-ink)]">
							Confirm Dispatch
						</h2>
					</div>
					<p className="text-xs text-[var(--sea-ink-soft)] mb-4">
						This will trigger auto-remediation for repository{" "}
						<span className="font-semibold text-[var(--sea-ink)]">
							{repositoryFullName}
						</span>
						. Eligible findings will be dispatched for automated PR generation
						based on the configured policy.
					</p>
					<div className="flex justify-end gap-2">
						<button
							type="button"
							onClick={() => setDispatchTarget(null)}
							className="signal-button secondary-button"
							style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
						>
							Cancel
						</button>
						<button
							type="button"
							disabled={isDispatchPending}
							onClick={async () => {
								await dispatchRemediation({ repositoryId: dispatchTarget });
								track("pr.generated", {
									repositoryName: repositoryFullName,
									fixType: "auto-remediation-batch" });
								setDispatchTarget(null);
							}}
							className="signal-button"
							style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
						>
							{isDispatchPending ? "Dispatching…" : "Dispatch"}
						</button>
					</div>
				</div>
			</div>
		)}
	</div>
	);
}
