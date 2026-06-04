import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Wrench } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import type { Id } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	formatTimestamp,
	priorityTierTone,
	slaComplianceTone,
	severityTone,
} from "../lib/utils";

export const Route = createFileRoute("/remediation")({ component: RemediationPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function RemediationPage() {
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
	const activeRepo =
		selectedRepo
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
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryId: Id<"repositories">;
	repositoryFullName: string;
}) {
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
		repositoryId,
	});
	const depUpdates = useQuery(
		api.dependencyUpdateIntel.getLatestDependencyUpdateRecommendations,
		{ tenantSlug, repositoryFullName },
	);

	return (
		<div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
			{/* Left: Priority queue */}
			<div>
			{queue && queue.summary.totalCandidates > 0 && (
				<div className="mb-4">
					<div className="section-header mb-3">
						<h2 className="section-title">Priority Queue</h2>
						<StatusPill label={`${queue.summary.totalCandidates} items`} tone="neutral" />
					</div>

					{/* Tier counts */}
					<div className="flex flex-wrap gap-2 mb-4">
						{queue.summary.p0Count > 0 && (
							<div className="inset-panel flex items-center gap-2">
								<StatusPill label="P0" tone="danger" />
								<span className="text-lg font-bold text-[var(--sea-ink)]">
									{queue.summary.p0Count}
								</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">critical</span>
							</div>
						)}
						{queue.summary.p1Count > 0 && (
							<div className="inset-panel flex items-center gap-2">
								<StatusPill label="P1" tone="warning" />
								<span className="text-lg font-bold text-[var(--sea-ink)]">
									{queue.summary.p1Count}
								</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">high</span>
							</div>
						)}
						{queue.summary.p2Count > 0 && (
							<div className="inset-panel flex items-center gap-2">
								<StatusPill label="P2" tone="info" />
								<span className="text-lg font-bold text-[var(--sea-ink)]">
									{queue.summary.p2Count}
								</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">medium</span>
							</div>
						)}
						{queue.summary.p3Count > 0 && (
							<div className="inset-panel flex items-center gap-2">
								<StatusPill label="P3" tone="neutral" />
								<span className="text-lg font-bold text-[var(--sea-ink)]">
									{queue.summary.p3Count}
								</span>
								<span className="text-xs text-[var(--sea-ink-soft)]">low</span>
							</div>
						)}
					</div>

					{/* Queue items */}
					<div className="space-y-2">
						{queue.queue.map((item) => (
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
								{sla.summary.withinSla} within · {sla.summary.approachingSla} approaching ·{" "}
								{sla.summary.breachedSla} breached of {sla.summary.totalTracked} active
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
					<h2 className="section-title mb-3">Auto-Remediation History</h2>
					<div className="space-y-2">
						{autoRemediation.slice(0, 10).map((run) => (
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
									Skipped: {run.skippedAlreadyHasPr} with PR · {run.skippedBelowTier} below tier · {run.skippedBelowSeverity} below severity
								</p>
								<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
									{formatTimestamp(run.computedAt)}
								</p>
							</div>
						))}
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
					<h2 className="section-title mb-3">Dependency Update Recommendations</h2>
					<div className="space-y-2">
						{depUpdates.recommendations.slice(0, 8).map((update) => (
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
	);
}

