import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Eye } from "lucide-react";
import { useState } from "react";
import RepositoryZeroDayDetectionPanel from "../components/panels/RepositoryZeroDayDetectionPanel";
import ZeroDaySignalGraph from "../components/panels/ZeroDaySignalGraph";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/zero-day")({
	errorComponent: RouteErrorBoundary,
	component: ZeroDayPage });

type SummaryData = NonNullable<
	FunctionReturnType<
		typeof api.zeroDayDetectionIntel.getZeroDayDetectionSummaryByTenant
	>
>;

type RepoSummary = SummaryData["repositories"][number];

function ZeroDayPage() {
	const TENANT = useTenantSlug();
	const summary = useQuery(
		api.zeroDayDetectionIntel.getZeroDayDetectionSummaryByTenant,
		{ tenantSlug: TENANT },
	);
	const [selectedRepoIdx, setSelectedRepoIdx] = useState(0);

	if (!summary) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
					{["a", "b", "c"].map((k) => (
						<div key={k} className="loading-panel h-40 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { repositories, tenantTotals } = summary;
	const activeRepo: RepoSummary | undefined =
		repositories[selectedRepoIdx] ?? repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Eye size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Zero-Day Detection</h1>
						<p className="page-subtitle">
							Anomaly detection for novel vulnerability patterns ·{" "}
							{tenantTotals.totalFindings} total findings across{" "}
							{repositories.length} repos
						</p>
					</div>
				</div>
			</div>

			{/* Tenant-wide summary pills */}
			<div className="page-body">
				<div className="flex flex-wrap gap-2 mb-4">
					<StatusPill
						label={`${tenantTotals.totalFindings} findings`}
						tone={tenantTotals.totalFindings > 0 ? "warning" : "success"}
					/>
					{tenantTotals.criticalCount > 0 && (
						<StatusPill
							label={`${tenantTotals.criticalCount} critical`}
							tone="danger"
						/>
					)}
					{tenantTotals.highCount > 0 && (
						<StatusPill
							label={`${tenantTotals.highCount} high`}
							tone="warning"
						/>
					)}
					{tenantTotals.uninvestigatedCount > 0 && (
						<StatusPill
							label={`${tenantTotals.uninvestigatedCount} uninvestigated`}
							tone="warning"
						/>
					)}
					<StatusPill
						label={`avg anomaly ${tenantTotals.avgAnomalyScore.toFixed(0)}`}
						tone="neutral"
					/>
				</div>

				{/* Repo tabs */}
				{repositories.length > 1 && (
					<div className="tab-bar mb-4">
						{repositories.map((repo: RepoSummary, idx: number) => (
							<button
								key={repo.repositoryId}
								type="button"
								className={`tab-btn ${selectedRepoIdx === idx ? "is-active" : ""}`}
								onClick={() => setSelectedRepoIdx(idx)}
							>
								{repo.repositoryFullName.split("/").pop()}
								{repo.findingCount > 0 && (
									<StatusPill
										label={`${repo.findingCount}`}
										tone={repo.criticalCount > 0 ? "danger" : "neutral"}
									/>
								)}
							</button>
						))}
					</div>
				)}

				{activeRepo && (
					<RepoZeroDaySection
						tenantSlug={TENANT}
						repositoryFullName={activeRepo.repositoryFullName}
					/>
				)}
			</div>
		</main>
	);
}

function RepoZeroDaySection({
	tenantSlug,
	repositoryFullName }: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const detection = useQuery(
		api.zeroDayDetectionIntel.getLatestZeroDayDetectionBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const history = useQuery(
		api.zeroDayDetectionIntel.getZeroDayDetectionHistory,
		{ tenantSlug, repositoryFullName, limit: 20 },
	);

	if (!detection && history === undefined) {
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
			{/* Left: Findings list */}
			<div>
				{detection ? (
					<RepositoryZeroDayDetectionPanel
						detection={detection}
						repositoryFullName={repositoryFullName}
					/>
				) : (
					<div className="card">
						<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
							<Eye size={24} className="mb-2 opacity-40" />
							<p className="text-sm text-[var(--sea-ink-soft)]">
								No zero-day detection data available for this repository yet.
							</p>
						</div>
					</div>
				)}
			</div>

			{/* Right: Signal graph */}
			<div>
				{history && history.length > 0 ? (
					<ZeroDaySignalGraph history={history} />
				) : (
					<ZeroDaySignalGraph history={[]} />
				)}
			</div>
		</div>
	);
}
