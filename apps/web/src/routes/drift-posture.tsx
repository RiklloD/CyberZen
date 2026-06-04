import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { Activity, ShieldCheck } from "lucide-react";
import { useState } from "react";
import DriftPostureScannerGrid from "../components/panels/DriftPostureScannerGrid";
import RepositoryDriftPosturePanel from "../components/panels/RepositoryDriftPosturePanel";
import { api } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/drift-posture")({
	errorComponent: RouteErrorBoundary,
	component: DriftPosturePage,
});

function DriftPosturePage() {
	const tenantSlug = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug });
	const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="loading-panel h-48 rounded-2xl mb-4" />
				<div className="loading-panel h-72 rounded-2xl" />
			</main>
		);
	}

	const { repositories } = overview;
	const activeRepo = selectedRepoId
		? repositories.find((r: (typeof repositories)[number]) => r._id === selectedRepoId)
		: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Activity size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Drift Posture</h1>
						<p className="page-subtitle">
							Configuration drift aggregate health · {repositories.length} repositories
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{repositories.length > 1 && (
					<div className="tab-bar">
						{repositories.map((r: (typeof repositories)[number]) => (
							<button
								key={r._id}
								type="button"
								className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
								onClick={() => setSelectedRepoId(r._id)}
							>
								{r.fullName.split("/").pop()}
							</button>
						))}
					</div>
				)}

				{activeRepo ? (
					<RepositoryDriftView
						tenantSlug={tenantSlug}
						repositoryFullName={activeRepo.fullName}
					/>
				) : (
					<div className="card">
						<ShieldCheck size={24} className="mb-2 opacity-30" />
						<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
							No repositories found
						</p>
						<p className="text-sm text-[var(--sea-ink-soft)]">
							Connect a repository to begin monitoring configuration drift posture.
						</p>
					</div>
				)}
			</div>
		</main>
	);
}

function RepositoryDriftView({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const report = useQuery(api.driftPostureIntel.getLatestDriftPostureBySlug, {
		tenantSlug,
		repositoryFullName,
	});

	if (report === undefined) {
		return (
			<>
				<div className="loading-panel h-64 rounded-2xl" />
				<div className="loading-panel h-48 rounded-2xl" />
			</>
		);
	}

	if (report === null) {
		return (
			<div className="card">
				<Activity size={24} className="mb-2 opacity-30" />
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No drift posture report for {repositoryFullName}
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					This repository has not been assessed yet. Drift posture reports are
					generated after the first scan cycle completes.
				</p>
			</div>
		);
	}

	return (
		<>
			<div className="flex items-center justify-between">
				<p className="text-xs text-[var(--sea-ink-soft)]">
					Computed {formatTimestamp(report.computedAt)}
				</p>
			</div>
			<div className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
				<RepositoryDriftPosturePanel report={report} />
				<DriftPostureScannerGrid report={report} />
			</div>
		</>
	);
}
