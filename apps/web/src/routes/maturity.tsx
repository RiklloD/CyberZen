import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Award } from "lucide-react";
import { useState } from "react";
import MaturityProgressionTimeline from "../components/panels/MaturityProgressionTimeline";
import RepositoryMaturityPanel from "../components/panels/RepositoryMaturityPanel";
import TenantMaturityRadar from "../components/panels/TenantMaturityRadar";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { useTenantSlug, useWorkspaceState } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/maturity")({
	errorComponent: RouteErrorBoundary,
	component: MaturityPage,
});

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function MaturityPage() {
	const tenantSlug = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug });
	const workspace = useWorkspaceState();
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
	const tenantId = workspace?.tenant._id as Id<"tenants"> | undefined;
	const activeRepo: OverviewRepository | undefined = selectedRepoId
		? repositories.find((r: OverviewRepository) => r._id === selectedRepoId)
		: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Award size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Maturity Assessment</h1>
						<p className="page-subtitle">
							CMMI 5-level security program maturity ·{" "}
							{repositories.length} repositories
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{tenantId && <TenantMaturitySummary tenantId={tenantId} />}

				{repositories.length > 1 && (
					<div className="tab-bar">
						{repositories.map((r: OverviewRepository) => (
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

				{activeRepo && (
					<RepositoryMaturityView
						tenantSlug={tenantSlug}
						repositoryFullName={activeRepo.fullName}
					/>
				)}
			</div>
		</main>
	);
}

function TenantMaturitySummary({
	tenantId,
}: {
	tenantId: Id<"tenants">;
}) {
	const summary = useQuery(
		api.maturityAssessmentIntel.getMaturityAssessmentSummaryByTenant,
		{ tenantId },
	);

	if (!summary) {
		return <div className="loading-panel h-48 rounded-2xl" />;
	}

	if (summary.assessedRepositories === 0) {
		return (
			<div className="card">
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No maturity assessments yet
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					Maturity assessments are triggered automatically after a repository
					completes its first scan cycle. Once any of your{" "}
					{summary.totalRepositories} repositories produce findings, this view
					will populate.
				</p>
			</div>
		);
	}

	return (
		<TenantMaturityRadar
			totalRepositories={summary.totalRepositories}
			assessedRepositories={summary.assessedRepositories}
			levelDistribution={summary.levelDistribution}
			averageScore={summary.averageScore}
		/>
	);
}

function RepositoryMaturityView({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const assessment = useQuery(
		api.maturityAssessmentIntel.getLatestMaturityAssessmentBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const history = useQuery(
		api.maturityAssessmentIntel.getMaturityAssessmentHistory,
		assessment ? { repositoryId: assessment.repositoryId } : "skip",
	);

	if (assessment === undefined) {
		return <div className="loading-panel h-72 rounded-2xl" />;
	}

	if (assessment === null) {
		return (
			<div className="card">
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No assessment for {repositoryFullName}
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					This repository has not been assessed yet. Maturity assessments run
					after the repository's first scan cycle.
				</p>
			</div>
		);
	}

	return (
		<div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
			<RepositoryMaturityPanel
				assessment={assessment}
				repositoryFullName={repositoryFullName}
			/>
			<MaturityProgressionTimeline history={history ?? []} />
		</div>
	);
}
