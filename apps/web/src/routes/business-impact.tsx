import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { BarChart3, Briefcase, ClipboardCheck, ShieldCheck, Trophy } from "lucide-react";
import HubTabs from "../components/HubTabs";

const REPORTS_TABS = [
	{ key: "posture", label: "Security Posture", icon: ShieldCheck, to: "/posture" },
	{ key: "executive", label: "Executive Report", icon: BarChart3, to: "/executive-report" },
	{ key: "maturity", label: "Maturity Assessment", icon: Trophy, to: "/maturity" },
	{ key: "business-impact", label: "Business Impact", icon: Briefcase, to: "/business-impact" },
	{ key: "compliance", label: "Compliance", icon: ClipboardCheck, to: "/compliance" },
];
import { useState } from "react";
import RepositoryBusinessImpactPanel from "../components/panels/RepositoryBusinessImpactPanel";
import TenantBusinessImpactSummary from "../components/panels/TenantBusinessImpactSummary";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { useTenantSlug, useWorkspaceState } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/business-impact")({
	errorComponent: RouteErrorBoundary,
	component: BusinessImpactPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function BusinessImpactPage() {
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
					<Briefcase size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Business Impact</h1>
						<p className="page-subtitle">
							Five-dimension exposure model · financial · regulatory · brand ·
							operational · customer
						</p>
					</div>
				</div>
			</div>

			<HubTabs tabs={REPORTS_TABS} activeKey="business-impact" />

			<div className="page-body space-y-6">
				{tenantId && <TenantBusinessImpactSummaryView tenantId={tenantId} />}

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
					<RepositoryBusinessImpactView
						tenantSlug={tenantSlug}
						repositoryFullName={activeRepo.fullName}
					/>
				)}
			</div>
		</main>
	);
}

function TenantBusinessImpactSummaryView({
	tenantId }: {
	tenantId: Id<"tenants">;
}) {
	const summary = useQuery(
		api.businessImpactIntel.getBusinessImpactSummaryByTenant,
		{ tenantId },
	);

	if (!summary) return <div className="loading-panel h-48 rounded-2xl" />;

	if (summary.assessedRepositories === 0) {
		return (
			<div className="card">
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No business impact assessments yet
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					Business impact is computed automatically after a repository's first
					scan cycle. Once findings and blast-radius data are present, the
					five-dimension model populates this view.
				</p>
			</div>
		);
	}

	return (
		<TenantBusinessImpactSummary
			totalRepositories={summary.totalRepositories}
			assessedRepositories={summary.assessedRepositories}
			levelDistribution={summary.levelDistribution}
			averageScore={summary.averageScore}
		/>
	);
}

function RepositoryBusinessImpactView({
	tenantSlug,
	repositoryFullName }: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const impact = useQuery(
		api.businessImpactIntel.getLatestBusinessImpactBySlug,
		{ tenantSlug, repositoryFullName },
	);

	if (impact === undefined)
		return <div className="loading-panel h-72 rounded-2xl" />;

	if (impact === null) {
		return (
			<div className="card">
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No business impact for {repositoryFullName}
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					Business impact runs after the repository's first scan cycle. Trigger
					a scan or wait for the next cycle to populate this view.
				</p>
			</div>
		);
	}

	return (
		<RepositoryBusinessImpactPanel
			impact={impact}
			repositoryFullName={repositoryFullName}
		/>
	);
}
