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
import PosturePillarBreakdown from "../components/panels/PosturePillarBreakdown";
import SecurityPostureSummaryPanel from "../components/panels/SecurityPostureSummaryPanel";
import { api } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/posture")({
	errorComponent: RouteErrorBoundary,
	component: SecurityPosturePage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function SecurityPosturePage() {
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
	const activeRepo: OverviewRepository | undefined = selectedRepoId
		? repositories.find((r: OverviewRepository) => r._id === selectedRepoId)
		: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<ShieldCheck size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Security Posture</h1>
						<p className="page-subtitle">
							Aggregate posture score · {repositories.length} repositories
						</p>
					</div>
				</div>
			</div>

			<HubTabs tabs={REPORTS_TABS} activeKey="posture" />

			<div className="page-body space-y-6">
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

				{activeRepo ? (
					<RepositoryPostureView
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
							Connect a repository to begin measuring security posture.
						</p>
					</div>
				)}
			</div>
		</main>
	);
}

function RepositoryPostureView({
	tenantSlug,
	repositoryFullName }: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const report = useQuery(api.securityPosture.getSecurityPostureReport, {
		tenantSlug,
		repositoryFullName });

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
				<ShieldCheck size={24} className="mb-2 opacity-30" />
				<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					No posture report for {repositoryFullName}
				</p>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					This repository has not been assessed yet. Posture reports are
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
			<div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
				<SecurityPostureSummaryPanel report={report} />
				<PosturePillarBreakdown report={report} />
			</div>
		</>
	);
}
