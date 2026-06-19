import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { GitCompare } from "lucide-react";
import TenantCrossRepoPanel from "../components/panels/TenantCrossRepoPanel";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/cross-repo")({
	errorComponent: RouteErrorBoundary,
	component: CrossRepoPage });

function CrossRepoPage() {
	const TENANT = useTenantSlug();
	const summary = useQuery(api.crossRepoIntel.getTenantCrossRepoSummaryBySlug, {
		tenantSlug: TENANT });

	if (!summary) {
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

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<GitCompare size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Cross-Repo Exposure</h1>
						<p className="page-subtitle">
							Lateral vulnerability spread across repositories ·{" "}
							{summary.totalPackagesTracked} packages tracked ·{" "}
							{summary.packagesWithSpread} with cross-repo spread
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<TenantCrossRepoPanel summary={summary} />
			</div>
		</main>
	);
}
