import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { Boxes, Eye, FlaskConical, GitCompare, ShieldCheck } from "lucide-react";
import HubTabs from "../components/HubTabs";
import TenantCrossRepoPanel from "../components/panels/TenantCrossRepoPanel";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/cross-repo")({
	errorComponent: RouteErrorBoundary,
	component: CrossRepoPage });

const SUPPLY_CHAIN_TABS = [
	{ key: "overview", label: "Supply Chain", icon: ShieldCheck, to: "/supply-chain" },
	{ key: "sbom", label: "SBOM", icon: Boxes, to: "/sbom" },
	{ key: "cross-repo", label: "Cross-Repo", icon: GitCompare, to: "/cross-repo" },
	{ key: "zero-day", label: "Zero-Day", icon: Eye, to: "/zero-day" },
	{ key: "exploit", label: "Exploit Validation", icon: FlaskConical, to: "/exploit-validation" },
];

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
			<HubTabs tabs={SUPPLY_CHAIN_TABS} activeKey="cross-repo" />

			<div className="page-body">
				<TenantCrossRepoPanel summary={summary} />
			</div>
		</main>
	);
}
