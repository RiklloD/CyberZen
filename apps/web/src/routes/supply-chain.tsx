import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import ModelSupplyChainPanel from "../components/panels/ModelSupplyChainPanel";
import PromptInjectionRecentScansPanel from "../components/panels/PromptInjectionRecentScansPanel";
import PromptInjectionSupplyChainPanel from "../components/panels/PromptInjectionSupplyChainPanel";
import RepositoryAbandonmentPanel from "../components/panels/RepositoryAbandonmentPanel";
import RepositoryConfusionScanPanel from "../components/panels/RepositoryConfusionScanPanel";
import RepositoryCryptoWeaknessPanel from "../components/panels/RepositoryCryptoWeaknessPanel";
import RepositoryEolPanel from "../components/panels/RepositoryEolPanel";
import RepositoryMaliciousScanPanel from "../components/panels/RepositoryMaliciousScanPanel";
import SecretDetectionPanel from "../components/panels/SecretDetectionPanel";
import SupplyChainOverviewHeader from "../components/panels/SupplyChainOverviewHeader";
import SupplyChainPosturePanel from "../components/panels/SupplyChainPosturePanel";
import TrafficAnomalyPanel from "../components/panels/TrafficAnomalyPanel";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/supply-chain")({
	errorComponent: RouteErrorBoundary,
	component: SupplyChainPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function SupplyChainPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
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
			<SupplyChainOverviewHeader />

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
					<RepoSupplyChainIntelligence
						tenantSlug={TENANT}
						repositoryFullName={activeRepo.fullName}
						repositoryId={activeRepo._id as string}
					/>
				)}
			</div>
		</main>
	);
}

function RepoSupplyChainIntelligence({
	tenantSlug,
	repositoryFullName,
	repositoryId }: {
	tenantSlug: string;
	repositoryFullName: string;
	repositoryId: string;
}) {
	const supplyChainPosture = useQuery(
		api.supplyChainPostureIntel.getLatestSupplyChainPosture,
		{ tenantSlug, repositoryFullName },
	);
	const promptScans = useQuery(api.promptIntelligence.recentScans, {
		tenantSlug,
		repositoryFullName,
		limit: 10 });
	const supplyChainAnalysis = useQuery(
		api.promptIntelligence.supplyChainAnalysis,
		{ tenantSlug, repositoryFullName },
	);
	const confusionAttack = useQuery(
		api.confusionAttackIntel.getLatestConfusionScan,
		{ tenantSlug, repositoryFullName },
	);
	const maliciousPackage = useQuery(
		api.maliciousPackageIntel.getLatestMaliciousScan,
		{ tenantSlug, repositoryFullName },
	);
	const abandonment = useQuery(
		api.abandonmentScanIntel.getLatestAbandonmentScan,
		{ tenantSlug, repositoryFullName },
	);
	const eolDetection = useQuery(api.eolDetectionIntel.getLatestEolScan, {
		tenantSlug,
		repositoryFullName });
	const cryptoWeakness = useQuery(
		api.cryptoWeaknessIntel.getLatestCryptoWeaknessScan,
		{ tenantSlug, repositoryFullName },
	);
	const trafficAnomaly = useQuery(
		api.trafficAnomalyIntel.getLatestTrafficAnomaly,
		{ tenantSlug, repositoryFullName },
	);
	const secretDetection = useQuery(
		api.secretDetectionIntel.getLatestSecretScan,
		{ tenantSlug, repositoryFullName },
	);
	const modelSupplyChain = useQuery(
		api.modelSupplyChainIntel.getLatestModelScan,
		{ repositoryId: repositoryId as any },
	);

	return (
		<div className="space-y-4">
			{/* Supply chain posture */}
			{supplyChainPosture && (
				<SupplyChainPosturePanel data={supplyChainPosture} />
			)}

			{/* Prompt Injection + Supply Chain Analysis */}
			<div className="grid gap-4 sm:grid-cols-2">
				{supplyChainAnalysis && (
					<PromptInjectionSupplyChainPanel data={supplyChainAnalysis} />
				)}

				{promptScans && promptScans.length > 0 && (
					<PromptInjectionRecentScansPanel scans={promptScans} />
				)}
			</div>

			{/* Dependency health grid */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{confusionAttack && (
					<RepositoryConfusionScanPanel data={confusionAttack} />
				)}

				{maliciousPackage && (
					<RepositoryMaliciousScanPanel data={maliciousPackage} />
				)}

				{abandonment && (
					<RepositoryAbandonmentPanel data={abandonment} />
				)}

				{eolDetection && (
					<RepositoryEolPanel data={eolDetection} />
				)}

				{cryptoWeakness && (
					<RepositoryCryptoWeaknessPanel data={cryptoWeakness} />
				)}

				{trafficAnomaly && (
					<TrafficAnomalyPanel data={trafficAnomaly} />
				)}

				{secretDetection && (
					<SecretDetectionPanel data={secretDetection} />
				)}
			</div>

			{/* Model Supply Chain panel */}
				{modelSupplyChain && (
					<ModelSupplyChainPanel scan={modelSupplyChain} />
				)}

				{/* Empty state — no scan data for this repo yet */}
				{!supplyChainPosture && !supplyChainAnalysis && (!promptScans || promptScans.length === 0) &&
					!confusionAttack && !maliciousPackage && !abandonment && !eolDetection &&
					!cryptoWeakness && !trafficAnomaly && !secretDetection && !modelSupplyChain && (
					<div className="empty-state">
						<ShieldCheck size={20} className="mb-2 opacity-30" />
						<p>No supply chain intelligence available yet.</p>
						<p className="text-xs mt-1">
							Supply chain panels appear after the repository completes its first scan cycle.
						</p>
					</div>
				)}
			</div>
	);
}
