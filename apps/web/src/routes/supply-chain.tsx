import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Link2 } from "lucide-react";
import { useState } from "react";
import { api } from "../../convex/_generated/api";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	injectionRiskTone,
	supplyChainRiskTone,
} from "../lib/utils";

export const Route = createFileRoute("/supply-chain")({ component: SupplyChainPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function SupplyChainPage() {
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
	const activeRepo =
		selectedRepo
			? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
			: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Link2 size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Supply Chain</h1>
						<p className="page-subtitle">
							Supply chain posture, prompt injection risk, and dependency health
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
					<RepoSupplyChainIntelligence
						tenantSlug={TENANT}
						repositoryFullName={activeRepo.fullName}
					/>
				)}
			</div>
		</main>
	);
}

function RepoSupplyChainIntelligence({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const supplyChainPosture = useQuery(
		api.supplyChainPostureIntel.getLatestSupplyChainPosture,
		{ tenantSlug, repositoryFullName },
	);
	const promptScans = useQuery(api.promptIntelligence.recentScans, {
		tenantSlug,
		repositoryFullName,
		limit: 10,
	});
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
	const eolDetection = useQuery(
		api.eolDetectionIntel.getLatestEolScan,
		{ tenantSlug, repositoryFullName },
	);
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

	return (
		<div className="space-y-4">
			{/* Supply chain posture */}
			{supplyChainPosture && (
				<div className="card">
					<p className="panel-label mb-2">Supply Chain Posture</p>
					<div className="flex flex-wrap gap-2">
					<StatusPill
						label={supplyChainPosture.riskLevel}
						tone={supplyChainRiskTone(supplyChainPosture.riskLevel)}
					/>
					<StatusPill
						label={`score ${supplyChainPosture.score.toFixed(0)}`}
						tone="neutral"
					/>
					<StatusPill
						label={`grade ${supplyChainPosture.grade}`}
						tone="neutral"
					/>
					</div>
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
						{supplyChainPosture.summary}
					</p>
				</div>
			)}

			{/* Prompt Injection + Supply Chain Analysis */}
			<div className="grid gap-4 sm:grid-cols-2">
				{supplyChainAnalysis && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Supply Chain Risk Analysis</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={supplyChainAnalysis.riskLevel}
								tone={supplyChainRiskTone(supplyChainAnalysis.riskLevel)}
							/>
							<StatusPill
								label={`score ${supplyChainAnalysis.overallRiskScore.toFixed(0)}`}
								tone="neutral"
							/>
							{supplyChainAnalysis.typosquatCandidates.length > 0 && (
								<StatusPill
									label={`${supplyChainAnalysis.typosquatCandidates.length} typosquat candidates`}
									tone="danger"
								/>
							)}
						</div>
						<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
							{supplyChainAnalysis.summary}
						</p>
						{supplyChainAnalysis.flaggedComponents.slice(0, 3).map((c) => (
							<div
								key={`${c.name}-${c.version}`}
								className="mt-2 flex flex-wrap items-center gap-1.5"
							>
								<StatusPill
									label={`${c.name}@${c.version}`}
									tone={supplyChainRiskTone(c.riskLevel)}
								/>
								<StatusPill
									label={c.isDirect ? "direct" : "transitive"}
									tone="neutral"
								/>
							</div>
						))}
					</div>
				)}

				{promptScans && promptScans.length > 0 && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Prompt Injection Scans</p>
						<div className="flex flex-wrap gap-1.5 mb-2">
							<StatusPill label={`${promptScans.length} scans`} tone="neutral" />
							{promptScans.some(
								(s) =>
									s.riskLevel === "confirmed_injection" ||
									s.riskLevel === "likely_injection",
							) ? (
								<StatusPill label="injection detected" tone="danger" />
							) : promptScans.some((s) => s.riskLevel === "suspicious") ? (
								<StatusPill label="suspicious" tone="warning" />
							) : (
								<StatusPill label="all clear" tone="success" />
							)}
						</div>
						{promptScans.map((scan) => (
							<div key={scan._id} className="flex flex-wrap items-center gap-1.5 mt-1">
								<StatusPill
									label={scan.riskLevel.replace(/_/g, " ")}
									tone={injectionRiskTone(scan.riskLevel)}
								/>
								<StatusPill label={scan.contentRef} tone="neutral" />
								<StatusPill
									label={`score ${scan.score}`}
									tone={
										scan.score > 50 ? "danger" : scan.score > 20 ? "warning" : "success"
									}
								/>
							</div>
						))}
					</div>
				)}
			</div>

			{/* Dependency health grid */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{confusionAttack && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Confusion Attack</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={confusionAttack.overallRisk}
							tone={supplyChainRiskTone(confusionAttack.overallRisk)}
						/>
						{confusionAttack.totalSuspicious > 0 && (
							<StatusPill
								label={`${confusionAttack.totalSuspicious} suspicious`}
								tone="danger"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{confusionAttack.summary}
						</p>
					</div>
				)}

				{maliciousPackage && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Malicious Package Scan</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={maliciousPackage.overallRisk}
							tone={supplyChainRiskTone(maliciousPackage.overallRisk)}
						/>
						{maliciousPackage.totalSuspicious > 0 && (
							<StatusPill
								label={`${maliciousPackage.totalSuspicious} suspicious`}
								tone="danger"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{maliciousPackage.summary}
						</p>
					</div>
				)}

				{abandonment && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Abandonment Scan</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`${abandonment.totalAbandoned} abandoned`}
							tone={abandonment.totalAbandoned > 0 ? "danger" : "success"}
						/>
						{abandonment.highCount > 0 && (
							<StatusPill
								label={`${abandonment.highCount} high risk`}
								tone="warning"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{abandonment.summary}
						</p>
					</div>
				)}

				{eolDetection && (
					<div className="card card-sm">
						<p className="panel-label mb-2">End-of-Life Detection</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={`${eolDetection.eolCount} EOL`}
								tone={eolDetection.eolCount > 0 ? "danger" : "success"}
							/>
							{eolDetection.nearEolCount > 0 && (
								<StatusPill
									label={`${eolDetection.nearEolCount} near EOL`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{eolDetection.summary}
						</p>
					</div>
				)}

				{cryptoWeakness && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Crypto Weakness</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={cryptoWeakness.overallRisk}
							tone={supplyChainRiskTone(cryptoWeakness.overallRisk)}
						/>
						{cryptoWeakness.criticalCount > 0 && (
							<StatusPill
								label={`${cryptoWeakness.criticalCount} critical`}
								tone="danger"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{cryptoWeakness.summary}
						</p>
					</div>
				)}

				{trafficAnomaly && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Traffic Anomaly</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={trafficAnomaly.level}
						tone={
							trafficAnomaly.level === "critical" ? "danger" :
							trafficAnomaly.level === "suspicious" ? "warning" :
							trafficAnomaly.level === "anomalous" ? "info" : "success"
						}
						/>
						{trafficAnomaly.patterns.length > 0 && (
							<StatusPill
								label={`${trafficAnomaly.patterns.length} patterns`}
								tone="warning"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{trafficAnomaly.summary}
						</p>
					</div>
				)}

				{secretDetection && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Secret Detection</p>
						<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={`${secretDetection.totalFound} secrets found`}
							tone={secretDetection.totalFound > 0 ? "danger" : "success"}
						/>
						{secretDetection.criticalCount > 0 && (
							<StatusPill
								label={`${secretDetection.criticalCount} critical`}
								tone="danger"
							/>
						)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{secretDetection.summary}
						</p>
					</div>
				)}
			</div>
		</div>
	);
}
