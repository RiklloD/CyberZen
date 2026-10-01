import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Boxes, Eye, FlaskConical, GitCompare, ShieldCheck } from "lucide-react";
import HubTabs from "../components/HubTabs";
import ModelSupplyChainPanel from "../components/panels/ModelSupplyChainPanel";
import PromptInjectionRecentScansPanel from "../components/panels/PromptInjectionRecentScansPanel";
import PromptInjectionSupplyChainPanel from "../components/panels/PromptInjectionSupplyChainPanel";
import RepositoryAbandonmentPanel from "../components/panels/RepositoryAbandonmentPanel";
import RepositoryConfusionScanPanel from "../components/panels/RepositoryConfusionScanPanel";
import RepositoryCryptoWeaknessPanel from "../components/panels/RepositoryCryptoWeaknessPanel";
import RepositoryEolPanel from "../components/panels/RepositoryEolPanel";
import RepositoryMaliciousScanPanel from "../components/panels/RepositoryMaliciousScanPanel";
import SecretDetectionPanel from "../components/panels/SecretDetectionPanel";
import SupplyChainPosturePanel from "../components/panels/SupplyChainPosturePanel";
import TrafficAnomalyPanel from "../components/panels/TrafficAnomalyPanel";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import PageHeader from "../components/ui/PageHeader";
import Section from "../components/ui/Section";
import EmptyState from "../components/ui/EmptyState";
import RepoPicker, { useSelectedRepo } from "../components/ui/RepoPicker";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/supply-chain")({
	errorComponent: RouteErrorBoundary,
	component: SupplyChainPage });

const SUPPLY_CHAIN_TABS = [
	{ key: "overview", label: "Overview", icon: ShieldCheck, to: "/supply-chain" },
	{ key: "sbom", label: "SBOM", icon: Boxes, to: "/sbom" },
	{ key: "cross-repo", label: "Cross-repo", icon: GitCompare, to: "/cross-repo" },
	{ key: "zero-day", label: "Zero-day", icon: Eye, to: "/zero-day" },
	{ key: "exploit", label: "Exploit validation", icon: FlaskConical, to: "/exploit-validation" },
];

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function SupplyChainPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const repositories: OverviewRepository[] = overview?.repositories ?? [];
	const [activeRepo, selectRepo] = useSelectedRepo(repositories);

	return (
		<main>
			<PageHeader
				title="Supply chain"
				description="Typosquats, malicious and abandoned packages, end-of-life runtimes, secrets and AI model provenance"
				actions={<RepoPicker repositories={repositories} active={activeRepo} onSelect={selectRepo} />}
			/>
			<HubTabs tabs={SUPPLY_CHAIN_TABS} activeKey="overview" />

			<div className="page-body">
				{!overview ? (
					<div className="grid gap-3 sm:grid-cols-2">
						{["a", "b"].map((k) => (
							<div key={k} className="skeleton h-40" />
						))}
					</div>
				) : activeRepo ? (
					<RepoSupplyChainIntelligence
						key={activeRepo._id}
						tenantSlug={TENANT}
						repositoryFullName={activeRepo.fullName}
						repositoryId={activeRepo._id as string}
					/>
				) : (
					<div className="list">
						<EmptyState title="No repositories yet" description="Add a repository to analyse its supply chain." />
					</div>
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

	const all = [
		supplyChainPosture, promptScans, supplyChainAnalysis, confusionAttack, maliciousPackage,
		abandonment, eolDetection, cryptoWeakness, trafficAnomaly, secretDetection, modelSupplyChain,
	];
	if (all.some((q) => q === undefined)) {
		return (
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{[1, 2, 3, 4, 5, 6].map((k) => (
					<div key={k} className="skeleton h-36" />
				))}
			</div>
		);
	}
	if (all.every((q) => !q || (Array.isArray(q) && q.length === 0))) {
		return (
			<div className="list">
				<EmptyState
					icon={ShieldCheck}
					title="No supply chain intelligence yet"
					description="These checks run after the repository completes its first full scan."
				/>
			</div>
		);
	}

	const dependencyPanels = [confusionAttack, maliciousPackage, abandonment, eolDetection].some(Boolean);
	const codePanels = [cryptoWeakness, secretDetection, trafficAnomaly].some(Boolean);
	const aiPanels = !!supplyChainAnalysis || (!!promptScans && promptScans.length > 0) || !!modelSupplyChain;

	return (
		<div>
			{supplyChainPosture && (
				<div className="section">
					<SupplyChainPosturePanel data={supplyChainPosture} />
				</div>
			)}

			{dependencyPanels && (
				<Section title="Dependency risk" description="Packages that could be hijacked, are malicious, unmaintained or past end-of-life">
					<div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
						{confusionAttack && <RepositoryConfusionScanPanel data={confusionAttack} />}
						{maliciousPackage && <RepositoryMaliciousScanPanel data={maliciousPackage} />}
						{abandonment && <RepositoryAbandonmentPanel data={abandonment} />}
						{eolDetection && <RepositoryEolPanel data={eolDetection} />}
					</div>
				</Section>
			)}

			{codePanels && (
				<Section title="Code & secrets" description="Cryptography, committed credentials and runtime traffic signals">
					<div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
						{cryptoWeakness && <RepositoryCryptoWeaknessPanel data={cryptoWeakness} />}
						{secretDetection && <SecretDetectionPanel data={secretDetection} />}
						{trafficAnomaly && <TrafficAnomalyPanel data={trafficAnomaly} />}
					</div>
				</Section>
			)}

			{aiPanels && (
				<Section title="AI supply chain" description="Prompt injection in dependencies and advisories, and model provenance">
					<div className="grid gap-3 lg:grid-cols-2">
						{supplyChainAnalysis && <PromptInjectionSupplyChainPanel data={supplyChainAnalysis} />}
						{promptScans && promptScans.length > 0 && <PromptInjectionRecentScansPanel scans={promptScans} />}
					</div>
					{modelSupplyChain && (
						<div className="mt-3">
							<ModelSupplyChainPanel scan={modelSupplyChain} />
						</div>
					)}
				</Section>
			)}
		</div>
	);
}
