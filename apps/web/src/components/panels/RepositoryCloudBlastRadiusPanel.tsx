import type { FunctionReturnType } from "convex/server";
import { Cloud, ShieldAlert } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type CloudBlastData = NonNullable<
	FunctionReturnType<
		typeof api.cloudBlastRadiusIntel.getCloudBlastRadiusBySlug
	>
>;

type CloudResource = CloudBlastData["reachableCloudResources"][number];

function cloudTierTone(
	tier: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (tier === "critical") return "danger";
	if (tier === "severe") return "warning";
	if (tier === "moderate") return "info";
	return "success";
}

function sensitivityTone(
	score: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (score >= 80) return "danger";
	if (score >= 60) return "warning";
	if (score >= 35) return "info";
	return "success";
}

function providerColor(provider: string): string {
	if (provider === "aws") return "text-[#ff9900]";
	if (provider === "gcp") return "text-[#4285f4]";
	if (provider === "azure") return "text-[#0078d4]";
	return "text-[var(--sea-ink-soft)]";
}

function providerBg(provider: string): string {
	if (provider === "aws") return "bg-[#ff9900]/10 border-[#ff9900]/25";
	if (provider === "gcp") return "bg-[#4285f4]/10 border-[#4285f4]/25";
	if (provider === "azure") return "bg-[#0078d4]/10 border-[#0078d4]/25";
	return "bg-[var(--line)] border-[var(--line)]";
}

function ProviderBadge({ provider }: { provider: string }) {
	const label = provider === "aws" ? "AWS" : provider === "gcp" ? "GCP" : "Azure";
	return (
		<span
			className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[0.65rem] font-bold tracking-wider uppercase ${providerBg(provider)} ${providerColor(provider)}`}
		>
			{label}
		</span>
	);
}

function ResourceFanOutNode({ resource }: { resource: CloudResource }) {
	return (
		<div className="flex items-center gap-2 py-1">
			<span
				className={`inline-block w-1.5 h-1.5 rounded-full ${
					resource.sensitivityScore >= 80
						? "bg-[var(--danger)]"
						: resource.sensitivityScore >= 60
							? "bg-[var(--warning)]"
							: "bg-[var(--teal)]"
				}`}
			/>
			<ProviderBadge provider={resource.provider} />
			<span className="text-xs font-medium text-[var(--sea-ink)]">
				{resource.label}
			</span>
			<StatusPill
				label={`${resource.sensitivityScore}`}
				tone={sensitivityTone(resource.sensitivityScore)}
			/>
		</div>
	);
}

function RiskFlag({
	active,
	label,
}: {
	active: boolean;
	label: string;
}) {
	if (!active) return null;
	return (
		<StatusPill
			label={`⚠ ${label}`}
			tone="danger"
		/>
	);
}

export default function RepositoryCloudBlastRadiusPanel({
	data,
	repositoryFullName,
}: {
	data: CloudBlastData;
	repositoryFullName: string;
}) {
	const {
		providers,
		reachableCloudResources,
		criticalResourceCount,
		iamEscalationRisk,
		dataExfiltrationRisk,
		secretsAccessRisk,
		lateralMovementRisk,
		cloudBlastScore,
		cloudRiskTier,
		cloudSummary,
	} = data;

	// Group resources by provider
	const byProvider = new Map<string, CloudResource[]>();
	for (const r of reachableCloudResources) {
		const list = byProvider.get(r.provider) ?? [];
		list.push(r);
		byProvider.set(r.provider, list);
	}

	// Sort each group by sensitivity descending
	for (const [, list] of byProvider) {
		list.sort((a, b) => b.sensitivityScore - a.sensitivityScore);
	}

	const riskFlags = [
		{ active: iamEscalationRisk, label: "IAM Escalation" },
		{ active: secretsAccessRisk, label: "Secrets Access" },
		{ active: dataExfiltrationRisk, label: "Data Exfiltration" },
		{ active: lateralMovementRisk, label: "Lateral Movement" },
	].filter((f) => f.active);

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-3 flex-wrap">
				<Cloud size={14} className="text-[var(--signal)]" />
				<h3 className="section-title">Cloud Blast Radius</h3>
				<span className="text-xs text-[var(--sea-ink-soft)]">
					{repositoryFullName}
				</span>
				<StatusPill
					label={cloudRiskTier.toUpperCase()}
					tone={cloudTierTone(cloudRiskTier)}
				/>
				<StatusPill label={`score ${cloudBlastScore}/100`} tone="neutral" />
			</div>

			{/* Provider badges */}
			{providers.length > 0 && (
				<div className="flex flex-wrap gap-1.5 mb-3">
					{providers.map((p: string) => (
						<ProviderBadge key={p} provider={p} />
					))}
					{providers.length > 1 && (
						<StatusPill label="multi-provider" tone="warning" />
					)}
				</div>
			)}

			{/* Risk flags */}
			{riskFlags.length > 0 && (
				<div className="flex flex-wrap gap-1.5 mb-3">
					<ShieldAlert size={12} className="text-[var(--danger)]" />
					{riskFlags.map((f) => (
						<RiskFlag key={f.label} active={f.active} label={f.label} />
					))}
				</div>
			)}

			{/* KPI tiles */}
			<div className="grid gap-2 grid-cols-2 sm:grid-cols-4 mb-4">
				<div className="inset-panel">
					<p className="panel-label mb-1">Cloud Resources</p>
					<div className="text-lg font-bold text-[var(--sea-ink)]">
						{reachableCloudResources.length}
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Critical Resources</p>
					<div className="text-lg font-bold text-[var(--danger)]">
						{criticalResourceCount}
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Providers</p>
					<div className="text-lg font-bold text-[var(--sea-ink)]">
						{providers.length}
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Risk Flags</p>
					<div
						className={`text-lg font-bold ${
							riskFlags.length > 0
								? "text-[var(--danger)]"
								: "text-[var(--success)]"
						}`}
					>
						{riskFlags.length}
					</div>
				</div>
			</div>

			{/* Resource fan-out graph — grouped by provider */}
			{reachableCloudResources.length > 0 && (
				<div>
					<p className="panel-label mb-2">
						Reachable Cloud Resources (fan-out)
					</p>
					<div className="space-y-3">
						{[...byProvider.entries()].map(([provider, resources]) => (
							<div key={provider}>
								<div className="flex items-center gap-1.5 mb-1">
									<ProviderBadge provider={provider} />
									<span className="text-[0.6rem] text-[var(--sea-ink-soft)] uppercase tracking-wider font-semibold">
										{resources.length} resource{resources.length !== 1 && "s"}
									</span>
								</div>
								<div className="ml-2 pl-3 border-l-2 border-[var(--line)] space-y-0.5">
									{resources.map((r) => (
										<ResourceFanOutNode
											key={`${r.provider}:${r.resourceType}`}
											resource={r}
										/>
									))}
								</div>
							</div>
						))}
					</div>
				</div>
			)}

			{/* Summary */}
			{cloudSummary && (
				<p className="mt-3 text-xs text-[var(--sea-ink-soft)]">{cloudSummary}</p>
			)}
		</div>
	);
}
