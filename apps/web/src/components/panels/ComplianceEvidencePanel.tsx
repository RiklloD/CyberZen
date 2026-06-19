import type { FunctionReturnType } from "convex/server";
import { Download, Filter, FolderArchive } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatDate } from "../../lib/utils";
import EvidenceArtifactCard from "./EvidenceArtifactCard";

type AllEvidence = NonNullable<
	FunctionReturnType<
		typeof api.complianceEvidenceIntel.getAllFrameworkEvidence
	>
>;

type Bundle = AllEvidence["bundles"][number];

const FRAMEWORKS = [
	{ key: "all", label: "All" },
	{ key: "SOC2", label: "SOC 2" },
	{ key: "PCI_DSS", label: "PCI-DSS" },
	{ key: "HIPAA", label: "HIPAA" },
	{ key: "GDPR", label: "GDPR" },
	{ key: "NIS2", label: "NIS2" },
] as const;

type FrameworkKey = (typeof FRAMEWORKS)[number]["key"];

function bundleStatusTone(
	status: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (status === "complete") return "success";
	if (status === "partial") return "warning";
	if (status === "missing") return "danger";
	return "neutral";
}

function handleBulkExport(bundles: Bundle[]) {
	const flat = bundles.flatMap((b) => b.artifacts);
	const blob = new Blob([JSON.stringify(flat, null, 2)], {
		type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = `compliance-evidence-${Date.now()}.json`;
	a.click();
	URL.revokeObjectURL(url);
}

export interface ComplianceEvidencePanelProps {
	evidence: AllEvidence;
}

export default function ComplianceEvidencePanel({
	evidence }: ComplianceEvidencePanelProps) {
	const [frameworkFilter, setFrameworkFilter] = useState<FrameworkKey>("all");

	const filteredBundles: Bundle[] =
		frameworkFilter === "all"
			? evidence.bundles
			: evidence.bundles.filter((b: Bundle) => b.framework === frameworkFilter);

	const totalArtifacts = filteredBundles.reduce(
		(sum: number, b: Bundle) => sum + b.artifacts.length,
		0,
	);
	const collectedCount = filteredBundles.reduce(
		(sum: number, b: Bundle) =>
			sum + b.artifacts.filter((a: Bundle["artifacts"][number]) => a.status === "collected").length,
		0,
	);
	const missingCount = filteredBundles.reduce(
		(sum: number, b: Bundle) =>
			sum + b.artifacts.filter((a: Bundle["artifacts"][number]) => a.status === "missing").length,
		0,
	);
	const staleCount = filteredBundles.reduce(
		(sum: number, b: Bundle) =>
			sum + b.artifacts.filter((a: Bundle["artifacts"][number]) => a.status === "stale").length,
		0,
	);

	return (
		<div className="space-y-4">
			{/* Header row */}
			<div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
				<div className="flex items-center gap-2">
					<FolderArchive
						size={16}
						className="text-[var(--signal)]"
					/>
					<h3 className="section-title">Evidence Collection</h3>
					<StatusPill
						label={`${totalArtifacts} artifacts`}
						tone="neutral"
					/>
				</div>

				<button
					type="button"
					onClick={() => handleBulkExport(filteredBundles)}
					className="signal-button secondary-button text-xs"
				>
					<Download size={12} className="inline -mt-0.5 mr-1" />
					Bulk Export
				</button>
			</div>

			{/* Summary stats */}
			<div className="grid gap-2 sm:grid-cols-4">
				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Total
					</div>
					<div className="text-lg font-bold text-[var(--sea-ink)]">
						{totalArtifacts}
					</div>
				</div>
				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Collected
					</div>
					<div className="text-lg font-bold text-[var(--success)]">
						{collectedCount}
					</div>
				</div>
				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Stale
					</div>
					<div className="text-lg font-bold text-[var(--warning)]">
						{staleCount}
					</div>
				</div>
				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Missing
					</div>
					<div className="text-lg font-bold text-[var(--danger)]">
						{missingCount}
					</div>
				</div>
			</div>

			{/* Framework filter */}
			<div className="flex items-center gap-2 flex-wrap">
				<Filter
					size={14}
					className="text-[var(--sea-ink-soft)]"
				/>
				{FRAMEWORKS.map((fw) => (
					<button
						key={fw.key}
						type="button"
						className={`tab-btn ${frameworkFilter === fw.key ? "is-active" : ""}`}
						onClick={() => setFrameworkFilter(fw.key)}
					>
						{fw.label}
					</button>
				))}
			</div>

			{/* Bundle list */}
			{filteredBundles.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl py-8 text-center">
					<FolderArchive
						size={24}
						className="mx-auto mb-2 opacity-40"
					/>
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No evidence bundles found for the selected framework.
					</p>
				</div>
			)}

			{filteredBundles.map((bundle) => (
				<div key={bundle.framework} className="card">
					<div className="flex items-center gap-2 mb-3 flex-wrap">
						<h4 className="text-sm font-bold text-[var(--sea-ink)]">
							{bundle.framework.replace(/_/g, " ")}
						</h4>
						<StatusPill
							label={bundle.status.replace(/_/g, " ")}
							tone={bundleStatusTone(bundle.status)}
						/>
						<StatusPill
							label={`${bundle.artifacts.length} artifacts`}
							tone="neutral"
						/>
						{bundle.lastUpdated && (
							<span className="text-xs text-[var(--sea-ink-soft)] ml-auto">
								Updated {formatDate(bundle.lastUpdated)}
							</span>
						)}
					</div>

					{bundle.summary && (
						<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
							{bundle.summary}
						</p>
					)}

					<div className="space-y-2">
						{bundle.artifacts.map((artifact: Bundle["artifacts"][number]) => (
							<EvidenceArtifactCard
								key={artifact.controlId}
								artifact={artifact}
							/>
						))}
					</div>
				</div>
			))}

			{evidence.summary && (
				<p className="text-xs text-[var(--sea-ink-soft)]">
					{evidence.summary}
				</p>
			)}
		</div>
	);
}
