import type { FunctionReturnType } from "convex/server";
import {
	Fingerprint,
	GitBranch,
	CheckCircle2,
	AlertTriangle,
	ShieldCheck,
	XCircle } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type ProvenanceScan = NonNullable<
	FunctionReturnType<
		typeof api.modelProvenanceIntel.getLatestModelProvenance
	>
>;

type ModelComponent = ProvenanceScan["components"][number];

function riskTone(
	riskLevel: string,
): "success" | "warning" | "danger" | "neutral" {
	if (riskLevel === "verified") return "success";
	if (riskLevel === "acceptable") return "neutral";
	if (riskLevel === "risky") return "danger";
	if (riskLevel === "unverified") return "warning";
	return "neutral";
}

function signalIcon(kind?: string) {
	if (!kind) return <ShieldCheck size={12} className="text-[var(--success)]" />;
	if (kind.includes("hash") || kind.includes("weights"))
		return <Fingerprint size={12} className="text-[var(--signal)]" />;
	if (kind.includes("license"))
		return <AlertTriangle size={12} className="text-[var(--warning)]" />;
	return <GitBranch size={12} className="text-[var(--sea-ink-soft)]" />;
}

function scoreBar(score: number) {
	const pct = Math.min(100, Math.max(0, score));
	const color =
		pct >= 80
			? "var(--success)"
			: pct >= 50
				? "var(--warning)"
				: "var(--danger)";
	return (
		<div className="w-full h-1.5 rounded-full bg-[rgba(130,122,110,0.12)] overflow-hidden">
			<div
				className="h-full rounded-full transition-all duration-300"
				style={{ width: `${pct}%`, backgroundColor: color }}
			/>
		</div>
	);
}

function ModelComponentRow({ component }: { component: ModelComponent }) {
	return (
		<div className="card card-sm">
			<div className="flex items-start justify-between gap-2 mb-1.5">
				<div className="min-w-0">
					<h4 className="text-sm font-semibold text-[var(--sea-ink)] truncate">
						{component.name}
					</h4>
					<p className="text-xs text-[var(--sea-ink-soft)] truncate">
						{component.resolvedSource}
					</p>
				</div>
				<StatusPill label={component.riskLevel} tone={riskTone(component.riskLevel)} />
			</div>

			{/* Provenance score bar */}
			<div className="mt-2 flex items-center gap-2">
				<span className="text-xs text-[var(--sea-ink-soft)] shrink-0">Score</span>
				<div className="flex-1">{scoreBar(component.provenanceScore)}</div>
				<span className="text-xs font-medium text-[var(--sea-ink)] shrink-0">
					{component.provenanceScore.toFixed(0)}
				</span>
			</div>

			{/* Metadata chain: model → hash/source → license */}
			<div className="mt-2 flex flex-wrap gap-1.5">
				{component.topSignalKind && (
					<span className="inline-flex items-center gap-1 text-xs text-[var(--sea-ink-soft)]">
						{signalIcon(component.topSignalKind)}
						{component.topSignalKind}
					</span>
				)}
				<StatusPill label={component.resolvedLicense || "Unknown license"} tone="neutral" />
			</div>

			{component.summary && (
				<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{component.summary}</p>
			)}
		</div>
	);
}

export default function ModelProvenancePanel({
	scan }: {
	scan: ProvenanceScan;
}) {
	const verifiedPct =
		scan.totalModels > 0
			? ((scan.verifiedCount / scan.totalModels) * 100).toFixed(0)
			: "0";

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3 flex-wrap gap-2">
				<div className="flex items-center gap-2">
					<Fingerprint size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Model Provenance</h3>
				</div>
				<StatusPill
					label={scan.overallRiskLevel}
					tone={riskTone(scan.overallRiskLevel)}
				/>
			</div>

			{/* Summary statistics */}
			<div className="grid gap-2 sm:grid-cols-4 mb-4">
				<div className="inset-panel">
					<p className="panel-label mb-1">Total Models</p>
					<span className="text-lg font-bold text-[var(--sea-ink)]">
						{scan.totalModels}
					</span>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Verified</p>
					<div className="flex items-center gap-1.5">
						<CheckCircle2 size={14} className="text-[var(--success)]" />
						<span className="text-lg font-bold text-[var(--success)]">
							{scan.verifiedCount}
						</span>
						<span className="text-xs text-[var(--sea-ink-soft)]">
							({verifiedPct}%)
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Risky</p>
					<div className="flex items-center gap-1.5">
						<XCircle size={14} className="text-[var(--danger)]" />
						<span className="text-lg font-bold text-[var(--danger)]">
							{scan.riskyCount}
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Provenance Score</p>
					<div className="flex items-center gap-1.5">
						<span
							className={`text-lg font-bold ${
								scan.aggregateScore >= 80
									? "text-[var(--success)]"
									: scan.aggregateScore >= 50
										? "text-[var(--warning)]"
										: "text-[var(--danger)]"
							}`}
						>
							{scan.aggregateScore.toFixed(0)}
						</span>
						<span className="text-xs text-[var(--sea-ink-soft)]">/100</span>
					</div>
					<div className="mt-1">{scoreBar(scan.aggregateScore)}</div>
				</div>
			</div>

			{/* Status pills */}
			<div className="flex flex-wrap gap-2 mb-3">
				<StatusPill
					label={`score ${scan.aggregateScore.toFixed(0)}/100`}
					tone={
						scan.aggregateScore >= 80
							? "success"
							: scan.aggregateScore >= 50
								? "warning"
								: "danger"
					}
				/>
				<StatusPill
					label={`scanned ${formatTimestamp(scan.scannedAt)}`}
					tone="neutral"
				/>
			</div>

			{scan.summary && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">{scan.summary}</p>
			)}

			{/* Per-model chain: model → hash → source */}
			<div className="space-y-2">
				{scan.components.map((comp: ModelComponent) => (
					<ModelComponentRow key={comp.name} component={comp} />
				))}
			</div>

			{scan.components.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl mt-2">
					<Fingerprint size={24} className="mb-2 opacity-40" />
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No AI model components detected in this repository's SBOM.
					</p>
				</div>
			)}
		</div>
	);
}
