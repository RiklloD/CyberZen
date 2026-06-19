import type { FunctionReturnType } from "convex/server";
import { ShieldCheck, ShieldAlert, ShieldX, Package } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp, supplyChainRiskTone } from "../../lib/utils";

type ModelScanData = NonNullable<
	FunctionReturnType<typeof api.modelSupplyChainIntel.getLatestModelScan>
>;

type FlaggedComponent = ModelScanData["flaggedComponents"][number];

export interface ModelSupplyChainPanelProps {
	scan: ModelScanData;
}

function signalKindLabel(kind: string): string {
	const map: Record<string, string> = {
		pickle_serialization_risk: "Pickle risk",
		unpinned_ml_framework: "Unpinned",
		outdated_ml_framework: "Vulnerable version",
		model_typosquat_risk: "Typosquat",
		remote_weight_download: "Remote weights",
		unsafe_model_loader: "Unsafe loader",
		none: "—" };
	return map[kind] ?? kind.replace(/_/g, " ");
}

function signalKindTone(
	kind: string,
): "danger" | "warning" | "neutral" | "success" {
	if (
		kind === "pickle_serialization_risk" ||
		kind === "outdated_ml_framework" ||
		kind === "unsafe_model_loader"
	)
		return "danger";
	if (
		kind === "unpinned_ml_framework" ||
		kind === "model_typosquat_risk" ||
		kind === "remote_weight_download"
	)
		return "warning";
	return "neutral";
}

export default function ModelSupplyChainPanel({ scan }: ModelSupplyChainPanelProps) {
	const {
		overallRiskScore,
		riskLevel,
		mlFrameworkCount,
		mlFrameworks,
		hasPickleRisk,
		hasUnpinnedFramework,
		vulnerableFrameworkCount,
		flaggedComponentCount,
		flaggedComponents,
		summary,
		scannedAt } = scan;

	return (
		<div className="card">
			{/* Header */}
			<div className="flex items-center justify-between flex-wrap gap-2 mb-3">
				<div className="flex items-center gap-2">
					<Package size={16} className="text-[var(--signal)]" />
					<h3 className="section-title">Model Supply Chain</h3>
					<StatusPill
						label={riskLevel}
						tone={supplyChainRiskTone(riskLevel)}
					/>
					<StatusPill
						label={`score ${overallRiskScore.toFixed(0)}`}
						tone="neutral"
					/>
				</div>
				<span className="text-xs text-[var(--sea-ink-soft)]">
					Scanned {formatTimestamp(scannedAt)}
				</span>
			</div>

			{/* Summary */}
			{summary && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">{summary}</p>
			)}

			{/* Risk indicators */}
			<div className="grid gap-2 sm:grid-cols-3 mb-4">
				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Serialization
					</div>
					<div className="flex items-center justify-center gap-1">
						{hasPickleRisk ? (
							<>
								<ShieldAlert size={14} className="text-[var(--danger)]" />
								<span className="text-sm font-bold text-[var(--danger)]">
									Unsigned
								</span>
							</>
						) : (
							<>
								<ShieldCheck size={14} className="text-[var(--success)]" />
								<span className="text-sm font-bold text-[var(--success)]">
									Signed
								</span>
							</>
						)}
					</div>
					<div className="text-[10px] text-[var(--sea-ink-soft)] mt-0.5">
						Pickle / safe-tensor status
					</div>
				</div>

				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Integrity Hash
					</div>
					<div className="flex items-center justify-center gap-1">
						{hasUnpinnedFramework ? (
							<>
								<ShieldX size={14} className="text-[var(--warning)]" />
								<span className="text-sm font-bold text-[var(--warning)]">
									Unpinned
								</span>
							</>
						) : (
							<>
								<ShieldCheck size={14} className="text-[var(--success)]" />
								<span className="text-sm font-bold text-[var(--success)]">
									Match
								</span>
							</>
						)}
					</div>
					<div className="text-[10px] text-[var(--sea-ink-soft)] mt-0.5">
						Version pinning & hash verify
					</div>
				</div>

				<div className="inset-panel text-center">
					<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
						Vulnerable Versions
					</div>
					<div className="text-lg font-bold">
						<span
							className={
								vulnerableFrameworkCount > 0
									? "text-[var(--danger)]"
									: "text-[var(--success)]"
							}
						>
							{vulnerableFrameworkCount}
						</span>
					</div>
					<div className="text-[10px] text-[var(--sea-ink-soft)] mt-0.5">
						Known CVE range matches
					</div>
				</div>
			</div>

			{/* Registry pull list */}
			{mlFrameworks.length > 0 && (
				<div className="mb-4">
					<p className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1.5">
						Registry Pulls ({mlFrameworkCount})
					</p>
					<div className="flex flex-wrap gap-1.5">
						{mlFrameworks.map((fw: string) => (
							<StatusPill key={fw} label={fw} tone="neutral" />
						))}
					</div>
				</div>
			)}

			{/* Flagged components */}
			{flaggedComponents.length > 0 && (
				<div>
					<p className="text-xs font-bold text-[var(--sea-ink-soft)] mb-2">
						Flagged Components ({flaggedComponentCount})
					</p>
					<div className="space-y-2">
						{flaggedComponents.map((c: FlaggedComponent) => (
							<div
								key={`${c.name}-${c.version}`}
								className="inset-panel"
							>
								<div className="flex flex-wrap items-center gap-1.5 mb-1">
									<span className="text-sm font-semibold text-[var(--sea-ink)]">
										{c.name}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										@{c.version}
									</span>
									<StatusPill
										label={c.riskLevel}
										tone={supplyChainRiskTone(c.riskLevel)}
									/>
									<StatusPill
										label={signalKindLabel(c.topSignalKind)}
										tone={signalKindTone(c.topSignalKind)}
									/>
									<StatusPill
										label={`score ${c.riskScore.toFixed(0)}`}
										tone="neutral"
									/>
								</div>
								{c.summary && (
									<p className="text-[11px] text-[var(--sea-ink-soft)] leading-relaxed">
										{c.summary}
									</p>
								)}
							</div>
						))}
					</div>
				</div>
			)}

			{flaggedComponents.length === 0 && mlFrameworkCount === 0 && (
				<div className="text-center py-4">
					<Package
						size={24}
						className="mx-auto mb-2 opacity-40"
					/>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No AI/ML frameworks detected in this repository's SBOM.
					</p>
				</div>
			)}
		</div>
	);
}
