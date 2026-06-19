import type { FunctionReturnType } from "convex/server";
import {
	GitCommitHorizontal,
	Package,
	Database,
	Cpu,
	Rocket,
	CheckCircle2,
	AlertTriangle,
	XCircle,
	ArrowRight } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

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

function riskIcon(riskLevel: string) {
	if (riskLevel === "verified")
		return <CheckCircle2 size={14} className="text-[var(--success)]" />;
	if (riskLevel === "risky")
		return <XCircle size={14} className="text-[var(--danger)]" />;
	return <AlertTriangle size={14} className="text-[var(--warning)]" />;
}

/**
 * Infers a lineage stage for a model component based on its name/signals.
 * Maps to: "training-data" → "fine-tune" → "deploy" pipeline.
 */
function inferStage(
	component: ModelComponent,
): "training-data" | "fine-tune" | "deploy" {
	const name = component.name.toLowerCase();
	const signal = component.topSignalKind?.toLowerCase() ?? "";

	if (
		name.includes("dataset") ||
		name.includes("corpus") ||
		signal.includes("training") ||
		signal.includes("dataset")
	) {
		return "training-data";
	}
	if (
		name.includes("adapter") ||
		name.includes("lora") ||
		name.includes("qlora") ||
		name.includes("fine") ||
		signal.includes("fine")
	) {
		return "fine-tune";
	}
	return "deploy";
}

const STAGE_CONFIG = {
	"training-data": {
		label: "Training Data",
		icon: Database,
		color: "var(--signal)" },
	"fine-tune": {
		label: "Fine-tune",
		icon: Cpu,
		color: "var(--warning)" },
	deploy: {
		label: "Deploy",
		icon: Rocket,
		color: "var(--success)" } } as const;

function ChainNode({
	component,
	isLast }: {
	component: ModelComponent;
	isLast: boolean;
}) {
	const stage = inferStage(component);
	const config = STAGE_CONFIG[stage];
	const Icon = config.icon;

	return (
		<div className="relative">
			{/* Connector line */}
			{!isLast && (
				<div className="absolute left-[15px] top-[34px] bottom-0 w-px bg-[var(--line)]" />
			)}

			<div className="flex items-start gap-3 pb-4">
				{/* Stage icon */}
				<div
					className="shrink-0 w-[30px] h-[30px] rounded-full flex items-center justify-center border"
					style={{
						borderColor: config.color,
						backgroundColor: `color-mix(in srgb, ${config.color} 10%, transparent)` }}
				>
					<Icon size={14} style={{ color: config.color }} />
				</div>

				{/* Content */}
				<div className="flex-1 min-w-0">
					<div className="flex items-center gap-1.5 mb-0.5">
						<span
							className="text-[10px] font-semibold uppercase tracking-wider"
							style={{ color: config.color }}
						>
							{config.label}
						</span>
						{riskIcon(component.riskLevel)}
					</div>

					<div className="flex items-center gap-2 mb-1">
						<Package size={12} className="text-[var(--sea-ink-soft)] shrink-0" />
						<span className="text-sm font-medium text-[var(--sea-ink)] truncate">
							{component.name}
						</span>
					</div>

					{/* Hash → Source chain */}
					<div className="flex items-center gap-1.5 flex-wrap text-xs text-[var(--sea-ink-soft)]">
						<span className="inline-flex items-center gap-1">
							<GitCommitHorizontal size={10} />
							<code className="truncate max-w-[120px]">
								{component.resolvedSource}
							</code>
						</span>
						<ArrowRight size={10} className="shrink-0 opacity-40" />
						<StatusPill label={component.riskLevel} tone={riskTone(component.riskLevel)} />
						<StatusPill
							label={`${component.provenanceScore.toFixed(0)}%`}
							tone={
								component.provenanceScore >= 80
									? "success"
									: component.provenanceScore >= 50
										? "warning"
										: "danger"
							}
						/>
					</div>

					{component.summary && (
						<p className="mt-1 text-xs text-[var(--sea-ink-soft)] line-clamp-2">
							{component.summary}
						</p>
					)}
				</div>
			</div>
		</div>
	);
}

export default function ModelProvenanceChainViewer({
	scan }: {
	scan: ProvenanceScan;
}) {
	// Group components by inferred lineage stage
	const sorted = [...scan.components].sort((a, b) => {
		const order = { "training-data": 0, "fine-tune": 1, deploy: 2 };
		return order[inferStage(a)] - order[inferStage(b)];
	});

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-4">
				<GitCommitHorizontal size={14} className="text-[var(--signal)]" />
				<h3 className="section-title">Provenance Chain</h3>
				<StatusPill label={`${scan.components.length} models`} tone="neutral" />
			</div>

			{/* Stage legend */}
			<div className="flex flex-wrap gap-3 mb-4">
				{(Object.entries(STAGE_CONFIG) as [keyof typeof STAGE_CONFIG, (typeof STAGE_CONFIG)[keyof typeof STAGE_CONFIG]][]).map(
					([key, cfg]) => {
						const Icon = cfg.icon;
						const count = scan.components.filter(
							(c: ProvenanceScan["components"][number]) => inferStage(c) === key,
						).length;
						return (
							<div
								key={key}
								className="flex items-center gap-1.5 text-xs text-[var(--sea-ink-soft)]"
							>
								<Icon size={12} style={{ color: cfg.color }} />
								<span>{cfg.label}</span>
								<span className="font-medium text-[var(--sea-ink)]">
									({count})
								</span>
							</div>
						);
					},
				)}
			</div>

			{/* DAG-style vertical chain */}
			{sorted.length > 0 ? (
				<div className="max-h-80 overflow-y-auto">
					{sorted.map((comp, i) => (
						<ChainNode
							key={comp.name}
							component={comp}
							isLast={i === sorted.length - 1}
						/>
					))}
				</div>
			) : (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<GitCommitHorizontal size={24} className="mb-2 opacity-40" />
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No model provenance chain to display.
					</p>
				</div>
			)}
		</div>
	);
}
