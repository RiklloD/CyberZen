import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { supplyChainRiskTone } from "../../lib/utils";

type SupplyChainAnalysisData = NonNullable<
	FunctionReturnType<typeof api.promptIntelligence.supplyChainAnalysis>
>;

export interface PromptInjectionSupplyChainPanelProps {
	data: SupplyChainAnalysisData;
}

export default function PromptInjectionSupplyChainPanel({
	data }: PromptInjectionSupplyChainPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Supply Chain Risk Analysis</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={data.riskLevel}
					tone={supplyChainRiskTone(data.riskLevel)}
				/>
				<StatusPill
					label={`score ${data.overallRiskScore.toFixed(0)}`}
					tone="neutral"
				/>
				{data.typosquatCandidates.length > 0 && (
					<StatusPill
						label={`${data.typosquatCandidates.length} typosquat candidates`}
						tone="danger"
					/>
				)}
			</div>
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
			{data.flaggedComponents.slice(0, 3).map((c: SupplyChainAnalysisData["flaggedComponents"][number]) => (
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
	);
}
