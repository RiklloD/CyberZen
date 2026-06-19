import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { supplyChainRiskTone } from "../../lib/utils";

type SupplyChainPostureData = NonNullable<
	FunctionReturnType<typeof api.supplyChainPostureIntel.getLatestSupplyChainPosture>
>;

export interface SupplyChainPosturePanelProps {
	data: SupplyChainPostureData;
}

export default function SupplyChainPosturePanel({
	data }: SupplyChainPosturePanelProps) {
	return (
		<div className="card">
			<p className="panel-label mb-2">Supply Chain Posture</p>
			<div className="flex flex-wrap gap-2">
				<StatusPill
					label={data.riskLevel}
					tone={supplyChainRiskTone(data.riskLevel)}
				/>
				<StatusPill
					label={`score ${data.score.toFixed(0)}`}
					tone="neutral"
				/>
				<StatusPill
					label={`grade ${data.grade}`}
					tone="neutral"
				/>
			</div>
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
