import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { supplyChainRiskTone } from "../../lib/utils";

type ConfusionScanData = NonNullable<
	FunctionReturnType<typeof api.confusionAttackIntel.getLatestConfusionScan>
>;

export interface RepositoryConfusionScanPanelProps {
	data: ConfusionScanData;
}

export default function RepositoryConfusionScanPanel({
	data,
}: RepositoryConfusionScanPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Confusion Attack</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={data.overallRisk}
					tone={supplyChainRiskTone(data.overallRisk)}
				/>
				{data.totalSuspicious > 0 && (
					<StatusPill
						label={`${data.totalSuspicious} suspicious`}
						tone="danger"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
