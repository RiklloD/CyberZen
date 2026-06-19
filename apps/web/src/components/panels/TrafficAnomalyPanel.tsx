import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type TrafficAnomalyData = NonNullable<
	FunctionReturnType<typeof api.trafficAnomalyIntel.getLatestTrafficAnomaly>
>;

export interface TrafficAnomalyPanelProps {
	data: TrafficAnomalyData;
}

export default function TrafficAnomalyPanel({
	data }: TrafficAnomalyPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Traffic Anomaly</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={data.level}
					tone={
						data.level === "critical"
							? "danger"
							: data.level === "suspicious"
								? "warning"
								: data.level === "anomalous"
									? "info"
									: "success"
					}
				/>
				{data.patterns.length > 0 && (
					<StatusPill
						label={`${data.patterns.length} patterns`}
						tone="warning"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
