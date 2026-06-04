import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type AbandonmentData = NonNullable<
	FunctionReturnType<typeof api.abandonmentScanIntel.getLatestAbandonmentScan>
>;

export interface RepositoryAbandonmentPanelProps {
	data: AbandonmentData;
}

export default function RepositoryAbandonmentPanel({
	data,
}: RepositoryAbandonmentPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Abandonment Scan</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`${data.totalAbandoned} abandoned`}
					tone={data.totalAbandoned > 0 ? "danger" : "success"}
				/>
				{data.highCount > 0 && (
					<StatusPill
						label={`${data.highCount} high risk`}
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
