import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type EolData = NonNullable<
	FunctionReturnType<typeof api.eolDetectionIntel.getLatestEolScan>
>;

export interface RepositoryEolPanelProps {
	data: EolData;
}

export default function RepositoryEolPanel({ data }: RepositoryEolPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">End-of-Life Detection</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`${data.eolCount} EOL`}
					tone={data.eolCount > 0 ? "danger" : "success"}
				/>
				{data.nearEolCount > 0 && (
					<StatusPill
						label={`${data.nearEolCount} near EOL`}
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
