import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type SecretDetectionData = NonNullable<
	FunctionReturnType<typeof api.secretDetectionIntel.getLatestSecretScan>
>;

export interface SecretDetectionPanelProps {
	data: SecretDetectionData;
}

export default function SecretDetectionPanel({
	data,
}: SecretDetectionPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Secret Detection</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`${data.totalFound} secrets found`}
					tone={data.totalFound > 0 ? "danger" : "success"}
				/>
				{data.criticalCount > 0 && (
					<StatusPill
						label={`${data.criticalCount} critical`}
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
