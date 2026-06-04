import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type SensitiveFiles = NonNullable<
	FunctionReturnType<typeof api.sensitiveFileIntel.getLatestSensitiveFileScanBySlug>
>;

export default function SensitiveFileScanPanel({
	data,
}: {
	data: SensitiveFiles;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Sensitive Files</p>
			<div className="flex flex-wrap gap-1.5">
				{data.criticalCount > 0 && (
					<StatusPill
						label={`${data.criticalCount} critical`}
						tone="danger"
					/>
				)}
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
