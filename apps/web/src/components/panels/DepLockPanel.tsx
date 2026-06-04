import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type DepLock = NonNullable<
	FunctionReturnType<typeof api.depLockIntel.getLatestDepLockVerifyScanBySlug>
>;

export default function DepLockPanel({ depLock }: { depLock: DepLock }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Dependency Lock</p>
			<div className="flex flex-wrap gap-1.5">
				{depLock.criticalCount > 0 && (
					<StatusPill
						label={`${depLock.criticalCount} critical discrepancies`}
						tone="danger"
					/>
				)}
				{depLock.highCount > 0 && (
					<StatusPill label={`${depLock.highCount} high`} tone="warning" />
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{depLock.summary}
			</p>
		</div>
	);
}
