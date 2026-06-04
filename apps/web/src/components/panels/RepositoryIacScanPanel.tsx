import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type IacScan = NonNullable<
	FunctionReturnType<typeof api.iacScanIntel.getLatestIacScan>
>;

export default function RepositoryIacScanPanel({ iacScan }: { iacScan: IacScan }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">IaC Security</p>
			<div className="flex flex-wrap gap-1.5">
				{iacScan.criticalCount > 0 && (
					<StatusPill
						label={`${iacScan.criticalCount} critical issues`}
						tone="danger"
					/>
				)}
				{iacScan.highCount > 0 && (
					<StatusPill label={`${iacScan.highCount} high`} tone="warning" />
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{iacScan.summary}
			</p>
		</div>
	);
}
