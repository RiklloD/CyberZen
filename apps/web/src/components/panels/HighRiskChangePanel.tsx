import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type HighRisk = NonNullable<
	FunctionReturnType<
		typeof api.highRiskChangeIntel.getLatestHighRiskChangeScanBySlug
	>
>;

export default function HighRiskChangePanel({ highRisk }: { highRisk: HighRisk }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">High-Risk Changes</p>
			<div className="flex flex-wrap gap-1.5">
				{highRisk.criticalCount > 0 && (
					<StatusPill
						label={`${highRisk.criticalCount} critical`}
						tone="danger"
					/>
				)}
				{highRisk.highCount > 0 && (
					<StatusPill label={`${highRisk.highCount} high`} tone="warning" />
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{highRisk.summary}
			</p>
		</div>
	);
}
