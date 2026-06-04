import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type CicdScan = NonNullable<
	FunctionReturnType<typeof api.cicdScanIntel.getLatestCicdScan>
>;

export default function RepositoryCicdScanPanel({ scan }: { scan: CicdScan }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">CI/CD Pipeline Scan</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={scan.overallRisk}
					tone={
						scan.overallRisk === "critical" || scan.overallRisk === "high"
							? "danger"
							: scan.overallRisk === "medium"
								? "warning"
								: "success"
					}
				/>
				{scan.totalFindings > 0 && (
					<StatusPill label={`${scan.totalFindings} issues`} tone="warning" />
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{scan.summary}
			</p>
		</div>
	);
}
