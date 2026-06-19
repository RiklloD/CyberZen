import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { supplyChainRiskTone } from "../../lib/utils";

type MaliciousScanData = NonNullable<
	FunctionReturnType<typeof api.maliciousPackageIntel.getLatestMaliciousScan>
>;

export interface RepositoryMaliciousScanPanelProps {
	data: MaliciousScanData;
}

export default function RepositoryMaliciousScanPanel({
	data }: RepositoryMaliciousScanPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Malicious Package Scan</p>
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
