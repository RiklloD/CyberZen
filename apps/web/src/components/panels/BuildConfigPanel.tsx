import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type BuildConfig = NonNullable<
	FunctionReturnType<
		typeof api.buildConfigIntel.getLatestBuildConfigScanBySlug
	>
>;

export default function BuildConfigPanel({ buildConfig }: { buildConfig: BuildConfig }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Build Config</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={buildConfig.riskLevel}
					tone={
						buildConfig.riskLevel === "critical" || buildConfig.riskLevel === "high"
							? "danger"
							: buildConfig.riskLevel === "medium"
								? "warning"
								: "success"
					}
				/>
				{buildConfig.totalFindings > 0 && (
					<StatusPill
						label={`${buildConfig.totalFindings} issues`}
						tone="warning"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{buildConfig.summary}
			</p>
		</div>
	);
}
