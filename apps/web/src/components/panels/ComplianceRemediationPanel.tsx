import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type ComplianceRemediation = NonNullable<
	FunctionReturnType<
		typeof api.complianceRemediationIntel.getLatestComplianceRemediationPlan
	>
>;

export default function ComplianceRemediationPanel({
	data }: {
	data: ComplianceRemediation;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Compliance Remediation</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`${data.actions.length} actions`}
					tone={
						data.actions.length > 0
							? "warning"
							: "success"
					}
				/>
				{data.criticalActions > 0 && (
					<StatusPill
						label={`${data.criticalActions} critical`}
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
