import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { slaComplianceTone } from "../../lib/utils";

type SlaData = NonNullable<
	FunctionReturnType<typeof api.slaIntel.getSlaStatusForRepository>
>;

export default function RepositorySlaPanel({ sla }: { sla: SlaData }) {
	return (
		<div className="card card-sm">
			<p className="panel-label">SLA Enforcement</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`${Math.round(sla.summary.complianceRate * 100)}% compliant`}
					tone={slaComplianceTone(sla.summary.complianceRate)}
				/>
				{sla.summary.breachedSla > 0 && (
					<StatusPill
						label={`${sla.summary.breachedSla} breached`}
						tone="danger"
					/>
				)}
				{sla.summary.approachingSla > 0 && (
					<StatusPill
						label={`${sla.summary.approachingSla} approaching`}
						tone="warning"
					/>
				)}
				{sla.summary.mttrHours !== null && (
					<StatusPill
						label={`MTTR ${Math.round(sla.summary.mttrHours)}h`}
						tone="neutral"
					/>
				)}
			</div>
		</div>
	);
}
