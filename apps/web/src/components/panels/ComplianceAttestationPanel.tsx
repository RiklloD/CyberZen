import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type ComplianceAttestation = NonNullable<
	FunctionReturnType<
		typeof api.complianceAttestationIntel.getLatestComplianceAttestation
	>
>;

export default function ComplianceAttestationPanel({
	data }: {
	data: ComplianceAttestation;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Compliance Attestation</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={data.overallStatus.replace(/_/g, " ")}
					tone={
						data.overallStatus === "compliant"
							? "success"
							: data.overallStatus === "at_risk"
								? "warning"
								: "danger"
					}
				/>
				<StatusPill
					label={`${data.fullyCompliantCount} fully compliant`}
					tone="neutral"
				/>
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
