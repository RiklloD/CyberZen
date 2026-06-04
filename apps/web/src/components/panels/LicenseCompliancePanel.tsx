import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type LicenseCompliance = NonNullable<
	FunctionReturnType<typeof api.licenseComplianceIntel.getLatestLicenseCompliance>
>;

type LicenseScan = NonNullable<
	FunctionReturnType<typeof api.licenseScanIntel.getLatestLicenseComplianceScan>
>;

export default function LicenseCompliancePanel({
	licenseCompliance,
	licenseScan,
}: {
	licenseCompliance?: LicenseCompliance;
	licenseScan?: LicenseScan;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">License Compliance</p>
			{licenseCompliance && (
				<div className="flex flex-wrap gap-1.5 mb-1">
					{licenseCompliance.violations.length > 0 && (
						<StatusPill
							label={`${licenseCompliance.violations.length} violations`}
							tone="danger"
						/>
					)}
					<StatusPill
						label={`${licenseCompliance.totalComponents} components checked`}
						tone="neutral"
					/>
				</div>
			)}
			{licenseScan && (
				<p className="text-xs text-[var(--sea-ink-soft)]">
					{licenseScan.summary}
				</p>
			)}
		</div>
	);
}
