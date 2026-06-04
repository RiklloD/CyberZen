import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { driftLevelTone, frameworkScoreTone } from "../../lib/utils";

type RegulatoryDrift = NonNullable<
	FunctionReturnType<typeof api.regulatoryDriftIntel.getLatestRegulatoryDrift>
>;

export default function RegulatoryDriftPanel({
	data,
}: {
	data: RegulatoryDrift;
}) {
	return (
		<div className="card">
			<p className="panel-label mb-2">Regulatory Drift</p>
			<div className="flex flex-wrap gap-2 mb-3">
				<StatusPill
					label={data.overallDriftLevel.replace("_", " ")}
					tone={driftLevelTone(data.overallDriftLevel)}
				/>
				{data.openGapCount > 0 && (
					<StatusPill
						label={`${data.openGapCount} open gaps`}
						tone="neutral"
					/>
				)}
				{data.criticalGapCount > 0 && (
					<StatusPill
						label={`${data.criticalGapCount} critical`}
						tone="danger"
					/>
				)}
			</div>

			{/* Framework scores */}
			<div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
				{[
					{ key: "soc2", label: "SOC 2", score: data.soc2Score },
					{ key: "gdpr", label: "GDPR", score: data.gdprScore },
					{
						key: "hipaa",
						label: "HIPAA",
						score: data.hipaaScore,
					},
					{
						key: "pci_dss",
						label: "PCI-DSS",
						score: data.pciDssScore,
					},
					{ key: "nis2", label: "NIS2", score: data.nis2Score },
				].map(({ key, label, score }) => (
					<div key={key} className="inset-panel text-center">
						<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1">
							{label}
						</div>
						<div
							className={`text-lg font-bold ${
								score >= 80
									? "text-[var(--success)]"
									: score >= 60
										? "text-[var(--warning)]"
										: "text-[var(--danger)]"
							}`}
						>
							{score}
						</div>
						<StatusPill
							label={
								score >= 80 ? "good" : score >= 60 ? "at risk" : "failing"
							}
							tone={frameworkScoreTone(score)}
						/>
					</div>
				))}
			</div>

			<p className="mt-3 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
