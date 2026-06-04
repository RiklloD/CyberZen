import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { injectionRiskTone } from "../../lib/utils";

type RecentScansData = NonNullable<
	FunctionReturnType<typeof api.promptIntelligence.recentScans>
>;

type ScanItem = RecentScansData[number];

export interface PromptInjectionRecentScansPanelProps {
	scans: RecentScansData;
}

export default function PromptInjectionRecentScansPanel({
	scans,
}: PromptInjectionRecentScansPanelProps) {
	if (scans.length === 0) return null;

	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Prompt Injection Scans</p>
			<div className="flex flex-wrap gap-1.5 mb-2">
				<StatusPill
					label={`${scans.length} scans`}
					tone="neutral"
				/>
				{scans.some(
					(s: ScanItem) =>
						s.riskLevel === "confirmed_injection" ||
						s.riskLevel === "likely_injection",
				) ? (
					<StatusPill label="injection detected" tone="danger" />
				) : scans.some((s: ScanItem) => s.riskLevel === "suspicious") ? (
					<StatusPill label="suspicious" tone="warning" />
				) : (
					<StatusPill label="all clear" tone="success" />
				)}
			</div>
			{scans.map((scan: ScanItem) => (
				<div
					key={scan._id}
					className="flex flex-wrap items-center gap-1.5 mt-1"
				>
					<StatusPill
						label={scan.riskLevel.replace(/_/g, " ")}
						tone={injectionRiskTone(scan.riskLevel)}
					/>
					<StatusPill label={scan.contentRef} tone="neutral" />
					<StatusPill
						label={`score ${scan.score}`}
						tone={
							scan.score > 50
								? "danger"
								: scan.score > 20
									? "warning"
									: "success"
						}
					/>
				</div>
			))}
		</div>
	);
}
