import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type EpssSnapshot = NonNullable<
	FunctionReturnType<typeof api.epssIntel.getLatestEpssSnapshot>
>;

export default function EpssThreatIntelPanel({
	epss,
}: {
	epss: EpssSnapshot;
}) {
	return (
		<div>
			<h2 className="section-title mb-3">EPSS Threat Intel</h2>
			<div className="card card-sm">
				<div className="flex flex-wrap gap-2 mb-2">
					<StatusPill
						label={`${epss.enrichedCount} tracked CVEs`}
						tone="neutral"
					/>
					{epss.criticalRiskCount > 0 && (
						<StatusPill
							label={`${epss.criticalRiskCount} critical EPSS`}
							tone="danger"
						/>
					)}
					{epss.highRiskCount > 0 && (
						<StatusPill
							label={`${epss.highRiskCount} high EPSS`}
							tone="warning"
						/>
					)}
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)]">
					{epss.summary}
				</p>
				{epss.topCves
					?.slice(0, 5)
					.map(
						(cve: {
							cveId: string;
							epssScore: number;
							packageName?: string;
						}) => (
							<div
								key={cve.cveId}
								className="mt-2 flex flex-wrap items-center gap-2"
							>
								<StatusPill
									label={cve.cveId}
									tone={
										cve.epssScore > 0.5
											? "danger"
											: cve.epssScore > 0.2
												? "warning"
												: "neutral"
									}
								/>
								<StatusPill
									label={`EPSS ${(cve.epssScore * 100).toFixed(1)}%`}
									tone="neutral"
								/>
								{cve.packageName && (
									<StatusPill label={cve.packageName} tone="info" />
								)}
							</div>
						),
					)}
			</div>
		</div>
	);
}
