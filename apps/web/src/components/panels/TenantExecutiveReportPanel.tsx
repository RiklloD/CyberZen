import type { FunctionReturnType } from "convex/server";
import {
	Activity,
	Download,
	GaugeCircle,
	GitBranch,
	ShieldCheck,
	Skull } from "lucide-react";
import StatusPill from "../../components/StatusPill";
import type { api } from "../../lib/convex";
import { repositoryHealthTone } from "../../lib/utils";

export interface TenantExecutiveReportPanelProps {
	report: NonNullable<
		FunctionReturnType<typeof api.executiveReportIntel.getExecutiveReport>
	>;
}

function exportCsv(
	report: TenantExecutiveReportPanelProps["report"],
): void {
	const rows: string[] = [];
	rows.push(["section", "key", "value"].join(","));
	rows.push(["overall", "tenantSlug", report.tenantSlug].join(","));
	rows.push(["overall", "overallScore", String(report.overallScore)].join(","));
	rows.push(["overall", "overallGrade", report.overallGrade].join(","));
	rows.push(["overall", "riskLevel", report.riskLevel].join(","));
	rows.push(
		["overall", "totalRepositories", String(report.totalRepositories)].join(","),
	);
	rows.push(
		[
			"overall",
			"scoredRepositories",
			String(report.scoredRepositories),
		].join(","),
	);
	rows.push(
		["domains", "healthAvg", String(report.domainAverages.healthAvg ?? "")].join(
			",",
		),
	);
	rows.push(
		[
			"domains",
			"driftPostureAvg",
			String(report.domainAverages.driftPostureAvg ?? ""),
		].join(","),
	);
	rows.push(
		[
			"domains",
			"supplyChainAvg",
			String(report.domainAverages.supplyChainAvg ?? ""),
		].join(","),
	);
	rows.push(
		[
			"domains",
			"complianceAvg",
			String(report.domainAverages.complianceAvg ?? ""),
		].join(","),
	);
	for (const r of report.worstRepos) {
		rows.push(
			[
				"worstRepo",
				r.repositoryFullName,
				`${r.compositeScore} (${r.grade}, ${r.riskLevel})`,
			]
				.map((c) => `"${c.replaceAll('"', '""')}"`)
				.join(","),
		);
	}
	for (const r of report.bestRepos) {
		rows.push(
			[
				"bestRepo",
				r.repositoryFullName,
				`${r.compositeScore} (${r.grade}, ${r.riskLevel})`,
			]
				.map((c) => `"${c.replaceAll('"', '""')}"`)
				.join(","),
		);
	}
	for (const fw of report.frameworkCompliance) {
		rows.push(
			[
				"framework",
				fw.framework,
				`${fw.complianceRate}% (${fw.compliantRepos}/${fw.totalRepos})`,
			]
				.map((c) => `"${c.replaceAll('"', '""')}"`)
				.join(","),
		);
	}
	const blob = new Blob([rows.join("\n")], { type: "text/csv" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = `executive-report-${report.tenantSlug}-${Date.now()}.csv`;
	a.click();
	URL.revokeObjectURL(url);
}

function exportJson(
	report: TenantExecutiveReportPanelProps["report"],
): void {
	const blob = new Blob([JSON.stringify(report, null, 2)], {
		type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = `executive-report-${report.tenantSlug}-${Date.now()}.json`;
	a.click();
	URL.revokeObjectURL(url);
}

function riskTone(
	risk: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (risk === "critical") return "danger";
	if (risk === "high") return "warning";
	if (risk === "medium") return "info";
	if (risk === "low") return "success";
	return "success";
}

function gradeTone(
	grade: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (grade === "A") return "success";
	if (grade === "B") return "success";
	if (grade === "C") return "warning";
	if (grade === "D") return "warning";
	return "danger";
}

function KpiTile({
	icon,
	label,
	value,
	hint,
	tone }: {
	icon: React.ReactNode;
	label: string;
	value: string | number;
	hint?: string;
	tone?: "neutral" | "success" | "warning" | "danger" | "info";
}) {
	return (
		<div className="card card-sm">
			<div className="flex items-center justify-between mb-2">
				<div className="flex items-center gap-2 text-[var(--sea-ink-soft)]">
					{icon}
					<span className="panel-label">{label}</span>
				</div>
				{tone && <StatusPill label={String(value)} tone={tone} />}
			</div>
			<div className="text-2xl font-bold text-[var(--sea-ink)]">{value}</div>
			{hint && (
				<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">{hint}</p>
			)}
		</div>
	);
}

export default function TenantExecutiveReportPanel({
	report }: TenantExecutiveReportPanelProps) {
	const { domainAverages } = report;

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-end gap-2">
				<button
					type="button"
					onClick={() => exportCsv(report)}
					className="signal-button secondary-button text-xs"
				>
					<Download size={12} className="inline -mt-0.5 mr-1" />
					Export CSV
				</button>
				<button
					type="button"
					onClick={() => exportJson(report)}
					className="signal-button secondary-button text-xs"
				>
					<Download size={12} className="inline -mt-0.5 mr-1" />
					Export JSON
				</button>
			</div>
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<KpiTile
					icon={<GaugeCircle size={14} />}
					label="Overall Score"
					value={`${report.overallScore}/100`}
					hint={`Grade ${report.overallGrade}`}
					tone={gradeTone(report.overallGrade)}
				/>
				<KpiTile
					icon={<Skull size={14} />}
					label="Risk Level"
					value={report.riskLevel.toUpperCase()}
					hint={`${report.scoredRepositories} of ${report.totalRepositories} scored`}
					tone={riskTone(report.riskLevel)}
				/>
				<KpiTile
					icon={<GitBranch size={14} />}
					label="Repositories"
					value={report.totalRepositories}
					hint={`${report.scoredRepositories} have scoring data`}
					tone="neutral"
				/>
				<KpiTile
					icon={<Activity size={14} />}
					label="Frameworks Tracked"
					value={report.frameworkCompliance.length}
					hint={
						report.frameworkCompliance[0]
							? `Worst: ${report.frameworkCompliance[0].framework} @ ${report.frameworkCompliance[0].complianceRate}%`
							: "no framework data"
					}
					tone={report.frameworkCompliance.length === 0 ? "neutral" : "info"}
				/>
			</div>

			<div>
				<h3 className="section-title mb-3">Domain Averages</h3>
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
					{[
						{
							key: "health",
							label: "Health",
							value: domainAverages.healthAvg },
						{
							key: "drift",
							label: "Drift Posture",
							value: domainAverages.driftPostureAvg },
						{
							key: "supply",
							label: "Supply Chain",
							value: domainAverages.supplyChainAvg },
						{
							key: "compliance",
							label: "Compliance",
							value: domainAverages.complianceAvg },
					].map(({ key, label, value }) => (
						<div key={key} className="inset-panel text-center">
							<div className="text-xs font-bold text-[var(--sea-ink-soft)] mb-1 uppercase tracking-wider">
								{label}
							</div>
							{value == null ? (
								<div className="text-lg font-bold text-[var(--sea-ink-soft)]">
									—
								</div>
							) : (
								<>
									<div className="text-2xl font-bold text-[var(--sea-ink)]">
										{value}
									</div>
									<StatusPill
										label={
											value >= 80
												? "healthy"
												: value >= 60
													? "drifting"
													: "critical"
										}
										tone={repositoryHealthTone(value)}
									/>
								</>
							)}
						</div>
					))}
				</div>
			</div>

			{report.topActions.length > 0 && (
				<div>
					<h3 className="section-title mb-3">Top Actions</h3>
					<div className="card">
						<ul className="space-y-2">
							{report.topActions.map((action: string, idx: number) => (
								<li
									key={action}
									className="flex items-start gap-3 text-sm text-[var(--sea-ink)]"
								>
									<StatusPill label={`#${idx + 1}`} tone="warning" />
									<span>{action}</span>
								</li>
							))}
						</ul>
					</div>
				</div>
			)}

			{report.frameworkCompliance.length > 0 && (
				<div>
					<h3 className="section-title mb-3">Framework Compliance</h3>
					<div className="card">
						<table className="data-table">
							<thead>
								<tr>
									<th>Framework</th>
									<th>Compliant</th>
									<th>At Risk</th>
									<th>Non-Compliant</th>
									<th>Rate</th>
								</tr>
							</thead>
							<tbody>
								{report.frameworkCompliance.map((fw: NonNullable<TenantExecutiveReportPanelProps["report"]>["frameworkCompliance"][number]) => (
									<tr key={fw.framework}>
										<td className="font-medium">{fw.framework}</td>
										<td>{fw.compliantRepos}</td>
										<td>{fw.atRiskRepos}</td>
										<td>{fw.nonCompliantRepos}</td>
										<td>
											<StatusPill
												label={`${fw.complianceRate}%`}
												tone={
													fw.complianceRate >= 80
														? "success"
														: fw.complianceRate >= 50
															? "warning"
															: "danger"
												}
											/>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
						<ShieldCheck size={12} className="inline -mt-0.5 mr-1" />
						Sorted worst-first across all repositories.
					</p>
				</div>
			)}
		</div>
	);
}
