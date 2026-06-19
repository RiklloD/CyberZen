import { createFileRoute } from "@tanstack/react-router";
import { useAction, useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { BarChart3, Calendar, Download, FileText, Loader2, RefreshCw } from "lucide-react";
import { useState } from "react";
import ExecutiveRepoLeaderboard from "../components/panels/ExecutiveRepoLeaderboard";
import ExecutiveTrendChart from "../components/panels/ExecutiveTrendChart";
import TenantExecutiveReportPanel from "../components/panels/TenantExecutiveReportPanel";
import ExportMenu from "../components/ExportMenu";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import QueryErrorFallback from "../components/QueryErrorFallback";

type GeneratedReport = NonNullable<FunctionReturnType<typeof api.reports.listReports>>[number];

export const Route = createFileRoute("/executive-report")({
	errorComponent: QueryErrorFallback,
	component: ExecutiveReportPage });

function ExecutiveReportPage() {
	const tenantSlug = useTenantSlug();
	const report = useQuery(api.executiveReportIntel.getExecutiveReport, {
		tenantSlug });

	if (report === undefined) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
					{["a", "b", "c", "d"].map((k) => (
						<div key={k} className="loading-panel h-24 rounded-2xl" />
					))}
				</div>
				<div className="loading-panel h-64 rounded-2xl" />
			</main>
		);
	}

	if (report === null) {
		return (
			<main className="page-body-padded">
				<div className="card">
					<BarChart3 size={24} className="mb-2 opacity-30" />
					<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
						No executive report yet
					</p>
					<p className="text-sm text-[var(--sea-ink-soft)]">
						The tenant has no repositories with scoring data yet. Once health,
						drift, supply chain, or compliance scores are computed, this view
						will populate automatically.
					</p>
				</div>
			</main>
		);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<BarChart3 size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Executive Report</h1>
						<p className="page-subtitle">
							Tenant-wide security posture · generated{" "}
							{formatTimestamp(report.generatedAt)}
						</p>
					</div>
					<div className="ml-auto">
						<ExportMenu tenantSlug={tenantSlug} variant="executive-report" />
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				<TenantExecutiveReportPanel report={report} />

				<ExecutiveTrendChart
					healthAvg={report.domainAverages.healthAvg}
					driftPostureAvg={report.domainAverages.driftPostureAvg}
					supplyChainAvg={report.domainAverages.supplyChainAvg}
					complianceAvg={report.domainAverages.complianceAvg}
				/>

				<ExecutiveRepoLeaderboard
					worstRepos={report.worstRepos}
					bestRepos={report.bestRepos}
				/>

				<GeneratedReportsSection tenantSlug={tenantSlug} />
			</div>
		</main>
	);
}

function GeneratedReportsSection({ tenantSlug }: { tenantSlug: string }) {
	const reports = useQuery(
		api.reports.listReports,
		{ tenantSlug },
	);
	const deliveryConfig = useQuery(
		api.reports.getDeliveryConfig,
		{ tenantSlug },
	);
	const generateReport = useAction(api.reports.generateExecutiveReport);
	const scheduleDelivery = useMutation(api.reports.scheduleReportDelivery);

	const [generating, setGenerating] = useState(false);
	const [period, setPeriod] = useState(() => {
		const now = new Date();
		return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
	});
	const [reportType, setReportType] = useState<"monthly" | "quarterly">("monthly");
	const [scheduleFreq, setScheduleFreq] = useState<"monthly" | "quarterly">("monthly");
	const [scheduleRecipients, setScheduleRecipients] = useState("");
	const [savingSchedule, setSavingSchedule] = useState(false);
	const [scheduleSaved, setScheduleSaved] = useState(false);

	const handleGenerate = async () => {
		setGenerating(true);
		try {
			await generateReport({ tenantSlug, period, type: reportType });
		} finally {
			setGenerating(false);
		}
	};

	const handleSaveSchedule = async () => {
		setSavingSchedule(true);
		try {
			const recipients = scheduleRecipients
				.split(",")
				.map((r) => r.trim())
				.filter(Boolean);
			await scheduleDelivery({
				tenantSlug,
				frequency: scheduleFreq,
				recipients,
				isActive: true });
			setScheduleSaved(true);
			setTimeout(() => setScheduleSaved(false), 3000);
		} finally {
			setSavingSchedule(false);
		}
	};

	const getDownloadUrl = (reportId: string) => {
		const base = window.location.origin;
		return `${base}/api/reports/download?reportId=${reportId}`;
	};

	return (
		<div>
			<h2 className="section-title mb-3">Generated Reports</h2>

			{/* Generate button */}
			<div className="card card-sm mb-3">
				<div className="flex flex-wrap items-end gap-3">
					<div>
						<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
							Period
						</label>
						<input
							type="month"
							value={period}
							onChange={(e) => setPeriod(e.target.value)}
							className="input-field text-xs"
						/>
					</div>
					<div>
						<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
							Type
						</label>
						<select
							value={reportType}
							onChange={(e) =>
								setReportType(e.target.value as "monthly" | "quarterly")
							}
							className="input-field text-xs"
						>
							<option value="monthly">Monthly</option>
							<option value="quarterly">Quarterly</option>
						</select>
					</div>
					<button
						type="button"
						onClick={handleGenerate}
						disabled={generating}
						className="btn signal-button inline-flex items-center gap-1.5 text-xs disabled:opacity-50"
					>
						{generating ? (
							<Loader2 size={12} className="animate-spin" />
						) : (
							<FileText size={12} />
						)}
						Generate Executive Report
					</button>
				</div>
			</div>

			{/* Report list */}
			{reports === undefined ? (
				<div className="loading-panel h-32 rounded-2xl mb-3" />
			) : reports.length === 0 ? (
				<div className="card card-sm mb-3">
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No generated reports yet. Use the form above to generate your first
						executive report.
					</p>
				</div>
			) : (
				<div className="card mb-3">
					<table className="data-table">
						<thead>
							<tr>
								<th>Period</th>
								<th>Type</th>
								<th>Status</th>
								<th>Generated</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{reports.map((r: GeneratedReport) => (
								<tr key={r._id}>
									<td className="font-medium">{r.period}</td>
									<td>
										<StatusPill label={r.type} tone="info" />
									</td>
									<td>
										<StatusPill
											label={r.status}
											tone={
												r.status === "ready"
													? "success"
													: r.status === "generating"
														? "warning"
														: "danger"
											}
										/>
									</td>
									<td className="text-[var(--sea-ink-soft)] text-xs">
										{formatTimestamp(r.generatedAt)}
									</td>
									<td>
										{r.status === "ready" && (
											<a
												href={getDownloadUrl(r._id)}
												download={`executive-report-${r.period}.html`}
												className="inline-flex items-center gap-1 text-xs text-[var(--signal)] hover:underline"
											>
												<Download size={12} />
												Download HTML
											</a>
										)}
										{r.status === "generating" && (
											<RefreshCw size={12} className="animate-spin text-[var(--sea-ink-soft)]" />
										)}
										{r.status === "failed" && (
											<span className="text-xs text-[var(--danger)]">
												{r.errorMessage ?? "Generation failed"}
											</span>
										)}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}

			{/* Auto-schedule config */}
			<div className="card card-sm">
				<div className="flex items-center gap-2 mb-3">
					<Calendar size={14} className="text-[var(--signal)]" />
					<span className="text-sm font-medium text-[var(--sea-ink)]">
						Auto-schedule delivery
					</span>
					{deliveryConfig?.isActive && (
						<StatusPill label="active" tone="success" />
					)}
				</div>
				<div className="flex flex-wrap items-end gap-3">
					<div>
						<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
							Frequency
						</label>
						<select
							value={scheduleFreq}
							onChange={(e) =>
								setScheduleFreq(e.target.value as "monthly" | "quarterly")
							}
							className="input-field text-xs"
						>
							<option value="monthly">Monthly</option>
							<option value="quarterly">Quarterly</option>
						</select>
					</div>
					<div className="flex-1 min-w-[200px]">
						<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
							Recipients (comma-separated emails)
						</label>
						<input
							type="text"
							value={
								scheduleRecipients ||
								(deliveryConfig?.recipients ?? []).join(", ")
							}
							onChange={(e) => setScheduleRecipients(e.target.value)}
							placeholder="ciso@company.com, cto@company.com"
							className="input-field text-xs w-full"
						/>
					</div>
					<button
						type="button"
						onClick={handleSaveSchedule}
						disabled={savingSchedule}
						className="btn signal-button inline-flex items-center gap-1.5 text-xs disabled:opacity-50"
					>
						{savingSchedule ? (
							<Loader2 size={12} className="animate-spin" />
						) : scheduleSaved ? (
							"Saved"
						) : (
							"Save schedule"
						)}
					</button>
				</div>
			</div>
		</div>
	);
}
