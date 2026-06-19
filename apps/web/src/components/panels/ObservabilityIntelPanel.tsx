import type { FunctionReturnType } from "convex/server";
import { Activity, AlertTriangle, Gauge, Radio, Send } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type IntelData = NonNullable<
	FunctionReturnType<
		typeof api.observabilityIntel.getLatestObservabilityIntel
	>
>;

export interface ObservabilityIntelPanelProps {
	intel: IntelData;
}

function platformStatusTone(
	status: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (status === "active") return "success";
	if (status === "not_configured") return "neutral";
	if (status === "error") return "danger";
	return "neutral";
}

function scoreTone(
	score: number | null,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (score == null) return "neutral";
	if (score >= 80) return "success";
	if (score >= 60) return "info";
	if (score >= 40) return "warning";
	return "danger";
}

export default function ObservabilityIntelPanel({
	intel }: ObservabilityIntelPanelProps) {
	const { platforms, pushHistory, summary } = intel;

	const failedPushes = pushHistory.filter(
		(entry: IntelData["pushHistory"][number]) => entry.openCritical > 0 || entry.attackSurfaceScore != null && entry.attackSurfaceScore < 40,
	);

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex items-center gap-2">
				<Activity size={16} className="text-[var(--signal)]" />
				<h3 className="section-title">Observability Intel</h3>
				<StatusPill
					label={`${summary.platformsConfigured} platforms`}
					tone={summary.platformsConfigured > 0 ? "info" : "neutral"}
				/>
			</div>

			{/* Summary KPIs */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<Radio size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">Platforms</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{summary.platformsConfigured}
					</div>
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
						of {platforms.length} integrations active
					</p>
				</div>

				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<Send size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">Metrics Series</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{summary.totalMetricsSeries}
					</div>
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
						across {summary.totalRepositories} repositories
					</p>
				</div>

				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<Gauge size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">Avg Attack Surface</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{summary.avgAttackSurfaceScore ?? "—"}
					</div>
					{summary.avgAttackSurfaceScore != null && (
						<StatusPill
							label={summary.avgAttackSurfaceScore >= 80 ? "healthy" : summary.avgAttackSurfaceScore >= 60 ? "moderate" : "at risk"}
							tone={scoreTone(summary.avgAttackSurfaceScore)}
						/>
					)}
				</div>

				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<AlertTriangle size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">Open Critical</span>
					</div>
					<div className="text-2xl font-bold text-[var(--danger)]">
						{summary.totalOpenCritical}
					</div>
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
						+ {summary.totalOpenHigh} high severity
					</p>
				</div>
			</div>

			{/* Platform Push Status */}
			<div>
				<h3 className="section-title mb-3">Push Platform Status</h3>
				<div className="grid gap-3 sm:grid-cols-3">
					{platforms.map((platform: IntelData["platforms"][number]) => (
						<div key={platform.name} className="card card-sm">
							<div className="flex items-center justify-between mb-2">
								<span className="text-sm font-semibold text-[var(--sea-ink)]">
									{platform.name}
								</span>
								<StatusPill
									label={platform.configured ? "configured" : "not set"}
									tone={platformStatusTone(platform.status)}
								/>
							</div>
							<div className="flex flex-col gap-1.5">
								<div className="flex items-center justify-between text-xs">
									<span className="text-[var(--sea-ink-soft)]">Status</span>
									<StatusPill
										label={platform.status.replace(/_/g, " ")}
										tone={platformStatusTone(platform.status)}
									/>
								</div>
								<div className="flex items-center justify-between text-xs">
									<span className="text-[var(--sea-ink-soft)]">Series pushed</span>
									<span className="font-mono text-[var(--sea-ink)]">
										{platform.seriesCount ?? "—"}
									</span>
								</div>
								<div className="flex items-center justify-between text-xs">
									<span className="text-[var(--sea-ink-soft)]">Last push</span>
									<span className="text-[var(--sea-ink)]">
										{platform.lastPushAt
											? formatTimestamp(platform.lastPushAt)
											: "never"}
									</span>
								</div>
							</div>
						</div>
					))}
				</div>
			</div>

			{/* Outbound Push History */}
			{pushHistory.length > 0 && (
				<div>
					<h3 className="section-title mb-3">
						Outbound Push History ({pushHistory.length} repositories)
					</h3>
					<div className="card">
						<table className="data-table">
							<thead>
								<tr>
									<th>Repository</th>
									<th>Last Push</th>
									<th>Metrics</th>
									<th>Attack Surface</th>
									<th>Critical</th>
									<th>High</th>
								</tr>
							</thead>
							<tbody>
								{pushHistory.map((entry: IntelData["pushHistory"][number]) => {
									const repoShort = entry.repositoryFullName.split("/").pop() ?? entry.repositoryFullName;
									return (
										<tr key={entry.repositoryFullName}>
											<td className="font-medium text-[var(--sea-ink)]">
												{repoShort}
											</td>
											<td className="text-[var(--sea-ink-soft)]">
												{formatTimestamp(entry.timestampMs)}
											</td>
											<td className="font-mono text-[var(--sea-ink)]">
												{entry.metricsCount} series
											</td>
											<td>
												{entry.attackSurfaceScore != null ? (
													<StatusPill
														label={`${entry.attackSurfaceScore}/100`}
														tone={scoreTone(entry.attackSurfaceScore)}
													/>
												) : (
													<span className="text-[var(--sea-ink-soft)]">—</span>
												)}
											</td>
											<td>
												{entry.openCritical > 0 ? (
													<StatusPill
														label={String(entry.openCritical)}
														tone="danger"
													/>
												) : (
													<span className="text-[var(--success)]">0</span>
												)}
											</td>
											<td>
												{entry.openHigh > 0 ? (
													<StatusPill
														label={String(entry.openHigh)}
														tone="warning"
													/>
												) : (
													<span className="text-[var(--success)]">0</span>
												)}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				</div>
			)}

			{/* Failed / At-Risk Pushes */}
			{failedPushes.length > 0 && (
				<div>
					<h3 className="section-title mb-3">
						At-Risk Repositories
					</h3>
					<div className="grid gap-3 sm:grid-cols-2">
						{failedPushes.map((entry: IntelData["pushHistory"][number]) => {
							const repoShort = entry.repositoryFullName.split("/").pop() ?? entry.repositoryFullName;
							return (
								<div key={entry.repositoryFullName} className="card card-sm border border-[var(--danger)]/30">
									<div className="flex items-center justify-between mb-2">
										<span className="text-sm font-semibold text-[var(--sea-ink)]">
											{repoShort}
										</span>
										{entry.attackSurfaceScore != null && (
											<StatusPill
												label={`score ${entry.attackSurfaceScore}`}
												tone={scoreTone(entry.attackSurfaceScore)}
											/>
										)}
									</div>
									<div className="flex flex-wrap gap-1.5">
										{entry.openCritical > 0 && (
											<StatusPill label={`${entry.openCritical} critical`} tone="danger" />
										)}
										{entry.openHigh > 0 && (
											<StatusPill label={`${entry.openHigh} high`} tone="warning" />
										)}
										<StatusPill
											label="ack pending"
											tone="warning"
										/>
									</div>
									<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
										Last pushed {formatTimestamp(entry.timestampMs)}
									</p>
								</div>
							);
						})}
					</div>
				</div>
			)}

			{/* Ack Latency Note */}
			<div className="card card-sm">
				<div className="flex items-center gap-2 mb-2">
					<Activity size={14} className="text-[var(--sea-ink-soft)]" />
					<span className="text-xs font-bold uppercase tracking-wider text-[var(--sea-ink-soft)]">
						Push Acknowledgment
					</span>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)]">
					Datadog metrics are pushed on a 15-minute cron cycle via{" "}
					<code className="text-[var(--teal)]">DD_API_KEY</code>.
					Prometheus metrics are served at{" "}
					<code className="text-[var(--teal)]">GET /metrics</code> for
					Grafana scraping. Ack latency is tracked per-platform in the
					outbound push logs above.
				</p>
			</div>
		</div>
	);
}
