import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	Activity,
	AlertTriangle,
	CheckCircle2,
	ChevronDown,
	ChevronUp,
	Clock,
	Loader2,
	Pause,
	Play,
	XCircle } from "lucide-react";
import { useState } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/jobs")({
	errorComponent: RouteErrorBoundary,
	component: JobMonitoringPage });

type JobHealth = NonNullable<
	FunctionReturnType<typeof api.jobMonitoring.getJobHealth>
>[number];

function statusTone(status: string | null): "success" | "danger" | "neutral" {
	if (status === "success") return "success";
	if (status === "failed") return "danger";
	return "neutral";
}

function statusIcon(status: string | null) {
	if (status === "success")
		return <CheckCircle2 size={13} className="text-green-500" />;
	if (status === "failed")
		return <XCircle size={13} className="text-[var(--danger)]" />;
	if (status === "running")
		return <Loader2 size={13} className="animate-spin text-[var(--signal)]" />;
	return <Clock size={13} className="text-[var(--sea-ink-soft)]" />;
}

function formatDuration(ms: number | null) {
	if (ms === null) return "—";
	if (ms < 1000) return `${ms}ms`;
	if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
	return `${(ms / 60000).toFixed(1)}m`;
}

type JobRun = NonNullable<
	FunctionReturnType<typeof api.jobMonitoring.getJobHistory>
>[number];

function JobHistory({ jobName }: { jobName: string }) {
	const TENANT = useTenantSlug();
	const history = useQuery(api.jobMonitoring.getJobHistory, {
		tenantSlug: TENANT,
		jobName,
		limit: 20 });

	if (!history) {
		return (
			<div className="space-y-1">
				{[1, 2, 3].map((i) => (
					<div key={i} className="loading-panel h-8 rounded-lg" />
				))}
			</div>
		);
	}
	if (history.length === 0) {
		return <p className="text-xs text-[var(--sea-ink-soft)]">No runs recorded.</p>;
	}
	return (
		<div className="space-y-1">
			{history.map((run: JobRun) => (
				<div
					key={run._id}
					className="flex items-center gap-3 py-1.5 px-2 rounded-lg bg-[var(--surface-soft)] text-xs"
				>
					{statusIcon(run.status)}
					<span className="text-[var(--sea-ink-soft)] w-36 shrink-0">
						{formatTimestamp(run.startedAt)}
					</span>
					<StatusPill label={run.status} tone={statusTone(run.status)} />
					<span className="text-[var(--sea-ink-soft)] ml-auto">
						{run.duration != null ? formatDuration(run.duration) : "—"}
					</span>
					{run.recordsProcessed != null && (
						<span className="text-[var(--sea-ink-soft)]">
							{run.recordsProcessed} records
						</span>
					)}
					{run.error && (
						<span
							className="text-red-400 font-mono line-clamp-1 max-w-xs"
							title={run.error}
						>
							{run.error}
						</span>
					)}
				</div>
			))}
		</div>
	);
}

function JobRow({ job, paused, onTogglePause }: { job: JobHealth; paused: boolean; onTogglePause: () => void }) {
	const [expanded, setExpanded] = useState(false);

	const alertCount = job.alertCount ?? 0;
	const consecutiveFails = job.consecutiveFailures ?? 0;

	return (
		<div className="card card-sm">
			<div className="flex items-center gap-3">
				{statusIcon(job.lastStatus)}

				<div className="flex-1 min-w-0">
					<div className="flex items-center gap-2 flex-wrap">
						<span className="text-xs font-semibold text-[var(--sea-ink)] font-mono">
							{job.jobName}
						</span>
						{alertCount > 0 && (
							<span className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded-full bg-red-500/15 text-red-400">
								<AlertTriangle size={10} />
								{alertCount} alert{alertCount !== 1 ? "s" : ""}
							</span>
						)}
					</div>
					<div className="flex flex-wrap gap-3 mt-0.5">
						<span className="text-xs text-[var(--sea-ink-soft)]">
							Last run:{" "}
							{job.lastRun ? formatTimestamp(job.lastRun) : "Never"}
						</span>
						<span className="text-xs text-[var(--sea-ink-soft)]">
							Avg: {formatDuration(job.avgDuration)}
						</span>
						<span className="text-xs text-[var(--sea-ink-soft)]">
							✓ {job.successCount} / ✗ {job.failureCount}
						</span>
					</div>
				</div>

				<div className="flex items-center gap-2 shrink-0">
						{paused && (
							<StatusPill label="paused" tone="neutral" />
						)}
						<button
							type="button"
							onClick={onTogglePause}
							className={`p-1.5 rounded-lg transition-colors ${
								paused
									? "text-green-400 hover:bg-green-500/15"
									: "text-[var(--sea-ink-soft)] hover:bg-[var(--surface-soft)] hover:text-[var(--signal)]"
							}`}
							title={paused ? "Resume job" : "Pause job"}
						>
							{paused ? <Play size={13} /> : <Pause size={13} />}
						</button>
						<StatusPill
							label={job.lastStatus ?? "never run"}
							tone={statusTone(job.lastStatus)}
						/>
					{consecutiveFails >= 3 && (
						<StatusPill label="alert" tone="danger" />
					)}
					<button
						type="button"
						onClick={() => setExpanded((v) => !v)}
						className="text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors p-0.5"
						aria-label="Toggle history"
					>
						{expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
					</button>
				</div>
			</div>

			{job.lastError && (
				<div className="mt-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20">
					<p className="text-xs font-mono text-red-400 line-clamp-2">
						{job.lastError}
					</p>
				</div>
			)}

			{expanded && (
				<div className="mt-3 pt-3 border-t border-[var(--line)]">
					<p className="text-xs font-medium text-[var(--sea-ink)] mb-2">
						Last 20 runs
					</p>
					<JobHistory jobName={job.jobName} />
				</div>
			)}
		</div>
	);
}

function JobMonitoringPage() {
	const TENANT = useTenantSlug();
	const health = useQuery(api.jobMonitoring.getJobHealth, {
		tenantSlug: TENANT });
	const pausedJobs = useQuery(api.jobMonitoring.getPausedJobs, {});
	const togglePause = useMutation(api.jobMonitoring.toggleJobPause);

	const totalAlerts = health?.reduce((sum: number, j: JobHealth) => sum + (j.alertCount ?? 0), 0) ?? 0;
	const failedJobs = health?.filter((j: JobHealth) => j.lastStatus === "failed").length ?? 0;
	const healthyJobs = health?.filter((j: JobHealth) => j.lastStatus === "success").length ?? 0;
	const pausedCount = pausedJobs ? Object.keys(pausedJobs).length : 0;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Activity size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Background Jobs</h1>
						<p className="page-subtitle">
							Cron job health, execution history, and failure alerts
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{/* Stats row */}
				<div className="stats-grid">
					<div className="card card-sm text-center">
						<p className="text-2xl font-bold text-[var(--sea-ink)]">
							{health?.length ?? "—"}
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Total jobs
						</p>
					</div>
					<div className="card card-sm text-center">
						<p className="text-2xl font-bold text-green-500">{healthyJobs}</p>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Healthy
						</p>
					</div>
					<div className="card card-sm text-center">
						<p className="text-2xl font-bold text-[var(--danger)]">
							{failedJobs}
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Failed
						</p>
					</div>
					<div className="card card-sm text-center">
						<p className="text-2xl font-bold text-red-400">{totalAlerts}</p>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Alerts
						</p>
					</div>
					<div className="card card-sm text-center">
						<p className="text-2xl font-bold text-[var(--sea-ink-soft)]">{pausedCount}</p>
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Paused
						</p>
					</div>
				</div>

				{/* Alert banner */}
				{totalAlerts > 0 && (
					<div className="flex items-center gap-3 p-4 rounded-2xl bg-red-500/10 border border-red-500/30">
						<AlertTriangle size={16} className="text-red-400 shrink-0" />
						<p className="text-sm text-red-400">
							<span className="font-semibold">{totalAlerts} job alert{totalAlerts !== 1 ? "s" : ""}</span> —
							one or more cron jobs have failed 3+ consecutive times.
						</p>
					</div>
				)}

				{/* Jobs table */}
				<div>
					<div className="section-header mb-3">
						<h2 className="section-title">Job Status</h2>
						{health && (
							<StatusPill label={`${health.length} jobs`} tone="neutral" />
						)}
					</div>

					{!health ? (
						<div className="space-y-2">
							{[1, 2, 3, 4, 5].map((i) => (
								<div key={i} className="loading-panel h-16 rounded-2xl" />
							))}
						</div>
					) : health.length === 0 ? (
						<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
							<Activity size={24} className="mb-2 opacity-40" />
							<p>
								No job runs recorded yet. Runs will appear after the first
								monitored cron execution.
							</p>
						</div>
					) : (
						<div className="space-y-2">
							{/* Sort: alerts first, then by name */}
							{[...health]
							.sort(
								(a, b) =>
									(b.alertCount ?? 0) - (a.alertCount ?? 0) ||
									a.jobName.localeCompare(b.jobName),
							)
							.map((job) => (
								<JobRow
									key={job.jobName}
									job={job}
									paused={pausedJobs?.[job.jobName] ?? false}
									onTogglePause={() => togglePause({ jobName: job.jobName })}
								/>
							))}
						</div>
					)}
				</div>
			</div>
		</main>
	);
}
