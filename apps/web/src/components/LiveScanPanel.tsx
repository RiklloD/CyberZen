import { useEffect, useRef, useState } from "react";
import { useQuery } from "convex/react";
import {
	AlertCircle,
	CheckCircle2,
	ChevronDown,
	ChevronRight,
	Clock,
	Loader2,
	Radio,
	Terminal,
	Zap,
} from "lucide-react";
import { api, type Id } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

// ── Types ─────────────────────────────────────────────────────────────────

type LogLevel = "info" | "success" | "warning" | "error";

interface ScanLog {
	_id: string;
	phase: string;
	level: LogLevel;
	message: string;
	detail?: string;
	createdAt: number;
}

interface ActiveScan {
	_id: Id<"workflowRuns">;
	workflowType: string;
	status: string;
	summary: string;
	startedAt: number;
	repositoryId: Id<"repositories">;
	repositoryName: string;
	repositoryFullName: string;
	completedTaskCount: number;
	totalTaskCount: number;
	logCount: number;
	latestLogAt?: number;
}

// ── Phase icon mapping ────────────────────────────────────────────────────

const PHASE_META: Record<string, { icon: typeof Terminal; label: string }> = {
	scan_start: { icon: Zap, label: "Start" },
	fetch_tree: { icon: Terminal, label: "Tree" },
	classify: { icon: Terminal, label: "Classify" },
	fetch_files: { icon: Terminal, label: "Fetch" },
	sbom: { icon: Terminal, label: "SBOM" },
	scanner_dispatch: { icon: Radio, label: "Dispatch" },
	scanner_result: { icon: CheckCircle2, label: "Result" },
	scan_complete: { icon: CheckCircle2, label: "Done" },
	scan_error: { icon: AlertCircle, label: "Error" },
};

function phaseLabel(phase: string): string {
	return PHASE_META[phase]?.label ?? phase;
}

function levelColor(level: LogLevel): string {
	switch (level) {
		case "success":
			return "text-[var(--success)]";
		case "warning":
			return "text-[var(--warning)]";
		case "error":
			return "text-[var(--danger)]";
		default:
			return "text-[var(--teal)]";
	}
}

function levelDot(level: LogLevel): string {
	switch (level) {
		case "success":
			return "bg-[var(--success)]";
		case "warning":
			return "bg-[var(--warning)]";
		case "error":
			return "bg-[var(--danger)]";
		default:
			return "bg-[var(--teal)]";
	}
}

function timeFmt(ts: number): string {
	const d = new Date(ts);
	const h = String(d.getHours()).padStart(2, "0");
	const m = String(d.getMinutes()).padStart(2, "0");
	const s = String(d.getSeconds()).padStart(2, "0");
	return `${h}:${m}:${s}`;
}

// ── Individual log line ───────────────────────────────────────────────────

function LogLine({ log }: { log: ScanLog }) {
	return (
		<div className="scan-log-line group">
			<div className="scan-log-time">{timeFmt(log.createdAt)}</div>
			<div className={`scan-log-dot ${levelDot(log.level)}`} />
			<div className="scan-log-phase">{phaseLabel(log.phase)}</div>
			<div className={`scan-log-msg ${levelColor(log.level)}`}>
				{log.message}
				{log.detail && (
					<span className="scan-log-detail">{log.detail}</span>
				)}
			</div>
		</div>
	);
}

// ── Active scan card with expandable live log ─────────────────────────────

function ActiveScanCard({ scan }: { scan: ActiveScan }) {
	const [expanded, setExpanded] = useState(true);
	const logs = useQuery(api.scanLogs.getScanLogs, {
		workflowRunId: scan._id,
		limit: 50,
	});
	const scrollRef = useRef<HTMLDivElement>(null);
	const prevLogCount = useRef(0);

	// Auto-scroll to bottom when new logs arrive
	useEffect(() => {
		if (!logs || !scrollRef.current) return;
		if (logs.length > prevLogCount.current) {
			scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
		}
		prevLogCount.current = logs.length;
	}, [logs]);

	const isRunning = scan.status === "running";

	return (
		<div className="scan-active-card">
			{/* Header */}
			<button
				type="button"
				onClick={() => setExpanded(!expanded)}
				className="scan-active-header"
			>
				<div className="flex items-center gap-2.5 min-w-0">
					{isRunning ? (
						<Loader2 size={16} className="animate-spin text-[var(--signal)] shrink-0" />
					) : (
						<Clock size={16} className="text-[var(--warning)] shrink-0" />
					)}
					<span className="text-sm font-semibold text-[var(--sea-ink)] truncate">
						{scan.repositoryFullName}
					</span>
					{isRunning && (
						<span className="scan-live-badge">
							<span className="scan-live-pulse" />
							LIVE
						</span>
					)}
				</div>
				<div className="flex items-center gap-3 shrink-0">
					<span className="text-xs text-[var(--sea-ink-soft)] tabular-nums">
						{scan.completedTaskCount}/{scan.totalTaskCount} tasks
					</span>
					{expanded ? (
						<ChevronDown size={16} className="text-[var(--sea-ink-soft)]" />
					) : (
						<ChevronRight size={16} className="text-[var(--sea-ink-soft)]" />
					)}
				</div>
			</button>

			{/* Summary bar */}
			<div className="scan-active-summary">
				<span className="text-xs text-[var(--sea-ink-soft)]">
					{scan.workflowType.replace(/_/g, " ")}
				</span>
				<span className="text-xs text-[var(--sea-ink-dim)]">·</span>
				<span className="text-xs text-[var(--sea-ink-soft)]">
					{timeFmt(scan.startedAt)}
				</span>
			</div>

			{/* Live log terminal */}
			{expanded && (
				<div className="scan-terminal" ref={scrollRef}>
					{logs && logs.length > 0 ? (
						logs.map((log: ScanLog) => (
							<LogLine key={log._id} log={log} />
						))
					) : (
						<div className="scan-terminal-empty">
							<Loader2 size={14} className="animate-spin text-[var(--sea-ink-dim)]" />
							<span>Waiting for scan output...</span>
						</div>
					)}
				</div>
			)}
		</div>
	);
}

// ── Recent activity feed (compact, when no scans are active) ──────────────

function RecentActivityFeed({ entries }: { entries: ScanLog[] }) {
	return (
		<div className="scan-terminal scan-terminal-compact">
			{entries.length > 0 ? (
				entries.slice(0, 15).map((log) => (
					<LogLine key={log._id} log={log} />
				))
			) : (
				<div className="scan-terminal-empty">
					<Terminal size={14} className="text-[var(--sea-ink-dim)]" />
					<span>No scan activity yet. Trigger a scan from the repositories page.</span>
				</div>
			)}
		</div>
	);
}

// ── Main panel ────────────────────────────────────────────────────────────

export default function LiveScanPanel() {
	const tenantSlug = useTenantSlug();
	const activeScans = useQuery(api.scanLogs.getActiveScans, { tenantSlug });
	const recentActivity = useQuery(api.scanLogs.getRecentScanActivity, {
		tenantSlug,
		limit: 20,
	});

	const hasActiveScans = activeScans && activeScans.length > 0;
	const hasRecentActivity = recentActivity && recentActivity.length > 0;

	return (
		<div className="scan-panel">
			{/* Section header */}
			<div className="scan-panel-header">
				<h2 className="section-title">
					<span className="inline-flex items-center gap-2">
						<Terminal size={15} className="text-[var(--signal)]" />
						Live Scan Activity
					</span>
				</h2>
				{hasActiveScans && (
					<span className="scan-live-badge">
						<span className="scan-live-pulse" />
						{activeScans.length} scan{activeScans.length > 1 ? "s" : ""} running
					</span>
				)}
			</div>

			{/* Active scans */}
			{hasActiveScans ? (
				<div className="space-y-3">
					{activeScans.map((scan: ActiveScan) => (
						<ActiveScanCard key={scan._id} scan={scan} />
					))}
				</div>
			) : (
				/* Recent activity or empty state */
				<div className="card card-sm">
					<div className="flex items-center justify-between mb-3">
						<span className="text-xs font-semibold text-[var(--sea-ink-soft)] tracking-[0.1em] uppercase">
							Recent Activity
						</span>
						<span className="text-xs text-[var(--sea-ink-dim)]">
							{hasRecentActivity ? "Last 20 events" : "Idle"}
						</span>
					</div>
					{hasRecentActivity ? (
						<RecentActivityFeed entries={recentActivity as ScanLog[]} />
					) : (
						<div className="scan-terminal scan-terminal-compact">
							<div className="scan-terminal-empty">
								<Terminal size={14} className="text-[var(--sea-ink-dim)]" />
								<span>No scan activity yet. Trigger a scan from the repositories page.</span>
							</div>
						</div>
					)}
				</div>
			)}
		</div>
	);
}
