import { useQuery } from "convex/react";
import { Activity } from "lucide-react";
import { api } from "../lib/convex";
import { absoluteTime, humanize, relativeTime, repoShortName } from "../lib/format";
import { useTenantSlug } from "../lib/workspace";
import EmptyState from "./ui/EmptyState";

const LEVEL_COLOR: Record<string, string> = {
	success: "var(--success)",
	warning: "var(--warning)",
	error: "var(--danger)",
	info: "var(--info)",
};

/**
 * One row per recent scan run: its latest log line, repo, and age.
 * The raw log stream is noisy; this answers "what has CyberZen been doing?".
 */
export default function ActivityFeed({ limit = 6 }: { limit?: number }) {
	const tenantSlug = useTenantSlug();
	const logs = useQuery(api.scanLogs.getRecentScanActivity, { tenantSlug, limit: 80 });

	if (logs === undefined) {
		return <div className="skeleton h-48" />;
	}

	type Log = (typeof logs)[number];
	const runs = new Map<string, { latest: Log; count: number; hasError: boolean }>();
	for (const log of logs) {
		const run = runs.get(log.workflowRunId);
		if (run) {
			run.count++;
			run.hasError ||= log.level === "error";
		} else {
			runs.set(log.workflowRunId, { latest: log, count: 1, hasError: log.level === "error" });
		}
	}
	const rows = [...runs.values()].slice(0, limit);

	if (rows.length === 0) {
		return (
			<div className="list">
				<EmptyState
					icon={Activity}
					title="No scan activity yet"
					description="Activity from scans and agents shows up here as it happens."
				/>
			</div>
		);
	}

	return (
		<div className="list">
			{rows.map(({ latest, hasError }) => {
				const running = latest.status === "running" || latest.status === "queued";
				const color = hasError ? LEVEL_COLOR.error : LEVEL_COLOR[latest.level] ?? LEVEL_COLOR.info;
				return (
					<div key={latest.workflowRunId} className="list-row !items-start">
						<span className="relative mt-1.5 flex h-2 w-2 shrink-0">
							{running && (
								<span
									className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60"
									style={{ background: color }}
								/>
							)}
							<span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: color }} />
						</span>
						<div className="min-w-0 flex-1">
							<p className="truncate text-[0.82rem] text-[var(--text)]">{latest.message}</p>
							<p className="truncate text-xs text-[var(--text-3)]">
								{repoShortName(latest.repositoryFullName)} · {humanize(latest.workflowType)}
								{latest.detail ? ` · ${latest.detail}` : ""}
							</p>
						</div>
						<span
							className="shrink-0 text-xs text-[var(--text-3)] tabular"
							title={absoluteTime(latest.createdAt)}
						>
							{running ? "Running" : relativeTime(latest.createdAt)}
						</span>
					</div>
				);
			})}
		</div>
	);
}
