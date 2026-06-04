import type { FunctionReturnType } from "convex/server";
import { useMutation } from "convex/react";
import { AlertTriangle, RefreshCw, Send, Shield } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type LatestPush = NonNullable<
	FunctionReturnType<typeof api.siemIntel.getLatestSiemPush>
>;

type HistoryEntry = {
	splunkStatus: string;
	elasticStatus: string;
	pushedAt: number;
};

function siemStatusTone(
	status: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (status === "ok") return "success";
	if (status === "error") return "danger";
	if (status === "skipped") return "neutral";
	return "neutral";
}

export interface SiemIntelPanelProps {
	latestPush: LatestPush | undefined;
	history: HistoryEntry[] | undefined;
	repositoryId: string;
}

export default function SiemIntelPanel({
	latestPush,
	history,
	repositoryId,
}: SiemIntelPanelProps) {
	const triggerPush = useMutation(api.siemIntel.triggerSiemPushForRepository);
	const [retrying, setRetrying] = useState(false);

	const handleRetry = async () => {
		setRetrying(true);
		try {
			await triggerPush({ repositoryId: repositoryId as any });
		} catch {
			/* mutation error shown via convex reactive state */
		}
		setTimeout(() => setRetrying(false), 2000);
	};

	const failedInHistory =
		history?.filter(
			(e) => e.splunkStatus === "error" || e.elasticStatus === "error",
		) ?? [];

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex items-center gap-2">
				<Shield size={16} className="text-[var(--signal)]" />
				<h3 className="section-title">SIEM Intel</h3>
				<StatusPill
					label={latestPush ? "configured" : "no pushes yet"}
					tone={latestPush ? "info" : "neutral"}
				/>
			</div>

			{/* Destination Status Cards */}
			<div className="grid gap-3 sm:grid-cols-2">
				{/* Splunk HEC */}
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<Send size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">
							Splunk HEC
						</span>
					</div>
					<div className="flex items-center justify-between mb-1.5">
						<span className="text-sm font-semibold text-[var(--sea-ink)]">
							Status
						</span>
						<StatusPill
							label={latestPush?.splunkStatus ?? "—"}
							tone={siemStatusTone(latestPush?.splunkStatus ?? "")}
						/>
					</div>
					{latestPush && (
						<>
							<div className="flex items-center justify-between text-xs">
								<span className="text-[var(--sea-ink-soft)]">Rules pushed</span>
								<span className="font-mono text-[var(--sea-ink)]">
									{latestPush.splunkRuleCount ?? 0}
								</span>
							</div>
							<div className="flex items-center justify-between text-xs mt-1">
								<span className="text-[var(--sea-ink-soft)]">Last push</span>
								<span className="text-[var(--sea-ink)]">
									{formatTimestamp(latestPush.pushedAt)}
								</span>
							</div>
							{latestPush.splunkError && (
								<p className="mt-2 text-xs text-[var(--danger)] break-all">
									{latestPush.splunkError}
								</p>
							)}
						</>
					)}
				</div>

				{/* Elastic _bulk */}
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<Send size={14} />
						<span className="text-xs font-bold uppercase tracking-wider">
							Elasticsearch
						</span>
					</div>
					<div className="flex items-center justify-between mb-1.5">
						<span className="text-sm font-semibold text-[var(--sea-ink)]">
							Status
						</span>
						<StatusPill
							label={latestPush?.elasticStatus ?? "—"}
							tone={siemStatusTone(latestPush?.elasticStatus ?? "")}
						/>
					</div>
					{latestPush && (
						<>
							<div className="flex items-center justify-between text-xs">
								<span className="text-[var(--sea-ink-soft)]">Rules pushed</span>
								<span className="font-mono text-[var(--sea-ink)]">
									{latestPush.elasticRuleCount ?? 0}
								</span>
							</div>
							<div className="flex items-center justify-between text-xs mt-1">
								<span className="text-[var(--sea-ink-soft)]">Last push</span>
								<span className="text-[var(--sea-ink)]">
									{formatTimestamp(latestPush.pushedAt)}
								</span>
							</div>
							{latestPush.elasticError && (
								<p className="mt-2 text-xs text-[var(--danger)] break-all">
									{latestPush.elasticError}
								</p>
							)}
						</>
					)}
				</div>
			</div>

			{/* Retry CTA */}
			{(latestPush?.splunkStatus === "error" ||
				latestPush?.elasticStatus === "error" ||
				!latestPush) && (
				<div className="card card-sm">
					<div className="flex items-center justify-between gap-3">
						<div className="flex items-center gap-2">
							<AlertTriangle
								size={14}
								className={
									latestPush ? "text-[var(--danger)]" : "text-[var(--sea-ink-soft)]"
								}
							/>
							<span className="text-xs text-[var(--sea-ink)]">
								{latestPush
									? "One or more destinations reported errors — retry the push now."
									: "No SIEM push recorded for this repository. Trigger a manual push to deliver detection rules."}
							</span>
						</div>
						<button
							type="button"
							className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--signal)]/30 bg-[var(--signal)]/10 px-3 py-1.5 text-xs font-semibold text-[var(--signal)] transition hover:bg-[var(--signal)]/20 disabled:opacity-50"
							onClick={handleRetry}
							disabled={retrying}
						>
							<RefreshCw
								size={12}
								className={retrying ? "animate-spin" : ""}
							/>
							{retrying ? "Scheduling…" : "Retry Push"}
						</button>
					</div>
				</div>
			)}

			{/* Push Attempt History */}
			{history && history.length > 0 && (
				<div>
					<h3 className="section-title mb-3">
						Push Attempt History (last {history.length})
					</h3>
					<div className="card">
						<table className="data-table">
							<thead>
								<tr>
									<th>Timestamp</th>
									<th>Splunk</th>
									<th>Elastic</th>
								</tr>
							</thead>
							<tbody>
								{history.map((entry, idx) => (
									<tr key={`${entry.pushedAt}-${idx}`}>
										<td className="text-[var(--sea-ink-soft)]">
											{formatTimestamp(entry.pushedAt)}
										</td>
										<td>
											<StatusPill
												label={entry.splunkStatus}
												tone={siemStatusTone(entry.splunkStatus)}
											/>
										</td>
										<td>
											<StatusPill
												label={entry.elasticStatus}
												tone={siemStatusTone(entry.elasticStatus)}
											/>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			)}

			{/* Failed Push Details */}
			{failedInHistory.length > 0 && (
				<div>
					<h3 className="section-title mb-3">Failed Pushes</h3>
					<div className="grid gap-3 sm:grid-cols-2">
						{failedInHistory.map((entry, idx) => (
							<div
								key={`fail-${entry.pushedAt}-${idx}`}
								className="card card-sm border border-[var(--danger)]/30"
							>
								<div className="flex items-center justify-between mb-2">
									<span className="text-sm font-semibold text-[var(--sea-ink)]">
										Push #{idx + 1}
									</span>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										{formatTimestamp(entry.pushedAt)}
									</span>
								</div>
								<div className="flex flex-wrap gap-1.5">
									{entry.splunkStatus === "error" && (
										<StatusPill label="Splunk failed" tone="danger" />
									)}
									{entry.elasticStatus === "error" && (
										<StatusPill label="Elastic failed" tone="danger" />
									)}
								</div>
							</div>
						))}
					</div>
				</div>
			)}

			{/* Payload Preview Hint */}
			<div className="card card-sm">
				<div className="flex items-center gap-2 mb-2">
					<Shield size={14} className="text-[var(--sea-ink-soft)]" />
					<span className="text-xs font-bold uppercase tracking-wider text-[var(--sea-ink-soft)]">
						Payload Format
					</span>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)]">
					Splunk receives JSON events via{" "}
					<code className="text-[var(--teal)]">
						POST /services/collector/event
					</code>{" "}
					(HEC). Elastic receives NDJSON via{" "}
					<code className="text-[var(--teal)]">POST /_bulk</code>. Each payload
					contains the latest detection rule snapshot for this repository,
					batched per destination format.
				</p>
			</div>
		</div>
	);
}
