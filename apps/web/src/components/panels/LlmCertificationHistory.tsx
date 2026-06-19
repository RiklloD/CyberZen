import type { FunctionReturnType } from "convex/server";
import { History } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type CertReport = NonNullable<
	FunctionReturnType<
		typeof api.llmCertificationIntel.getLatestCertificationReport
	>
>;

type HistoryEntry = CertReport;

function overallTone(
	status: string,
): "success" | "warning" | "danger" | "neutral" {
	if (status === "certified") return "success";
	if (status === "pending") return "warning";
	if (status === "uncertified") return "danger";
	return "neutral";
}

export default function LlmCertificationHistory({
	history }: {
	history: HistoryEntry[];
}) {
	if (history.length === 0) {
		return (
			<div className="card">
				<div className="flex items-center gap-2 mb-3">
					<History size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Certification History</h3>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)] italic">
					No historical certification data yet. Past certification outcomes
					will appear here as they complete.
				</p>
			</div>
		);
	}

	// Chronological: newest first (already returned that way from backend)

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<History size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Certification History</h3>
				</div>
				<StatusPill label={`${history.length} records`} tone="neutral" />
			</div>

			<div className="space-y-1.5 max-h-64 overflow-y-auto">
				{history.map((entry) => {
					const certifiedPaths = entry.paths.filter(
						(p: CertReport["paths"][number]) => p.status === "certified",
					).length;
					const totalPaths = entry.totalPaths || entry.paths.length;

					return (
						<div
							key={entry._id}
							className="flex items-center justify-between gap-2 text-xs py-1.5 px-2 rounded-lg hover:bg-[rgba(130,122,110,0.05)]"
						>
							<div className="flex items-center gap-2 min-w-0">
								<StatusPill
									label={entry.overallStatus}
									tone={overallTone(entry.overallStatus)}
								/>
								<span className="text-[var(--sea-ink)] font-medium truncate">
									{certifiedPaths}/{totalPaths} paths
								</span>
							</div>

							<div className="flex items-center gap-2 shrink-0">
								{entry.certifiedAt && (
									<span className="text-[var(--sea-ink-soft)]">
										{formatTimestamp(entry.certifiedAt)}
									</span>
								)}
								{!entry.certifiedAt && (
									<span className="text-[var(--sea-ink-soft)]">
										{formatTimestamp(entry._creationTime)}
									</span>
								)}

								{entry.uncertifiedPaths > 0 && (
									<StatusPill
										label={`${entry.uncertifiedPaths} failed`}
										tone="danger"
									/>
								)}

								{entry.paths.some((p: CertReport["paths"][number]) => p.failureReasons.length > 0) && (
									<StatusPill
										label={`${entry.paths.reduce((sum: number, p: CertReport["paths"][number]) => sum + p.failureReasons.length, 0)} issues`}
										tone="warning"
									/>
								)}
							</div>
						</div>
					);
				})}
			</div>

			{/* Trend summary */}
			<div className="mt-3 pt-3 border-t border-[var(--line)]">
				<div className="flex items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
					<span>
						Latest:{" "}
						<strong className="text-[var(--sea-ink)]">
							{history[0].overallStatus}
						</strong>
					</span>
					{history.length > 1 && (
						<span>
							Previous:{" "}
							<strong className="text-[var(--sea-ink)]">
								{history[1].overallStatus}
							</strong>
						</span>
					)}
					{history[0].summary && (
						<span className="truncate flex-1 text-right">
							{history[0].summary}
						</span>
					)}
				</div>
			</div>
		</div>
	);
}
