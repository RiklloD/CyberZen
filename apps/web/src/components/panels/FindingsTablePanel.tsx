import type { FunctionReturnType } from "convex/server";
import type { ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp, severityTone } from "../../lib/utils";

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewFinding = OverviewData["findings"][number];

export default function FindingsTablePanel({
	findings,
	selectedId,
	onSelect,
	renderDetail,
	selectedIds,
	onToggleSelect,
}: {
	findings: OverviewFinding[];
	selectedId: string | null;
	onSelect: (id: string | null) => void;
	renderDetail?: (finding: OverviewFinding) => ReactNode;
	selectedIds?: Set<string>;
	onToggleSelect?: (id: string) => void;
}) {
	const hasSelection = selectedIds !== undefined && onToggleSelect !== undefined;
	const allSelected =
		hasSelection && findings.length > 0 && findings.every((f) => selectedIds.has(f._id));
	const someSelected = hasSelection && findings.some((f) => selectedIds.has(f._id));

	function toggleAll() {
		if (!onToggleSelect) return;
		if (allSelected) {
			for (const f of findings) onToggleSelect(f._id);
		} else {
			for (const f of findings) {
				if (!selectedIds!.has(f._id)) onToggleSelect(f._id);
			}
		}
	}

	return (
		<div className="space-y-3">
			{hasSelection && findings.length > 0 && (
				<div className="flex items-center gap-2 px-1">
					<label className="flex items-center gap-2 cursor-pointer text-xs text-[var(--sea-ink-soft)]">
						<input
							type="checkbox"
							checked={allSelected}
							ref={(el) => {
								if (el) el.indeterminate = someSelected && !allSelected;
							}}
							onChange={toggleAll}
							className="w-3.5 h-3.5 rounded accent-[var(--signal)]"
						/>
						Select all ({findings.length})
					</label>
					{selectedIds!.size > 0 && (
						<span className="text-xs font-medium text-[var(--signal)]">
							{selectedIds!.size} selected
						</span>
					)}
				</div>
			)}

			{findings.map((finding: OverviewFinding) => (
				<div key={finding._id}>
					<div className="relative flex items-start gap-2">
						{hasSelection && (
							<div className="flex-shrink-0 pt-3 pl-1">
								<input
									type="checkbox"
									checked={selectedIds!.has(finding._id)}
									onChange={() => onToggleSelect!(finding._id)}
									onClick={(e) => e.stopPropagation()}
									className="w-3.5 h-3.5 rounded accent-[var(--signal)] cursor-pointer"
								/>
							</div>
						)}
						<button
							type="button"
							onClick={() =>
								onSelect(selectedId === finding._id ? null : finding._id)
							}
							className={`card card-sm w-full text-left ${
								selectedId === finding._id
									? "border-[rgba(158,255,100,0.35)]"
									: ""
							}`}
						>
							<div className="flex flex-wrap items-center gap-2">
								<StatusPill
									label={finding.severity}
									tone={severityTone(finding.severity)}
								/>
								<StatusPill label={finding.source} tone="info" />
								<StatusPill
									label={finding.validationStatus}
									tone={
										finding.validationStatus === "validated"
											? "success"
											: finding.validationStatus === "likely_exploitable"
												? "warning"
												: "neutral"
									}
								/>
								<StatusPill
									label={finding.status.replace(/_/g, " ")}
									tone={finding.status === "open" ? "danger" : "neutral"}
								/>
							</div>
							<h3 className="mt-2 text-sm font-semibold text-[var(--sea-ink)]">
								{finding.title}
							</h3>
							<div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--sea-ink-soft)]">
								<span>
									Confidence: {Math.round(finding.confidence * 100)}%
								</span>
								<span>Raised: {formatTimestamp(finding.createdAt)}</span>
							</div>
						</button>
					</div>
					{selectedId === finding._id && renderDetail?.(finding)}
				</div>
			))}
			{findings.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<AlertTriangle size={24} className="mb-2 opacity-40" />
					<p>No findings match the current filter.</p>
				</div>
			)}
		</div>
	);
}

export type { OverviewFinding };
