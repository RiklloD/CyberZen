import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useMutation } from "convex/react";
import { AlertTriangle, X, Download, UserCheck, ShieldAlert, EyeOff } from "lucide-react";
import { useState, useCallback } from "react";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import FindingsSeverityFilterChips, {
	type SeverityFilter,
} from "../components/panels/FindingsSeverityFilterChips";
import FindingsTablePanel, {
	type OverviewFinding,
} from "../components/panels/FindingsTablePanel";
import FindingDetailDrawer from "../components/panels/FindingDetailDrawer";
import ExportMenu from "../components/ExportMenu";
import QueryErrorFallback from "../components/QueryErrorFallback";

export const Route = createFileRoute("/findings")({ errorComponent: QueryErrorFallback, component: FindingsPage });

type BulkAction = null | "dismiss" | "assign" | "severity";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;

function FindingsPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
	const [selected, setSelected] = useState<string | null>(null);

	// Bulk selection state
	const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
	const [bulkAction, setBulkAction] = useState<BulkAction>(null);
	const [bulkReason, setBulkReason] = useState("");
	const [bulkAssignee, setBulkAssignee] = useState("");
	const [bulkSeverity, setBulkSeverity] = useState<(typeof SEVERITIES)[number]>("high");
	const [bulkLoading, setBulkLoading] = useState(false);

	const bulkDismiss = useMutation(api.findings.bulkDismissFindings);
	const bulkAssign = useMutation(api.findings.bulkAssignFindings);
	const bulkUpdateSeverity = useMutation(api.findings.bulkUpdateSeverity);

	function toggleSelect(id: string) {
		setSelectedIds((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			return next;
		});
	}

	function clearSelection() {
		setSelectedIds(new Set());
		setBulkAction(null);
		setBulkReason("");
		setBulkAssignee("");
	}

	async function executeBulkAction() {
		if (selectedIds.size === 0) return;
		const ids = Array.from(selectedIds) as Id<"findings">[];
		setBulkLoading(true);
		try {
			if (bulkAction === "dismiss") {
				if (!bulkReason.trim()) return;
				await bulkDismiss({ findingIds: ids, reason: bulkReason });
			} else if (bulkAction === "assign") {
				if (!bulkAssignee.trim()) return;
				await bulkAssign({ findingIds: ids, assigneeId: bulkAssignee });
			} else if (bulkAction === "severity") {
				await bulkUpdateSeverity({ findingIds: ids, severity: bulkSeverity });
			}
			clearSelection();
		} finally {
			setBulkLoading(false);
		}
	}

	const exportSelectedAsCsv = useCallback(() => {
		if (!overview) return;
		const selected = overview.findings.filter((f: OverviewFinding) =>
			selectedIds.has(f._id),
		);
		const headers = ["ID", "Title", "Severity", "Status", "Source", "Repository", "Created At"];
		const rows = selected.map((f: OverviewFinding) => [
			f._id,
			`"${f.title.replace(/"/g, '""')}"`,
			f.severity,
			f.status,
			f.source,
			f.repositoryFullName ?? "",
			new Date(f.createdAt).toISOString(),
		]);
		const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
		const blob = new Blob([csv], { type: "text/csv" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `findings-selected-${Date.now()}.csv`;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}, [overview, selectedIds]);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3">
					{["a", "b", "c", "d"].map((k) => (
						<div key={k} className="loading-panel h-24 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const findings = overview.findings.filter(
		(f: OverviewFinding) =>
			severityFilter === "all" || f.severity === severityFilter,
	);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<AlertTriangle size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Findings</h1>
						<p className="page-subtitle">
							{overview.findings.length} total open findings ·{" "}
							{overview.stats.criticalFindings} critical/high
						</p>
					</div>
					<div className="ml-auto">
						<ExportMenu tenantSlug={TENANT} variant="findings" severity={severityFilter !== "all" ? severityFilter : undefined} />
					</div>
				</div>
			</div>

			<div className="page-body">
				<FindingsSeverityFilterChips
					findings={overview.findings}
					severityFilter={severityFilter}
					onChange={setSeverityFilter}
				/>

				<FindingsTablePanel
					findings={findings}
					selectedId={selected}
					onSelect={setSelected}
					renderDetail={(finding) => (
						<FindingDetailDrawer
							findingId={finding._id as Id<"findings">}
							finding={finding}
						/>
					)}
					selectedIds={selectedIds}
					onToggleSelect={toggleSelect}
				/>
			</div>

			{/* Sticky bulk action bar */}
			{selectedIds.size > 0 && (
				<div className="fixed bottom-0 left-0 right-0 z-30 border-t border-[var(--line)] bg-[var(--panel-bg)] shadow-2xl">
					<div className="max-w-7xl mx-auto px-4 py-3">
						{/* Header row */}
						<div className="flex items-center gap-3 mb-3">
							<span className="text-sm font-semibold text-[var(--sea-ink)]">
								{selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""} selected
							</span>
							<div className="flex items-center gap-2 ml-auto">
								<button
									type="button"
									className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)] transition-colors"
									onClick={exportSelectedAsCsv}
								>
									<Download size={12} />
									Export CSV
								</button>
								<button
									type="button"
									className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)]"
									onClick={clearSelection}
									aria-label="Clear selection"
								>
									<X size={16} />
								</button>
							</div>
						</div>

						{/* Action buttons */}
						{!bulkAction && (
							<div className="flex items-center gap-2">
								<button
									type="button"
									className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] hover:text-red-500 transition-colors"
									onClick={() => setBulkAction("dismiss")}
								>
									<EyeOff size={12} />
									Dismiss
								</button>
								<button
									type="button"
									className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
									onClick={() => setBulkAction("assign")}
								>
									<UserCheck size={12} />
									Assign
								</button>
								<button
									type="button"
									className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] hover:text-amber-500 transition-colors"
									onClick={() => setBulkAction("severity")}
								>
									<ShieldAlert size={12} />
									Change Severity
								</button>
							</div>
						)}

						{/* Dismiss form */}
						{bulkAction === "dismiss" && (
							<div className="flex items-center gap-2">
								<span className="text-xs text-[var(--sea-ink-soft)]">Reason:</span>
								<input
									type="text"
									className="input-field flex-1 text-xs py-1"
									placeholder="e.g., False positive, risk accepted..."
									value={bulkReason}
									onChange={(e) => setBulkReason(e.target.value)}
									autoFocus
								/>
								<button
									type="button"
									className="signal-button text-xs px-3 py-1.5"
									onClick={executeBulkAction}
									disabled={bulkLoading || !bulkReason.trim()}
								>
									{bulkLoading ? "Dismissing..." : "Dismiss"}
								</button>
								<button
									type="button"
									className="secondary-button text-xs px-3 py-1.5"
									onClick={() => setBulkAction(null)}
								>
									Cancel
								</button>
							</div>
						)}

						{/* Assign form */}
						{bulkAction === "assign" && (
							<div className="flex items-center gap-2">
								<span className="text-xs text-[var(--sea-ink-soft)]">Assign to:</span>
								<input
									type="text"
									className="input-field flex-1 text-xs py-1"
									placeholder="e.g., alice@example.com"
									value={bulkAssignee}
									onChange={(e) => setBulkAssignee(e.target.value)}
									autoFocus
								/>
								<button
									type="button"
									className="signal-button text-xs px-3 py-1.5"
									onClick={executeBulkAction}
									disabled={bulkLoading || !bulkAssignee.trim()}
								>
									{bulkLoading ? "Assigning..." : "Assign"}
								</button>
								<button
									type="button"
									className="secondary-button text-xs px-3 py-1.5"
									onClick={() => setBulkAction(null)}
								>
									Cancel
								</button>
							</div>
						)}

						{/* Change severity form */}
						{bulkAction === "severity" && (
							<div className="flex items-center gap-2">
								<span className="text-xs text-[var(--sea-ink-soft)]">Severity:</span>
								<select
									className="input-field text-xs py-1"
									value={bulkSeverity}
									onChange={(e) => setBulkSeverity(e.target.value as typeof bulkSeverity)}
								>
									{SEVERITIES.map((s) => (
										<option key={s} value={s}>
											{s.charAt(0).toUpperCase() + s.slice(1)}
										</option>
									))}
								</select>
								<button
									type="button"
									className="signal-button text-xs px-3 py-1.5"
									onClick={executeBulkAction}
									disabled={bulkLoading}
								>
									{bulkLoading ? "Updating..." : "Update"}
								</button>
								<button
									type="button"
									className="secondary-button text-xs px-3 py-1.5"
									onClick={() => setBulkAction(null)}
								>
									Cancel
								</button>
							</div>
						)}
					</div>
				</div>
			)}
		</main>
	);
}
