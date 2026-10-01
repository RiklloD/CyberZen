import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import {
	AlertTriangle,
	CheckCircle2,
	Clock,
	Download,
	EyeOff,
	Layers,
	Search,
	ShieldAlert,
	UserCheck,
	Wrench,
	X,
	Zap,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import ExportMenu from "../components/ExportMenu";
import FindingListRow from "../components/FindingListRow";
import FindingSheet from "../components/FindingSheet";
import QueryErrorFallback from "../components/QueryErrorFallback";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import {
	compareByPriority,
	countBySeverity,
	type FindingGroup,
	type FindingRow,
	groupFindings,
	isExploitable,
} from "../lib/findings";
import { humanize, repoShortName, SEVERITY_ORDER } from "../lib/format";
import { useTenantSlug } from "../lib/workspace";

type StatusView = "open" | "resolved" | "suppressed" | "all";

type FindingsSearch = {
	id?: string;
	q?: string;
	status?: StatusView;
	/** A severity level, or "urgent" for critical + high. */
	severity?: string;
	repo?: string;
	source?: string;
	exploitable?: boolean;
	fixable?: boolean;
	flat?: boolean;
};

const STATUS_VIEWS: { value: StatusView; label: string; statuses: string[] | null }[] = [
	{ value: "open", label: "Open", statuses: ["open", "pr_opened"] },
	{ value: "resolved", label: "Resolved", statuses: ["resolved", "merged"] },
	{
		value: "suppressed",
		label: "Suppressed",
		statuses: ["accepted_risk", "false_positive", "ignored", "snoozed"],
	},
	{ value: "all", label: "All", statuses: null },
];

const bool = (v: unknown) => (v === true || v === "true" ? true : undefined);
const str = (v: unknown) => (typeof v === "string" && v.length > 0 ? v : undefined);

export const Route = createFileRoute("/findings")({
	errorComponent: QueryErrorFallback,
	component: FindingsPage,
	validateSearch: (search: Record<string, unknown>): FindingsSearch => ({
		id: str(search.id),
		q: str(search.q),
		status: STATUS_VIEWS.some((s) => s.value === search.status)
			? (search.status as StatusView)
			: undefined,
		severity: str(search.severity),
		repo: str(search.repo),
		source: str(search.source),
		exploitable: bool(search.exploitable),
		fixable: bool(search.fixable),
		flat: bool(search.flat),
	}),
});

type BulkAction = null | "dismiss" | "assign" | "severity";

function FindingsPage() {
	const tenantSlug = useTenantSlug();
	const search = Route.useSearch();
	const navigate = useNavigate({ from: "/findings" });
	const rows = useQuery(api.findings.list, { tenantSlug, limit: 200 }) as FindingRow[] | undefined;

	const setSearch = useCallback(
		(patch: Partial<FindingsSearch>, replace = true) =>
			void navigate({ search: (prev) => ({ ...prev, ...patch }), replace }),
		[navigate],
	);

	const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

	const statusView = search.status ?? "open";
	const grouped = !search.flat;

	// Step 1: status scope (drives the severity counts shown in chips).
	const inStatus = useMemo(() => {
		if (!rows) return [];
		const view = STATUS_VIEWS.find((v) => v.value === statusView);
		return view?.statuses ? rows.filter((f) => view.statuses!.includes(f.status)) : rows;
	}, [rows, statusView]);

	// Step 2: every other filter.
	const filtered = useMemo(() => {
		const q = search.q?.toLowerCase().trim();
		return inStatus
			.filter((f) => {
				if (search.severity === "urgent") {
					if (f.severity !== "critical" && f.severity !== "high") return false;
				} else if (search.severity && f.severity !== search.severity) return false;
				if (search.repo && f.repositoryId !== search.repo) return false;
				if (search.source && f.source !== search.source) return false;
				if (search.exploitable && !isExploitable(f)) return false;
				if (search.fixable && !f.fixVersion) return false;
				if (q) {
					const hay = `${f.title} ${f.repositoryFullName} ${f.source} ${f.vulnClass} ${f.affectedPackages.join(" ")} ${f.disclosureRef ?? ""}`.toLowerCase();
					if (!hay.includes(q)) return false;
				}
				return true;
			})
			.sort(compareByPriority);
	}, [inStatus, search]);

	const groups: FindingGroup[] = useMemo(
		() =>
			grouped
				? groupFindings(filtered)
				: filtered.map((f) => ({ key: f._id, lead: f, items: [f] })),
		[filtered, grouped],
	);

	if (rows === undefined) {
		return (
			<main className="page-body-padded">
				<div className="skeleton mb-6 h-8 w-48" />
				<div className="skeleton mb-4 h-9" />
				<div className="skeleton h-[480px]" />
			</main>
		);
	}

	const severityCounts = countBySeverity(inStatus);
	const repoOptions = [
		...new Map<string, string>(rows.map((f) => [f.repositoryId, f.repositoryFullName || f.repositoryName])).entries(),
	];
	const sourceOptions = [...new Set(rows.map((f) => f.source))].sort();
	const openCount = rows.filter((f) => f.status === "open" || f.status === "pr_opened").length;
	const urgentOpen = rows.filter(
		(f) => (f.status === "open" || f.status === "pr_opened") && (f.severity === "critical" || f.severity === "high"),
	).length;

	const hasFilters =
		!!search.q || !!search.severity || !!search.repo || !!search.source || !!search.exploitable || !!search.fixable;

	// Selection / sheet navigation operates on the visible group leads.
	const activeGroupIndex = groups.findIndex((g) => g.items.some((i) => i._id === search.id));
	const activeGroup = activeGroupIndex >= 0 ? groups[activeGroupIndex] : undefined;
	const openFinding = (id: string | undefined) => setSearch({ id }, false);

	function toggleGroup(group: FindingGroup) {
		setSelectedIds((prev) => {
			const next = new Set(prev);
			const allSelected = group.items.every((i) => next.has(i._id));
			for (const i of group.items) allSelected ? next.delete(i._id) : next.add(i._id);
			return next;
		});
	}

	const visibleIds = groups.flatMap((g) => g.items.map((i) => i._id));
	const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.has(id));

	return (
		<main>
			<PageHeader
				title="Findings"
				description={
					<>
						{openCount} open
						{urgentOpen > 0 && (
							<>
								{" · "}
								<span className="text-[var(--sev-critical)]">{urgentOpen} critical or high</span>
							</>
						)}
					</>
				}
				actions={
					<>
						<Link to="/timeline" className="btn btn-ghost">
							<Clock size={14} />
							Timeline
						</Link>
						<ExportMenu
							tenantSlug={tenantSlug}
							variant="findings"
							severity={search.severity && search.severity !== "urgent" ? search.severity : undefined}
						/>
					</>
				}
			/>

			<div className="page-body">
				{/* ── Toolbar ─────────────────────────────────────────────── */}
				<div className="mb-3 flex flex-wrap items-center gap-2">
					<div className="segmented" role="group" aria-label="Status">
						{STATUS_VIEWS.map((v) => (
							<button
								key={v.value}
								type="button"
								aria-pressed={statusView === v.value}
								onClick={() => setSearch({ status: v.value === "open" ? undefined : v.value, id: undefined })}
							>
								{v.label}
							</button>
						))}
					</div>

					<label className="search-input min-w-[220px] flex-1 sm:max-w-sm">
						<Search size={14} />
						<input
							type="search"
							placeholder="Search title, package, advisory…"
							value={search.q ?? ""}
							onChange={(e) => setSearch({ q: e.target.value || undefined })}
						/>
					</label>

					<select
						className="input !w-auto"
						value={search.repo ?? ""}
						onChange={(e) => setSearch({ repo: e.target.value || undefined })}
						aria-label="Repository"
					>
						<option value="">All repositories</option>
						{repoOptions.map(([id, name]) => (
							<option key={id} value={id}>
								{repoShortName(name)}
							</option>
						))}
					</select>

					<select
						className="input !w-auto"
						value={search.source ?? ""}
						onChange={(e) => setSearch({ source: e.target.value || undefined })}
						aria-label="Source"
					>
						<option value="">All sources</option>
						{sourceOptions.map((s) => (
							<option key={s} value={s}>
								{humanize(s)}
							</option>
						))}
					</select>
				</div>

				<div className="mb-4 flex flex-wrap items-center gap-1.5">
					<button
						type="button"
						className="chip"
						aria-pressed={!search.severity}
						onClick={() => setSearch({ severity: undefined })}
					>
						All severities <span className="tab-count">{inStatus.length}</span>
					</button>
					<button
						type="button"
						className="chip"
						aria-pressed={search.severity === "urgent"}
						onClick={() => setSearch({ severity: search.severity === "urgent" ? undefined : "urgent" })}
					>
						<ShieldAlert size={12} className="text-[var(--sev-critical)]" />
						Critical + high <span className="tab-count">{severityCounts.critical + severityCounts.high}</span>
					</button>
					{SEVERITY_ORDER.map((s) =>
						severityCounts[s] === 0 && search.severity !== s ? null : (
							<button
								key={s}
								type="button"
								className="chip"
								aria-pressed={search.severity === s}
								onClick={() => setSearch({ severity: search.severity === s ? undefined : s })}
							>
								<span data-sev={s} className="h-2 w-2 rounded-[2px]" style={{ background: "var(--sev)" }} />
								{s === "informational" ? "Info" : humanize(s)}
								<span className="tab-count">{severityCounts[s]}</span>
							</button>
						),
					)}
					<span className="mx-1 h-4 w-px bg-[var(--line-strong)]" />
					<button
						type="button"
						className="chip"
						aria-pressed={!!search.exploitable}
						onClick={() => setSearch({ exploitable: search.exploitable ? undefined : true })}
					>
						<Zap size={12} />
						Exploitable
					</button>
					<button
						type="button"
						className="chip"
						aria-pressed={!!search.fixable}
						onClick={() => setSearch({ fixable: search.fixable ? undefined : true })}
					>
						<Wrench size={12} />
						Fix available
					</button>
					<button
						type="button"
						className="chip"
						aria-pressed={grouped}
						onClick={() => setSearch({ flat: grouped ? true : undefined })}
						title="Collapse identical findings in the same repository"
					>
						<Layers size={12} />
						Group duplicates
					</button>
					{hasFilters && (
						<button
							type="button"
							className="btn btn-ghost btn-sm"
							onClick={() =>
								setSearch({
									q: undefined,
									severity: undefined,
									repo: undefined,
									source: undefined,
									exploitable: undefined,
									fixable: undefined,
								})
							}
						>
							<X size={12} />
							Clear filters
						</button>
					)}
				</div>

				{/* ── List ────────────────────────────────────────────────── */}
				{groups.length === 0 ? (
					<div className="list">
						{rows.length === 0 ? (
							<EmptyState
								icon={CheckCircle2}
								title="No findings yet"
								description="Run a scan on a repository and findings will show up here, ranked by what to fix first."
								actions={
									<Link to="/repositories" className="btn btn-primary">
										Go to repositories
									</Link>
								}
							/>
						) : (
							<EmptyState
								icon={AlertTriangle}
								title="No findings match these filters"
								description={
									statusView === "open" && !hasFilters
										? "Nothing open. Nice work."
										: "Try a different status or clear the filters."
								}
							/>
						)}
					</div>
				) : (
					<div className="list">
						<div className="flex items-center gap-3 border-b border-[var(--line)] bg-[var(--surface-2)] px-4 py-2 text-xs text-[var(--text-3)]">
							<input
								type="checkbox"
								aria-label="Select all visible findings"
								checked={allVisibleSelected}
								ref={(el) => {
									if (el) el.indeterminate = !allVisibleSelected && visibleIds.some((id) => selectedIds.has(id));
								}}
								onChange={() =>
									setSelectedIds(allVisibleSelected ? new Set() : new Set(visibleIds))
								}
							/>
							<span>
								{grouped && groups.length !== filtered.length
									? `${groups.length} groups · ${filtered.length} findings`
									: `${filtered.length} findings`}
							</span>
							<span className="ml-auto hidden sm:inline">Sorted by fix priority</span>
						</div>
						{groups.map((g) => (
							<FindingListRow
								key={g.key}
								group={g}
								selected={activeGroup?.key === g.key}
								onOpen={() => openFinding(g.lead._id)}
								leading={
									<input
										type="checkbox"
										aria-label={`Select ${g.lead.title}`}
										checked={g.items.every((i) => selectedIds.has(i._id))}
										onChange={() => toggleGroup(g)}
									/>
								}
							/>
						))}
					</div>
				)}
			</div>

			{search.id && (
				<FindingSheet
					key={search.id}
					findingId={search.id as Id<"findings">}
					occurrences={activeGroup?.items}
					onSelect={(id) => setSearch({ id })}
					onClose={() => openFinding(undefined)}
					onPrev={
						activeGroupIndex > 0 ? () => setSearch({ id: groups[activeGroupIndex - 1].lead._id }) : undefined
					}
					onNext={
						activeGroupIndex >= 0 && activeGroupIndex < groups.length - 1
							? () => setSearch({ id: groups[activeGroupIndex + 1].lead._id })
							: undefined
					}
				/>
			)}

			{selectedIds.size > 0 && (
				<BulkBar
					rows={rows}
					selectedIds={selectedIds}
					onClear={() => setSelectedIds(new Set())}
				/>
			)}
		</main>
	);
}

const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;

function BulkBar({
	rows,
	selectedIds,
	onClear,
}: {
	rows: FindingRow[];
	selectedIds: Set<string>;
	onClear: () => void;
}) {
	const [action, setAction] = useState<BulkAction>(null);
	const [reason, setReason] = useState("");
	const [assignee, setAssignee] = useState("");
	const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>("high");
	const [loading, setLoading] = useState(false);
	const bulkDismiss = useMutation(api.findings.bulkDismissFindings);
	const bulkAssign = useMutation(api.findings.bulkAssignFindings);
	const bulkUpdateSeverity = useMutation(api.findings.bulkUpdateSeverity);

	async function execute() {
		const ids = Array.from(selectedIds) as Id<"findings">[];
		setLoading(true);
		try {
			if (action === "dismiss") {
				if (!reason.trim()) return;
				await bulkDismiss({ findingIds: ids, reason });
			} else if (action === "assign") {
				if (!assignee.trim()) return;
				await bulkAssign({ findingIds: ids, assigneeId: assignee });
			} else if (action === "severity") {
				await bulkUpdateSeverity({ findingIds: ids, severity });
			}
			onClear();
		} finally {
			setLoading(false);
		}
	}

	function exportCsv() {
		const selected = rows.filter((f) => selectedIds.has(f._id));
		const headers = ["ID", "Title", "Severity", "Status", "Source", "Repository", "Created At"];
		const lines = selected.map((f) => [
			f._id,
			`"${f.title.replace(/"/g, '""')}"`,
			f.severity,
			f.status,
			f.source,
			f.repositoryFullName,
			new Date(f.createdAt).toISOString(),
		]);
		const csv = [headers, ...lines].map((r) => r.join(",")).join("\n");
		const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = `findings-selected-${Date.now()}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}

	return (
		<div className="fixed bottom-5 left-1/2 z-40 w-[min(720px,calc(100vw-2rem))] -translate-x-1/2 md:ml-[calc(var(--sidebar-w)/2)]">
			<div className="flex flex-wrap items-center gap-2 rounded-[var(--radius-lg)] border border-[var(--line-strong)] bg-[var(--surface)] px-3 py-2 shadow-[var(--shadow-lg)]">
				<span className="px-1 text-[0.82rem] font-medium tabular">{selectedIds.size} selected</span>
				<span className="h-4 w-px bg-[var(--line-strong)]" />
				{action === null && (
					<>
						<button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction("dismiss")}>
							<EyeOff size={13} />
							Dismiss
						</button>
						<button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction("assign")}>
							<UserCheck size={13} />
							Assign
						</button>
						<button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction("severity")}>
							<ShieldAlert size={13} />
							Severity
						</button>
						<button type="button" className="btn btn-ghost btn-sm" onClick={exportCsv}>
							<Download size={13} />
							Export
						</button>
					</>
				)}
				{action === "dismiss" && (
					<input
						className="input !min-h-[26px] flex-1 !py-1 text-xs"
						placeholder="Reason, e.g. false positive, test fixture…"
						value={reason}
						onChange={(e) => setReason(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && void execute()}
						autoFocus
					/>
				)}
				{action === "assign" && (
					<input
						className="input !min-h-[26px] flex-1 !py-1 text-xs"
						placeholder="Assignee email"
						value={assignee}
						onChange={(e) => setAssignee(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && void execute()}
						autoFocus
					/>
				)}
				{action === "severity" && (
					<select
						className="input !min-h-[26px] !w-auto !py-0.5 text-xs"
						value={severity}
						onChange={(e) => setSeverity(e.target.value as typeof severity)}
					>
						{SEVERITIES.map((s) => (
							<option key={s} value={s}>
								{humanize(s)}
							</option>
						))}
					</select>
				)}
				{action !== null && (
					<>
						<button
							type="button"
							className="btn btn-primary btn-sm"
							onClick={execute}
							disabled={
								loading || (action === "dismiss" && !reason.trim()) || (action === "assign" && !assignee.trim())
							}
						>
							{loading ? "Applying…" : "Apply"}
						</button>
						<button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction(null)}>
							Cancel
						</button>
					</>
				)}
				<button type="button" className="icon-button ml-auto !h-7 !w-7" onClick={onClear} aria-label="Clear selection">
					<X size={14} />
				</button>
			</div>
		</div>
	);
}
