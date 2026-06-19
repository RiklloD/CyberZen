import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "../lib/clerk-compat";
import { useQuery } from "convex/react";
import { ScrollText, Search, ShieldCheck, Loader2 } from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/audit-log")({
	errorComponent: RouteErrorBoundary,
	component: AuditLogPage,
});

const ACTION_OPTIONS = [
	"role.created",
	"role.updated",
	"role.deleted",
	"role.assigned",
	"role.removed",
	"api_key.created",
	"api_key.rotated",
	"api_key.revoked",
	"member.invited",
	"member.removed",
	"member.role_changed",
	"finding.false_positive",
	"finding.snoozed",
	"risk.accepted",
	"risk.revoked",
	"gate.override",
	"scan.triggered",
];

const RESOURCE_TYPE_OPTIONS = [
	"users",
	"roles",
	"apiKeys",
	"findings",
	"repositories",
	"gateDecisions",
];

function AuditLogPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";

	const [actionFilter, setActionFilter] = useState<string | undefined>(undefined);
	const [resourceTypeFilter, setResourceTypeFilter] = useState<string | undefined>(undefined);
	const [searchQuery, setSearchQuery] = useState("");
	const [shouldVerify, setShouldVerify] = useState(false);

	const entries = useQuery(
		api.auditLog.listForTenant,
		authToken
			? {
					authToken,
					tenantSlug: TENANT,
					actionFilter,
					resourceTypeFilter,
					limit: 200,
				}
			: "skip",
	);

	const integrityResult = useQuery(
		api.auditLog.verifyAuditIntegrity,
		shouldVerify && authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<ScrollText size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Audit Log</h1>
						<p className="page-subtitle">
							Track all actions across your workspace
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<AuditLogFilters
					actionFilter={actionFilter}
					resourceTypeFilter={resourceTypeFilter}
					onActionFilterChange={setActionFilter}
					onResourceTypeFilterChange={setResourceTypeFilter}
					searchQuery={searchQuery}
					onSearchQueryChange={setSearchQuery}
				/>

				{entries ? (
					<AuditLogTable entries={entries} searchQuery={searchQuery} />
				) : (
					<div className="space-y-2">
						{["a", "b", "c", "d", "e"].map((k) => (
							<div key={k} className="loading-panel h-14 rounded-2xl" />
						))}
					</div>
				)}

				<div className="card card-sm space-y-3 mt-6">
					<div className="flex items-center gap-2">
						<ShieldCheck size={16} className="text-[var(--signal)]" />
						<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
							Audit Trail Integrity
						</h2>
					</div>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Verify cryptographic hash chain integrity of the audit log.
					</p>

					{!shouldVerify ? (
						<button
							type="button"
							className="signal-button inline-flex items-center gap-1.5 text-xs"
							onClick={() => setShouldVerify(true)}
						>
							<ShieldCheck size={12} />
							Verify Audit Trail Integrity
						</button>
					) : integrityResult === undefined ? (
						<div className="flex items-center gap-2 text-xs text-[var(--sea-ink-soft)]">
							<Loader2 size={14} className="animate-spin" />
							Verifying…
						</div>
					) : (
						<div className="space-y-2">
							<div
								className={`text-xs px-3 py-2 rounded-lg border font-medium ${integrityResult.isIntact ? "text-[var(--success)] border-[var(--success)]" : "text-[var(--danger)] border-[var(--danger)]"}`}
							>
								{integrityResult.isIntact
									? "Audit trail is intact — no tampering detected."
									: `Integrity violation detected at entry: ${integrityResult.brokenAt ?? "unknown"}`}
							</div>
							<div className="grid grid-cols-2 md:grid-cols-4 gap-3">
								<div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-3">
									<div className="text-[11px] text-[var(--sea-ink-soft)]">Total Entries</div>
									<div className="text-sm font-semibold text-[var(--sea-ink)]">{integrityResult.totalEntries}</div>
								</div>
								<div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-3">
									<div className="text-[11px] text-[var(--sea-ink-soft)]">Verified</div>
									<div className="text-sm font-semibold text-[var(--sea-ink)]">{integrityResult.verifiedEntries}</div>
								</div>
								{integrityResult.preHashEraEntries !== undefined && integrityResult.preHashEraEntries > 0 && (
									<div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] p-3">
										<div className="text-[11px] text-[var(--sea-ink-soft)]">Pre-Hash Era</div>
										<div className="text-sm font-semibold text-[var(--sea-ink)]">{integrityResult.preHashEraEntries}</div>
									</div>
								)}
							</div>
							<button
								type="button"
								className="text-xs text-[var(--signal)] hover:underline"
								onClick={() => setShouldVerify(false)}
							>
								Reset
							</button>
						</div>
					)}
				</div>
			</div>
		</main>
	);
}

// ─── AuditLogFilters ────────────────────────────────────────────────────────

interface AuditLogFiltersProps {
	actionFilter: string | undefined;
	resourceTypeFilter: string | undefined;
	searchQuery: string;
	onActionFilterChange: (v: string | undefined) => void;
	onResourceTypeFilterChange: (v: string | undefined) => void;
	onSearchQueryChange: (v: string) => void;
}

function AuditLogFilters({
	actionFilter,
	resourceTypeFilter,
	searchQuery,
	onActionFilterChange,
	onResourceTypeFilterChange,
	onSearchQueryChange,
}: AuditLogFiltersProps) {
	return (
		<div className="flex flex-wrap items-center gap-2 mb-4">
			<div className="relative">
				<Search
					size={14}
					className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--sea-ink-soft)]"
				/>
				<input
					type="text"
					value={searchQuery}
					onChange={(e) => onSearchQueryChange(e.target.value)}
					placeholder="Search actions, resources..."
					className="rounded-lg border border-[var(--line)] bg-[var(--surface)] pl-8 pr-3 py-1.5 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
					style={{ width: "220px" }}
				/>
			</div>

			<select
				value={actionFilter ?? ""}
				onChange={(e) =>
					onActionFilterChange(e.target.value || undefined)
				}
				className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
			>
				<option value="">All Actions</option>
				{ACTION_OPTIONS.map((a) => (
					<option key={a} value={a}>
						{a}
					</option>
				))}
			</select>

			<select
				value={resourceTypeFilter ?? ""}
				onChange={(e) =>
					onResourceTypeFilterChange(e.target.value || undefined)
				}
				className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
			>
				<option value="">All Resources</option>
				{RESOURCE_TYPE_OPTIONS.map((r) => (
					<option key={r} value={r}>
						{r}
					</option>
				))}
			</select>

			{(actionFilter || resourceTypeFilter) && (
				<button
					type="button"
					onClick={() => {
						onActionFilterChange(undefined);
						onResourceTypeFilterChange(undefined);
					}}
					className="text-xs text-[var(--signal)] hover:underline"
				>
					Clear filters
				</button>
			)}
		</div>
	);
}

// ─── AuditLogTable ──────────────────────────────────────────────────────────

type AuditEntry = {
	_id: string;
	actorUserId?: string;
	actorEmail?: string;
	actorName?: string;
	action: string;
	resourceType: string;
	resourceId?: string;
	payload?: string;
	at: number;
	ip?: string;
	ua?: string;
};

interface AuditLogTableProps {
	entries: AuditEntry[];
	searchQuery: string;
}

function actionTone(action: string): "info" | "warning" | "danger" | "success" | "neutral" {
	if (action.includes("created") || action.includes("assigned")) return "success";
	if (action.includes("deleted") || action.includes("revoked") || action.includes("removed")) return "danger";
	if (action.includes("updated") || action.includes("rotated") || action.includes("override")) return "warning";
	if (action.includes("false_positive") || action.includes("accepted")) return "info";
	return "neutral";
}

function formatTime(ts: number): string {
	const d = new Date(ts);
	return d.toLocaleString(undefined, {
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	});
}

function AuditLogTable({ entries, searchQuery }: AuditLogTableProps) {
	const filtered = searchQuery
		? entries.filter(
				(e) =>
					e.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
					e.resourceType.toLowerCase().includes(searchQuery.toLowerCase()) ||
					(e.actorEmail ?? "").toLowerCase().includes(searchQuery.toLowerCase()) ||
					(e.actorName ?? "").toLowerCase().includes(searchQuery.toLowerCase()) ||
					(e.resourceId ?? "").toLowerCase().includes(searchQuery.toLowerCase()),
			)
		: entries;

	return (
		<div className="space-y-1.5">
			<div className="flex items-center gap-2 mb-2">
				<StatusPill
					label={`${filtered.length} event${filtered.length !== 1 ? "s" : ""}`}
					tone="neutral"
				/>
			</div>

			{filtered.map((entry) => (
				<div key={entry._id} className="card card-sm">
					<div className="flex items-start justify-between gap-3">
						<div className="flex items-start gap-3 min-w-0">
							<div className="flex-shrink-0 mt-0.5">
								<StatusPill
									label={entry.action}
									tone={actionTone(entry.action)}
								/>
							</div>
							<div className="min-w-0">
								<p className="text-sm text-[var(--sea-ink)]">
									<span className="font-semibold">{entry.resourceType}</span>
									{entry.resourceId && (
										<span className="text-[var(--sea-ink-soft)] ml-1.5 text-xs">
											{entry.resourceId.slice(0, 12)}…
										</span>
									)}
								</p>
								<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
									{entry.actorName || entry.actorEmail || "System"}{" "}
									{entry.ip && (
										<span className="ml-1 opacity-60">from {entry.ip}</span>
									)}
								</p>
								{entry.payload && (
									<details className="mt-1">
										<summary className="text-[0.65rem] text-[var(--signal)] cursor-pointer hover:underline">
											Details
										</summary>
										<pre className="mt-1 text-[0.65rem] text-[var(--sea-ink-soft)] bg-[var(--surface)] rounded-lg p-2 overflow-x-auto max-w-full">
											{(() => {
												try {
													return JSON.stringify(JSON.parse(entry.payload), null, 2);
												} catch {
													return entry.payload;
												}
											})()}
										</pre>
									</details>
								)}
							</div>
						</div>

						<div className="flex-shrink-0 text-right">
							<p className="text-xs text-[var(--sea-ink-soft)] whitespace-nowrap">
								{formatTime(entry.at)}
							</p>
						</div>
					</div>
				</div>
			))}

			{filtered.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<ScrollText size={24} className="mb-2 opacity-40" />
					<p>
						{entries.length === 0
							? "No audit log entries yet."
							: "No entries match your filters."}
					</p>
				</div>
			)}
		</div>
	);
}
