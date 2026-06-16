import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "@convex-dev/auth/react";
import { useMutation, useQuery } from "convex/react";
import { LayoutDashboard, Plus, Trash2, X } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/dashboards/$id")({
	errorComponent: RouteErrorBoundary,
	component: DashboardBuilderPage,
});

// ---------------------------------------------------------------------------
// Widget type catalog
// ---------------------------------------------------------------------------

const WIDGET_CATALOG = [
	{ type: "kpi_tiles", label: "KPI Tiles", description: "Critical findings, MTTR, risk score" },
	{ type: "findings_feed", label: "Recent Findings", description: "Latest security findings feed" },
	{ type: "severity_chart", label: "Severity Distribution", description: "Pie/bar chart by severity" },
	{ type: "repo_leaderboard", label: "Repo Leaderboard", description: "Top repositories by risk score" },
	{ type: "trend_sparkline", label: "Trend Sparkline", description: "30-day trend line" },
	{ type: "gate_decisions", label: "Gate Decisions", description: "Recent CI/CD gate pass/fail" },
	{ type: "compliance_summary", label: "Compliance Summary", description: "Framework compliance status" },
	{ type: "blast_radius", label: "Blast Radius Heatmap", description: "Cross-repo exposure matrix" },
] as const;


function DashboardBuilderPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";

	// For now, show a list of dashboards + a default builder
	const dashboards = useQuery(
		api.dashboards.listDashboards,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	if (!dashboards) {
		return (
			<main>
				<div className="page-header">
					<div className="flex items-center gap-3">
						<LayoutDashboard size={20} className="text-[var(--signal)]" />
						<h1 className="page-title">Dashboard Builder</h1>
					</div>
				</div>
				<div className="page-body">
					<div className="space-y-2">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-24 rounded-2xl" />
						))}
					</div>
				</div>
			</main>
		);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<LayoutDashboard size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Dashboard Builder</h1>
						<p className="page-subtitle">Create custom dashboards with configurable widgets</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="section-header mb-3">
					<h2 className="section-title">Your Dashboards</h2>
					<StatusPill label={`${dashboards.length} dashboard${dashboards.length !== 1 ? "s" : ""}`} tone="neutral" />
					<CreateDashboardButton authToken={authToken} tenantSlug={TENANT} />
				</div>

				<div className="space-y-3">
					{dashboards.map((d: (typeof dashboards)[number]) => (
						<DashboardCard key={d._id} dashboard={d} authToken={authToken} tenantSlug={TENANT} />
					))}

					{dashboards.length === 0 && (
						<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
							<LayoutDashboard size={24} className="mb-2 opacity-40" />
							<p>No dashboards yet. Create your first custom dashboard.</p>
						</div>
					)}
				</div>

				{/* Widget Catalog Preview */}
				<div className="mt-8">
					<div className="section-header mb-3">
						<h2 className="section-title">Widget Catalog</h2>
					</div>
					<div className="grid grid-cols-2 md:grid-cols-4 gap-3">
						{WIDGET_CATALOG.map((widget) => (
							<div key={widget.type} className="card card-sm p-3">
								<div className="flex items-center gap-2 mb-1">
									<div className="w-7 h-7 rounded-lg bg-[var(--signal)]/10 flex items-center justify-center">
										<LayoutDashboard size={14} className="text-[var(--signal)]" />
									</div>
									<p className="text-xs font-semibold text-[var(--sea-ink)]">{widget.label}</p>
								</div>
								<p className="text-[0.65rem] text-[var(--sea-ink-soft)]">{widget.description}</p>
							</div>
						))}
					</div>
				</div>
			</div>
		</main>
	);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DashboardCard({
	dashboard,
	authToken,
	tenantSlug,
}: {
	dashboard: any;
	authToken: string;
	tenantSlug: string;
}) {
	const [isPending, startTransition] = useTransition();
	const deleteDashboard = useMutation(api.dashboards.deleteDashboard);

	function handleDelete() {
		if (!confirm(`Delete dashboard "${dashboard.name}"?`)) return;
		startTransition(async () => {
			await deleteDashboard({ authToken, tenantSlug, dashboardId: dashboard._id });
		});
	}

	return (
		<div className="card card-sm">
			<div className="flex items-center justify-between gap-3">
				<div className="flex items-center gap-3 min-w-0">
					<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
						<LayoutDashboard size={14} className="text-[var(--signal)]" />
					</div>
					<div className="min-w-0">
						<div className="flex items-center gap-2">
							<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">{dashboard.name}</p>
							{dashboard.isDefault && <StatusPill label="default" tone="neutral" />}
						</div>
						{dashboard.description && (
							<p className="text-xs text-[var(--sea-ink-soft)]">{dashboard.description}</p>
						)}
						<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
							Updated {new Date(dashboard.updatedAt).toLocaleDateString()}
						</p>
					</div>
				</div>
				{!dashboard.isDefault && (
					<button
						type="button"
						onClick={handleDelete}
						disabled={isPending}
						className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
						title="Delete dashboard"
					>
						<Trash2 size={14} />
					</button>
				)}
			</div>
		</div>
	);
}

function CreateDashboardButton({ authToken, tenantSlug }: { authToken: string; tenantSlug: string }) {
	const [isOpen, setIsOpen] = useState(false);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [isPending, startTransition] = useTransition();
	const createDashboard = useMutation(api.dashboards.createDashboard);

	function handleCreate() {
		if (!name.trim()) return;
		startTransition(async () => {
			const defaultLayout = JSON.stringify({
				widgets: [
					{ type: "kpi_tiles", title: "Security KPIs", gridArea: "1 / 1 / 3 / 3" },
					{ type: "findings_feed", title: "Recent Findings", gridArea: "1 / 3 / 3 / 5" },
				],
			});
			await createDashboard({
				authToken,
				tenantSlug,
				name: name.trim(),
				description: description.trim() || undefined,
				layout: defaultLayout,
			});
			setName("");
			setDescription("");
			setIsOpen(false);
		});
	}

	return (
		<>
			<button
				type="button"
				onClick={() => setIsOpen(true)}
				className="signal-button ml-auto"
				style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
			>
				<Plus size={14} className="mr-1" />
				New Dashboard
			</button>

			{isOpen && (
				<div className="drawer-overlay" onClick={() => setIsOpen(false)}>
					<div className="drawer-panel" style={{ maxWidth: "480px" }} onClick={(e) => e.stopPropagation()}>
						<div className="drawer-header">
							<h2 className="drawer-title">Create Dashboard</h2>
							<button type="button" onClick={() => setIsOpen(false)} className="drawer-close">
								<X size={18} />
							</button>
						</div>
						<div className="drawer-body space-y-4">
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">Name</label>
								<input
									type="text"
									value={name}
									onChange={(e) => setName(e.target.value)}
									placeholder="e.g. Security Overview"
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
								/>
							</div>
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">Description</label>
								<textarea
									value={description}
									onChange={(e) => setDescription(e.target.value)}
									placeholder="Optional description"
									rows={3}
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none"
								/>
							</div>
						</div>
						<div className="drawer-footer">
							<button
								type="button"
								onClick={() => setIsOpen(false)}
								className="secondary-button"
								style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
							>
								Cancel
							</button>
							<button
								type="button"
								onClick={handleCreate}
								disabled={isPending || !name.trim()}
								className="signal-button"
								style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
							>
								{isPending ? "Creating..." : "Create Dashboard"}
							</button>
						</div>
					</div>
				</div>
			)}
		</>
	);
}
