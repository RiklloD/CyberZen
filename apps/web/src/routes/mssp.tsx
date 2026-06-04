import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Building2, Pause, Play, Save } from "lucide-react";
import { useState } from "react";
import RouteErrorBoundary from "../components/RouteErrorBoundary";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";

export const Route = createFileRoute("/mssp")({
	errorComponent: RouteErrorBoundary,
	component: MsspPortalPage,
});

type Tab = "tenants" | "billing" | "white-label";
type ManagedTenant = NonNullable<FunctionReturnType<typeof api.mssp.listManagedTenants>>[number];
type BillingRollupData = NonNullable<FunctionReturnType<typeof api.mssp.getBillingRollup>>;
type ByPlanEntry = BillingRollupData["byPlan"][number];
type RecentInvoice = BillingRollupData["recentInvoices"][number];

function MsspPortalPage() {
	const [activeTab, setActiveTab] = useState<Tab>("tenants");

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Building2 size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">MSSP Partner Portal</h1>
						<p className="page-subtitle">
							Manage customer tenants, billing rollups, and white-label branding
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="tab-bar mb-4">
					<button
						type="button"
						className={`tab-btn ${activeTab === "tenants" ? "is-active" : ""}`}
						onClick={() => setActiveTab("tenants")}
					>
						Managed Tenants
					</button>
					<button
						type="button"
						className={`tab-btn ${activeTab === "billing" ? "is-active" : ""}`}
						onClick={() => setActiveTab("billing")}
					>
						Billing Rollup
					</button>
					<button
						type="button"
						className={`tab-btn ${activeTab === "white-label" ? "is-active" : ""}`}
						onClick={() => setActiveTab("white-label")}
					>
						White Label
					</button>
				</div>

				{activeTab === "tenants" && <MsspTenantList />}
				{activeTab === "billing" && <MsspBillingRollup />}
				{activeTab === "white-label" && <MsspWhiteLabelSettings />}
			</div>
		</main>
	);
}

// ─── Managed Tenants ─────────────────────────────────────────────────────

function MsspTenantList() {
	const tenants = useQuery(api.mssp.listManagedTenants, {});
	const setStatus = useMutation(api.mssp.setManagedTenantStatus);
	const [pendingSlug, setPendingSlug] = useState<string | null>(null);

	if (!tenants) {
		return (
			<div className="space-y-2">
				{["a", "b", "c"].map((k) => (
					<div key={k} className="loading-panel h-12 rounded-lg" />
				))}
			</div>
		);
	}

	if (tenants.length === 0) {
		return (
			<div className="card">
				<p className="text-sm text-[var(--sea-ink-soft)]">
					No managed tenants yet. Provision tenants via the MSSP API to see them
					listed here.
				</p>
			</div>
		);
	}

	async function toggle(slug: string, status: "active" | "paused") {
		setPendingSlug(slug);
		try {
			await setStatus({
				tenantSlug: slug,
				status: status === "active" ? "paused" : "active",
			});
		} finally {
			setPendingSlug(null);
		}
	}

	return (
		<div className="card overflow-x-auto">
			<table className="w-full text-xs">
				<thead className="text-left text-[10px] uppercase tracking-wide text-[var(--sea-ink-soft)]">
					<tr className="border-b border-[var(--line)]">
						<th className="py-2 pr-3">Tenant</th>
						<th className="py-2 pr-3">Status</th>
						<th className="py-2 pr-3">Plan</th>
						<th className="py-2 pr-3">Deployment</th>
						<th className="py-2 pr-3">Repos</th>
						<th className="py-2 pr-3">Usage</th>
						<th className="py-2 pr-3">Health</th>
						<th className="py-2 pr-3">Created</th>
						<th className="py-2 pr-3 text-right">Actions</th>
					</tr>
				</thead>
				<tbody>
					{tenants.map((t: ManagedTenant) => {
						const healthTone =
							t.health === "critical"
								? "danger"
								: t.health === "warning"
									? "warning"
									: "success";
						const statusTone = t.status === "active" ? "success" : "warning";
						return (
							<tr
								key={t._id}
								className="border-b border-[var(--line)] last:border-b-0 hover:bg-[var(--surface-soft)]"
							>
								<td className="py-2 pr-3">
									<div className="font-semibold text-[var(--sea-ink)]">
										{t.name}
									</div>
									<div className="text-[10px] text-[var(--sea-ink-soft)]">
										{t.slug}
									</div>
								</td>
								<td className="py-2 pr-3">
									<StatusPill label={t.status} tone={statusTone} />
								</td>
								<td className="py-2 pr-3">{t.planSlug ?? "—"}</td>
								<td className="py-2 pr-3">{t.deploymentMode}</td>
								<td className="py-2 pr-3">{t.repositories}</td>
								<td className="py-2 pr-3">
									<span className="text-[var(--danger)]">
										{t.criticalFindings} crit
									</span>
									{" · "}
									<span className="text-[var(--warning)]">
										{t.highFindings} high
									</span>
								</td>
								<td className="py-2 pr-3">
									<StatusPill label={t.health} tone={healthTone} />
								</td>
								<td className="py-2 pr-3 text-[var(--sea-ink-soft)]">
									{formatTimestamp(t.createdAt)}
								</td>
								<td className="py-2 pr-3 text-right">
									<button
										type="button"
										onClick={() => toggle(t.slug, t.status)}
										disabled={pendingSlug === t.slug}
										className="signal-button"
										style={{ padding: "0.3rem 0.6rem", fontSize: "0.7rem" }}
									>
										{t.status === "active" ? (
											<>
												<Pause size={11} className="mr-1" />
												Pause
											</>
										) : (
											<>
												<Play size={11} className="mr-1" />
												Resume
											</>
										)}
									</button>
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}

// ─── Billing Rollup ───────────────────────────────────────────────────────

function MsspBillingRollup() {
	const rollup = useQuery(api.mssp.getBillingRollup, {});

	if (!rollup) {
		return (
			<div className="grid gap-3 sm:grid-cols-3">
				{["a", "b", "c"].map((k) => (
					<div key={k} className="loading-panel h-24 rounded-2xl" />
				))}
			</div>
		);
	}

	const currency = rollup.currency.toUpperCase();
	const monthlyRevenue = (rollup.totalMonthlyRevenueCents / 100).toLocaleString(
		undefined,
		{ minimumFractionDigits: 2, maximumFractionDigits: 2 },
	);

	return (
		<div className="space-y-4">
			<div className="grid gap-3 sm:grid-cols-3">
				<StatCard label="Managed Tenants" value={String(rollup.totalTenants)} />
				<StatCard
					label="Active Subscriptions"
					value={String(rollup.totalActiveSubscriptions)}
				/>
				<StatCard
					label="MRR (sum)"
					value={`${currency} ${monthlyRevenue}`}
				/>
			</div>

			<div className="card">
				<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">
					Revenue by Plan
				</h3>
				{rollup.byPlan.length === 0 ? (
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No active subscriptions yet.
					</p>
				) : (
					<div className="space-y-2">
						{rollup.byPlan.map((p: ByPlanEntry) => (
							<div
								key={p.planSlug}
								className="flex items-center justify-between rounded-lg bg-[var(--surface-soft)] px-3 py-2"
							>
								<div className="flex items-center gap-3">
									<StatusPill label={p.planSlug} tone="neutral" />
									<span className="text-xs text-[var(--sea-ink-soft)]">
										{p.tenantCount} tenant{p.tenantCount === 1 ? "" : "s"}
									</span>
								</div>
								<span className="text-xs font-semibold text-[var(--sea-ink)]">
									{currency} {(p.monthlyRevenueCents / 100).toFixed(2)}/mo
								</span>
							</div>
						))}
					</div>
				)}
			</div>

			<div className="card">
				<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">
					Recent Invoices
				</h3>
				{rollup.recentInvoices.length === 0 ? (
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No invoices yet across managed tenants.
					</p>
				) : (
					<div className="space-y-1.5">
						{rollup.recentInvoices.map((inv: RecentInvoice, i: number) => (
							<div
								key={`${inv.tenantSlug}-${inv.periodStart}-${i}`}
								className="flex items-center justify-between text-xs"
							>
								<span className="text-[var(--sea-ink)]">
									{inv.tenantSlug} · {formatTimestamp(inv.periodStart)}
								</span>
								<span className="flex items-center gap-2">
									<StatusPill
										label={inv.status}
										tone={
											inv.status === "paid"
												? "success"
												: inv.status === "void"
													? "neutral"
													: "warning"
										}
									/>
									<span className="font-semibold text-[var(--sea-ink)]">
										{inv.currency.toUpperCase()} {(inv.amountCents / 100).toFixed(2)}
									</span>
								</span>
							</div>
						))}
					</div>
				)}
			</div>
		</div>
	);
}

function StatCard({ label, value }: { label: string; value: string }) {
	return (
		<div className="card">
			<p className="text-[10px] font-medium uppercase tracking-wide text-[var(--sea-ink-soft)]">
				{label}
			</p>
			<p className="mt-1 text-2xl font-bold text-[var(--sea-ink)]">{value}</p>
		</div>
	);
}

// ─── White Label Settings ─────────────────────────────────────────────────

function MsspWhiteLabelSettings() {
	const settings = useQuery(api.mssp.getWhiteLabelSettings, {});
	const [brandName, setBrandName] = useState<string | null>(null);
	const [portalUrl, setPortalUrl] = useState<string | null>(null);
	const [supportEmail, setSupportEmail] = useState<string | null>(null);
	const [primaryColor, setPrimaryColor] = useState<string | null>(null);
	const [logoUrl, setLogoUrl] = useState<string | null>(null);

	if (!settings) {
		return <div className="loading-panel h-48 rounded-2xl" />;
	}

	const values = {
		brandName: brandName ?? settings.brandName,
		portalUrl: portalUrl ?? settings.portalUrl,
		supportEmail: supportEmail ?? settings.supportEmail,
		primaryColor: primaryColor ?? settings.primaryColor,
		logoUrl: logoUrl ?? settings.logoUrl,
	};

	return (
		<form
			className="card space-y-4"
			onSubmit={(e) => {
				e.preventDefault();
				// White-label settings are sourced from env vars (MSSP_BRAND_NAME,
				// MSSP_DASHBOARD_URL, MSSP_SUPPORT_EMAIL, MSSP_PRIMARY_COLOR,
				// MSSP_LOGO_URL) so they survive Convex restarts. Persisting from
				// the UI prints the equivalent `npx convex env set` commands to the
				// console for an operator to copy/paste.
				console.info(
					"Apply the following Convex env updates to make these white-label changes effective:",
				);
				console.info(`npx convex env set MSSP_BRAND_NAME "${values.brandName}"`);
				console.info(`npx convex env set MSSP_DASHBOARD_URL "${values.portalUrl}"`);
				console.info(`npx convex env set MSSP_SUPPORT_EMAIL "${values.supportEmail}"`);
				console.info(`npx convex env set MSSP_PRIMARY_COLOR "${values.primaryColor}"`);
				console.info(`npx convex env set MSSP_LOGO_URL "${values.logoUrl}"`);
			}}
		>
			<div>
				<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
					Brand Customization
				</h3>
				<p className="text-xs text-[var(--sea-ink-soft)]">
					Customer-facing branding applied to webhook payloads, report headers,
					and the portal shell.
				</p>
			</div>

			<TextField
				label="Brand Name"
				value={values.brandName}
				onChange={setBrandName}
				placeholder="Sentinel"
			/>
			<TextField
				label="Portal URL"
				value={values.portalUrl}
				onChange={setPortalUrl}
				placeholder="https://portal.your-mssp.com"
			/>
			<TextField
				label="Support Email"
				value={values.supportEmail}
				onChange={setSupportEmail}
				placeholder="support@your-mssp.com"
				type="email"
			/>
			<div className="grid gap-3 sm:grid-cols-2">
				<TextField
					label="Primary Color"
					value={values.primaryColor}
					onChange={setPrimaryColor}
					placeholder="#3478f6"
				/>
				<TextField
					label="Logo URL"
					value={values.logoUrl}
					onChange={setLogoUrl}
					placeholder="https://cdn.example.com/logo.svg"
				/>
			</div>

			<div className="flex items-center justify-between">
				<p className="text-[10px] text-[var(--sea-ink-soft)]">
					These values are read from Convex env vars at request time.
				</p>
				<button
					type="submit"
					className="signal-button inline-flex items-center gap-1"
					style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
				>
					<Save size={12} />
					Save (prints env commands)
				</button>
			</div>
		</form>
	);
}

function TextField({
	label,
	value,
	onChange,
	placeholder,
	type = "text",
}: {
	label: string;
	value: string;
	onChange: (v: string) => void;
	placeholder?: string;
	type?: string;
}) {
	return (
		<label className="block">
			<span className="block text-[10px] font-medium uppercase tracking-wide text-[var(--sea-ink-soft)] mb-1">
				{label}
			</span>
			<input
				type={type}
				value={value}
				onChange={(e) => onChange(e.target.value)}
				placeholder={placeholder}
				className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:border-[var(--signal)] focus:outline-none"
			/>
		</label>
	);
}
