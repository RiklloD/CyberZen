import { createFileRoute } from "@tanstack/react-router";
import type { FunctionReturnType } from "convex/server";
import { AlertTriangle, Database, Plus, Trash2, ToggleLeft, ToggleRight } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "#/lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import { useAuthToken } from "../../lib/clerk-compat";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/retention")({
	errorComponent: RouteErrorBoundary,
	component: RetentionSettingsPage,
});

type RetentionPolicy = NonNullable<FunctionReturnType<typeof api.retention.listRetentionPolicies>>[number];

const DATA_TYPE_LABELS: Record<string, string> = {
	findings: "Findings",
	audit_logs: "Audit Logs",
	sbom_snapshots: "SBOM Snapshots",
	webhook_deliveries: "Webhook Deliveries",
	sandbox_environments: "Sandbox Environments",
	ingestion_events: "Ingestion Events",
};

const DATA_TYPE_OPTIONS = Object.entries(DATA_TYPE_LABELS);

const ENFORCEMENT_MINIMUMS = {
	findingsDays: 90,
	auditLogsDays: 365,
	apiUsageRecordsDays: 30,
	webhookDeliveriesDays: 7,
};

const ENFORCEMENT_LABELS: Record<string, string> = {
	findingsDays: "Closed Findings",
	auditLogsDays: "Audit Logs",
	apiUsageRecordsDays: "API Usage Records",
	webhookDeliveriesDays: "Webhook Deliveries",
};

function nextCleanupDate(): string {
	const now = new Date();
	const next = new Date(now);
	next.setUTCDate(next.getUTCDate() + 1);
	next.setUTCHours(5, 30, 0, 0);
	return next.toLocaleString("en-US", {
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
		timeZoneName: "short",
	});
}

function RetentionSettingsPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";

	const policies = useQuery(api.retention.listPolicies, {
		authToken,
		tenantSlug: TENANT,
	});

	const enforcement = useQuery(api.dataRetention.getRetentionPolicies, {
		authToken,
		tenantSlug: TENANT,
	});

	const createPolicy = useMutation(api.retention.createPolicy);
	const updatePolicy = useMutation(api.retention.updatePolicy);
	const deletePolicy = useMutation(api.retention.deletePolicy);
	const updateEnforcement = useMutation(api.dataRetention.updateRetentionPolicies);

	const [showForm, setShowForm] = useState(false);
	const [formState, setFormState] = useState({
		name: "",
		dataType: "findings" as string,
		retentionDays: 90,
		action: "archive" as string,
		enabled: true,
	});

	const [enforcementForm, setEnforcementForm] = useState<{
		findingsDays: number;
		auditLogsDays: number;
		apiUsageRecordsDays: number;
		webhookDeliveriesDays: number;
	} | null>(null);

	const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
	const [saving, setSaving] = useState(false);

	function flash(text: string, ok: boolean) {
		setMsg({ text, ok });
		setTimeout(() => setMsg(null), 5000);
	}

	const currentEnforcement = enforcementForm ?? (enforcement ? {
		findingsDays: enforcement.findingsDays,
		auditLogsDays: enforcement.auditLogsDays,
		apiUsageRecordsDays: enforcement.apiUsageRecordsDays,
		webhookDeliveriesDays: enforcement.webhookDeliveriesDays,
	} : null);

	function hasMinimumWarning(key: keyof typeof ENFORCEMENT_MINIMUMS, value: number): boolean {
		return value > 0 && value < ENFORCEMENT_MINIMUMS[key];
	}

	async function handleCreate() {
		await createPolicy({
			authToken,
			tenantSlug: TENANT,
			name: formState.name,
			dataType: formState.dataType as "findings",
			retentionDays: formState.retentionDays,
			action: formState.action as "archive",
			enabled: formState.enabled,
		});
		setShowForm(false);
		setFormState({
			name: "",
			dataType: "findings",
			retentionDays: 90,
			action: "archive",
			enabled: true,
		});
	}

	async function handleToggle(policyId: string, currentEnabled: boolean) {
		await updatePolicy({
			authToken,
			tenantSlug: TENANT,
			policyId: policyId as any,
			enabled: !currentEnabled,
		});
	}

	async function handleDelete(policyId: string) {
		await deletePolicy({
			authToken,
			tenantSlug: TENANT,
			policyId: policyId as any,
		});
	}

	async function handleSaveEnforcement() {
		if (!currentEnforcement) return;
		setSaving(true);
		try {
			await updateEnforcement({
				authToken,
				tenantSlug: TENANT,
				...currentEnforcement,
			});
			setEnforcementForm(null);
			flash("Retention periods saved.", true);
		} catch (err) {
			flash(err instanceof Error ? err.message : "Save failed.", false);
		} finally {
			setSaving(false);
		}
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Database size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Data Retention</h1>
						<p className="page-subtitle">
							Configure retention policies for findings, logs, and artifacts
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{msg && (
					<div className={`text-xs px-3 py-2 rounded-lg border ${msg.ok ? "text-[var(--success)] border-[var(--success)]" : "text-[var(--danger)] border-[var(--danger)]"}`}>
						{msg.text}
					</div>
				)}

				{/* Enforcement periods */}
				<div className="card">
					<div className="flex items-center justify-between mb-4">
						<div>
							<h2 className="section-title">Retention Periods</h2>
							<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
								Expired records are automatically deleted daily at 05:30 UTC.
								Next cleanup: <span className="font-medium">{nextCleanupDate()}</span>
							</p>
						</div>
					</div>

					{!enforcement ? (
						<div className="loading-panel p-4">Loading configuration…</div>
					) : currentEnforcement ? (
						<div className="space-y-3">
							{(["findingsDays", "auditLogsDays", "apiUsageRecordsDays", "webhookDeliveriesDays"] as const).map((key) => {
								const value = currentEnforcement[key];
								const warn = hasMinimumWarning(key, value);
								return (
									<div key={key} className="flex items-center gap-3">
										<label className="text-xs font-medium text-[var(--sea-ink)] w-44 shrink-0">
											{ENFORCEMENT_LABELS[key]}
										</label>
										<div className="flex items-center gap-2 flex-1">
											<input
												type="number"
												min={0}
												className="w-24 rounded-xl border border-[var(--line)] bg-[var(--bg-panel)] text-[var(--sea-ink)] p-2 text-xs"
												value={value}
												onChange={(e) =>
													setEnforcementForm((prev) => ({
														...(prev ?? currentEnforcement),
														[key]: parseInt(e.target.value) || 0,
													}))
												}
											/>
											<span className="text-xs text-[var(--sea-ink-soft)]">days</span>
											<span className="text-[10px] text-[var(--sea-ink-dim)]">
												{value === 0 ? "retain forever" : `delete after ${value}d`}
											</span>
										</div>
										{warn && (
											<div className="flex items-center gap-1 text-yellow-600 text-[11px]">
												<AlertTriangle size={12} />
												Below recommended minimum ({ENFORCEMENT_MINIMUMS[key]}d)
											</div>
										)}
									</div>
								);
							})}

							{enforcementForm && (
								<div className="flex gap-2 pt-2">
									<button
										type="button"
										className="signal-button"
										onClick={handleSaveEnforcement}
										disabled={saving}
									>
										{saving ? "Saving…" : "Save Changes"}
									</button>
									<button
										type="button"
										className="secondary-button signal-button"
										onClick={() => setEnforcementForm(null)}
									>
										Cancel
									</button>
								</div>
							)}

							{enforcement.updatedAt && (
								<p className="text-[11px] text-[var(--sea-ink-dim)]">
									Last updated {new Date(enforcement.updatedAt).toLocaleDateString()}
								</p>
							)}
						</div>
					) : null}
				</div>

				{/* Policy list */}
				<div className="card">
					<div className="flex items-center justify-between mb-4">
						<h2 className="section-title">Archive Policies</h2>
						<button
							type="button"
							className="signal-button"
							onClick={() => setShowForm(!showForm)}
							aria-label="Add retention policy"
						>
							<Plus size={14} />
							Add Policy
						</button>
					</div>

					{!policies ? (
						<div className="loading-panel p-4">Loading policies…</div>
					) : policies.length === 0 ? (
						<div className="empty-state">
							<Database size={32} className="mb-2 opacity-40" />
							<p>No archive policies configured yet.</p>
							<p className="text-xs mt-1 opacity-60">
								Create a policy to manage data lifecycle.
							</p>
						</div>
					) : (
						<div className="space-y-2">
							{policies.map((policy: RetentionPolicy) => (
								<div
									key={policy._id}
									className="flex items-center justify-between gap-3 p-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]"
								>
									<div className="min-w-0 flex-1">
										<div className="flex items-center gap-2">
											<span className="text-sm font-semibold text-[var(--sea-ink)]">
												{policy.name}
											</span>
											<span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--accent-tint)] text-[var(--signal)] border border-[var(--accent-line)]">
												{DATA_TYPE_LABELS[policy.dataType] ?? policy.dataType}
											</span>
										</div>
										<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
											{policy.retentionDays === 0
												? "Retain forever"
												: `${policy.retentionDays} days → ${policy.action}`}
											{policy.lastAppliedAt
												? ` · Last applied ${new Date(policy.lastAppliedAt).toLocaleDateString()}`
												: " · Not yet applied"}
										</p>
									</div>

									<div className="flex items-center gap-2">
										<button
											type="button"
											className="p-1.5 rounded-lg hover:bg-[var(--surface-soft)] transition-colors"
											onClick={() => handleToggle(policy._id, policy.enabled)}
											aria-label={policy.enabled ? "Disable policy" : "Enable policy"}
											title={policy.enabled ? "Disable" : "Enable"}
										>
											{policy.enabled ? (
												<ToggleRight size={20} className="text-[var(--signal)]" />
											) : (
												<ToggleLeft size={20} className="text-[var(--sea-ink-dim)]" />
											)}
										</button>
										<button
											type="button"
											className="p-1.5 rounded-lg hover:bg-red-50 text-[var(--danger)] transition-colors"
											onClick={() => handleDelete(policy._id)}
											aria-label="Delete policy"
										>
											<Trash2 size={16} />
										</button>
									</div>
								</div>
							))}
						</div>
					)}
				</div>

				{/* Create form */}
				{showForm && (
					<div className="card" role="form" aria-label="Create retention policy">
						<h2 className="section-title mb-4">New Archive Policy</h2>

						<div className="space-y-3">
							<div className="auth-field">
								<label htmlFor="ret-name" className="text-xs font-medium">
									Policy Name
								</label>
								<input
									id="ret-name"
									type="text"
									value={formState.name}
									onChange={(e) =>
										setFormState((s) => ({ ...s, name: e.target.value }))
									}
									placeholder="e.g. Standard Findings Retention"
								/>
							</div>

							<div className="auth-field">
								<label htmlFor="ret-type" className="text-xs font-medium">
									Data Category
								</label>
								<select
									id="ret-type"
									value={formState.dataType}
									onChange={(e) =>
										setFormState((s) => ({ ...s, dataType: e.target.value }))
									}
									className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-panel)] text-[var(--sea-ink)] p-2.5"
								>
									{DATA_TYPE_OPTIONS.map(([value, label]) => (
										<option key={value} value={value}>
											{label}
										</option>
									))}
								</select>
							</div>

							<div className="grid grid-cols-2 gap-3">
								<div className="auth-field">
									<label htmlFor="ret-days" className="text-xs font-medium">
										Retention Days
									</label>
									<input
										id="ret-days"
										type="number"
										min={0}
										value={formState.retentionDays}
										onChange={(e) =>
											setFormState((s) => ({
												...s,
												retentionDays: parseInt(e.target.value) || 0,
											}))
										}
										placeholder="90"
									/>
									<span className="text-[10px] text-[var(--sea-ink-dim)]">
										0 = retain forever
									</span>
								</div>

								<div className="auth-field">
									<label htmlFor="ret-action" className="text-xs font-medium">
										Expiry Action
									</label>
									<select
										id="ret-action"
										value={formState.action}
										onChange={(e) =>
											setFormState((s) => ({ ...s, action: e.target.value }))
										}
										className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-panel)] text-[var(--sea-ink)] p-2.5"
									>
										<option value="archive">Archive</option>
										<option value="delete">Delete</option>
									</select>
								</div>
							</div>

							<div className="flex gap-2 pt-2">
								<button
									type="button"
									className="signal-button"
									onClick={handleCreate}
									disabled={!formState.name.trim()}
								>
									Create Policy
								</button>
								<button
									type="button"
									className="secondary-button signal-button"
									onClick={() => setShowForm(false)}
								>
									Cancel
								</button>
							</div>
						</div>
					</div>
				)}
			</div>
		</main>
	);
}
