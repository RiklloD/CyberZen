import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import {
	BarChart2,
	Download,
	FileText,
	Loader2,
	Shield,
	Trash2,
	X } from "lucide-react";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/data-privacy")({
	errorComponent: QueryErrorFallback,
	component: DataPrivacyPage });

const TYPE_LABELS: Record<string, string> = {
	access: "Data Access",
	deletion: "Data Deletion",
	portability: "Data Export" };

const STATUS_COLORS: Record<string, string> = {
	pending: "text-yellow-600",
	processing: "text-blue-600",
	complete: "text-[var(--success)]",
	cancelled: "text-[var(--sea-ink-soft)]" };

function formatDate(ts: number) {
	return new Date(ts).toLocaleDateString("en-US", {
		year: "numeric",
		month: "short",
		day: "numeric" });
}

function DataPrivacyPage() {
	const TENANT = useTenantSlug();
	const [pending, setPending] = useState<string | null>(null);
	const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

	const requests = useQuery(
		api.dataPrivacy.listDataRequests,
		{ tenantSlug: TENANT },
	);

	const consentRecord = useQuery(
		api.analyticsConsent.getMyConsent,
	);
	const updateConsent = useMutation(api.analyticsConsent.updateMyConsent);

	const requestAccess = useMutation(api.dataPrivacy.requestDataAccess);
	const requestDeletion = useMutation(api.dataPrivacy.requestDataDeletion);
	const requestExport = useMutation(api.dataPrivacy.requestDataExport);
	const cancelRequest = useMutation(api.dataPrivacy.cancelDataRequest);

	function flash(text: string, ok: boolean) {
		setMsg({ text, ok });
		setTimeout(() => setMsg(null), 5000);
	}

	async function handle(
		action: "access" | "deletion" | "portability",
		confirm?: string,
	) {
		if (confirm && !window.confirm(confirm)) return;
		setPending(action);
		try {
			if (action === "access")
				await requestAccess({ tenantSlug: TENANT });
			else if (action === "deletion")
				await requestDeletion({ tenantSlug: TENANT });
			else await requestExport({ tenantSlug: TENANT });
			flash("Request submitted. Processing may take up to 24 hours.", true);
		} catch (err) {
			flash(
				err instanceof Error ? err.message : "Request failed.",
				false,
			);
		} finally {
			setPending(null);
		}
	}

	async function handleCancel(id: string) {
		try {
			await cancelRequest({ requestId: id as any });
			flash("Request cancelled.", true);
		} catch (err) {
			flash(
				err instanceof Error ? err.message : "Failed to cancel.",
				false,
			);
		}
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Shield size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Data Privacy</h1>
						<p className="page-subtitle">
							GDPR rights — access, export, and deletion requests (Articles
							15/17/20)
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{msg && (
					<div
						className={`text-xs px-3 py-2 rounded-lg border ${msg.ok ? "text-[var(--success)] border-[var(--success)]" : "text-[var(--danger)] border-[var(--danger)]"}`}
					>
						{msg.text}
					</div>
				)}

				<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
					<div className="card card-sm space-y-3">
						<div className="flex items-center gap-2 text-[var(--signal)]">
							<FileText size={16} />
							<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
								Request My Data
							</h3>
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							Receive a copy of all data we hold about you (GDPR Art. 15).
						</p>
						<button
							type="button"
							className="signal-button inline-flex items-center gap-1.5 text-xs"
							onClick={() => handle("access")}
							disabled={pending === "access"}
						>
							{pending === "access" ? (
								<Loader2 size={12} className="animate-spin" />
							) : (
								<FileText size={12} />
							)}
							Request Access
						</button>
					</div>

					<div className="card card-sm space-y-3">
						<div className="flex items-center gap-2 text-[var(--signal)]">
							<Download size={16} />
							<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
								Export My Data
							</h3>
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							Download your data in machine-readable JSON format (GDPR Art. 20).
						</p>
						<button
							type="button"
							className="signal-button inline-flex items-center gap-1.5 text-xs"
							onClick={() => handle("portability")}
							disabled={pending === "portability"}
						>
							{pending === "portability" ? (
								<Loader2 size={12} className="animate-spin" />
							) : (
								<Download size={12} />
							)}
							Export Data
						</button>
					</div>

					<div className="card card-sm space-y-3">
						<div className="flex items-center gap-2 text-[var(--danger)]">
							<Trash2 size={16} />
							<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
								Delete My Data
							</h3>
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							Request permanent deletion of your account data. A 30-day grace
							period applies (GDPR Art. 17).
						</p>
						<button
							type="button"
							className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-[var(--danger)] text-[var(--danger)] hover:bg-red-50 transition-colors disabled:opacity-50"
							onClick={() =>
								handle(
									"deletion",
									"This will delete all your data after a 30-day grace period. You can cancel within that window. Continue?",
								)
							}
							disabled={pending === "deletion"}
						>
							{pending === "deletion" ? (
								<Loader2 size={12} className="animate-spin" />
							) : (
								<Trash2 size={12} />
							)}
							Delete My Data
						</button>
					</div>
				</div>

				{/* Analytics consent toggle */}
				<div className="card card-sm space-y-3">
					<div className="flex items-center justify-between">
						<div className="flex items-center gap-2">
							<BarChart2 size={16} className="text-[var(--signal)]" />
							<h2 className="text-sm font-semibold text-[var(--sea-ink)]">Analytics</h2>
						</div>
						{consentRecord !== undefined && (
							<button
								type="button"
								className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${consentRecord?.consent ? "bg-[var(--signal)]" : "bg-[var(--line)]"}`}
								role="switch"
								aria-checked={consentRecord?.consent ?? false}
								onClick={() =>
									updateConsent({ consent: !(consentRecord?.consent ?? false) })
								}
								aria-label="Toggle analytics consent"
							>
								<span
									className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${consentRecord?.consent ? "translate-x-[18px]" : "translate-x-[3px]"}`}
								/>
							</button>
						)}
					</div>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Allow CyberZen to collect anonymous usage data to improve the product.
						{consentRecord?.consentedAt && (
							<span className="ml-1 text-[var(--sea-ink-dim)]">
								Enabled {new Date(consentRecord.consentedAt).toLocaleDateString()}.
							</span>
						)}
					</p>
				</div>

				<div className="card card-sm space-y-3">
					<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
						Request History
					</h2>

					{requests === undefined ? (
						<div className="loading-panel h-24 rounded-xl" />
					) : requests.length === 0 ? (
						<p className="text-xs text-[var(--sea-ink-soft)]">
							No data requests submitted yet.
						</p>
					) : (
						<div className="divide-y divide-[var(--line)]">
							{requests.map((r) => (
								<div
									key={r._id}
									className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0"
								>
									<div className="flex-1 min-w-0">
										<div className="flex items-center gap-2">
											<span className="text-xs font-medium text-[var(--sea-ink)]">
												{TYPE_LABELS[r.type] ?? r.type}
											</span>
											<span
												className={`text-[11px] capitalize ${STATUS_COLORS[r.status] ?? ""}`}
											>
												{r.status}
											</span>
										</div>
										<div className="flex items-center gap-3 mt-0.5">
											<span className="text-[11px] text-[var(--sea-ink-soft)]">
												Requested {formatDate(r.requestDate)}
											</span>
											{r.completionDate && (
												<span className="text-[11px] text-[var(--sea-ink-soft)]">
													Completed {formatDate(r.completionDate)}
												</span>
											)}
											{r.gracePeriodEnd && r.status === "pending" && (
												<span className="text-[11px] text-yellow-600">
													Grace period ends {formatDate(r.gracePeriodEnd)}
												</span>
											)}
										</div>
									</div>
									{r.status === "pending" && (
										<button
											type="button"
											className="text-[var(--sea-ink-soft)] hover:text-[var(--danger)] transition-colors"
											onClick={() => handleCancel(r._id)}
											title="Cancel request"
										>
											<X size={14} />
										</button>
									)}
								</div>
							))}
						</div>
					)}
				</div>
			</div>
		</main>
	);
}
