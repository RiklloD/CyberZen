import { createFileRoute } from "@tanstack/react-router";
import {
	Webhook,
	Plus,
	X,
	Send,
	Trash2,
	Edit3,
	ChevronDown,
	ChevronUp,
	RefreshCw,
	AlertCircle,
	CheckCircle2,
	Clock,
} from "lucide-react";
import { useMutation, useQuery, useAction } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
import { formatTimestamp } from "../../lib/utils";

const ALL_WEBHOOK_EVENT_TYPES = [
	"finding.validated",
	"finding.pr_opened",
	"finding.resolved",
	"finding.severity_escalated",
	"trust_score.degraded",
	"trust_score.compromised",
	"honeypot.triggered",
	"gate.blocked",
	"gate.override",
	"regulatory.gap_detected",
	"sbom.drift_detected",
	"attack_surface.increased",
] as const;

type Endpoint = NonNullable<
	FunctionReturnType<typeof api.webhooks.listEndpoints>
>[number];
type DlqEntry = NonNullable<
	FunctionReturnType<typeof api.webhooks.listDeadLetterQueue>
>[number];
type RetryStat = NonNullable<
	FunctionReturnType<typeof api.webhooks.listRetryStats>
>[number];
type Delivery = NonNullable<
	FunctionReturnType<typeof api.webhooks.listRecentDeliveries>
>[number];

export const Route = createFileRoute("/settings/webhooks")({
	errorComponent: RouteErrorBoundary,
	component: WebhooksSettingsPage,
});

function WebhooksSettingsPage() {
	const TENANT = useTenantSlug();

	const endpoints = useQuery(api.webhooks.listEndpoints, {
		tenantSlug: TENANT,
	});
	const deliveries = useQuery(api.webhooks.listRecentDeliveries, {
		tenantSlug: TENANT,
		limit: 50,
	});
	const dlq = useQuery(api.webhooks.listDeadLetterQueue, {
		tenantSlug: TENANT,
	});
	const retryStats = useQuery(api.webhooks.listRetryStats, {
		tenantSlug: TENANT,
	});

	const registerEndpoint = useMutation(api.webhooks.registerEndpoint);
	const updateEndpoint = useMutation(api.webhooks.updateEndpoint);
	const deleteEndpoint = useMutation(api.webhooks.deleteEndpoint);
	const retryDeadLetter = useMutation(api.webhooks.retryDeadLetter);
	const testFireEndpoint = useAction(api.webhooks.testFireEndpoint);

	const [editorOpen, setEditorOpen] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [formUrl, setFormUrl] = useState("");
	const [formSecret, setFormSecret] = useState("");
	const [formChangeSecret, setFormChangeSecret] = useState(false);
	const [formEvents, setFormEvents] = useState<string[]>([
		ALL_WEBHOOK_EVENT_TYPES[0],
	]);
	const [formDescription, setFormDescription] = useState("");

	const [testResult, setTestResult] = useState<{
		ok: boolean;
		status: number;
		body: string;
	} | null>(null);
	const [testing, setTesting] = useState<string | null>(null);
	const [retrying, setRetrying] = useState<string | null>(null);
	const [expandedId, setExpandedId] = useState<string | null>(null);
	const [showDlq, setShowDlq] = useState(false);

	function openCreate() {
		setEditingId(null);
		setFormUrl("");
		setFormSecret("");
		setFormChangeSecret(true);
		setFormEvents([ALL_WEBHOOK_EVENT_TYPES[0]]);
		setFormDescription("");
		setEditorOpen(true);
	}

	function openEdit(ep: Endpoint) {
		setEditingId(ep._id);
		setFormUrl(ep.url);
		setFormSecret("");
		setFormChangeSecret(false);
		setFormEvents(ep.events.length > 0 ? ep.events : [ALL_WEBHOOK_EVENT_TYPES[0]]);
		setFormDescription(ep.description ?? "");
		setEditorOpen(true);
	}

	async function handleSave() {
		if (!formUrl || formEvents.length === 0) return;
		if (!editingId && !formSecret) return;

		if (editingId) {
			await updateEndpoint({
				endpointId: editingId as any,
				url: formUrl,
				events: formEvents,
				description: formDescription || undefined,
				...(formChangeSecret && formSecret ? { secret: formSecret } : {}),
			});
		} else {
			await registerEndpoint({
				tenantSlug: TENANT,
				url: formUrl,
				secret: formSecret,
				events: formEvents,
				description: formDescription || undefined,
			});
		}
		setEditorOpen(false);
	}

	async function handleTestFire(id: string) {
		setTesting(id);
		setTestResult(null);
		const result = await testFireEndpoint({ endpointId: id as any });
		setTestResult(result);
		setTesting(null);
	}

	function handleDelete(ep: Endpoint) {
		if (confirm("Delete this webhook endpoint? This cannot be undone.")) {
			deleteEndpoint({ tenantSlug: TENANT, endpointId: ep._id });
		}
	}

	async function handleRetry(entryId: string) {
		setRetrying(entryId);
		await retryDeadLetter({ entryId: entryId as any });
		setRetrying(null);
	}

	function toggleEvent(event: string) {
		setFormEvents((prev) =>
			prev.includes(event)
				? prev.filter((e) => e !== event)
				: [...prev, event],
		);
	}

	const statsByEndpoint = new Map<string, RetryStat>(
		(retryStats ?? []).map((s: RetryStat) => [s.endpointId, s]),
	);

	const dlqByEndpoint = new Map<string, DlqEntry[]>();
	for (const e of dlq ?? []) {
		const arr = dlqByEndpoint.get(e.endpointId) ?? [];
		arr.push(e);
		dlqByEndpoint.set(e.endpointId, arr);
	}

	const totalDead = (dlq ?? []).length;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<Webhook size={20} className="text-[var(--signal)]" />
						<div>
							<h1 className="page-title">Outgoing Webhooks</h1>
							<p className="page-subtitle">
								Configure signed webhook endpoints to receive real-time event
								deliveries
							</p>
						</div>
					</div>
					<div className="flex items-center gap-2">
						{totalDead > 0 && (
							<button
								type="button"
								className="secondary-button flex items-center gap-1.5"
								onClick={() => setShowDlq(!showDlq)}
							>
								<AlertCircle size={13} className="text-red-500" />
								{totalDead} dead
							</button>
						)}
						<button
							type="button"
							className="signal-button"
							onClick={openCreate}
						>
							<Plus size={14} />
							Add Webhook
						</button>
					</div>
				</div>
			</div>

			<div className="page-body space-y-4">
				{/* Endpoint List */}
				<div className="panel">
					{endpoints === undefined && (
						<div className="p-6 text-sm text-[var(--sea-ink-soft)]">
							Loading webhooks...
						</div>
					)}

					{endpoints !== undefined && endpoints.length === 0 && (
						<div className="flex flex-col items-center justify-center gap-3 py-16 text-[var(--sea-ink-soft)]">
							<Webhook size={32} className="opacity-30" />
							<p className="text-sm">
								No webhook endpoints configured. Add one to start receiving events.
							</p>
						</div>
					)}

					{endpoints !== undefined && endpoints.length > 0 && (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-[var(--line)]">
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											URL
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Events
										</th>
										<th className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]">
											Status
										</th>
										<th className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]">
											Retrying
										</th>
										<th className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]">
											Dead
										</th>
										<th className="px-4 py-3 text-right font-semibold text-[var(--sea-ink-soft)]">
											Actions
										</th>
									</tr>
								</thead>
								<tbody>
									{endpoints.map((ep: Endpoint) => {
										const stats: RetryStat | undefined = statsByEndpoint.get(ep._id);
										const epDeliveries: Delivery[] = (deliveries ?? []).filter(
											(d: Delivery) => d.endpointId === ep._id,
										);
										const isExpanded = expandedId === ep._id;

										return (
											<>
												<tr
													key={ep._id}
													className="border-b border-[var(--line)]"
												>
													<td className="px-4 py-3">
														<div className="text-[var(--sea-ink)] font-mono text-xs truncate max-w-xs">
															{ep.url}
														</div>
														{ep.description && (
															<div className="text-[var(--sea-ink-soft)] text-xs mt-0.5">
																{ep.description}
															</div>
														)}
														{ep.lastDeliveryAt && (
															<div className="text-[var(--sea-ink-soft)] text-[0.6rem] mt-0.5">
																Last delivery: {formatTimestamp(ep.lastDeliveryAt)}
															</div>
														)}
													</td>
													<td className="px-4 py-3">
														<div className="flex flex-wrap gap-1">
															{ep.events.length === 0 ? (
																<span className="inline-flex rounded-full bg-[var(--chip-bg)] border border-[var(--chip-line)] px-2 py-0.5 text-[0.6rem] font-medium text-[var(--sea-ink-soft)]">
																	all events
																</span>
															) : (
																ep.events.slice(0, 3).map((e: string) => (
																	<span
																		key={e}
																		className="inline-flex rounded-full bg-[var(--chip-bg)] border border-[var(--chip-line)] px-2 py-0.5 text-[0.6rem] font-medium text-[var(--sea-ink-soft)]"
																	>
																		{e}
																	</span>
																))
															)}
															{ep.events.length > 3 && (
																<span className="text-[0.6rem] text-[var(--sea-ink-soft)]">
																	+{ep.events.length - 3}
																</span>
															)}
														</div>
													</td>
													<td className="px-4 py-3 text-center">
														<span
															className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold ${
																ep.active
																	? "bg-green-100 text-green-700"
																	: "bg-gray-100 text-gray-500"
															}`}
														>
															{ep.active ? "Active" : "Disabled"}
														</span>
													</td>
													<td className="px-4 py-3 text-center text-[var(--sea-ink-soft)] text-xs">
														{stats?.pending ? (
															<span className="text-amber-600 font-medium">
																{stats.pending}
															</span>
														) : (
															"—"
														)}
													</td>
													<td className="px-4 py-3 text-center text-xs">
														{stats?.dead ? (
															<span className="text-red-600 font-medium">
																{stats.dead}
															</span>
														) : (
															<span className="text-[var(--sea-ink-soft)]">—</span>
														)}
													</td>
													<td className="px-4 py-3">
														<div className="flex items-center justify-end gap-1">
															<button
																type="button"
																className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
																onClick={() =>
																	setExpandedId(
																		isExpanded ? null : ep._id,
																	)
																}
																aria-label="Show delivery history"
															>
																{isExpanded ? (
																	<ChevronUp size={14} />
																) : (
																	<ChevronDown size={14} />
																)}
															</button>
															<button
																type="button"
																className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
																onClick={() => handleTestFire(ep._id)}
																disabled={testing === ep._id}
																aria-label="Test fire webhook"
															>
																<Send size={14} />
															</button>
															<button
																type="button"
																className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
																onClick={() => openEdit(ep)}
																aria-label="Edit webhook"
															>
																<Edit3 size={14} />
															</button>
															<button
																type="button"
																className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-red-500"
																onClick={() => handleDelete(ep)}
																aria-label="Delete webhook"
															>
																<Trash2 size={14} />
															</button>
														</div>
													</td>
												</tr>

												{/* Delivery History + DLQ inline */}
												{isExpanded && (
													<tr key={`${ep._id}-details`} className="bg-[var(--surface-soft)]">
														<td colSpan={6} className="px-4 py-3">
															<div className="space-y-3">
																{/* Recent deliveries */}
																<div>
																	<p className="text-xs font-semibold text-[var(--sea-ink-soft)] mb-2">
																		Recent Deliveries
																	</p>
																	{epDeliveries.length === 0 ? (
																		<p className="text-xs text-[var(--sea-ink-soft)] italic">
																			No deliveries recorded.
																		</p>
																	) : (
																		<div className="space-y-1">
																			{epDeliveries.slice(0, 10).map((d: Delivery) => (
																				<div
																					key={d._id}
																					className="flex items-center gap-2 text-xs"
																				>
																					{d.success ? (
																						<CheckCircle2
																							size={12}
																							className="text-green-500 flex-shrink-0"
																						/>
																					) : (
																						<AlertCircle
																							size={12}
																							className="text-red-500 flex-shrink-0"
																						/>
																					)}
																					<span className="font-mono text-[var(--sea-ink-soft)]">
																						{d.eventType}
																					</span>
																					{d.statusCode && (
																						<span
																							className={
																								d.success
																									? "text-green-600"
																									: "text-red-600"
																							}
																						>
																							HTTP {d.statusCode}
																						</span>
																					)}
																					<span className="text-[var(--sea-ink-soft)] ml-auto">
																						{formatTimestamp(d.attemptedAt)}
																					</span>
																				</div>
																			))}
																		</div>
																	)}
																</div>

																{/* Dead letter queue for this endpoint */}
																{(dlqByEndpoint.get(ep._id) ?? []).length > 0 && (
																	<div>
																		<p className="text-xs font-semibold text-red-600 mb-2">
																			Dead Letter Queue (
																			{dlqByEndpoint.get(ep._id)!.length})
																		</p>
																		<div className="space-y-1">
																			{dlqByEndpoint.get(ep._id)!.map((e) => (
																				<div
																					key={e._id}
																					className="flex items-center gap-2 text-xs"
																				>
																					<AlertCircle
																						size={12}
																						className="text-red-500 flex-shrink-0"
																					/>
																					<span className="font-mono text-[var(--sea-ink-soft)]">
																						{e.eventType}
																					</span>
																					<span className="text-[var(--sea-ink-soft)]">
																						{e.attempts} attempt
																						{e.attempts !== 1 ? "s" : ""}
																					</span>
																					{e.errorMessage && (
																						<span className="text-red-500 truncate max-w-[200px]">
																							{e.errorMessage}
																						</span>
																					)}
																					<span className="text-[var(--sea-ink-soft)]">
																						{formatTimestamp(e.createdAt)}
																					</span>
																					<button
																						type="button"
																						className="ml-auto flex items-center gap-1 rounded px-2 py-0.5 text-[0.6rem] font-medium bg-[var(--chip-bg)] border border-[var(--chip-line)] text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
																						onClick={() => handleRetry(e._id)}
																						disabled={retrying === e._id}
																					>
																						<RefreshCw
																							size={10}
																							className={
																								retrying === e._id
																									? "animate-spin"
																									: ""
																							}
																						/>
																						Retry
																					</button>
																				</div>
																			))}
																		</div>
																	</div>
																)}
															</div>
														</td>
													</tr>
												)}
											</>
										);
									})}
								</tbody>
							</table>
						</div>
					)}
				</div>

				{/* Global DLQ summary panel */}
				{showDlq && totalDead > 0 && (
					<div className="panel">
						<div className="px-4 py-3 border-b border-[var(--line)] flex items-center justify-between">
							<div className="flex items-center gap-2">
								<AlertCircle size={14} className="text-red-500" />
								<span className="text-sm font-semibold text-[var(--sea-ink)]">
									Dead Letter Queue — {totalDead}{" "}
									{totalDead === 1 ? "entry" : "entries"}
								</span>
							</div>
							<button
								type="button"
								className="text-xs text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)]"
								onClick={() => setShowDlq(false)}
							>
								Dismiss
							</button>
						</div>
						<div className="divide-y divide-[var(--line)]">
							{(dlq ?? []).map((e: DlqEntry) => {
								const ep: Endpoint | undefined = (endpoints ?? []).find(
									(x: Endpoint) => x._id === e.endpointId,
								);
								return (
									<div
										key={e._id}
										className="px-4 py-3 flex items-center gap-3 text-xs"
									>
										<Clock size={12} className="text-[var(--sea-ink-soft)] flex-shrink-0" />
										<div className="flex-1 min-w-0">
											<span className="font-mono text-[var(--sea-ink)]">
												{e.eventType}
											</span>
											{ep && (
												<span className="text-[var(--sea-ink-soft)] ml-2 truncate">
													→ {ep.url}
												</span>
											)}
											<span className="text-[var(--sea-ink-soft)] ml-2">
												{e.attempts} attempt{e.attempts !== 1 ? "s" : ""}
											</span>
											{e.errorMessage && (
												<span className="text-red-500 ml-2 truncate max-w-[200px]">
													{e.errorMessage}
												</span>
											)}
										</div>
										<span className="text-[var(--sea-ink-soft)] flex-shrink-0">
											{formatTimestamp(e.createdAt)}
										</span>
										<button
											type="button"
											className="flex items-center gap-1 rounded px-2 py-0.5 text-[0.6rem] font-medium bg-[var(--chip-bg)] border border-[var(--chip-line)] text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
											onClick={() => handleRetry(e._id)}
											disabled={retrying === e._id}
										>
											<RefreshCw
												size={10}
												className={retrying === e._id ? "animate-spin" : ""}
											/>
											Retry
										</button>
									</div>
								);
							})}
						</div>
					</div>
				)}

				{/* Test Result */}
				{testResult && (
					<div className="panel">
						<div className="px-4 py-3">
							<div className="flex items-center gap-2 mb-2">
								<span
									className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold ${
										testResult.ok
											? "bg-green-100 text-green-700"
											: "bg-red-100 text-red-700"
									}`}
								>
									{testResult.ok ? "Success" : "Failed"} — HTTP{" "}
									{testResult.status}
								</span>
							</div>
							<pre className="overflow-x-auto rounded-md bg-[var(--bg)] p-3 text-xs text-[var(--sea-ink-soft)]">
								{testResult.body}
							</pre>
							<button
								type="button"
								className="mt-2 text-xs text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)]"
								onClick={() => setTestResult(null)}
							>
								Dismiss
							</button>
						</div>
					</div>
				)}
			</div>

			{/* Editor Drawer */}
			{editorOpen && (
				<>
					<div
						className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm"
						onClick={() => setEditorOpen(false)}
						aria-hidden="true"
					/>
					<aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-lg flex-col border-l border-[var(--line)] bg-[var(--panel-bg)] shadow-2xl">
						<div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
							<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
								{editingId ? "Edit Webhook" : "Add Webhook"}
							</h2>
							<button
								type="button"
								className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)]"
								onClick={() => setEditorOpen(false)}
								aria-label="Close"
							>
								<X size={16} />
							</button>
						</div>

						<div className="flex-1 overflow-y-auto p-4 space-y-4">
							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Endpoint URL
								</label>
								<input
									type="url"
									className="input-field w-full"
									placeholder="https://example.com/webhooks/cyberzen"
									value={formUrl}
									onChange={(e) => setFormUrl(e.target.value)}
								/>
							</div>

							<div>
								<div className="mb-1 flex items-center justify-between">
									<label className="text-xs font-semibold text-[var(--sea-ink-soft)]">
										Signing Secret (HMAC-SHA256)
									</label>
									{editingId && (
										<label className="flex items-center gap-1.5 text-xs text-[var(--sea-ink-soft)] cursor-pointer">
											<input
												type="checkbox"
												checked={formChangeSecret}
												onChange={(e) => setFormChangeSecret(e.target.checked)}
											/>
											Change secret
										</label>
									)}
								</div>
								{(!editingId || formChangeSecret) && (
									<input
										type="password"
										className="input-field w-full"
										placeholder="whsec_..."
										value={formSecret}
										onChange={(e) => setFormSecret(e.target.value)}
									/>
								)}
								{editingId && !formChangeSecret && (
									<p className="text-xs text-[var(--sea-ink-soft)] italic">
										Current secret preserved. Check "Change secret" to update.
									</p>
								)}
							</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Description (optional)
								</label>
								<input
									type="text"
									className="input-field w-full"
									placeholder="e.g., PagerDuty alerts"
									value={formDescription}
									onChange={(e) => setFormDescription(e.target.value)}
								/>
							</div>

							<div>
								<label className="mb-2 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Subscribed Events{" "}
									<span className="font-normal text-[var(--sea-ink-soft)]">
										(leave all unchecked for all events)
									</span>
								</label>
								<div className="flex flex-wrap gap-2">
									{ALL_WEBHOOK_EVENT_TYPES.map((event) => (
										<label
											key={event}
											className={`inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
												formEvents.includes(event)
													? "border-[var(--signal)] bg-[rgba(158,255,100,0.12)] text-[var(--signal)]"
													: "border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)]"
											}`}
										>
											<input
												type="checkbox"
												checked={formEvents.includes(event)}
												onChange={() => toggleEvent(event)}
												className="sr-only"
											/>
											{event}
										</label>
									))}
								</div>
							</div>
						</div>

						<div className="border-t border-[var(--line)] px-4 py-3">
							<div className="flex justify-end gap-2">
								<button
									type="button"
									className="secondary-button"
									onClick={() => setEditorOpen(false)}
								>
									Cancel
								</button>
								<button
									type="button"
									className="signal-button"
									onClick={handleSave}
									disabled={
										!formUrl ||
										formEvents.length === 0 ||
										(!editingId && !formSecret)
									}
								>
									{editingId ? "Update" : "Create"} Webhook
								</button>
							</div>
						</div>
					</aside>
				</>
			)}
		</main>
	);
}
