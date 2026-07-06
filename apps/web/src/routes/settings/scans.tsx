import { createFileRoute } from "@tanstack/react-router";
import { CalendarClock, Plus, Play, Trash2, Edit3, X } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

type ScanSchedule = NonNullable<FunctionReturnType<typeof api.scanScheduling.listSchedules>>[number];

export const Route = createFileRoute("/settings/scans")({
	errorComponent: RouteErrorBoundary,
	component: ScanSchedulingPage });

const SCANNER_SLUGS = [
	"sast",
	"sca",
	"dast",
	"container_scan",
	"iac_scan",
	"secret_detection",
	"license_compliance",
	"dependency_audit",
	"sbom_generator",
	"prompt_injection",
] as const;

function ScanSchedulingPage() {
	const TENANT = useTenantSlug();
	const schedules = useQuery(api.scanScheduling.listSchedules, {
		tenantSlug: TENANT });

	const createSchedule = useMutation(api.scanScheduling.createSchedule);
	const updateSchedule = useMutation(api.scanScheduling.updateSchedule);
	const deleteSchedule = useMutation(api.scanScheduling.deleteSchedule);
	const runScanNow = useMutation(api.scanScheduling.runScanNow);

	const [editorOpen, setEditorOpen] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [formScanner, setFormScanner] = useState<(typeof SCANNER_SLUGS)[number]>(SCANNER_SLUGS[0]);
	const [formCron, setFormCron] = useState("0 * * * *");
	const [formDescription, setFormDescription] = useState("");
	const [formEnabled, setFormEnabled] = useState(true);
	const [runningId, setRunningId] = useState<string | null>(null);
	const [cronError, setCronError] = useState<string | null>(null);

	function openCreate() {
		setEditingId(null);
		setFormScanner(SCANNER_SLUGS[0]);
		setFormCron("0 * * * *");
		setFormDescription("");
		setFormEnabled(true);
		setEditorOpen(true);
	}

	function openEdit(
		id: string,
		scanner: string,
		cron: string,
		desc?: string,
		enabled?: boolean,
	) {
		setEditingId(id);
		setFormScanner(scanner as (typeof SCANNER_SLUGS)[number]);
		setFormCron(cron);
		setFormDescription(desc ?? "");
		setFormEnabled(enabled ?? true);
		setEditorOpen(true);
	}

	function handleSave() {
		if (!formCron) return;

		const parts = formCron.trim().split(/\s+/);
		if (parts.length !== 5) {
			setCronError("Cron expression must have exactly 5 fields: minute hour day-of-month month day-of-week");
			return;
		}
		const cronPattern = /^[\d*/\-,\s]+$/;
		if (!cronPattern.test(formCron)) {
			setCronError("Cron expression contains invalid characters. Only digits, *, /, -, and commas are allowed.");
			return;
		}
		setCronError(null);

		if (editingId) {
			updateSchedule({
				scheduleId: editingId as any,
				scannerSlug: formScanner,
				cronExpression: formCron,
				description: formDescription || undefined,
				enabled: formEnabled });
		} else {
			createSchedule({
				tenantSlug: TENANT,
				scannerSlug: formScanner,
				cronExpression: formCron,
				repositoryIds: [],
				description: formDescription || undefined,
				enabled: formEnabled });
		}
		setEditorOpen(false);
	}

	async function handleRunNow(id: string) {
		setRunningId(id);
		await runScanNow({ scheduleId: id as any });
		setRunningId(null);
	}

	function handleDelete(id: string) {
		if (confirm("Delete this scan schedule?")) {
			deleteSchedule({ scheduleId: id as any });
		}
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-3">
						<CalendarClock size={20} className="text-[var(--signal)]" />
						<div>
							<h1 className="page-title">Scan Scheduling</h1>
							<p className="page-subtitle">
								Configure scheduled and on-demand scan triggers
							</p>
						</div>
					</div>
					<button type="button" className="signal-button" onClick={openCreate}>
						<Plus size={14} />
						Add Schedule
					</button>
				</div>
			</div>

			<div className="page-body">
				<div className="panel">
					{schedules === undefined && (
						<div className="p-6 text-sm text-[var(--sea-ink-soft)]">
							Loading schedules...
						</div>
					)}

					{schedules !== undefined && schedules.length === 0 && (
						<div className="flex flex-col items-center justify-center gap-3 py-16 text-[var(--sea-ink-soft)]">
							<CalendarClock size={32} className="opacity-30" />
							<p className="text-sm">
								No scan schedules configured. Add one to automate scans.
							</p>
						</div>
					)}

					{schedules !== undefined && schedules.length > 0 && (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-[var(--line)]">
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Scanner
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Cron
										</th>
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Last Run
										</th>
										<th className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]">
											Status
										</th>
										<th className="px-4 py-3 text-right font-semibold text-[var(--sea-ink-soft)]">
											Actions
										</th>
									</tr>
								</thead>
								<tbody>
									{schedules.map((s: ScanSchedule) => (
										<tr key={s._id} className="border-b border-[var(--line)]">
											<td className="px-4 py-3">
												<div className="font-medium text-[var(--sea-ink)]">
													{s.scannerSlug}
												</div>
												{s.description && (
													<div className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
														{s.description}
													</div>
												)}
											</td>
											<td className="px-4 py-3">
												<code className="text-xs font-mono text-[var(--sea-ink-soft)] bg-[var(--chip-bg)] rounded px-1.5 py-0.5">
													{s.cronExpression}
												</code>
											</td>
											<td className="px-4 py-3 text-[var(--sea-ink-soft)] text-xs">
												{s.lastRunAt
													? new Date(s.lastRunAt).toLocaleString()
													: "Never"}
											</td>
											<td className="px-4 py-3 text-center">
												<span
													className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold ${
														s.enabled
															? "bg-green-100 text-green-700"
															: "bg-gray-100 text-gray-500"
													}`}
												>
													{s.enabled ? "Enabled" : "Disabled"}
												</span>
											</td>
											<td className="px-4 py-3">
												<div className="flex items-center justify-end gap-1">
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
														onClick={() => handleRunNow(s._id)}
														disabled={runningId === s._id}
														aria-label="Run scan now"
													>
														<Play size={14} />
													</button>
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
														onClick={() =>
															openEdit(
																s._id,
																s.scannerSlug,
																s.cronExpression,
																s.description ?? undefined,
																s.enabled,
															)
														}
														aria-label="Edit schedule"
													>
														<Edit3 size={14} />
													</button>
													<button
														type="button"
														className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-red-500"
														onClick={() => handleDelete(s._id)}
														aria-label="Delete schedule"
													>
														<Trash2 size={14} />
													</button>
												</div>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
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
								{editingId ? "Edit Schedule" : "Add Schedule"}
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
									Scanner
								</label>
								<select
									className="input-field w-full"
									value={formScanner}
									onChange={(e) =>
										setFormScanner(e.target.value as (typeof SCANNER_SLUGS)[number])
									}
								>
									{SCANNER_SLUGS.map((slug) => (
										<option key={slug} value={slug}>
											{slug}
										</option>
									))}
								</select>
							</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Cron Expression
								</label>
								<input
									type="text"
									className="input-field w-full font-mono"
									placeholder="0 * * * *"
									value={formCron}
									onChange={(e) => { setFormCron(e.target.value); setCronError(null); }}
									/>
									<p className="mt-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
									Standard 5-field cron: minute hour day-of-month month day-of-week
									</p>
									{cronError && (
									<p className="mt-1 text-xs text-red-600">{cronError}</p>
									)}
									</div>

							<div>
								<label className="mb-1 block text-xs font-semibold text-[var(--sea-ink-soft)]">
									Description (optional)
								</label>
								<input
									type="text"
									className="input-field w-full"
									placeholder="e.g., Hourly SAST scan for all repos"
									value={formDescription}
									onChange={(e) => setFormDescription(e.target.value)}
								/>
							</div>

							<div className="flex items-center gap-2">
								<input
									type="checkbox"
									id="schedule-enabled"
									checked={formEnabled}
									onChange={(e) => setFormEnabled(e.target.checked)}
									className="rounded border-[var(--chip-line)]"
								/>
								<label
									htmlFor="schedule-enabled"
									className="text-xs font-medium text-[var(--sea-ink)]"
								>
									Enabled
								</label>
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
									disabled={!formCron}
								>
									{editingId ? "Update" : "Create"} Schedule
								</button>
							</div>
						</div>
					</aside>
				</>
			)}
		</main>
	);
}
