import { createFileRoute } from "@tanstack/react-router";
import {
	CalendarClock,
	Plus,
	Trash2,
	Users,
	ToggleLeft,
	ToggleRight,
	AlertTriangle } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { api } from "#/lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

type OnCallSchedule = NonNullable<FunctionReturnType<typeof api.onCall.listSchedules>>[number];
type OnCallScheduleMember = OnCallSchedule["members"][number];
type EscalationPolicy = NonNullable<FunctionReturnType<typeof api.onCall.listEscalationPolicies>>[number];

export const Route = createFileRoute("/settings/on-call")({
	errorComponent: RouteErrorBoundary,
	component: OnCallSettingsPage });

const ROTATION_LABELS: Record<string, string> = {
	daily: "Daily",
	weekly: "Weekly",
	biweekly: "Bi-weekly",
	monthly: "Monthly" };

const CHANNEL_LABELS: Record<string, string> = {
	email: "Email",
	slack: "Slack",
	sms: "SMS",
	webhook: "Webhook" };

function OnCallSettingsPage() {
	const TENANT = useTenantSlug();
	const schedules = useQuery(api.onCall.listSchedules, {
		tenantSlug: TENANT });
	const escalationPolicies = useQuery(api.onCall.listEscalationPolicies, {
		tenantSlug: TENANT });

	const createSchedule = useMutation(api.onCall.createSchedule);
	const deleteSchedule = useMutation(api.onCall.deleteSchedule);
	const updateSchedule = useMutation(api.onCall.updateSchedule);
	const createEscalationPolicy = useMutation(api.onCall.createEscalationPolicy);
	const deleteEscalationPolicy = useMutation(api.onCall.deleteEscalationPolicy);

	const [showScheduleForm, setShowScheduleForm] = useState(false);
	const [showEscalationForm, setShowEscalationForm] = useState(false);
	const [scheduleForm, setScheduleForm] = useState({
		name: "",
		rotationType: "weekly",
		timezone: "UTC",
		enabled: true });
	const [escalationForm, setEscalationForm] = useState({
		name: "",
		scheduleId: "",
		delayMinutes: 15,
		channels: ["email"] as string[],
		repeatCount: 0,
		enabled: true });

	async function handleCreateSchedule() {
		await createSchedule({
			tenantSlug: TENANT,
			name: scheduleForm.name,
			rotationType: scheduleForm.rotationType as any,
			memberIds: [], // Will be populated via team member selector
			timezone: scheduleForm.timezone,
			enabled: scheduleForm.enabled });
		setShowScheduleForm(false);
		setScheduleForm({
			name: "",
			rotationType: "weekly",
			timezone: "UTC",
			enabled: true });
	}

	async function handleCreateEscalation() {
		if (!escalationForm.scheduleId) return;
		await createEscalationPolicy({
			tenantSlug: TENANT,
			name: escalationForm.name,
			onCallScheduleId: escalationForm.scheduleId as any,
			steps: [
				{
					delayMinutes: escalationForm.delayMinutes,
					target: "current_on_call" as const,
					channels: escalationForm.channels as any },
			],
			repeatCount: escalationForm.repeatCount,
			enabled: escalationForm.enabled });
		setShowEscalationForm(false);
		setEscalationForm({
			name: "",
			scheduleId: "",
			delayMinutes: 15,
			channels: ["email"],
			repeatCount: 0,
			enabled: true });
	}

	// Generate calendar-like grid for the current week
	function renderCalendarGrid() {
		if (!schedules || schedules.length === 0) return null;

		const now = new Date();
		const startOfWeek = new Date(now);
		startOfWeek.setDate(now.getDate() - now.getDay())
		startOfWeek.setHours(0, 0, 0, 0);

		const days = Array.from({ length: 7 }, (_, i) => {
			const d = new Date(startOfWeek);
			d.setDate(d.getDate() + i);
			return d;
		});

		const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

		return (
			<div className="mt-4">
				<h3 className="section-title mb-3">This Week's Rotation</h3>
				<div
					className="grid grid-cols-7 gap-2"
					role="grid"
					aria-label="Weekly on-call rotation"
				>
					{days.map((day, i) => {
						const isToday = day.toDateString() === now.toDateString();
						return (
							<div
								key={i}
								className={`rounded-xl border p-2 text-center ${
									isToday
										? "border-[var(--accent-line)] bg-[var(--accent-tint)]"
										: "border-[var(--line)] bg-[var(--surface)]"
								}`}
								role="gridcell"
								aria-label={`${dayNames[i]} ${day.getDate()}`}
							>
								<div className="text-[10px] font-semibold text-[var(--sea-ink-soft)] uppercase tracking-wider">
									{dayNames[i]}
								</div>
								<div className="text-sm font-bold text-[var(--sea-ink)] mt-0.5">
									{day.getDate()}
								</div>
								{schedules
									.filter((s: OnCallSchedule) => s.enabled)
									.slice(0, 1)
									.map((schedule: OnCallSchedule) => {
										const currentMember =
											schedule.members[schedule.currentRotationIndex % schedule.members.length];
										return (
											<div
												key={schedule._id}
												className="mt-1.5 text-[9px] font-medium text-[var(--signal)] truncate"
												title={currentMember?.name ?? "Unassigned"}
											>
												{currentMember?.name ?? "—"}
											</div>
										);
									})}
							</div>
						);
					})}
				</div>
			</div>
		);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<CalendarClock size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">On-Call Rotation</h1>
						<p className="page-subtitle">
							Manage on-call schedules and escalation policies
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Calendar grid */}
				<div className="card mb-4">
					{renderCalendarGrid()}
					{(!schedules || schedules.length === 0) && (
						<div className="empty-state mt-2">
							<CalendarClock size={28} className="mb-2 opacity-40" />
							<p>No schedules yet. Create one to see the rotation calendar.</p>
						</div>
					)}
				</div>

				{/* Schedules */}
				<div className="card mb-4">
					<div className="flex items-center justify-between mb-4">
						<h2 className="section-title flex items-center gap-2">
							<Users size={14} />
							Schedules
						</h2>
						<button
							type="button"
							className="signal-button"
							onClick={() => setShowScheduleForm(!showScheduleForm)}
							aria-label="Add on-call schedule"
						>
							<Plus size={14} />
							Add Schedule
						</button>
					</div>

					{!schedules ? (
						<div className="loading-panel p-4">Loading schedules…</div>
					) : schedules.length === 0 ? (
						<div className="empty-state">
							<p>No on-call schedules configured.</p>
						</div>
					) : (
						<div className="space-y-2">
							{schedules.map((schedule: OnCallSchedule) => (
								<div
									key={schedule._id}
									className="flex items-center justify-between gap-3 p-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]"
								>
									<div className="min-w-0 flex-1">
										<div className="flex items-center gap-2">
											<span className="text-sm font-semibold text-[var(--sea-ink)]">
												{schedule.name}
											</span>
											<span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--accent-tint)] text-[var(--signal)] border border-[var(--accent-line)]">
												{ROTATION_LABELS[schedule.rotationType] ?? schedule.rotationType}
											</span>
										</div>
										<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
											{schedule.members.length} member{schedule.members.length !== 1 ? "s" : ""} · {schedule.timezone}
										</p>
										<div className="flex gap-1 mt-1.5">
											{schedule.members.map((m: OnCallScheduleMember) => (
												<span
													key={m._id as string}
													className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--chip-bg)] border border-[var(--chip-line)] text-[var(--sea-ink-soft)]"
												>
													{m.name}
												</span>
											))}
										</div>
									</div>

									<div className="flex items-center gap-2">
										<button
											type="button"
											className="p-1.5 rounded-lg hover:bg-[var(--surface-soft)] transition-colors"
											onClick={() =>
												updateSchedule({
													tenantSlug: TENANT,
													scheduleId: schedule._id,
													enabled: !schedule.enabled })
											}
											aria-label={schedule.enabled ? "Disable schedule" : "Enable schedule"}
										>
											{schedule.enabled ? (
												<ToggleRight size={20} className="text-[var(--signal)]" />
											) : (
												<ToggleLeft size={20} className="text-[var(--sea-ink-dim)]" />
											)}
										</button>
										<button
											type="button"
											className="p-1.5 rounded-lg hover:bg-red-50 text-[var(--danger)] transition-colors"
											onClick={() => deleteSchedule({ tenantSlug: TENANT, scheduleId: schedule._id })}
											aria-label="Delete schedule"
										>
											<Trash2 size={16} />
										</button>
									</div>
								</div>
							))}
						</div>
					)}

					{showScheduleForm && (
						<div className="mt-4 pt-4 border-t border-[var(--line)] space-y-3" role="form" aria-label="Create on-call schedule">
							<div className="auth-field">
								<label htmlFor="oc-name" className="text-xs font-medium">Schedule Name</label>
								<input
									id="oc-name"
									type="text"
									value={scheduleForm.name}
									onChange={(e) => setScheduleForm((s) => ({ ...s, name: e.target.value }))}
									placeholder="e.g. Primary On-Call"
								/>
							</div>
							<div className="grid grid-cols-2 gap-3">
								<div className="auth-field">
									<label htmlFor="oc-rotation" className="text-xs font-medium">Rotation</label>
									<select
										id="oc-rotation"
										value={scheduleForm.rotationType}
										onChange={(e) => setScheduleForm((s) => ({ ...s, rotationType: e.target.value }))}
										className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-panel)] text-[var(--sea-ink)] p-2.5"
									>
										{Object.entries(ROTATION_LABELS).map(([k, v]) => (
											<option key={k} value={k}>{v}</option>
										))}
									</select>
								</div>
								<div className="auth-field">
									<label htmlFor="oc-tz" className="text-xs font-medium">Timezone</label>
									<input
										id="oc-tz"
										type="text"
										value={scheduleForm.timezone}
										onChange={(e) => setScheduleForm((s) => ({ ...s, timezone: e.target.value }))}
										placeholder="UTC"
									/>
								</div>
							</div>
							<div className="flex gap-2">
								<button type="button" className="signal-button" onClick={handleCreateSchedule} disabled={!scheduleForm.name.trim()}>
									Create Schedule
								</button>
								<button type="button" className="secondary-button signal-button" onClick={() => setShowScheduleForm(false)}>
									Cancel
								</button>
							</div>
						</div>
					)}
				</div>

				{/* Escalation Policies */}
				<div className="card">
					<div className="flex items-center justify-between mb-4">
						<h2 className="section-title flex items-center gap-2">
							<AlertTriangle size={14} />
							Escalation Policies
						</h2>
						<button
							type="button"
							className="signal-button"
							onClick={() => setShowEscalationForm(!showEscalationForm)}
							aria-label="Add escalation policy"
						>
							<Plus size={14} />
							Add Policy
						</button>
					</div>

					{!escalationPolicies ? (
						<div className="loading-panel p-4">Loading escalation policies…</div>
					) : escalationPolicies.length === 0 ? (
						<div className="empty-state">
							<p>No escalation policies configured.</p>
						</div>
					) : (
						<div className="space-y-2">
							{escalationPolicies.map((policy: EscalationPolicy) => (
								<div
									key={policy._id}
									className="flex items-center justify-between gap-3 p-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]"
								>
									<div className="min-w-0 flex-1">
										<div className="flex items-center gap-2">
											<span className="text-sm font-semibold text-[var(--sea-ink)]">
												{policy.name}
											</span>
											<span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--surface-soft)] border border-[var(--line)] text-[var(--sea-ink-soft)]">
												{policy.scheduleName}
											</span>
										</div>
										<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
											{policy.steps.length} step{policy.steps.length !== 1 ? "s" : ""} · Repeat {policy.repeatCount}× · Channels: {policy.steps[0]?.channels.map((c: string) => CHANNEL_LABELS[c] ?? c).join(", ")}
										</p>
									</div>
									<button
										type="button"
										className="p-1.5 rounded-lg hover:bg-red-50 text-[var(--danger)] transition-colors"
										onClick={() => deleteEscalationPolicy({ tenantSlug: TENANT, policyId: policy._id })}
										aria-label="Delete escalation policy"
									>
										<Trash2 size={16} />
									</button>
								</div>
							))}
						</div>
					)}

					{showEscalationForm && (
						<div className="mt-4 pt-4 border-t border-[var(--line)] space-y-3" role="form" aria-label="Create escalation policy">
							<div className="auth-field">
								<label htmlFor="ep-name" className="text-xs font-medium">Policy Name</label>
								<input
									id="ep-name"
									type="text"
									value={escalationForm.name}
									onChange={(e) => setEscalationForm((s) => ({ ...s, name: e.target.value }))}
									placeholder="e.g. Critical Alert Escalation"
								/>
							</div>
							<div className="auth-field">
								<label htmlFor="ep-schedule" className="text-xs font-medium">Bound Schedule</label>
								<select
									id="ep-schedule"
									value={escalationForm.scheduleId}
									onChange={(e) => setEscalationForm((s) => ({ ...s, scheduleId: e.target.value }))}
									className="w-full rounded-xl border border-[var(--line)] bg-[var(--bg-panel)] text-[var(--sea-ink)] p-2.5"
								>
									<option value="">Select a schedule…</option>
									{(schedules ?? []).map((s: OnCallSchedule) => (
										<option key={s._id as string} value={s._id as string}>
											{s.name}
										</option>
									))}
								</select>
							</div>
							<div className="grid grid-cols-2 gap-3">
								<div className="auth-field">
									<label htmlFor="ep-delay" className="text-xs font-medium">Delay (minutes)</label>
									<input
										id="ep-delay"
										type="number"
										min={1}
										value={escalationForm.delayMinutes}
										onChange={(e) => setEscalationForm((s) => ({ ...s, delayMinutes: parseInt(e.target.value) || 15 }))}
									/>
								</div>
								<div className="auth-field">
									<label htmlFor="ep-repeat" className="text-xs font-medium">Repeat Count</label>
									<input
										id="ep-repeat"
										type="number"
										min={0}
										value={escalationForm.repeatCount}
										onChange={(e) => setEscalationForm((s) => ({ ...s, repeatCount: parseInt(e.target.value) || 0 }))}
									/>
								</div>
							</div>
							<div className="flex gap-2">
								<button
									type="button"
									className="signal-button"
									onClick={handleCreateEscalation}
									disabled={!escalationForm.name.trim() || !escalationForm.scheduleId}
								>
									Create Policy
								</button>
								<button
									type="button"
									className="secondary-button signal-button"
									onClick={() => setShowEscalationForm(false)}
								>
									Cancel
								</button>
							</div>
						</div>
					)}
				</div>
			</div>
		</main>
	);
}
