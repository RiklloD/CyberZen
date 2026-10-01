import { X, Check, CheckCheck, Bell } from "lucide-react";
import type { Id } from "../lib/convex";
import { relativeTime } from "../lib/format";
import StatusPill from "./StatusPill";

type Notification = {
	_id: Id<"notifications">;
	_creationTime: number;
	userId: Id<"users">;
	tenantId: Id<"tenants">;
	type: string;
	payload: string;
	readAt?: number;
	createdAt: number;
};

type Props = {
	open: boolean;
	onClose: () => void;
	notifications: Notification[];
	onMarkRead: (id: Id<"notifications">) => void;
	onMarkAllRead: () => void;
};

const TYPE_LABELS: Record<string, string> = {
	finding_critical: "Critical Finding",
	finding_high: "High Finding",
	gate_blocked: "Gate Blocked",
	gate_overridden: "Gate Overridden",
	exploit_validated: "Exploit Validated",
	remediation_dispatched: "Remediation Dispatched",
	pr_generated: "PR Generated",
	scan_completed: "Scan Completed",
	sla_breach: "SLA Breach",
	member_invited: "Member Invited",
	system: "System" };

const TYPE_TONES: Record<string, "danger" | "warning" | "success" | "info" | "neutral"> = {
	finding_critical: "danger",
	finding_high: "warning",
	gate_blocked: "danger",
	gate_overridden: "warning",
	exploit_validated: "danger",
	remediation_dispatched: "info",
	pr_generated: "success",
	scan_completed: "success",
	sla_breach: "danger",
	member_invited: "info",
	system: "neutral" };

export default function NotificationDrawer({
	open,
	onClose,
	notifications,
	onMarkRead,
	onMarkAllRead }: Props) {
	const unread = notifications.filter((n) => !n.readAt);

	if (!open) return null;

	return (
		<>
			{/* Backdrop */}
			<div
				className="fixed inset-0 z-[60] bg-[var(--overlay)]"
				onClick={onClose}
				aria-hidden="true"
			/>

			{/* Drawer */}
			<aside className="fixed right-0 top-0 z-[61] flex h-full w-full max-w-md flex-col border-l border-[var(--line-strong)] bg-[var(--surface)] shadow-2xl">
				{/* Header */}
				<div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
					<div className="flex items-center gap-2">
						
						<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
							Notifications
						</h2>
						{unread.length > 0 && (
							<span className="badge" data-tone="danger">
								{unread.length}
							</span>
						)}
					</div>
					<div className="flex items-center gap-2">
						{unread.length > 0 && (
							<button
								type="button"
								className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
								onClick={onMarkAllRead}
							>
								<CheckCheck size={14} />
								Mark all read
							</button>
						)}
						<button
							type="button"
							className="flex h-7 w-7 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--sea-ink)]"
							onClick={onClose}
							aria-label="Close notifications"
						>
							<X size={16} />
						</button>
					</div>
				</div>

				{/* List */}
				<div className="flex-1 overflow-y-auto">
					{notifications.length === 0 && (
						<div className="flex flex-col items-center justify-center gap-3 py-16 text-[var(--sea-ink-soft)]">
							<Bell size={32} className="opacity-30" />
							<p className="text-sm">No notifications yet</p>
						</div>
					)}
					{notifications.map((n) => {
						let parsed: Record<string, unknown> = {};
						try {
							parsed = JSON.parse(n.payload);
						} catch {
							// ignore
						}

						const label =
							TYPE_LABELS[n.type] ?? n.type;
						const tone = TYPE_TONES[n.type] ?? "neutral";

						return (
							<div
								key={n._id}
								className={`border-b border-[var(--line)] px-4 py-3 transition-colors hover:bg-[var(--surface-2)] ${!n.readAt ? "bg-[var(--accent-soft)]" : ""}`}
							>
								<div className="flex items-start gap-3">
									<div className="flex-1 min-w-0">
										<div className="flex items-center gap-2 mb-1">
											<StatusPill label={label} tone={tone} />
											{!n.readAt && (
												<span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
											)}
										</div>
										<p className="text-sm text-[var(--sea-ink)] truncate">
											{(parsed.message as string) ?? n.type}
										</p>
										<p className="mt-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
											{relativeTime(n.createdAt)}
										</p>
									</div>
									{!n.readAt && (
										<button
											type="button"
											className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-md text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
											onClick={() => onMarkRead(n._id)}
											aria-label="Mark as read"
										>
											<Check size={14} />
										</button>
									)}
								</div>
							</div>
						);
					})}
				</div>
			</aside>
		</>
	);
}
