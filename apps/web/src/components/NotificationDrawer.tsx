import { X, Check, CheckCheck, Bell } from "lucide-react";
import type { Id } from "../lib/convex";

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
	system: "System",
};

const TYPE_COLORS: Record<string, string> = {
	finding_critical: "bg-red-100 text-red-700",
	finding_high: "bg-orange-100 text-orange-700",
	gate_blocked: "bg-red-100 text-red-700",
	gate_overridden: "bg-yellow-100 text-yellow-700",
	exploit_validated: "bg-red-100 text-red-700",
	remediation_dispatched: "bg-blue-100 text-blue-700",
	pr_generated: "bg-green-100 text-green-700",
	scan_completed: "bg-green-100 text-green-700",
	sla_breach: "bg-red-100 text-red-700",
	member_invited: "bg-blue-100 text-blue-700",
	system: "bg-gray-100 text-gray-700",
};

export default function NotificationDrawer({
	open,
	onClose,
	notifications,
	onMarkRead,
	onMarkAllRead,
}: Props) {
	const unread = notifications.filter((n) => !n.readAt);

	if (!open) return null;

	return (
		<>
			{/* Backdrop */}
			<div
				className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm"
				onClick={onClose}
				aria-hidden="true"
			/>

			{/* Drawer */}
			<aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col border-l border-[var(--line)] bg-[var(--panel-bg)] shadow-2xl">
				{/* Header */}
				<div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3">
					<div className="flex items-center gap-2">
						<Bell size={18} className="text-[var(--signal)]" />
						<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
							Notifications
						</h2>
						{unread.length > 0 && (
							<span className="rounded-full bg-red-500 px-2 py-0.5 text-[0.65rem] font-bold text-white">
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
						const color =
							TYPE_COLORS[n.type] ?? "bg-gray-100 text-gray-700";

						return (
							<div
								key={n._id}
								className={`border-b border-[var(--line)] px-4 py-3 transition-colors hover:bg-[var(--chip-bg)] ${!n.readAt ? "bg-[var(--chip-bg)]" : ""}`}
							>
								<div className="flex items-start gap-3">
									<div className="flex-1 min-w-0">
										<div className="flex items-center gap-2 mb-1">
											<span
												className={`inline-flex rounded-full px-2 py-0.5 text-[0.6rem] font-semibold ${color}`}
											>
												{label}
											</span>
											{!n.readAt && (
												<span className="h-2 w-2 rounded-full bg-blue-500" />
											)}
										</div>
										<p className="text-sm text-[var(--sea-ink)] truncate">
											{(parsed.message as string) ?? n.type}
										</p>
										<p className="mt-1 text-[0.65rem] text-[var(--sea-ink-soft)]">
											{new Date(n.createdAt).toLocaleString()}
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
