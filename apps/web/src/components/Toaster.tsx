import { useAuthToken } from "../lib/clerk-compat";
import { useQuery } from "convex/react";
import { useEffect, useRef, useState } from "react";
import { X, AlertTriangle, CheckCircle, Info, AlertOctagon } from "lucide-react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

type Toast = {
	id: string;
	type: string;
	message: string;
	severity: "critical" | "warning" | "info" | "success";
	createdAt: number;
};

const SEVERITY_MAP: Record<string, Toast["severity"]> = {
	finding_critical: "critical",
	finding_high: "warning",
	gate_blocked: "critical",
	gate_overridden: "warning",
	exploit_validated: "critical",
	sla_breach: "critical",
	remediation_dispatched: "info",
	pr_generated: "success",
	scan_completed: "success",
	member_invited: "info",
	system: "info",
};

const SEVERITY_STYLES: Record<
	Toast["severity"],
	{ bg: string; border: string; icon: typeof AlertTriangle; iconColor: string }
> = {
	critical: {
		bg: "bg-red-50 dark:bg-red-950/40",
		border: "border-red-300 dark:border-red-800",
		icon: AlertOctagon,
		iconColor: "text-red-500",
	},
	warning: {
		bg: "bg-orange-50 dark:bg-orange-950/40",
		border: "border-orange-300 dark:border-orange-800",
		icon: AlertTriangle,
		iconColor: "text-orange-500",
	},
	info: {
		bg: "bg-blue-50 dark:bg-blue-950/40",
		border: "border-blue-300 dark:border-blue-800",
		icon: Info,
		iconColor: "text-blue-500",
	},
	success: {
		bg: "bg-green-50 dark:bg-green-950/40",
		border: "border-green-300 dark:border-green-800",
		icon: CheckCircle,
		iconColor: "text-green-500",
	},
};

const TOAST_DURATION_MS = 6000;
const MAX_TOASTS = 5;

/**
 * §6.21 — Toast Notifications
 *
 * Subscribes to the Convex notifications query and surfaces new critical/important
 * items as auto-dismissing toast popups. Mounted once in __root.tsx.
 */
export default function Toaster() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken();

	const notifications = useQuery(api.notifications.listForUser, {
		tenantSlug: TENANT,
	});

	const [toasts, setToasts] = useState<Toast[]>([]);
	const seenIds = useRef<Set<string>>(new Set());
	const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

	useEffect(() => {
		if (!notifications) return;

		// On first load, mark all existing as seen (don't toast old items)
		if (seenIds.current.size === 0) {
			for (const n of notifications) {
				seenIds.current.add(n._id);
			}
			return;
		}

		// Find genuinely new unread notifications
		const newItems = notifications.filter(
			(n: (typeof notifications)[number]) => !n.readAt && !seenIds.current.has(n._id),
		);

		for (const n of newItems) {
			seenIds.current.add(n._id);

			let payload: { message?: string } = {};
			try {
				payload = JSON.parse(n.payload);
			} catch {
				// ignore
			}

			const severity = SEVERITY_MAP[n.type] ?? "info";
			const message =
				(payload.message as string) ??
				n.type.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());

			const toast: Toast = {
				id: n._id,
				type: n.type,
				message,
				severity,
				createdAt: n.createdAt,
			};

			setToasts((prev) => {
				const next = [toast, ...prev].slice(0, MAX_TOASTS);
				return next;
			});

			// Auto-dismiss after duration
			const timer = setTimeout(() => {
				setToasts((prev) => prev.filter((t) => t.id !== toast.id));
				timers.current.delete(toast.id);
			}, TOAST_DURATION_MS);
			timers.current.set(toast.id, timer);
		}
	}, [notifications]);

	// Cleanup timers on unmount
	useEffect(() => {
		const currentTimers = timers.current;
		return () => {
			for (const timer of currentTimers.values()) {
				clearTimeout(timer);
			}
		};
	}, []);

	function dismiss(id: string) {
		setToasts((prev) => prev.filter((t) => t.id !== id));
		const timer = timers.current.get(id);
		if (timer) {
			clearTimeout(timer);
			timers.current.delete(id);
		}
	}

	if (toasts.length === 0) return null;

	return (
		<div className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 w-full max-w-sm pointer-events-none">
			{toasts.map((toast) => {
				const style = SEVERITY_STYLES[toast.severity];
				const Icon = style.icon;
				return (
					<div
						key={toast.id}
						className={`pointer-events-auto flex items-start gap-3 rounded-lg border ${style.border} ${style.bg} px-4 py-3 shadow-lg animate-[slideInRight_0.25s_ease-out]`}
						role="alert"
					>
						<Icon size={18} className={`mt-0.5 flex-shrink-0 ${style.iconColor}`} />
						<div className="flex-1 min-w-0">
							<p className="text-sm font-medium text-[var(--sea-ink)]">
								{toast.message}
							</p>
							<p className="mt-0.5 text-[0.65rem] text-[var(--sea-ink-soft)]">
								{new Date(toast.createdAt).toLocaleTimeString()}
							</p>
						</div>
						<button
							type="button"
							className="flex-shrink-0 text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--sea-ink)]"
							onClick={() => dismiss(toast.id)}
							aria-label="Dismiss notification"
						>
							<X size={14} />
						</button>
					</div>
				);
			})}
		</div>
	);
}
