import { useAuthToken } from "@convex-dev/auth/react";
import { Bell } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import { useState } from "react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import NotificationDrawer from "./NotificationDrawer";

export default function NotificationBell() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken();
	const [drawerOpen, setDrawerOpen] = useState(false);

	const unreadCount = useQuery(api.notifications.unreadCount, {
		tenantSlug: TENANT,
		authToken: authToken ?? "",
	});

	const notifications = useQuery(api.notifications.listForUser, {
		tenantSlug: TENANT,
		authToken: authToken ?? "",
	});

	const markRead = useMutation(api.notifications.markRead);
	const markAllRead = useMutation(api.notifications.markAllRead);

	const count = unreadCount ?? 0;

	return (
		<>
			<button
				type="button"
				className="relative flex h-9 w-9 items-center justify-center rounded-full border border-[var(--chip-line)] bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] transition-colors hover:text-[var(--signal)]"
				onClick={() => setDrawerOpen(true)}
				aria-label={`Notifications${count > 0 ? ` (${count} unread)` : ""}`}
			>
				<Bell size={16} />
				{count > 0 && (
					<span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[0.6rem] font-bold text-white">
						{count > 99 ? "99+" : count}
					</span>
				)}
			</button>

			<NotificationDrawer
				open={drawerOpen}
				onClose={() => setDrawerOpen(false)}
				notifications={notifications ?? []}
				onMarkRead={(id) =>
					markRead({ notificationId: id, authToken: authToken ?? "" })
				}
				onMarkAllRead={() =>
					markAllRead({ tenantSlug: TENANT, authToken: authToken ?? "" })
				}
			/>
		</>
	);
}
