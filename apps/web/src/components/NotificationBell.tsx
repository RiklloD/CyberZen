import { Bell } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import { useState } from "react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import NotificationDrawer from "./NotificationDrawer";

export default function NotificationBell() {
	const TENANT = useTenantSlug();
	const [drawerOpen, setDrawerOpen] = useState(false);

	const unreadCount = useQuery(api.notifications.unreadCount, {
		tenantSlug: TENANT });

	const notifications = useQuery(api.notifications.listForUser, {
		tenantSlug: TENANT });

	const markRead = useMutation(api.notifications.markRead);
	const markAllRead = useMutation(api.notifications.markAllRead);

	const count = unreadCount ?? 0;

	return (
		<>
			<button
				type="button"
				className="icon-button"
				onClick={() => setDrawerOpen(true)}
				aria-label={`Notifications${count > 0 ? ` (${count} unread)` : ""}`}
			>
				<Bell size={16} />
				{count > 0 && (
					<span className="icon-button-badge">
						{count > 99 ? "99+" : count}
					</span>
				)}
			</button>

			<NotificationDrawer
				open={drawerOpen}
				onClose={() => setDrawerOpen(false)}
				notifications={notifications ?? []}
				onMarkRead={(id) =>
					markRead({ notificationId: id })
				}
				onMarkAllRead={() =>
					markAllRead({ tenantSlug: TENANT })
				}
			/>
		</>
	);
}
