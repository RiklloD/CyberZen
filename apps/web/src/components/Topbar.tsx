import { Search } from "lucide-react";
import Breadcrumbs from "./Breadcrumbs";
import { openCommandPalette } from "./CommandPalette";
import NotificationBell from "./NotificationBell";

const IS_MAC =
	typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

export default function Topbar() {
	return (
		<div className="topbar">
			<Breadcrumbs />
			<div className="topbar-spacer" />
			<button type="button" className="topbar-search" onClick={openCommandPalette}>
				<Search size={14} />
				<span className="topbar-search-label">Search findings, repos, pages…</span>
				<span className="kbd">{IS_MAC ? "⌘K" : "Ctrl K"}</span>
			</button>
			<NotificationBell />
		</div>
	);
}
