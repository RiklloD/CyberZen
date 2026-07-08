import { Link } from "@tanstack/react-router";
import { type LucideIcon } from "lucide-react";

/**
 * Shared tab bar for hub pages (Supply Chain, Reports, Agents).
 *
 * Uses query-param `?tab=X` for active state so each tab is shareable
 * and back/forward works. Falls back to the first tab when no param set.
 */

export type HubTab = {
	key: string;
	label: string;
	icon: LucideIcon;
	/** Where to navigate when this tab is clicked. */
	to: string;
};

export default function HubTabs({
	tabs,
	activeKey,
}: {
	tabs: HubTab[];
	/** Currently active tab key. */
	activeKey: string;
}) {
	return (
		<div className="hub-tabs" role="tablist">
			{tabs.map((tab) => {
				const isActive = tab.key === activeKey;
				// If the tab navigates to a different route, use Link.
				// If it's the same route with ?tab=, use Link with search.
				return (
					<Link
						key={tab.key}
						to={tab.to as "/"}
						className={`hub-tab${isActive ? " is-active" : ""}`}
						role="tab"
						aria-selected={isActive}
					>
						<tab.icon size={14} />
						<span>{tab.label}</span>
					</Link>
				);
			})}
		</div>
	);
}
