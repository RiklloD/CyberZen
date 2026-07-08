import HubTabs, { type HubTab } from "./HubTabs";

/**
 * Wraps a hub page with consistent header + tab bar.
 *
 * Usage in a route file:
 *   <HubPage title="Supply Chain" subtitle="..." tabs={TABS} activeKey="overview">
 *     ...page content...
 *   </HubPage>
 */
export default function HubPage({
	title,
	subtitle,
	tabs,
	activeKey,
	children,
}: {
	title: string;
	subtitle?: string;
	tabs: HubTab[];
	activeKey: string;
	children: React.ReactNode;
}) {
	return (
		<main>
			<div className="page-header">
				<h1 className="page-title">{title}</h1>
				{subtitle && <p className="page-subtitle">{subtitle}</p>}
			</div>
			<HubTabs tabs={tabs} activeKey={activeKey} />
			<div className="page-body">{children}</div>
		</main>
	);
}
