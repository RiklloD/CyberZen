import { Link, useRouterState } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import {
	AlertTriangle,
	BarChart3,
	Bot,
	FolderGit2,
	GitPullRequestArrow,
	Home,
	Lock,
	Menu,
	Network,
	Package,
	Radar,
	Settings,
	Wrench,
	X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/convex";
import { useFeatureFlag } from "../lib/featureFlags";
import { useTenantSlug } from "../lib/workspace";
import ThemeToggle from "./ThemeToggle";
import UserProfileButton from "./UserProfileButton";
import WorkspaceSwitcher from "./WorkspaceSwitcher";

type NavItem = {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
	featureFlag?: string;
	/** Extra path prefixes that should light this item up. */
	match?: string[];
	countKey?: "findings";
};

type NavGroup = { label?: string; items: NavItem[] };

/**
 * Navigation is organised around the job a security engineer is doing,
 * not around the product's internal modules:
 *
 *   triage   → what's wrong right now (Overview, Findings, Repositories)
 *   respond  → getting it fixed and keeping it from coming back
 *   intel    → why it matters and where it might come from next
 */
const NAV: NavGroup[] = [
	{
		items: [
			{ to: "/", label: "Overview", icon: Home },
			{
				to: "/findings",
				label: "Findings",
				icon: AlertTriangle,
				match: ["/timeline"],
				countKey: "findings",
			},
			{ to: "/repositories", label: "Repositories", icon: FolderGit2 },
		],
	},
	{
		label: "Respond",
		items: [
			{ to: "/remediation", label: "Remediation", icon: Wrench },
			{ to: "/ci-cd", label: "CI/CD gates", icon: GitPullRequestArrow },
		],
	},
	{
		label: "Intelligence",
		items: [
			{ to: "/breach-intel", label: "Breach intel", icon: Radar },
			{
				to: "/supply-chain",
				label: "Supply chain",
				icon: Package,
				match: ["/sbom", "/cross-repo", "/zero-day", "/exploit-validation"],
			},
			{ to: "/attack-paths", label: "Attack paths", icon: Network },
			{
				to: "/agent-activity",
				label: "Agents",
				icon: Bot,
				match: ["/agents", "/neural-memory"],
			},
		],
	},
	{
		label: "Workspace",
		items: [
			{
				to: "/reports",
				label: "Reports",
				icon: BarChart3,
				match: [
					"/posture",
					"/executive-report",
					"/maturity",
					"/business-impact",
					"/compliance",
					"/dashboards",
				],
			},
			{
				to: "/settings",
				label: "Settings",
				icon: Settings,
				match: ["/integrations", "/audit-log"],
			},
		],
	},
];

export default function Sidebar() {
	const [mobileOpen, setMobileOpen] = useState(false);
	const currentPath = useRouterState({ select: (s) => s.location.pathname });
	const tenantSlug = useTenantSlug();
	const findingStats = useQuery(api.findings.stats, { tenantSlug });

	// Close the mobile sheet whenever the route changes.
	useEffect(() => {
		setMobileOpen(false);
	}, [currentPath]);

	const counts: Record<NonNullable<NavItem["countKey"]>, number | undefined> = {
		findings: findingStats?.openAndCritical,
	};

	function isActive(item: NavItem) {
		const prefixes = [item.to, ...(item.match ?? [])];
		return prefixes.some((p) =>
			p === "/" ? currentPath === "/" : currentPath === p || currentPath.startsWith(`${p}/`),
		);
	}

	return (
		<>
			<a href="#main-content" className="skip-link">
				Skip to main content
			</a>
			<button
				type="button"
				className="sidebar-mobile-toggle"
				onClick={() => setMobileOpen(!mobileOpen)}
				aria-label="Toggle navigation"
				aria-expanded={mobileOpen}
				aria-controls="sidebar-nav"
			>
				{mobileOpen ? <X size={16} /> : <Menu size={16} />}
			</button>

			{mobileOpen && (
				<div
					className="sidebar-overlay"
					onClick={() => setMobileOpen(false)}
					aria-hidden="true"
				/>
			)}

			<aside
				id="sidebar-nav"
				className={`sidebar${mobileOpen ? " is-open" : ""}`}
				aria-label="Main navigation"
			>
				<div className="sidebar-inner">
					<div className="sidebar-top">
						<WorkspaceSwitcher />
					</div>

					<nav className="sidebar-nav">
						{NAV.map((group, gi) => (
							<div key={group.label ?? gi}>
								{group.label && (
									<div className="sidebar-group-label">{group.label}</div>
								)}
								<div className="sidebar-group-items">
									{group.items.map((item) => (
										<SidebarItem
											key={item.to}
											item={item}
											isActive={isActive(item)}
											count={item.countKey ? counts[item.countKey] : undefined}
										/>
									))}
								</div>
							</div>
						))}
					</nav>

					<div className="sidebar-footer">
						<UserProfileButton />
						<ThemeToggle />
					</div>
				</div>
			</aside>
		</>
	);
}

function SidebarItem({
	item,
	isActive,
	count,
}: {
	item: NavItem;
	isActive: boolean;
	count?: number;
}) {
	const flagEnabled = useFeatureFlag(item.featureFlag ?? "");
	const isLocked = !!item.featureFlag && flagEnabled === false;

	if (isLocked) {
		return (
			<Link
				to="/pricing"
				className="sidebar-item"
				title={`${item.label} requires an Enterprise plan`}
			>
				<item.icon size={15} />
				<span>{item.label}</span>
				<Lock size={11} className="ml-auto opacity-60" />
			</Link>
		);
	}

	return (
		<Link
			to={item.to as "/"}
			className={`sidebar-item${isActive ? " is-active" : ""}`}
			aria-current={isActive ? "page" : undefined}
		>
			<item.icon size={15} />
			<span>{item.label}</span>
			{count !== undefined && count > 0 && (
				<span
					className="sidebar-item-count is-danger"
					title={`${count} open critical/high findings`}
				>
					{count > 99 ? "99+" : count}
				</span>
			)}
		</Link>
	);
}
