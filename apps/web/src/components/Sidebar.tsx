import { Link, useRouterState } from "@tanstack/react-router";
import {
	AlertTriangle,
	BarChart3,
	Bot,
	GitBranch,
	GitMerge,
	Link2,
	Lock,
	LayoutDashboard,
	Menu,
	Settings,
	Shield,
	ShieldCheck,
	Wrench,
	X,
	ChevronRight,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useFeatureFlag } from "../lib/featureFlags";
import ThemeToggle from "./ThemeToggle";
import UserProfileButton from "./UserProfileButton";
import WorkspaceSwitcher from "./WorkspaceSwitcher";

type NavItem = {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
	featureFlag?: string;
};

type NavGroup = {
	label: string;
	items: NavItem[];
	/** When true, this group sits in the footer area below a divider. */
	isFooter?: boolean;
};

/**
 * Progressive-disclosure navigation.
 *
 * Only daily-use destinations appear at the top level. Everything else
 * (settings, reports, hub pages) is reachable from those pages or from
 * the footer links. This keeps the sidebar scannable and the mental model
 * clear: the 5 top items are "what needs my attention", the rest is
 * deeper analysis and configuration.
 */
const navGroups: NavGroup[] = [
	{
		label: "Main",
		items: [
			{ to: "/", label: "Dashboard", icon: LayoutDashboard },
			{ to: "/findings", label: "Findings", icon: AlertTriangle },
			{ to: "/repositories", label: "Repositories", icon: GitBranch },
			{ to: "/breach-intel", label: "Breach Intel", icon: Shield },
		],
	},
	{
		label: "Analysis",
		items: [
			{ to: "/attack-paths", label: "Attack Paths", icon: ShieldCheck },
			{ to: "/supply-chain", label: "Supply Chain", icon: Link2 },
		],
	},
	{
		label: "Automation",
		items: [
			{ to: "/ci-cd", label: "CI / CD Gates", icon: GitMerge },
			{ to: "/remediation", label: "Remediation", icon: Wrench },
		],
	},
	{
		label: "Intelligence",
		items: [
			{ to: "/agent-activity", label: "Agents", icon: Bot },
		],
	},
	// ── Footer links (below a divider) ────────────────────────────────────
	{
		label: "More",
		isFooter: true,
		items: [
			{ to: "/reports", label: "Reports", icon: BarChart3 },
			{ to: "/settings", label: "Settings", icon: Settings },
		],
	},
];

// ── Collapsible group state ───────────────────────────────────────────────

const COLLAPSED_KEY = "cyberzen.sidebar.collapsed";

function useCollapsedGroups() {
	const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

	// Load persisted state on mount
	useEffect(() => {
		try {
			const raw = localStorage.getItem(COLLAPSED_KEY);
			if (raw) setCollapsed(new Set(JSON.parse(raw)));
		} catch { /* ignore parse errors */ }
	}, []);

	const toggle = (label: string) => {
		setCollapsed((prev) => {
			const next = new Set(prev);
			if (next.has(label)) next.delete(label);
			else next.add(label);
			try { localStorage.setItem(COLLAPSED_KEY, JSON.stringify([...next])); } catch { /* ignore */ }
			return next;
		});
	};

	return { collapsed, toggle };
}

// ── Component ─────────────────────────────────────────────────────────────

export default function Sidebar() {
	const [mobileOpen, setMobileOpen] = useState(false);
	const routerState = useRouterState();
	const currentPath = routerState.location.pathname;
	const { collapsed, toggle } = useCollapsedGroups();

	function isActive(to: string) {
		if (to === "/") return currentPath === "/";
		return currentPath === to || currentPath.startsWith(`${to}/`);
	}

	/** Auto-expand a group if any of its items is active. */
	function isGroupAutoExpanded(group: NavGroup) {
		return group.items.some((item) => isActive(item.to));
	}

	// Split into main groups and footer links
	const mainGroups = navGroups.filter((g) => !g.isFooter);
	const footerGroup = navGroups.find((g) => g.isFooter);

	const nav = (
		<div className="sidebar-inner">
			<div className="sidebar-brand">
				<span className="sidebar-brand-icon">
					<Shield size={18} />
				</span>
				<div className="sidebar-brand-text">
					<div className="sidebar-brand-name">CyberZen</div>
					<div className="sidebar-brand-sub">Sentinel control plane</div>
				</div>
			</div>

			<div className="sidebar-workspace">
				<WorkspaceSwitcher />
			</div>

			<nav className="sidebar-nav">
				{mainGroups.map((group) => {
					const isCollapsed = collapsed.has(group.label) && !isGroupAutoExpanded(group);
					return (
						<div key={group.label} className="sidebar-group">
							<button
								type="button"
								className="sidebar-group-label"
								onClick={() => toggle(group.label)}
								aria-expanded={!isCollapsed}
								aria-label={`Toggle ${group.label} section`}
							>
								<span>{group.label}</span>
								<ChevronRight
									size={12}
									className="sidebar-group-chevron"
									style={{ transform: isCollapsed ? "rotate(0deg)" : "rotate(90deg)", transition: "transform 160ms ease" }}
								/>
							</button>
							{!isCollapsed && (
								<div className="sidebar-group-items">
									{group.items.map((item) => (
										<SidebarItem
											key={item.to}
											item={item}
											isActive={isActive(item.to)}
											onNavigate={() => setMobileOpen(false)}
										/>
									))}
								</div>
							)}
						</div>
					);
				})}

				{footerGroup && (
					<>
						<div className="sidebar-divider" />
						<div className="sidebar-group-items">
							{footerGroup.items.map((item) => (
								<SidebarItem
									key={item.to}
									item={item}
									isActive={isActive(item.to)}
									onNavigate={() => setMobileOpen(false)}
								/>
							))}
						</div>
					</>
				)}
			</nav>

			<div className="sidebar-footer">
				<UserProfileButton />
				<ThemeToggle />
			</div>
		</div>
	);

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
				{mobileOpen ? <X size={20} /> : <Menu size={20} />}
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
				role="navigation"
				aria-label="Main navigation"
			>
				{nav}
			</aside>
		</>
	);
}

function SidebarItem({
	item,
	isActive,
	onNavigate }: {
	item: NavItem;
	isActive: boolean;
	onNavigate: () => void;
}) {
	const flagEnabled = useFeatureFlag(item.featureFlag ?? "");
	const isGated = !!item.featureFlag;
	const isLocked = isGated && flagEnabled === false;

	if (isLocked) {
		return (
			<Link
				to="/pricing"
				className={`sidebar-item is-locked${isActive ? " is-active" : ""}`}
				onClick={onNavigate}
				title={`${item.label} requires an Enterprise plan`}
				aria-label={`${item.label} (Enterprise — locked, click to view pricing)`}
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
			onClick={onNavigate}
		>
			<item.icon size={15} />
			<span>{item.label}</span>
		</Link>
	);
}
