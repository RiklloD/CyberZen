import { Link, useRouterState } from "@tanstack/react-router";
import {
	AlertTriangle,
	Bot,
	Boxes,
	FileCheck2,
	GitBranch,
	GitMerge,
	LayoutDashboard,
	Link2,
	Menu,
	Plug,
	Shield,
	Wrench,
	X,
} from "lucide-react";
import { useState } from "react";
import ThemeToggle from "./ThemeToggle";

type NavItem = {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
};

type NavGroup = {
	label: string;
	items: NavItem[];
};

const navGroups: NavGroup[] = [
	{
		label: "Overview",
		items: [{ to: "/", label: "Dashboard", icon: LayoutDashboard }],
	},
	{
		label: "Security",
		items: [
			{ to: "/findings", label: "Findings", icon: AlertTriangle },
			{ to: "/breach-intel", label: "Breach Intel", icon: Shield },
			{ to: "/supply-chain", label: "Supply Chain", icon: Link2 },
		],
	},
	{
		label: "Inventory",
		items: [
			{ to: "/repositories", label: "Repositories", icon: GitBranch },
			{ to: "/sbom", label: "SBOM", icon: Boxes },
		],
	},
	{
		label: "Operations",
		items: [
			{ to: "/ci-cd", label: "CI / CD Gates", icon: GitMerge },
			{ to: "/remediation", label: "Remediation", icon: Wrench },
			{ to: "/compliance", label: "Compliance", icon: FileCheck2 },
		],
	},
	{
		label: "Intelligence",
		items: [{ to: "/agents", label: "Agents & Learning", icon: Bot }],
	},
	{
		label: "System",
		items: [
			{ to: "/integrations", label: "Integrations", icon: Plug },
		],
	},
];

export default function Sidebar() {
	const [mobileOpen, setMobileOpen] = useState(false);
	const routerState = useRouterState();
	const currentPath = routerState.location.pathname;

	function isActive(to: string) {
		if (to === "/") return currentPath === "/";
		return currentPath === to || currentPath.startsWith(`${to}/`);
	}

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

			<nav className="sidebar-nav">
				{navGroups.map((group) => (
					<div key={group.label} className="sidebar-group">
						<div className="sidebar-group-label">{group.label}</div>
						{group.items.map((item) => (
							<Link
								key={item.to}
								to={item.to as "/"}
								className={`sidebar-item${isActive(item.to) ? " is-active" : ""}`}
								onClick={() => setMobileOpen(false)}
							>
								<item.icon size={15} />
								<span>{item.label}</span>
							</Link>
						))}
					</div>
				))}
			</nav>

		<div className="sidebar-footer">
			<ThemeToggle />
		</div>
		</div>
	);

	return (
		<>
			<button
				type="button"
				className="sidebar-mobile-toggle"
				onClick={() => setMobileOpen(!mobileOpen)}
				aria-label="Toggle navigation"
			>
				{mobileOpen ? <X size={20} /> : <Menu size={20} />}
			</button>

			{mobileOpen && (
				// biome-ignore lint/a11y/useKeyWithClickEvents: overlay dismiss
				<div
					className="sidebar-overlay"
					onClick={() => setMobileOpen(false)}
					aria-hidden="true"
				/>
			)}

			<aside className={`sidebar${mobileOpen ? " is-open" : ""}`}>{nav}</aside>
		</>
	);
}
