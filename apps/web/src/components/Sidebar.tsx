import { Link, useRouterState } from "@tanstack/react-router";
import {
	Activity,
	AlertTriangle,
	BarChart3,
	Bell,
	BookOpen,
	Bot,
	Boxes,
	Brain,
	Briefcase,
	Building2,
	CalendarClock,
	ClipboardCheck,
	Clock,
	CreditCard,
	Database,
	Eye,
	FileCheck2,
	FilterX,
	FlaskConical,
	GitBranch,
	GitCompare,
	Github,
	GitMerge,
	Globe,
	Key,
	Laptop,
	LayoutDashboard,
	Link2,
	Lock,
	Menu,
	Plug,
	Rocket,
	ScrollText,
	Server,
	Settings,
	Shield,
	ShieldCheck,
	ShieldQuestion,
	Store,
	Trophy,
	Users,
	Webhook,
	Wrench,
	X,
} from "lucide-react";
import { useState } from "react";
import { useFeatureFlag } from "../lib/featureFlags";
import ThemeToggle from "./ThemeToggle";
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
};

const navGroups: NavGroup[] = [
	{
		label: "Overview",
		items: [
			{ to: "/", label: "Dashboard", icon: LayoutDashboard },
			{ to: "/dashboards", label: "Dashboard Builder", icon: BarChart3 },
			{ to: "/onboarding", label: "Onboarding", icon: Rocket },
		],
	},
	{
		label: "Security",
		items: [
			{ to: "/findings", label: "Findings", icon: AlertTriangle },
			{ to: "/timeline", label: "Timeline", icon: Clock },
			{ to: "/breach-intel", label: "Breach Intel", icon: Shield },
			{ to: "/attack-paths", label: "Attack Paths", icon: ShieldCheck },
			{ to: "/supply-chain", label: "Supply Chain", icon: Link2 },
			{ to: "/cross-repo", label: "Cross-Repo Exposure", icon: GitCompare },
			{ to: "/zero-day", label: "Zero-Day Detection", icon: Eye },
			{ to: "/exploit-validation", label: "Exploit Validation", icon: FlaskConical },
			{ to: "/audit-log", label: "Audit Log", icon: ScrollText },
		],
	},
	{
		label: "Inventory",
		items: [
			{ to: "/repositories", label: "Repositories", icon: GitBranch },
			{ to: "/connect/github", label: "Connect GitHub", icon: Github },
			{ to: "/sbom", label: "SBOM", icon: Boxes },
		],
	},
	{
		label: "Operations",
		items: [
			{ to: "/ci-cd", label: "CI / CD Gates", icon: GitMerge },
			{ to: "/drift-posture", label: "Drift Posture", icon: Activity },
			{ to: "/remediation", label: "Remediation", icon: Wrench },
			{ to: "/compliance", label: "Compliance", icon: FileCheck2 },
		],
	},
	{
		label: "Intelligence",
		items: [
			{ to: "/agents", label: "Agents & Learning", icon: Bot },
			{ to: "/neural-memory", label: "Neural Memory", icon: Brain },
		],
	},
	{
		label: "Reports",
		items: [
			{ to: "/posture", label: "Security Posture", icon: ShieldCheck },
			{ to: "/executive-report", label: "Executive Report", icon: BarChart3 },
			{ to: "/maturity", label: "Maturity Assessment", icon: Trophy },
			{ to: "/business-impact", label: "Business Impact", icon: Briefcase },
		],
	},
	{
		label: "Resources",
		items: [
			{ to: "/docs/api", label: "API Docs", icon: BookOpen },
			{ to: "/docs/github-integration", label: "GitHub Action", icon: Github },
		],
	},
	{
		label: "System",
		items: [
			{ to: "/integrations", label: "Integrations", icon: Plug },
			{ to: "/marketplace", label: "Marketplace", icon: Store },
			{ to: "/mssp", label: "MSSP Portal", icon: Building2, featureFlag: "mssp_portal" },
			{ to: "/status", label: "Status", icon: Activity },
			{ to: "/pricing", label: "Pricing", icon: CreditCard },
			{ to: "/settings", label: "Settings", icon: Settings },
			{ to: "/settings/roles", label: "Roles", icon: Users },
			{ to: "/settings/sso", label: "SSO / SAML", icon: ShieldCheck, featureFlag: "sso" },
			{ to: "/settings/deployment", label: "Deployment Mode", icon: Server, featureFlag: "deployment_toggle" },
			{ to: "/settings/api-keys", label: "API Keys", icon: Key },
			{ to: "/settings/webhooks", label: "Webhooks", icon: Webhook },
			{ to: "/settings/scans", label: "Scan Schedules", icon: CalendarClock },
			{ to: "/settings/suppression", label: "Suppression Rules", icon: FilterX },
			{ to: "/settings/policies", label: "Policy Builder", icon: ShieldQuestion },
			{ to: "/settings/notifications", label: "Notifications", icon: Bell },
			{ to: "/settings/retention", label: "Data Retention", icon: Database },
			{ to: "/settings/on-call", label: "On-Call", icon: CalendarClock },
			{ to: "/settings/billing", label: "Billing", icon: CreditCard }, // FIX: W2 — missing settings routes
			{ to: "/settings/general", label: "General", icon: Settings },
			{ to: "/settings/jobs", label: "Background Jobs", icon: Activity },
			{ to: "/settings/sla", label: "SLA Policies", icon: Clock },
			{ to: "/settings/team", label: "Team", icon: Users },
			{ to: "/settings/two-factor", label: "Two-Factor Auth", icon: ShieldCheck },
			{ to: "/settings/sessions", label: "Sessions", icon: Laptop },
			{ to: "/settings/data-privacy", label: "Data Privacy", icon: Shield },
			{ to: "/settings/access-review", label: "Access Review", icon: ClipboardCheck },
			{ to: "/settings/mssp-keys", label: "MSSP Keys", icon: Key },
			{ to: "/settings/ip-allowlist", label: "IP Allowlist", icon: Globe },
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

			<div className="sidebar-workspace">
				<WorkspaceSwitcher />
			</div>

			<nav className="sidebar-nav">
				{navGroups.map((group) => (
					<div key={group.label} className="sidebar-group">
						<div className="sidebar-group-label">{group.label}</div>
						{group.items.map((item) => (
							<SidebarItem
								key={item.to}
								item={item}
								isActive={isActive(item.to)}
								onNavigate={() => setMobileOpen(false)}
							/>
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
	onNavigate,
}: {
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
