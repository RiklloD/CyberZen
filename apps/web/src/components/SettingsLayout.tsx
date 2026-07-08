import { Link, useRouterState } from "@tanstack/react-router";
import {
	Activity,
	Bell,
	BookOpen,
	CalendarClock,
	ClipboardCheck,
	Cpu,
	CreditCard,
	Database,
	Globe,
	Key,
	Laptop,
	Lock,
	type LucideIcon,
	Plug,
	ScrollText,
	Server,
	Settings,
	Shield,
	Store,
	Users,
	Webhook,
	Github,
	BarChart3,
	Clock,
	FilterX,
	ShieldQuestion,
} from "lucide-react";
import { useFeatureFlag } from "../lib/featureFlags";

/**
 * Settings sub-navigation.
 *
 * All settings pages share this left sub-nav, organized into 5 logical
 * groups. This replaces the old flat list of 26 items in the main sidebar.
 */

type SettingsLink = {
	to: string;
	label: string;
	icon: LucideIcon;
	featureFlag?: string;
};

type SettingsGroup = {
	label: string;
	links: SettingsLink[];
};

const SETTINGS_GROUPS: SettingsGroup[] = [
	{
		label: "Workspace",
		links: [
			{ to: "/settings/general", label: "General", icon: Settings },
			{ to: "/settings/team", label: "Team", icon: Users },
			{ to: "/settings/roles", label: "Roles & Permissions", icon: Shield },
			{ to: "/settings/billing", label: "Billing", icon: CreditCard },
		],
	},
	{
		label: "Integrations",
		links: [
			{ to: "/integrations", label: "Integrations", icon: Plug },
			{ to: "/marketplace", label: "Marketplace", icon: Store },
			{ to: "/settings/llm-providers", label: "LLM Providers", icon: Cpu },
			{ to: "/settings/api-keys", label: "API Keys", icon: Key },
			{ to: "/settings/webhooks", label: "Webhooks", icon: Webhook },
			{ to: "/docs/github-integration", label: "GitHub Action", icon: Github },
			{ to: "/docs/api", label: "API Docs", icon: BookOpen },
		],
	},
	{
		label: "Security Policy",
		links: [
			{ to: "/settings/scans", label: "Scan Schedules", icon: CalendarClock },
			{ to: "/settings/policies", label: "Policy Builder", icon: ShieldQuestion },
			{ to: "/settings/suppression", label: "Suppression Rules", icon: FilterX },
			{ to: "/settings/notifications", label: "Notifications", icon: Bell },
			{ to: "/settings/on-call", label: "On-Call", icon: Clock },
			{ to: "/audit-log", label: "Audit Log", icon: ScrollText },
		],
	},
	{
		label: "Access & Auth",
		links: [
			{ to: "/settings/two-factor", label: "Two-Factor Auth", icon: Shield },
			{ to: "/settings/sso", label: "SSO / SAML", icon: Shield, featureFlag: "sso" },
			{ to: "/settings/sessions", label: "Sessions", icon: Laptop },
			{ to: "/settings/ip-allowlist", label: "IP Allowlist", icon: Globe },
			{ to: "/settings/access-review", label: "Access Review", icon: ClipboardCheck },
			{ to: "/settings/mssp-keys", label: "MSSP Keys", icon: Key },
		],
	},
	{
		label: "Advanced",
		links: [
			{ to: "/settings/retention", label: "Data Retention", icon: Database },
			{ to: "/settings/data-privacy", label: "Data Privacy", icon: Shield },
			{ to: "/settings/jobs", label: "Background Jobs", icon: Activity },
			{ to: "/settings/sla", label: "SLA Policies", icon: Clock },
			{ to: "/dashboards", label: "Dashboard Builder", icon: BarChart3 },
			{ to: "/settings/deployment", label: "Deployment Mode", icon: Server, featureFlag: "deployment_toggle" },
		],
	},
];

export default function SettingsLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	const routerState = useRouterState();
	const currentPath = routerState.location.pathname;

	function isActive(to: string) {
		return currentPath === to || currentPath.startsWith(`${to}/`);
	}

	return (
		<div className="settings-layout">
			<aside className="settings-subnav">
				<div className="settings-subnav-header">
					<Settings size={16} className="text-[var(--signal)]" />
					<span>Settings</span>
				</div>
				{SETTINGS_GROUPS.map((group) => (
					<div key={group.label} className="settings-subnav-group">
						<div className="settings-subnav-label">{group.label}</div>
						{group.links.map((link) => (
							<SettingsLinkItem
								key={link.to}
								link={link}
								isActive={isActive(link.to)}
							/>
						))}
					</div>
				))}
			</aside>
			<div className="settings-content">{children}</div>
		</div>
	);
}

function SettingsLinkItem({
	link,
	isActive,
}: {
	link: SettingsLink;
	isActive: boolean;
}) {
	const flagEnabled = useFeatureFlag(link.featureFlag ?? "");
	const isLocked = !!link.featureFlag && flagEnabled === false;

	if (isLocked) {
		return (
			<Link
				to="/pricing"
				className={`settings-subnav-item is-locked${isActive ? " is-active" : ""}`}
				title={`${link.label} requires an Enterprise plan`}
			>
				<link.icon size={14} />
				<span>{link.label}</span>
				<Lock size={10} className="ml-auto opacity-50" />
			</Link>
		);
	}

	return (
		<Link
			to={link.to as "/"}
			className={`settings-subnav-item${isActive ? " is-active" : ""}`}
		>
			<link.icon size={14} />
			<span>{link.label}</span>
		</Link>
	);
}
