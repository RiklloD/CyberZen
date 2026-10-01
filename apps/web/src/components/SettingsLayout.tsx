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
	description?: string;
	icon: LucideIcon;
	featureFlag?: string;
};

type SettingsGroup = {
	label: string;
	links: SettingsLink[];
};

export const SETTINGS_GROUPS: SettingsGroup[] = [
	{
		label: "Workspace",
		links: [
			{ to: "/settings/general", label: "General", description: "Workspace name, slug and defaults", icon: Settings },
			{ to: "/settings/team", label: "Team", description: "Invite teammates and manage members", icon: Users },
			{ to: "/settings/roles", label: "Roles & permissions", description: "Custom roles and fine-grained access", icon: Shield },
			{ to: "/settings/billing", label: "Billing", description: "Plan, usage and invoices", icon: CreditCard },
		],
	},
	{
		label: "Integrations",
		links: [
			{ to: "/integrations", label: "Integrations", description: "Slack, Jira, Linear, PagerDuty and more", icon: Plug },
			{ to: "/marketplace", label: "Marketplace", description: "Community scanners and policies", icon: Store },
			{ to: "/settings/llm-providers", label: "LLM providers", description: "Models used by the AI agents", icon: Cpu },
			{ to: "/settings/api-keys", label: "API keys", description: "Keys for the CLI, CI and automation", icon: Key },
			{ to: "/settings/webhooks", label: "Webhooks", description: "Push events to your own systems", icon: Webhook },
			{ to: "/docs/github-integration", label: "GitHub Action", description: "Gate pull requests in CI", icon: Github },
			{ to: "/docs/api", label: "API docs", description: "REST API reference", icon: BookOpen },
		],
	},
	{
		label: "Security policy",
		links: [
			{ to: "/settings/scans", label: "Scan schedules", description: "When repositories are re-scanned", icon: CalendarClock },
			{ to: "/settings/policies", label: "Policy builder", description: "Rules that block merges and deploys", icon: ShieldQuestion },
			{ to: "/settings/suppression", label: "Suppression rules", description: "Silence known noise automatically", icon: FilterX },
			{ to: "/settings/notifications", label: "Notifications", description: "Who gets alerted, and how", icon: Bell },
			{ to: "/settings/on-call", label: "On-call", description: "Escalation rotations", icon: Clock },
			{ to: "/audit-log", label: "Audit log", description: "Every action taken in this workspace", icon: ScrollText },
		],
	},
	{
		label: "Access & authentication",
		links: [
			{ to: "/settings/two-factor", label: "Two-factor auth", description: "Protect your account", icon: Shield },
			{ to: "/settings/sso", label: "SSO / SAML", description: "Single sign-on for your organisation", icon: Shield, featureFlag: "sso" },
			{ to: "/settings/sessions", label: "Sessions", description: "Active sign-ins and devices", icon: Laptop },
			{ to: "/settings/ip-allowlist", label: "IP allowlist", description: "Restrict access by network", icon: Globe },
			{ to: "/settings/access-review", label: "Access review", description: "Periodic review of who has access", icon: ClipboardCheck },
			{ to: "/settings/mssp-keys", label: "MSSP keys", description: "Managed security provider access", icon: Key },
		],
	},
	{
		label: "Advanced",
		links: [
			{ to: "/settings/retention", label: "Data retention", description: "How long findings and logs are kept", icon: Database },
			{ to: "/settings/data-privacy", label: "Data privacy", description: "Exports, deletion and PII handling", icon: Shield },
			{ to: "/settings/jobs", label: "Background jobs", description: "Scheduled work and its health", icon: Activity },
			{ to: "/settings/sla", label: "SLA policies", description: "Time-to-fix targets per severity", icon: Clock },
			{ to: "/dashboards", label: "Dashboard builder", description: "Custom dashboards for your team", icon: BarChart3 },
			{ to: "/settings/deployment", label: "Deployment mode", description: "Cloud, hybrid or self-hosted", icon: Server, featureFlag: "deployment_toggle" },
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
