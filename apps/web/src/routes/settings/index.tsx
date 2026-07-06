import { createFileRoute, Link } from "@tanstack/react-router";
import {
	Activity,
	Bell,
	Bot,
	CalendarClock,
	ClipboardList,
	CreditCard,
	Clock,
	Database,
	Globe,
	Key,
	Laptop,
	Settings,
	Shield,
	Users,
	Webhook } from "lucide-react";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/")({
	errorComponent: RouteErrorBoundary,
	component: SettingsHubPage });

/**
 * §6.14 — Settings Hub landing page.
 *
 * Central card-grid linking to every settings sub-page.
 */

type SettingsCard = {
	to: string;
	label: string;
	description: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
	badge?: string;
};

const SETTINGS_CARDS: SettingsCard[] = [
	{
		to: "/settings/general",
		label: "General",
		description: "Workspace name, default policy, deployment mode",
		icon: Settings },
	{
		to: "/settings/team",
		label: "Team",
		description: "Members, invitations, and role assignments",
		icon: Users },
	{
		to: "/settings/roles",
		label: "Roles & Permissions",
		description: "Custom RBAC roles, permission matrices",
		icon: Shield },
	{
		to: "/settings/api-keys",
		label: "API Keys",
		description: "Manage service tokens and personal access keys",
		icon: Key },
	{
		to: "/settings/webhooks",
		label: "Webhooks",
		description: "Outbound webhook endpoints for event streaming",
		icon: Webhook },
	{
		to: "/settings/sla",
		label: "SLA Policy",
		description: "Per-severity response deadlines and escalation rules",
		icon: Clock },
	{
		to: "/settings/notifications",
		label: "Notifications",
		description: "Email, Slack, and in-app notification preferences",
		icon: Bell },
	{
		to: "/settings/billing",
		label: "Billing",
		description: "Plan details, usage, invoices, and payment methods",
		icon: CreditCard },
	{
		to: "/integrations",
		label: "Integrations",
		description: "GitHub, GitLab, SIEM, observability, and scanner integrations",
		icon: Globe,
		badge: "External" },
	{
		to: "/agents",
		label: "Agent Configuration",
		description: "Configure learning agents, red/blue team behavior",
		icon: Bot,
		badge: "External" },
	{
		to: "/settings/retention",
		label: "Data Retention",
		description: "Retention policies for findings, logs, and artifacts",
		icon: Database },
	{
		to: "/settings/on-call",
		label: "On-Call Rotation",
		description: "Schedules, escalation policies, and rotation calendars",
		icon: CalendarClock },
	{
		to: "/settings/sessions",
		label: "Active Sessions",
		description: "View and revoke active device sessions",
		icon: Laptop },
	{
		to: "/settings/data-privacy",
		label: "Data Privacy",
		description: "GDPR data access, export, and deletion requests",
		icon: Shield },
	{
		to: "/settings/jobs",
		label: "Background Jobs",
		description: "Cron job health, execution history, and failure alerts",
		icon: Activity,
		badge: "Admin" },
	{
		to: "/settings/access-review",
		label: "Access Review",
		description: "SOC2/SOX quarterly member access reviews",
		icon: ClipboardList,
		badge: "Compliance" },
	{
		to: "/settings/mssp-keys",
		label: "MSSP API Keys",
		description: "Per-partner API keys for managed security providers",
		icon: Shield },
	{
		to: "/settings/ip-allowlist",
		label: "IP Allowlist",
		description: "Restrict API access to approved IP ranges",
		icon: Globe },
	{
		to: "/settings/sso",
		label: "SSO / SAML",
		description: "SAML and OIDC identity provider configuration",
		icon: Shield },
	{
		to: "/settings/two-factor",
		label: "Two-Factor Auth",
		description: "TOTP enrollment and organization 2FA policy",
		icon: Shield },
	{
		to: "/settings/suppression",
		label: "Suppression Rules",
		description: "Regex-based finding suppression and noise filtering",
		icon: Settings },
	{
		to: "/settings/policies",
		label: "Policy Builder",
		description: "Custom DSL security policy rules and enforcement",
		icon: Shield },
	{
		to: "/settings/deployment",
		label: "Deployment Mode",
		description: "Switch between Cloud SaaS, Hybrid VPC, and On-Prem",
		icon: Settings },
];

function SettingsHubPage() {
	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Settings size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Settings</h1>
						<p className="page-subtitle">
							Workspace configuration, team, integrations, and policies
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
					{SETTINGS_CARDS.map((card) => (
						<Link
							key={card.to}
							to={card.to as "/"}
							className="card card-sm group flex items-start gap-4 hover:border-[var(--signal)] transition-colors"
						>
							<div className="flex-shrink-0 w-10 h-10 rounded-xl bg-[var(--signal-soft)] flex items-center justify-center text-[var(--signal)]">
								<card.icon size={18} />
							</div>
							<div className="min-w-0 flex-1">
								<div className="flex items-center gap-2">
									<h3 className="text-sm font-semibold text-[var(--sea-ink)] group-hover:text-[var(--signal)] transition-colors">
										{card.label}
									</h3>
									{card.badge && (
										<span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--surface-soft)] text-[var(--sea-ink-soft)] border border-[var(--line)]">
											{card.badge}
										</span>
									)}
								</div>
								<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5 leading-relaxed">
									{card.description}
								</p>
							</div>
						</Link>
					))}
				</div>

				<div className="mt-8 p-4 rounded-2xl bg-[var(--surface-soft)] border border-[var(--line)]">
					<div className="flex items-center gap-2 mb-2">
						<Settings size={14} className="text-[var(--sea-ink-soft)]" />
						<span className="text-xs font-medium text-[var(--sea-ink)]">
							Quick Tip
						</span>
					</div>
					<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
						Press <kbd className="kbd">⌘K</kbd> to open the command palette for
						instant navigation to any settings page. Press{" "}
						<kbd className="kbd">?</kbd> to view all keyboard shortcuts.
					</p>
				</div>
			</div>
		</main>
	);
}
