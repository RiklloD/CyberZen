import { Link } from "@tanstack/react-router";
import {
	AlertTriangle,
	CheckCircle2,
	Circle,
	Github,
	Key,
	Plus,
	Rocket,
	Shield,
	Users,
} from "lucide-react";

/**
 * Setup checklist shown on the dashboard when the workspace
 * hasn't completed basic configuration. Each step links to the
 * relevant page so the user knows exactly what to do next.
 *
 * Steps collapse (entire checklist hidden) once all are complete.
 */

type ChecklistStep = {
	key: string;
	label: string;
	hint: string;
	done: boolean;
	linkTo?: string;
	linkLabel?: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
};

export default function SetupChecklist({
	hasRepos,
	hasGithub,
	hasFindings,
	hasGatePolicy,
	hasTeamMembers,
	hasApiKey,
}: {
	hasRepos: boolean;
	hasGithub: boolean;
	hasFindings: boolean;
	hasGatePolicy: boolean;
	hasTeamMembers: boolean;
	hasApiKey: boolean;
}) {
	const steps: ChecklistStep[] = [
		{
			key: "workspace",
			label: "Create workspace",
			hint: "Tenant provisioned and ready",
			done: true, // if we're past onboarding, this is done
			icon: Shield,
		},
		{
			key: "github",
			label: "Connect GitHub",
			hint: "Link your GitHub account for repo access",
			done: hasGithub,
			linkTo: "/connect/github",
			linkLabel: "Connect →",
			icon: Github,
		},
		{
			key: "repos",
			label: "Link repositories",
			hint: "Add at least one repository to monitor",
			done: hasRepos,
			linkTo: "/repositories",
			linkLabel: "Add →",
			icon: Plus,
		},
		{
			key: "scan",
			label: "Run first scan",
			hint: "Trigger an initial security scan",
			done: hasFindings || hasRepos,
			linkTo: "/repositories",
			linkLabel: "Scan →",
			icon: Rocket,
		},
		{
			key: "gate",
			label: "Configure CI/CD gate",
			hint: "Set up gate policies to block risky PRs",
			done: hasGatePolicy,
			linkTo: "/settings/policies",
			linkLabel: "Set up →",
			icon: AlertTriangle,
		},
		{
			key: "team",
			label: "Invite team",
			hint: "Add teammates to collaborate",
			done: hasTeamMembers,
			linkTo: "/settings/team",
			linkLabel: "Invite →",
			icon: Users,
		},
		{
			key: "apikey",
			label: "Create API key",
			hint: "Generate an API key for CI integration",
			done: hasApiKey,
			linkTo: "/settings/api-keys",
			linkLabel: "Create →",
			icon: Key,
		},
	];

	const completedCount = steps.filter((s) => s.done).length;
	const totalCount = steps.length;
	const allDone = completedCount === totalCount;

	// Don't render if everything is complete
	if (allDone) return null;

	return (
		<div className="setup-checklist">
			<div className="setup-checklist-header">
				<div className="flex items-center gap-2">
					<Rocket size={16} className="text-[var(--signal)]" />
					<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
						Get started
					</h2>
					<span className="text-xs text-[var(--sea-ink-soft)]">
						({completedCount}/{totalCount})
					</span>
				</div>
				<div className="setup-checklist-progress">
					<div
						className="setup-checklist-progress-bar"
						style={{ width: `${(completedCount / totalCount) * 100}%` }}
					/>
				</div>
			</div>
			<div className="setup-checklist-steps">
				{steps.map((step) => (
					<div
						key={step.key}
						className={`setup-checklist-item${step.done ? " is-done" : ""}`}
					>
						<div className="flex items-center gap-3">
							{step.done ? (
								<CheckCircle2 size={16} className="text-[var(--success, #22c55e)] flex-shrink-0" />
							) : (
								<Circle size={16} className="text-[var(--sea-ink-dim)] flex-shrink-0" />
							)}
							<step.icon size={14} className={step.done ? "opacity-40" : "text-[var(--signal)]"} />
							<div className="min-w-0">
								<p className={`text-xs font-medium ${step.done ? "text-[var(--sea-ink-soft)] line-through" : "text-[var(--sea-ink)]"}`}>
									{step.label}
								</p>
								<p className="text-[11px] text-[var(--sea-ink-dim)]">
									{step.hint}
								</p>
							</div>
						</div>
						{!step.done && step.linkTo && (
							<Link
								to={step.linkTo as "/"}
								className="setup-checklist-link"
							>
								{step.linkLabel}
							</Link>
						)}
					</div>
				))}
			</div>
		</div>
	);
}
