import { Link } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { ArrowRight, Check, X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

/**
 * Onboarding checklist for the overview page. Each step is derived from real
 * workspace state; the first incomplete step is promoted as the next action.
 * Hidden once complete or when dismissed (per workspace, persisted locally).
 */

type Step = {
	key: string;
	label: string;
	hint: string;
	done: boolean;
	to: string;
	cta: string;
};

const DISMISS_KEY = "cyberzen.setup.dismissed";

export default function SetupChecklist({
	repositoryCount,
	scannedRepositoryCount,
	gateDecisionCount,
}: {
	repositoryCount: number;
	scannedRepositoryCount: number;
	gateDecisionCount: number;
}) {
	const tenantSlug = useTenantSlug();
	const profile = useQuery(api.userProfile.getProfile);
	const members = useQuery(api.workspaceAuth.listMembers, { tenantSlug });
	const apiKeys = useQuery(api.apiKeys.listApiKeys, { tenantSlug });
	const [dismissed, setDismissed] = useState(true);

	useEffect(() => {
		try {
			const raw = localStorage.getItem(DISMISS_KEY);
			setDismissed(raw ? (JSON.parse(raw) as string[]).includes(tenantSlug) : false);
		} catch {
			setDismissed(false);
		}
	}, [tenantSlug]);

	if (dismissed || profile === undefined || members === undefined || apiKeys === undefined) {
		return null;
	}

	const steps: Step[] = [
		{
			key: "github",
			label: "Connect GitHub",
			hint: "Lets CyberZen read repos and open fix PRs",
			done: !!profile?.githubConnected || repositoryCount > 0,
			to: "/connect/github",
			cta: "Connect",
		},
		{
			key: "repos",
			label: "Add a repository",
			hint: "Pick the codebases you want monitored",
			done: repositoryCount > 0,
			to: "/repositories",
			cta: "Add",
		},
		{
			key: "scan",
			label: "Run the first scan",
			hint: "Builds the SBOM and runs every scanner",
			done: scannedRepositoryCount > 0,
			to: "/repositories",
			cta: "Scan",
		},
		{
			key: "gate",
			label: "Enforce a CI/CD gate",
			hint: "Block merges that introduce critical risk",
			done: gateDecisionCount > 0,
			to: "/docs/github-integration",
			cta: "Set up",
		},
		{
			key: "team",
			label: "Invite your team",
			hint: "Share triage and assign owners",
			done: members.length > 1,
			to: "/settings/team",
			cta: "Invite",
		},
		{
			key: "apikey",
			label: "Create an API key",
			hint: "For the CLI, CI, and integrations",
			done: apiKeys.length > 0,
			to: "/settings/api-keys",
			cta: "Create",
		},
	];

	const doneCount = steps.filter((s) => s.done).length;
	if (doneCount === steps.length) return null;
	const nextKey = steps.find((s) => !s.done)?.key;

	function dismiss() {
		setDismissed(true);
		try {
			const raw = localStorage.getItem(DISMISS_KEY);
			const list = raw ? (JSON.parse(raw) as string[]) : [];
			localStorage.setItem(DISMISS_KEY, JSON.stringify([...new Set([...list, tenantSlug])]));
		} catch {
			/* ignore */
		}
	}

	return (
		<div className="card !p-0">
			<div className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-3">
				<div>
					<h2 className="section-title">Finish setting up</h2>
					<p className="text-xs text-[var(--text-3)]">
						{doneCount} of {steps.length} complete
					</p>
				</div>
				<button
					type="button"
					className="icon-button !h-7 !w-7"
					onClick={dismiss}
					aria-label="Dismiss setup checklist"
					title="Dismiss"
				>
					<X size={14} />
				</button>
			</div>
			<div className="meter mx-4 mb-2">
				<span style={{ width: `${(doneCount / steps.length) * 100}%` }} />
			</div>
			<ul className="pb-1.5">
				{steps.map((step) => {
					const isNext = step.key === nextKey;
					return (
						<li key={step.key}>
							<Link
								to={step.to as "/"}
								className={`flex items-center gap-3 px-4 py-2 hover:bg-[var(--surface-2)] ${step.done ? "pointer-events-none" : ""}`}
								tabIndex={step.done ? -1 : undefined}
							>
								<span
									className={`flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border ${
										step.done
											? "border-transparent bg-[var(--accent)] text-[var(--accent-fg)]"
											: isNext
												? "border-[var(--accent)]"
												: "border-[var(--line-strong)]"
									}`}
								>
									{step.done && <Check size={11} strokeWidth={3} />}
								</span>
								<span className="min-w-0 flex-1">
									<span
										className={`block text-[0.82rem] ${step.done ? "text-[var(--text-3)] line-through" : "font-medium text-[var(--text)]"}`}
									>
										{step.label}
									</span>
									{isNext && (
										<span className="block text-xs text-[var(--text-3)]">{step.hint}</span>
									)}
								</span>
								{isNext && (
									<span className="btn btn-primary btn-sm">
										{step.cta}
										<ArrowRight size={12} />
									</span>
								)}
							</Link>
						</li>
					);
				})}
			</ul>
		</div>
	);
}
