import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { Check, CreditCard, Sparkles } from "lucide-react";
import { api } from "../lib/convex";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/pricing")({
	errorComponent: RouteErrorBoundary,
	component: PricingPage });

function PricingPage() {
	const plans = useQuery(api.plans.listPlans);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<CreditCard size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Pricing</h1>
						<p className="page-subtitle">
							Choose the plan that fits your team — upgrade or downgrade
							anytime.
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{!plans ? (
					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-72 rounded-xl" />
						))}
					</div>
				) : (
					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						{[...plans]
							.sort((a, b) => a.monthlyPrice - b.monthlyPrice)
							.map((plan) => (
								<PlanCard key={plan._id} plan={plan} />
							))}
					</div>
				)}

				<div className="card">
					<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-2">
						Need a custom contract?
					</h3>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Enterprise plans include SSO, custom RBAC, on-prem deployment,
						MSSP partner portal, and a dedicated success manager. Get in
						touch via <Link to="/settings/billing" className="text-[var(--signal)] underline">billing settings</Link>.
					</p>
				</div>
			</div>
		</main>
	);
}

type Plan = {
	_id: string;
	slug: string;
	name: string;
	monthlyPrice: number;
	repoLimit: number;
	seatLimit: number;
	featureFlags: string[];
};

const FLAG_LABELS: Record<string, string> = {
	basic_scanning: "Basic vulnerability scanning",
	sbom: "SBOM generation",
	security_posture: "Security posture score",
	exploit_validation: "Exploit validation sandbox",
	auto_remediation: "Auto-remediation PRs",
	gate_policies: "Gate enforcement policies",
	executive_reports: "Executive reports",
	api_access: "API access",
	cross_repo_intel: "Cross-repo intelligence",
	sso: "SSO / SAML",
	rbac_custom: "Custom RBAC",
	on_prem: "On-prem deployment",
	deployment_toggle: "Deployment mode toggle",
	mssp_portal: "MSSP partner portal",
	compliance_attestation: "Compliance attestation",
	custom_policies: "Custom policy builder",
	dedicated_support: "Dedicated support" };

function PlanCard({ plan }: { plan: Plan }) {
	const highlighted = plan.slug === "team";
	const repoLabel =
		plan.repoLimit < 0 ? "Unlimited" : `${plan.repoLimit} repos`;
	const seatLabel =
		plan.seatLimit < 0 ? "Unlimited seats" : `${plan.seatLimit} seats`;
	return (
		<div
			className={`rounded-xl border p-5 transition-colors ${
				highlighted
					? "border-[var(--signal)] bg-[var(--signal-soft)]"
					: "border-[var(--line)]"
			}`}
		>
			<div className="flex items-center justify-between mb-3">
				<h2 className="text-base font-semibold text-[var(--sea-ink)]">
					{plan.name}
				</h2>
				{highlighted && (
					<span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-[var(--signal)]">
						<Sparkles size={10} /> Popular
					</span>
				)}
			</div>
			<p className="text-3xl font-bold text-[var(--sea-ink)]">
				${plan.monthlyPrice}
				<span className="text-xs font-normal text-[var(--sea-ink-soft)]">
					/mo
				</span>
			</p>
			<p className="text-xs text-[var(--sea-ink-soft)] mt-1">
				{repoLabel} · {seatLabel}
			</p>

			<ul className="space-y-1.5 mt-4">
				{plan.featureFlags.map((flag) => (
					<li
						key={flag}
						className="flex items-start gap-1.5 text-xs text-[var(--sea-ink)]"
					>
						<Check
							size={12}
							className="text-[var(--success)] flex-shrink-0 mt-0.5"
						/>
						<span>{FLAG_LABELS[flag] ?? flag}</span>
					</li>
				))}
			</ul>

			<Link
				to="/settings/billing"
				className="signal-button mt-5 w-full inline-flex justify-center"
				style={{ padding: "0.5rem 0.8rem", fontSize: "0.8rem" }}
			>
				{plan.monthlyPrice === 0 ? "Get started" : `Choose ${plan.name}`}
			</Link>
		</div>
	);
}
