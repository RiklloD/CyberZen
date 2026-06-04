import { createFileRoute, Link } from "@tanstack/react-router";
import {
	Activity,
	Boxes,
	CheckCircle2,
	FlaskConical,
	GitBranch,
	Quote,
	Radar,
	ScanLine,
	ShieldCheck,
	Sparkles,
	Wrench,
	Zap,
} from "lucide-react";
import StatusPill from "../components/StatusPill";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/about")({
	errorComponent: RouteErrorBoundary,
	component: AboutPage,
});

const features: Array<{
	icon: typeof ShieldCheck;
	title: string;
	body: string;
}> = [
	{
		icon: ShieldCheck,
		title: "Automated security posture",
		body: "Forty plus drift detectors continuously analyze your repositories, cloud, CI, and runtime to surface real risk, not noise.",
	},
	{
		icon: Activity,
		title: "Real-time monitoring",
		body: "Every commit, build, and deploy emits typed events. Findings, exploit attempts, and policy violations stream live to your team.",
	},
	{
		icon: FlaskConical,
		title: "Exploit validation",
		body: "Sandbox-backed proof of exploitability ranks vulnerabilities by reality, not theory. Stop chasing CVSS-only false positives.",
	},
	{
		icon: CheckCircle2,
		title: "Compliance evidence",
		body: "SOC 2, PCI, HIPAA, GDPR, and NIS2 control mappings collect themselves. Audit packages export in one click.",
	},
	{
		icon: Boxes,
		title: "SBOM living registry",
		body: "Track packages, transitive dependencies, and integrity hashes across every repository. Get notified when a breach touches you.",
	},
	{
		icon: Sparkles,
		title: "AI-powered remediation",
		body: "Suggested fixes ship as draft pull requests with diff, blast radius, and rollback notes — not raw advisory dumps.",
	},
];

const testimonials = [
	{
		quote:
			"CyberZen replaced four tools and gave our auditors a one-click evidence pack. The first quarter cut our triage backlog by 60 percent.",
		name: "Priya Anand",
		role: "Head of Security, Fintech (Series C)",
	},
	{
		quote:
			"The exploit validation layer is the only reason we trust the severity rankings. We finally stopped paging on theoretical vulns.",
		name: "Marcus Lee",
		role: "Principal Engineer, Healthcare SaaS",
	},
	{
		quote:
			"Drift posture across forty surfaces — IAM, K8s admission, secret mgmt, web servers — is what our previous SIEM promised and never delivered.",
		name: "Elena Costa",
		role: "VP Platform, Manufacturing IoT",
	},
];

const socialProof = [
	{ value: "8,600+", label: "Backend tests passing" },
	{ value: "40+", label: "Drift detectors" },
	{ value: "150+", label: "Convex intelligence modules" },
	{ value: "5", label: "Compliance frameworks mapped" },
];

function AboutPage() {
	return (
		<main className="page-body-padded">
			<HeroSection />
			<FeatureGrid />
			<ArchitectureDiagram />
			<SocialProofSection />
			<TestimonialsSection />
			<FooterLinks />
		</main>
	);
}

function HeroSection() {
	return (
		<section className="panel rounded-[2rem] px-6 py-10 sm:px-12 sm:py-14">
			<div className="flex flex-wrap gap-2 mb-6">
				<StatusPill label="Continuous security posture" tone="info" />
				<StatusPill label="AI-powered" tone="success" />
			</div>
			<h1 className="display-title max-w-4xl text-4xl leading-[1.04] text-[var(--sea-ink)] sm:text-6xl">
				Stop guessing. Ship code with proof your security holds.
			</h1>
			<p className="mt-6 max-w-3xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
				CyberZen is the AI-powered security posture platform that scans your
				code, validates real exploitability, and remediates with auditable
				evidence — from commit to cloud.
			</p>
			<div className="mt-8 flex flex-wrap gap-3">
				<Link to="/onboarding" className="signal-button">
					Get started
				</Link>
				<a href="#features" className="signal-button secondary-button">
					See the platform
				</a>
			</div>
		</section>
	);
}

function FeatureGrid() {
	return (
		<section id="features" className="mt-10">
			<div className="mb-6">
				<p className="island-kicker mb-2">What you get</p>
				<h2 className="text-2xl font-semibold text-[var(--sea-ink)] sm:text-3xl">
					Four pillars, one continuous loop.
				</h2>
			</div>
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
				{features.map((feature) => {
					const Icon = feature.icon;
					return (
						<article
							key={feature.title}
							className="panel rounded-[1.5rem] p-6 transition-colors hover:bg-[rgba(30,157,154,0.04)]"
						>
							<div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-xl bg-[rgba(30,157,154,0.10)] text-[var(--teal)]">
								<Icon size={20} />
							</div>
							<h3 className="text-base font-semibold text-[var(--sea-ink)]">
								{feature.title}
							</h3>
							<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
								{feature.body}
							</p>
						</article>
					);
				})}
			</div>
		</section>
	);
}

function ArchitectureDiagram() {
	return (
		<section className="mt-10">
			<div className="mb-6">
				<p className="island-kicker mb-2">How it works</p>
				<h2 className="text-2xl font-semibold text-[var(--sea-ink)] sm:text-3xl">
					Scan, analyze, remediate — repeated continuously.
				</h2>
			</div>

			<article className="panel rounded-[2rem] p-6 sm:p-10">
				<div className="flow-diagram">
					<FlowStage
						icon={ScanLine}
						title="Scan"
						subtitle="Connect & ingest"
						bullets={[
							"GitHub, GitLab, Bitbucket, Azure DevOps",
							"CI events from Jenkins, CircleCI, Buildkite",
							"SBOM, IaC, secrets, cloud config",
						]}
					/>
					<FlowArrow />
					<FlowStage
						icon={Radar}
						title="Analyze"
						subtitle="Correlate & validate"
						bullets={[
							"Drift detection across 40+ surfaces",
							"Sandboxed exploit validation",
							"Cross-repo lateral impact",
						]}
					/>
					<FlowArrow />
					<FlowStage
						icon={Wrench}
						title="Remediate"
						subtitle="Fix & verify"
						bullets={[
							"AI-drafted pull requests",
							"Policy-gated CI enforcement",
							"Compliance evidence collection",
						]}
					/>
				</div>

				<div className="mt-10 grid gap-4 sm:grid-cols-3">
					<FlowSubsystem
						icon={GitBranch}
						label="Code surface"
						body="Repository hooks, SBOM diffing, semantic fingerprinting"
					/>
					<FlowSubsystem
						icon={Zap}
						label="Runtime surface"
						body="Cloud blast radius, runtime drift, traffic anomalies"
					/>
					<FlowSubsystem
						icon={ShieldCheck}
						label="Policy surface"
						body="Custom policies, risk acceptance, compliance frameworks"
					/>
				</div>
			</article>

			<style>{`
				.flow-diagram {
					display: grid;
					grid-template-columns: 1fr;
					gap: 1rem;
					align-items: stretch;
				}
				@media (min-width: 768px) {
					.flow-diagram {
						grid-template-columns: 1fr auto 1fr auto 1fr;
						align-items: center;
					}
				}
				.flow-stage {
					display: flex;
					flex-direction: column;
					gap: 0.75rem;
					padding: 1.25rem;
					border-radius: 1.25rem;
					background: rgba(30, 157, 154, 0.05);
					border: 1px solid rgba(30, 157, 154, 0.18);
				}
				.flow-arrow {
					display: flex;
					align-items: center;
					justify-content: center;
					color: var(--teal);
					font-size: 1.5rem;
					font-weight: 600;
					transform: rotate(90deg);
				}
				@media (min-width: 768px) {
					.flow-arrow {
						transform: rotate(0deg);
					}
				}
				.flow-stage-icon {
					display: inline-flex;
					align-items: center;
					justify-content: center;
					width: 2.5rem;
					height: 2.5rem;
					border-radius: 0.75rem;
					background: rgba(30, 157, 154, 0.12);
					color: var(--teal);
				}
				.flow-stage-bullets {
					display: flex;
					flex-direction: column;
					gap: 0.25rem;
				}
				.flow-subsystem {
					display: flex;
					gap: 0.75rem;
					padding: 1rem;
					border-radius: 1rem;
					border: 1px solid rgba(130, 122, 110, 0.18);
				}
			`}</style>
		</section>
	);
}

function FlowStage({
	icon: Icon,
	title,
	subtitle,
	bullets,
}: {
	icon: typeof ShieldCheck;
	title: string;
	subtitle: string;
	bullets: string[];
}) {
	return (
		<div className="flow-stage">
			<div className="flow-stage-icon">
				<Icon size={20} />
			</div>
			<div>
				<p className="tiny-label">{subtitle}</p>
				<h3 className="text-lg font-semibold text-[var(--sea-ink)]">
					{title}
				</h3>
			</div>
			<ul className="flow-stage-bullets text-sm text-[var(--sea-ink-soft)]">
				{bullets.map((b) => (
					<li key={b}>· {b}</li>
				))}
			</ul>
		</div>
	);
}

function FlowArrow() {
	return <div className="flow-arrow">→</div>;
}

function FlowSubsystem({
	icon: Icon,
	label,
	body,
}: {
	icon: typeof ShieldCheck;
	label: string;
	body: string;
}) {
	return (
		<div className="flow-subsystem">
			<div className="flow-stage-icon">
				<Icon size={18} />
			</div>
			<div>
				<p className="tiny-label">{label}</p>
				<p className="mt-1 text-sm text-[var(--sea-ink)]">{body}</p>
			</div>
		</div>
	);
}

function SocialProofSection() {
	return (
		<section className="mt-10">
			<article className="panel rounded-[1.75rem] p-6 sm:p-8">
				<div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
					{socialProof.map((item) => (
						<div key={item.label}>
							<p className="text-3xl font-semibold text-[var(--sea-ink)] sm:text-4xl">
								{item.value}
							</p>
							<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
								{item.label}
							</p>
						</div>
					))}
				</div>
			</article>
		</section>
	);
}

function TestimonialsSection() {
	return (
		<section className="mt-10">
			<div className="mb-6">
				<p className="island-kicker mb-2">Why teams choose CyberZen</p>
				<h2 className="text-2xl font-semibold text-[var(--sea-ink)] sm:text-3xl">
					Built for the security teams shipping fastest.
				</h2>
			</div>
			<div className="grid gap-4 md:grid-cols-3">
				{testimonials.map((t) => (
					<article key={t.name} className="panel rounded-[1.5rem] p-6">
						<Quote
							size={20}
							className="text-[var(--teal)] opacity-70 mb-3"
						/>
						<p className="text-sm text-[var(--sea-ink)] leading-relaxed">
							{t.quote}
						</p>
						<div className="mt-5">
							<p className="text-sm font-semibold text-[var(--sea-ink)]">
								{t.name}
							</p>
							<p className="text-xs text-[var(--sea-ink-soft)]">{t.role}</p>
						</div>
					</article>
				))}
			</div>
		</section>
	);
}

function FooterLinks() {
	return (
		<section className="mt-10 panel rounded-[2rem] p-6 sm:p-10">
			<div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)] sm:text-3xl">
						See it for yourself.
					</h2>
					<p className="mt-2 max-w-xl text-sm text-[var(--sea-ink-soft)]">
						Connect a repo in under five minutes. The first scan surfaces
						real findings before your demo call ends.
					</p>
				</div>
				<div className="flex flex-wrap gap-3">
					<Link to="/onboarding" className="signal-button">
						Sign up
					</Link>
					<Link to="/docs/api" className="signal-button secondary-button">
						API docs
					</Link>
					<Link to="/status" className="signal-button secondary-button">
						Status
					</Link>
				</div>
			</div>
		</section>
	);
}
