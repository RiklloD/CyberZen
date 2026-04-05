import { createFileRoute, Link } from "@tanstack/react-router";
import StatusPill from "../components/StatusPill";

export const Route = createFileRoute("/about")({
	component: ArchitecturePage,
});

const chosenStack = [
	["Dashboard", "TanStack Start + React + Tailwind + Bun"],
	["Control plane", "Convex"],
	["Analytics", "PostHog"],
	["Agent logic", "Python"],
	["High-throughput services", "Go later when the toolchain is installed"],
];

const buildOrder = [
	"Decision layer",
	"Repository and platform foundation",
	"Minimal runtime and data plane",
	"GitHub integration first",
	"SBOM Living Registry",
	"Breach Intel Aggregator",
	"Findings API and dashboard slices",
];

function ArchitecturePage() {
	return (
		<main className="page-wrap px-4 pb-14 pt-10">
			<section className="panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<p className="island-kicker mb-4">Architecture synthesis</p>
				<h1 className="display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
					The four project Markdown files converge on one message: build the
					workflow spine first, not the flashy autonomy features.
				</h1>
				<p className="mt-5 max-w-3xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
					The spec is product-complete, but the implementation docs correctly
					call for a layered build. That is why the first runnable slice in this
					repo focuses on typed control-plane state, operator visibility, and a
					clean path into GitHub, SBOM, and breach-intel workflows.
				</p>
				<div className="mt-8 flex flex-wrap gap-3">
					<StatusPill label="ws-01 done" tone="success" />
					<StatusPill label="ws-02 in progress" tone="warning" />
					<StatusPill label="github first" tone="info" />
				</div>
			</section>

			<section className="mt-8 grid gap-4 lg:grid-cols-[1fr_1fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Chosen stack</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						What we locked in for the first build.
					</h2>
					<div className="mt-5 space-y-3">
						{chosenStack.map(([label, value]) => (
							<div key={label} className="signal-row">
								<p className="tiny-label">{label}</p>
								<p className="mt-2 text-sm text-[var(--sea-ink)]">{value}</p>
							</div>
						))}
					</div>
				</article>

				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Recommended build order</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						The tracker and split doc already told us how not to get lost.
					</h2>
					<div className="mt-5 grid gap-3">
						{buildOrder.map((step, index) => (
							<div key={step} className="timeline-step">
								<div className="timeline-index">{index + 1}</div>
								<p className="text-sm text-[var(--sea-ink)]">{step}</p>
							</div>
						))}
					</div>
				</article>
			</section>

			<section className="mt-8 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Convex fit</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Convex is a good first system of record if we keep the contract
						clean.
					</h2>
					<div className="mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]">
						<p>
							It is a strong fit for the control plane because it gives us typed
							functions, realtime UI state, and fast iteration on tenants,
							workflows, findings, and SBOM data.
						</p>
						<p>
							It is not the final answer for every heavyweight analysis problem.
							Large semantic vector indexes, deep graph traversal, and some
							compliance export workloads can still graduate into specialized
							stores later.
						</p>
						<p>
							That hybrid path keeps us honest: fast MVP now, room for the
							spec&apos;s mature data plane later.
						</p>
					</div>
				</article>

				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Service boundaries</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Python and Go stay in the design, but only where they truly help.
					</h2>
					<div className="mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]">
						<p>
							Python is reserved for the orchestration and intelligence layer:
							embeddings, scraping, reasoning, and exploit execution.
						</p>
						<p>
							Go remains the target for the sandbox manager and high-throughput
							event gateway once those contracts harden and the local toolchain
							is installed.
						</p>
						<p>
							The dashboard and control plane stay in one fast-moving TypeScript
							surface for now so we can keep shipping.
						</p>
					</div>
				</article>
			</section>

			<section className="mt-8 flex flex-wrap gap-3">
				<Link to="/" className="signal-button">
					Back to dashboard
				</Link>
				<a
					href="https://docs.convex.dev/quickstart/tanstack-start"
					target="_blank"
					rel="noreferrer"
					className="signal-button secondary-button"
				>
					Convex + TanStack docs
				</a>
			</section>
		</main>
	);
}
