export default function Footer() {
	const year = new Date().getFullYear();

	return (
		<footer className="site-footer mt-20 px-4 pb-14 pt-10 text-[var(--sea-ink-soft)]">
			<div className="page-wrap flex flex-col items-center justify-between gap-4 text-center sm:flex-row sm:text-left">
				<div>
					<p className="m-0 text-sm text-[var(--sea-ink)]">
						&copy; {year} CyberZen. Sentinel foundation workspace.
					</p>
					<p className="mt-1 text-sm">
						Built for the first product slice: event routing, SBOM state, breach
						intel, and operator visibility.
					</p>
				</div>
				<p className="island-kicker m-0">TanStack Start + Convex + PostHog</p>
			</div>
			<div className="mt-4 flex justify-center gap-4 sm:justify-start">
				<a
					href="https://tanstack.com/start"
					target="_blank"
					rel="noreferrer"
					className="rounded-xl p-2 text-[var(--sea-ink-soft)] transition hover:bg-[var(--link-bg-hover)] hover:text-[var(--sea-ink)]"
				>
					TanStack Start
				</a>
				<a
					href="https://docs.convex.dev"
					target="_blank"
					rel="noreferrer"
					className="rounded-xl p-2 text-[var(--sea-ink-soft)] transition hover:bg-[var(--link-bg-hover)] hover:text-[var(--sea-ink)]"
				>
					Convex Docs
				</a>
				<a
					href="https://posthog.com/docs"
					target="_blank"
					rel="noreferrer"
					className="rounded-xl p-2 text-[var(--sea-ink-soft)] transition hover:bg-[var(--link-bg-hover)] hover:text-[var(--sea-ink)]"
				>
					PostHog Docs
				</a>
			</div>
		</footer>
	);
}
