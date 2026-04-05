import { Link } from "@tanstack/react-router";
import { Shield, Waypoints } from "lucide-react";
import ThemeToggle from "./ThemeToggle";

export default function Header() {
	return (
		<header className="sticky top-0 z-50 border-b border-[var(--line)] bg-[var(--header-bg)] px-4 backdrop-blur-lg">
			<nav className="page-wrap flex flex-wrap items-center gap-x-3 gap-y-2 py-3 sm:py-4">
				<h2 className="m-0 flex-shrink-0 text-base font-semibold tracking-tight">
					<Link
						to="/"
						className="inline-flex items-center gap-3 rounded-full border border-[var(--chip-line)] bg-[var(--chip-bg)] px-3 py-1.5 text-sm text-[var(--sea-ink)] no-underline shadow-[0_12px_28px_rgba(7,12,16,0.12)] sm:px-4 sm:py-2"
					>
						<span className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-[rgba(158,255,100,0.28)] bg-[rgba(158,255,100,0.12)] text-[var(--signal)]">
							<Shield size={16} />
						</span>
						<span className="flex flex-col leading-none">
							<span className="text-[0.72rem] uppercase tracking-[0.28em] text-[var(--sea-ink-soft)]">
								CyberZen
							</span>
							<span className="mt-1 text-sm font-semibold text-[var(--sea-ink)]">
								Sentinel control plane
							</span>
						</span>
					</Link>
				</h2>

				<div className="ml-auto flex items-center gap-1.5 sm:ml-0 sm:gap-2">
					<div className="hidden items-center gap-2 rounded-full border border-[var(--chip-line)] bg-[var(--chip-bg)] px-3 py-2 text-xs font-semibold tracking-[0.18em] text-[var(--sea-ink-soft)] uppercase sm:inline-flex">
						<Waypoints size={14} />
						Phase 0 to Phase 1
					</div>

					<ThemeToggle />
				</div>

				<div className="order-3 flex w-full flex-wrap items-center gap-x-4 gap-y-1 pb-1 text-sm font-semibold sm:order-2 sm:w-auto sm:flex-nowrap sm:pb-0">
					<Link
						to="/"
						className="nav-link"
						activeProps={{ className: "nav-link is-active" }}
					>
						Home
					</Link>
					<Link
						to="/about"
						className="nav-link"
						activeProps={{ className: "nav-link is-active" }}
					>
						Architecture
					</Link>
					<a
						href="https://docs.convex.dev/quickstart/tanstack-start"
						className="nav-link"
						target="_blank"
						rel="noreferrer"
					>
						Convex
					</a>
				</div>
			</nav>
		</header>
	);
}
