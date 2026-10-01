import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import {
	AlertTriangle,
	BarChart3,
	Bot,
	GitBranch,
	GitPullRequestArrow,
	Home,
	Key,
	Network,
	Package,
	Plug,
	Radar,
	Search,
	Settings,
	Shield,
	UserPlus,
	Wrench,
	X } from "lucide-react";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

/**
 * §6.15 — Command Palette.
 *
 * Cmd/Ctrl+K overlay with a search input and categorized results.
 * Navigates to the selected item on Enter/Click.
 *
 * Also provides static navigation entries for common routes.
 */

type NavEntry = {
	type: "navigate";
	label: string;
	sublabel: string;
	route: string;
	icon: React.ComponentType<{ size?: number; className?: string }>;
};

const NAV_ENTRIES: NavEntry[] = [
	{ type: "navigate", label: "Overview", sublabel: "What needs attention", route: "/", icon: Home },
	{ type: "navigate", label: "Findings", sublabel: "Triage open issues", route: "/findings", icon: AlertTriangle },
	{ type: "navigate", label: "Repositories", sublabel: "Monitored codebases", route: "/repositories", icon: GitBranch },
	{ type: "navigate", label: "Remediation", sublabel: "Fix queue, auto-PRs, SLAs", route: "/remediation", icon: Wrench },
	{ type: "navigate", label: "CI/CD gates", sublabel: "Merge & deploy policy", route: "/ci-cd", icon: GitPullRequestArrow },
	{ type: "navigate", label: "Breach intel", sublabel: "Advisories matched to your inventory", route: "/breach-intel", icon: Radar },
	{ type: "navigate", label: "Supply chain", sublabel: "SBOM, typosquats, zero-days", route: "/supply-chain", icon: Package },
	{ type: "navigate", label: "Attack paths", sublabel: "Dependency graph & blast radius", route: "/attack-paths", icon: Network },
	{ type: "navigate", label: "Agents", sublabel: "AI agent activity", route: "/agent-activity", icon: Bot },
	{ type: "navigate", label: "Reports", sublabel: "Posture, compliance, executive", route: "/reports", icon: BarChart3 },
	{ type: "navigate", label: "Compliance", sublabel: "Framework evidence", route: "/compliance", icon: Shield },
	{ type: "navigate", label: "Settings", sublabel: "Workspace configuration", route: "/settings", icon: Settings },
	{ type: "navigate", label: "Invite teammates", sublabel: "Settings → Team", route: "/settings/team", icon: UserPlus },
	{ type: "navigate", label: "Create API key", sublabel: "Settings → API keys", route: "/settings/api-keys", icon: Key },
	{ type: "navigate", label: "Integrations", sublabel: "Slack, Jira, PagerDuty…", route: "/integrations", icon: Plug },
];

const OPEN_EVENT = "cyberzen:open-command-palette";

/** Open the palette from anywhere (e.g. the top bar search button). */
export function openCommandPalette() {
	document.dispatchEvent(new Event(OPEN_EVENT));
}

type SearchResult = {
	_id: string;
	type: "repository" | "finding" | "advisory";
	label: string;
	sublabel: string;
	route: string;
};

type FlatResult =
	| { kind: "nav"; entry: NavEntry; index: number }
	| { kind: "search"; entry: SearchResult; index: number };

export default function CommandPalette() {
	const [open, setOpen] = useState(false);
	const [query, setQuery] = useState("");
	const [activeIndex, setActiveIndex] = useState(0);
	const inputRef = useRef<HTMLInputElement>(null);
	const navigate = useNavigate();
	const TENANT = useTenantSlug();
	// Derive tenantId from slug (we need it for the search query)
	const workspace = useQuery(api.workspaceAuth.currentWorkspace);

	const tenantId = workspace?.workspaces?.find(
		(w: { tenantSlug: string; tenantId: string }) => w.tenantSlug === TENANT,
	)?.tenantId;

	const searchResults = useQuery(
		api.search.universalSearch,
		tenantId && query.trim().length >= 2
			? { tenantId, query: query.trim() }
			: "skip",
	);

	// Build flat result list
	const results: FlatResult[] = [];

	if (query.trim().length < 2) {
		// Show navigation entries filtered by query
		const filtered = query.trim()
			? NAV_ENTRIES.filter((e) =>
					e.label.toLowerCase().includes(query.toLowerCase()),
				)
			: NAV_ENTRIES;
		filtered.forEach((entry, i) => {
			results.push({ kind: "nav", entry, index: i });
		});
	} else if (searchResults) {
		searchResults.repositories.forEach((r: SearchResult, i: number) => {
			results.push({ kind: "search", entry: r, index: i });
		});
		searchResults.findings.forEach((r: SearchResult, i: number) => {
			results.push({ kind: "search", entry: r, index: i });
		});
		searchResults.advisories.forEach((r: SearchResult, i: number) => {
			results.push({ kind: "search", entry: r, index: i });
		});
	}

	// Keyboard listener for Cmd/Ctrl+K and Escape
	useEffect(() => {
		function handleKeyDown(e: KeyboardEvent) {
			if ((e.metaKey || e.ctrlKey) && e.key === "k") {
				e.preventDefault();
				setOpen((prev) => !prev);
				setQuery("");
				setActiveIndex(0);
			}
			if (e.key === "Escape" && open) {
				setOpen(false);
			}
		}
		function handleOpen() {
			setOpen(true);
			setQuery("");
			setActiveIndex(0);
		}
		document.addEventListener("keydown", handleKeyDown);
		document.addEventListener(OPEN_EVENT, handleOpen);
		return () => {
			document.removeEventListener("keydown", handleKeyDown);
			document.removeEventListener(OPEN_EVENT, handleOpen);
		};
	}, [open]);

	// Focus input on open
	useEffect(() => {
		if (open) {
			setTimeout(() => inputRef.current?.focus(), 0);
		}
	}, [open]);

	// Arrow key navigation
	const handleKeyDown = useCallback(
		(e: React.KeyboardEvent) => {
			if (e.key === "ArrowDown") {
				e.preventDefault();
				setActiveIndex((i) => Math.min(i + 1, results.length - 1));
			} else if (e.key === "ArrowUp") {
				e.preventDefault();
				setActiveIndex((i) => Math.max(i - 1, 0));
			} else if (e.key === "Enter" && results[activeIndex]) {
				const item = results[activeIndex];
				const route =
					item.kind === "nav" ? item.entry.route : item.entry.route;
				setOpen(false);
				void navigate({ to: route as "/" });
			}
		},
		[activeIndex, results, navigate],
	);

	if (!open) return null;

	const categoryIcon = (type: string) => {
		switch (type) {
			case "repository":
				return <GitBranch size={14} />;
			case "finding":
				return <AlertTriangle size={14} />;
			case "advisory":
				return <Shield size={14} />;
			default:
				return <Search size={14} />;
		}
	};

	return (
		<div className="command-palette-overlay" onClick={() => setOpen(false)}>
			<div
				className="command-palette-modal"
				onClick={(e) => e.stopPropagation()}
			>
				<div className="command-palette-header">
					<Search size={16} className="text-[var(--sea-ink-soft)]" />
					<input
						ref={inputRef}
						type="text"
						className="command-palette-input"
						placeholder="Search findings, repos, or type a command..."
						value={query}
						onChange={(e) => {
							setQuery(e.target.value);
							setActiveIndex(0);
						}}
						onKeyDown={handleKeyDown}
					/>
					<button
						type="button"
						className="command-palette-close"
						onClick={() => setOpen(false)}
						aria-label="Close"
					>
						<X size={14} />
					</button>
				</div>

				<div className="command-palette-results">
					{results.length === 0 && query.trim().length >= 2 && (
						<div className="command-palette-empty">
							No results for "{query}"
						</div>
					)}

					{results.map((item, idx) => {
						const isActive = idx === activeIndex;
						const label =
							item.kind === "nav" ? item.entry.label : item.entry.label;
						const sublabel =
							item.kind === "nav" ? item.entry.sublabel : item.entry.sublabel;
						const icon =
							item.kind === "nav"
								? item.entry.icon
								: () => categoryIcon(item.entry.type);

						return (
							<button
								key={`${item.kind}-${label}-${idx}`}
								type="button"
								className={`command-palette-item${isActive ? " is-active" : ""}`}
								onClick={() => {
									const route =
										item.kind === "nav"
											? item.entry.route
											: item.entry.route;
									setOpen(false);
									void navigate({ to: route as "/" });
								}}
								onMouseEnter={() => setActiveIndex(idx)}
							>
								<span className="command-palette-item-icon">
									{React.createElement(icon as React.ComponentType<{ size?: number }>, { size: 14 })}
								</span>
								<div className="command-palette-item-text">
									<span className="command-palette-item-label">{label}</span>
									<span className="command-palette-item-sub">
										{sublabel}
									</span>
								</div>
								{item.kind === "search" && (
									<span className="command-palette-item-badge">
										{item.entry.type}
									</span>
								)}
							</button>
						);
					})}
				</div>

				<div className="command-palette-footer">
					<span>
						<kbd className="kbd">↑↓</kbd> navigate
					</span>
					<span>
						<kbd className="kbd">↵</kbd> select
					</span>
					<span>
						<kbd className="kbd">esc</kbd> close
					</span>
				</div>
			</div>
		</div>
	);
}
