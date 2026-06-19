import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import {
	AlertTriangle,
	ArrowRight,
	GitBranch,
	Search,
	Shield,
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
	{ type: "navigate", label: "Dashboard", sublabel: "Home", route: "/", icon: Search },
	{ type: "navigate", label: "Findings", sublabel: "Security findings", route: "/findings", icon: AlertTriangle },
	{ type: "navigate", label: "Repositories", sublabel: "Connected repos", route: "/repositories", icon: GitBranch },
	{ type: "navigate", label: "Compliance", sublabel: "Regulatory status", route: "/compliance", icon: Shield },
	{ type: "navigate", label: "Remediation", sublabel: "Auto-fix & PRs", route: "/remediation", icon: ArrowRight },
	{ type: "navigate", label: "CI/CD Gates", sublabel: "Gate decisions", route: "/ci-cd", icon: ArrowRight },
	{ type: "navigate", label: "Supply Chain", sublabel: "Dependency security", route: "/supply-chain", icon: ArrowRight },
	{ type: "navigate", label: "Settings", sublabel: "Workspace config", route: "/settings", icon: Search },
];

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
		document.addEventListener("keydown", handleKeyDown);
		return () => document.removeEventListener("keydown", handleKeyDown);
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
