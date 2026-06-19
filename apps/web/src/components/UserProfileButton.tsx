import { useClerk } from "@clerk/tanstack-react-start";
import { Link } from "@tanstack/react-router";
import {
	ChevronUp,
	Github,
	Key,
	LogOut,
	Plug,
	Settings,
	User } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "../lib/convex";

export default function UserProfileButton() {
	const profile = useQuery(api.userProfile.getProfile);
	const { signOut } = useClerk();
	const [open, setOpen] = useState(false);
	const ref = useRef<HTMLDivElement>(null);

	// Close on outside click.
	useEffect(() => {
		if (!open) return;
		function handleClick(e: MouseEvent) {
			if (ref.current && !ref.current.contains(e.target as Node)) {
				setOpen(false);
			}
		}
		document.addEventListener("mousedown", handleClick);
		return () => document.removeEventListener("mousedown", handleClick);
	}, [open]);

	if (!profile) return null;

	const initials = (profile.name ?? profile.email ?? "?")
		.split(/\s+/)
		.map((w) => w[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();

	return (
		<div ref={ref} className="relative">
			<button
				type="button"
				className="sidebar-user-trigger"
				onClick={() => setOpen((v) => !v)}
				aria-expanded={open}
				aria-haspopup="true"
			>
				{profile.image ? (
					<img
						src={profile.image}
						alt=""
						className="h-7 w-7 rounded-full object-cover"
					/>
				) : (
					<span className="sidebar-user-avatar">{initials}</span>
				)}
				<span className="sidebar-user-name truncate">
					{profile.name ?? profile.email}
				</span>
				<ChevronUp
					size={13}
					className={`ml-auto transition-transform ${open ? "" : "rotate-180"}`}
				/>
			</button>

			{open && (
				<div className="sidebar-user-dropdown">
					{/* User info header */}
					<div className="sidebar-user-header">
						{profile.image ? (
							<img
								src={profile.image}
								alt=""
								className="h-9 w-9 rounded-full object-cover"
							/>
						) : (
							<span className="sidebar-user-avatar-lg">{initials}</span>
						)}
						<div className="min-w-0">
							<p className="truncate text-sm font-semibold text-[var(--sea-ink)]">
								{profile.name ?? "User"}
							</p>
							<p className="truncate text-xs text-[var(--sea-ink-soft)]">
								{profile.email}
							</p>
						</div>
					</div>

					{/* GitHub connection status */}
					<div className="sidebar-user-section">
						<div className="flex items-center gap-2">
							<Github size={14} />
							<span className="text-xs font-medium">
								{profile.githubConnected
									? `Connected as @${profile.githubLogin}`
									: "GitHub not connected"}
							</span>
							<span
								className={`ml-auto h-2 w-2 rounded-full ${
									profile.githubConnected
										? "bg-[var(--success)]"
										: "bg-[var(--muted)]"
								}`}
							/>
						</div>
						{!profile.githubConnected && (
							<Link
								to="/onboarding"
								className="mt-1.5 block text-xs font-semibold text-[var(--lagoon-deep)] hover:underline"
								onClick={() => setOpen(false)}
							>
								Connect GitHub →
							</Link>
						)}
					</div>

					{/* Quick links */}
					<div className="sidebar-user-links">
						<Link
							to="/settings"
							className="sidebar-user-link"
							onClick={() => setOpen(false)}
						>
							<Settings size={14} />
							Settings
						</Link>
						<Link
							to="/settings/api-keys"
							className="sidebar-user-link"
							onClick={() => setOpen(false)}
						>
							<Key size={14} />
							API Keys
						</Link>
						<Link
							to="/integrations"
							className="sidebar-user-link"
							onClick={() => setOpen(false)}
						>
							<Plug size={14} />
							Integrations
						</Link>
					</div>

					{/* Sign out */}
					<div className="sidebar-user-footer">
						<button
							type="button"
							className="sidebar-user-link w-full text-left text-[var(--danger)]"
							onClick={() => {
								setOpen(false);
								void signOut();
							}}
						>
							<LogOut size={14} />
							Sign out
						</button>
					</div>
				</div>
			)}
		</div>
	);
}
