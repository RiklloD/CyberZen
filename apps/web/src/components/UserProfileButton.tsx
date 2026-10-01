import { useClerk } from "@clerk/react";
import { Link } from "@tanstack/react-router";
import { BookOpen, Github, Key, Keyboard, LogOut, Plug, Settings } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "../lib/convex";
import { useDismiss } from "../lib/useDismiss";

export default function UserProfileButton() {
	const profile = useQuery(api.userProfile.getProfile);
	const { signOut } = useClerk();
	const [open, setOpen] = useState(false);
	const ref = useRef<HTMLDivElement>(null);
	const close = useCallback(() => setOpen(false), []);
	useDismiss(ref, open, close);

	if (!profile) return <div className="flex-1" />;

	const display = profile.name ?? profile.email ?? "Account";
	const initials = display
		.split(/[\s@.]+/)
		.filter(Boolean)
		.map((w: string) => w[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();

	const avatar = (size: "sm" | "lg") =>
		profile.image ? (
			<img
				src={profile.image}
				alt=""
				className={`${size === "sm" ? "h-[22px] w-[22px]" : "h-8 w-8"} rounded-full object-cover`}
			/>
		) : (
			<span className={size === "sm" ? "sidebar-user-avatar" : "sidebar-user-avatar-lg"}>
				{initials}
			</span>
		);

	return (
		<div ref={ref} className="relative min-w-0 flex-1">
			<button
				type="button"
				className="sidebar-user-trigger w-full"
				onClick={() => setOpen((v) => !v)}
				aria-expanded={open}
				aria-haspopup="menu"
			>
				{avatar("sm")}
				<span className="sidebar-user-name truncate">{display}</span>
			</button>

			{open && (
				<div className="menu bottom-[calc(100%+6px)] left-0 w-[220px]" role="menu">
					<div className="flex items-center gap-2.5 px-2 py-2">
						{avatar("lg")}
						<div className="min-w-0">
							<p className="truncate text-sm font-medium">{profile.name ?? "Account"}</p>
							<p className="truncate text-xs text-[var(--text-3)]">{profile.email}</p>
						</div>
					</div>
					<div className="menu-sep" />
					{profile.githubConnected ? (
						<div className="menu-item cursor-default hover:!bg-transparent">
							<Github size={14} />
							<span className="flex-1 truncate">@{profile.githubLogin}</span>
							<span className="h-1.5 w-1.5 rounded-full bg-[var(--success)]" />
						</div>
					) : (
						<Link to="/connect/github" className="menu-item" onClick={close}>
							<Github size={14} />
							<span className="flex-1">Connect GitHub</span>
						</Link>
					)}
					<Link to="/settings" className="menu-item" onClick={close}>
						<Settings size={14} />
						Settings
					</Link>
					<Link to="/settings/api-keys" className="menu-item" onClick={close}>
						<Key size={14} />
						API keys
					</Link>
					<Link to="/integrations" className="menu-item" onClick={close}>
						<Plug size={14} />
						Integrations
					</Link>
					<Link to="/docs/api" className="menu-item" onClick={close}>
						<BookOpen size={14} />
						API docs
					</Link>
					<button
						type="button"
						className="menu-item"
						onClick={() => {
							close();
							document.dispatchEvent(new KeyboardEvent("keydown", { key: "?" }));
						}}
					>
						<Keyboard size={14} />
						<span className="flex-1">Keyboard shortcuts</span>
						<span className="kbd">?</span>
					</button>
					<div className="menu-sep" />
					<button
						type="button"
						className="menu-item is-danger"
						onClick={() => {
							close();
							void signOut();
						}}
					>
						<LogOut size={14} />
						Sign out
					</button>
				</div>
			)}
		</div>
	);
}
