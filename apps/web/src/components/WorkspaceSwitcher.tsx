import { useClerk } from "@clerk/react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Check, ChevronsUpDown, LogOut, Plus, Settings, UserPlus } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { api } from "#/lib/convex";
import { humanize } from "#/lib/format";
import { useDismiss } from "#/lib/useDismiss";

type WorkspaceMembership = {
	tenantId: string;
	tenantSlug: string;
	tenantName: string;
	role: "owner" | "admin" | "member";
	selectedAt: number;
};

function initials(name: string) {
	return name
		.split(/\s+/)
		.map((w) => w[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();
}

export default function WorkspaceSwitcher() {
	const workspace = useQuery(api.workspaceAuth.currentWorkspace);
	const switchWorkspace = useMutation(api.workspaceAuth.switchWorkspace);
	const { signOut } = useClerk();
	const [open, setOpen] = useState(false);
	const [isSwitching, setIsSwitching] = useState(false);
	const ref = useRef<HTMLDivElement>(null);
	const close = useCallback(() => setOpen(false), []);
	useDismiss(ref, open, close);

	if (workspace === undefined) {
		return <div className="skeleton h-10" />;
	}

	if (!workspace) {
		return (
			<Link to="/onboarding" className="ws-trigger">
				<span className="ws-logo">
					<Plus size={14} />
				</span>
				<span className="ws-name">Create workspace</span>
			</Link>
		);
	}

	const workspaces = workspace.workspaces as WorkspaceMembership[];
	const current = workspaces.find((w) => w.tenantSlug === workspace.tenant.slug);

	return (
		<div ref={ref} className="relative">
			<button
				type="button"
				className="ws-trigger"
				onClick={() => setOpen((v) => !v)}
				aria-expanded={open}
				aria-haspopup="menu"
			>
				<span className="ws-logo">{initials(workspace.tenant.name)}</span>
				<span className="min-w-0 flex-1">
					<span className="ws-name block">{workspace.tenant.name}</span>
					<span className="ws-sub block">
						{humanize(current?.role ?? "member")} · {workspaces.length} workspace
						{workspaces.length === 1 ? "" : "s"}
					</span>
				</span>
				<ChevronsUpDown size={14} className="shrink-0 text-[var(--text-3)]" />
			</button>

			{open && (
				<div className="menu left-0 right-0 top-[calc(100%+4px)]" role="menu">
					<div className="menu-label truncate">{workspace.user.email}</div>
					{workspaces.map((member) => {
						const isCurrent = member.tenantSlug === workspace.tenant.slug;
						return (
							<button
								key={member.tenantId}
								type="button"
								role="menuitem"
								className="menu-item"
								disabled={isSwitching}
								onClick={async () => {
									if (isCurrent) return close();
									setIsSwitching(true);
									try {
										await switchWorkspace({ tenantSlug: member.tenantSlug });
									} finally {
										setIsSwitching(false);
										close();
									}
								}}
							>
								<span className="ws-logo !h-5 !w-5 !rounded-[5px] !text-[0.6rem]">
									{initials(member.tenantName)}
								</span>
								<span className="flex-1 truncate">{member.tenantName}</span>
								{isCurrent && <Check size={14} />}
							</button>
						);
					})}
					<div className="menu-sep" />
					<Link to="/settings" className="menu-item" onClick={close} role="menuitem">
						<Settings size={14} />
						Workspace settings
					</Link>
					<Link to="/settings/team" className="menu-item" onClick={close} role="menuitem">
						<UserPlus size={14} />
						Invite teammates
					</Link>
					<Link to="/onboarding" className="menu-item" onClick={close} role="menuitem">
						<Plus size={14} />
						New workspace
					</Link>
					<div className="menu-sep" />
					<button
						type="button"
						role="menuitem"
						className="menu-item is-danger"
						onClick={() => void signOut()}
					>
						<LogOut size={14} />
						Sign out
					</button>
				</div>
			)}
		</div>
	);
}
