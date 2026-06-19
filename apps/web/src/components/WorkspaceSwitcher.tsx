import { useClerk } from "@clerk/tanstack-react-start";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Building2, ChevronsUpDown, LogOut } from "lucide-react";
import { useState } from "react";
import { api } from "#/lib/convex";

type WorkspaceMembership = {
	tenantId: string;
	tenantSlug: string;
	tenantName: string;
	role: "owner" | "admin" | "member";
	selectedAt: number;
};

export default function WorkspaceSwitcher() {
	const workspace = useQuery(api.workspaceAuth.currentWorkspace);
	const switchWorkspace = useMutation(api.workspaceAuth.switchWorkspace);
	const { signOut } = useClerk();
	const [isSwitching, setIsSwitching] = useState(false);

	if (workspace === undefined) {
		return (
			<div className="workspace-switcher workspace-switcher--loading">
				<p className="workspace-switcher-title">Loading workspaces</p>
			</div>
		);
	}

	if (!workspace) {
		return (
			<div className="workspace-switcher workspace-switcher--empty">
				<div className="workspace-switcher-head">
					<div className="workspace-switcher-icon">
						<Building2 size={16} />
					</div>
					<div>
						<p className="workspace-switcher-title">No workspace yet</p>
						<p className="workspace-switcher-copy">
							Create a company workspace or join an invite to unlock the
							dashboard.
						</p>
					</div>
				</div>

				<Link to="/onboarding" className="workspace-switcher-link">
					Start onboarding
				</Link>

				<button
					type="button"
					className="workspace-switcher-signout"
					onClick={() => {
						void signOut();
					}}
				>
					<LogOut size={14} />
					Sign out
				</button>
			</div>
		);
	}

	const hasMultipleWorkspaces = workspace.workspaces.length > 1;
	const workspaces = workspace.workspaces as WorkspaceMembership[];

	return (
		<div className="workspace-switcher">
			<div className="workspace-switcher-head">
				<div className="workspace-switcher-icon">
					<Building2 size={16} />
				</div>
				<div className="workspace-switcher-text">
					<p className="workspace-switcher-title">Workspace</p>
					<p className="workspace-switcher-name">{workspace.tenant.name}</p>
					<p className="workspace-switcher-copy">
						{workspace.user.email ?? "Signed-in account"}
					</p>
				</div>
			</div>

			{hasMultipleWorkspaces && (
				<label className="workspace-switcher-select">
					<span className="workspace-switcher-select-label">
						<ChevronsUpDown size={14} />
						Switch workspace
					</span>
					<select
						value={workspace.tenant.slug}
						disabled={isSwitching}
						onChange={async (event) => {
							setIsSwitching(true);
							try {
								await switchWorkspace({
									tenantSlug: event.currentTarget.value,
								});
							} finally {
								setIsSwitching(false);
							}
						}}
					>
						{workspaces.map((member: WorkspaceMembership) => (
							<option key={member.tenantId} value={member.tenantSlug}>
								{member.tenantName}
							</option>
						))}
					</select>
				</label>
			)}

			<button
				type="button"
				className="workspace-switcher-signout"
				onClick={() => {
					void signOut();
				}}
			>
				<LogOut size={14} />
				Sign out
			</button>
		</div>
	);
}
