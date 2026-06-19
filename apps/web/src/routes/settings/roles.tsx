import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Plus, Shield, Trash2, X, Check, Pencil, UserCog } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";

export const Route = createFileRoute("/settings/roles")({
	errorComponent: RouteErrorBoundary,
	component: RolesPage });

const AVAILABLE_PERMISSIONS = [
	"read:findings",
	"write:findings",
	"read:repositories",
	"write:repositories",
	"admin:team",
	"admin:roles",
	"admin:api_keys",
	"admin:settings",
	"admin:integrations",
	"read:audit_log",
	"admin:compliance",
	"admin:remediation",
	"admin:gates",
	"admin:scans",
];

function RolesPage() {
	const TENANT = useTenantSlug();
	const [drawerOpen, setDrawerOpen] = useState(false);
	const [editingRoleId, setEditingRoleId] = useState<string | null>(null);

	const roles = useQuery(
		api.rbac.listRoles,
		{ tenantSlug: TENANT },
	);

	const currentUser = useQuery(api.workspaceAuth.currentWorkspace);

	const currentUserCanAdmin =
		currentUser?.workspaces?.some(
			(w: { tenantSlug: string; role: string }) => w.tenantSlug === TENANT && (w.role === "owner" || w.role === "admin"),
		) ?? false;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Shield size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Roles & Permissions</h1>
						<p className="page-subtitle">
							Manage custom roles and permission assignments
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="section-header mb-3">
					<h2 className="section-title">Roles</h2>
					{roles && (
						<StatusPill
							label={`${roles.length} role${roles.length !== 1 ? "s" : ""}`}
							tone="neutral"
						/>
					)}
					{currentUserCanAdmin && (
						<button
							type="button"
							onClick={() => {
								setEditingRoleId(null);
								setDrawerOpen(true);
							}}
							className="signal-button ml-auto"
							style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
						>
							<Plus size={14} className="mr-1" />
							Create Role
						</button>
					)}
				</div>

				{roles ? (
					<RoleListTable
						roles={roles}
						tenantSlug={TENANT}
						currentUserCanAdmin={currentUserCanAdmin}
						onEdit={(roleId) => {
							setEditingRoleId(roleId);
							setDrawerOpen(true);
						}}
					/>
				) : (
					<div className="space-y-2">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-14 rounded-2xl" />
						))}
					</div>
				)}
			</div>

			{drawerOpen && currentUserCanAdmin && (
				<RoleEditorDrawer
					tenantSlug={TENANT}
					roleId={editingRoleId}
					roles={roles ?? []}
					onClose={() => {
						setDrawerOpen(false);
						setEditingRoleId(null);
					}}
				/>
			)}

			{currentUserCanAdmin && (
				<DelegatedAdminSection
					tenantSlug={TENANT}
				/>
			)}
		</main>
	);
}

// ─── RoleListTable ──────────────────────────────────────────────────────────

type Role = {
	_id: string;
	name: string;
	description?: string;
	permissions: string[];
	isSystem: boolean;
	userCount: number;
	createdAt: number;
	updatedAt: number;
};

interface RoleListTableProps {
	roles: Role[];
	tenantSlug: string;
	currentUserCanAdmin: boolean;
	onEdit: (roleId: string) => void;
}

function RoleListTable({
	roles,
	tenantSlug,
	currentUserCanAdmin,
	onEdit }: RoleListTableProps) {
	const [isPending, startTransition] = useTransition();
	const deleteRole = useMutation(api.rbac.deleteRole);

	function handleDelete(roleId: string, name: string) {
		if (!confirm(`Delete role "${name}"? This will remove all grants for this role.`))
			return;
		startTransition(async () => {
			await deleteRole({ tenantSlug, roleId: roleId as any });
		});
	}

	return (
		<div className="space-y-2">
			{roles.map((role) => (
				<div key={role._id} className="card card-sm">
					<div className="flex items-center justify-between gap-3">
						<div className="flex items-center gap-3 min-w-0">
							<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
								<Shield size={14} className="text-[var(--signal)]" />
							</div>
							<div className="min-w-0">
								<div className="flex items-center gap-2">
									<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
										{role.name}
									</p>
									{role.isSystem && <StatusPill label="system" tone="info" />}
								</div>
								{role.description && (
									<p className="text-xs text-[var(--sea-ink-soft)] truncate">
										{role.description}
									</p>
								)}
								<div className="flex gap-1.5 mt-1 flex-wrap">
									{role.permissions.slice(0, 5).map((p) => (
										<StatusPill key={p} label={p} tone="neutral" />
									))}
									{role.permissions.length > 5 && (
										<StatusPill
											label={`+${role.permissions.length - 5} more`}
											tone="neutral"
										/>
									)}
								</div>
							</div>
						</div>

						<div className="flex items-center gap-2 flex-shrink-0">
							<StatusPill
								label={`${role.userCount} user${role.userCount !== 1 ? "s" : ""}`}
								tone="neutral"
							/>
							{currentUserCanAdmin && !role.isSystem && (
								<>
									<button
										type="button"
										onClick={() => onEdit(role._id)}
										className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--signal)] hover:bg-[var(--signal)]/10 transition-colors"
										title="Edit role"
									>
										<Pencil size={14} />
									</button>
									<button
										type="button"
										disabled={isPending}
										onClick={() => handleDelete(role._id, role.name)}
										className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
										title="Delete role"
									>
										<Trash2 size={14} />
									</button>
								</>
							)}
						</div>
					</div>
				</div>
			))}

			{roles.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<Shield size={24} className="mb-2 opacity-40" />
					<p>No custom roles defined yet. Create one to get started.</p>
				</div>
			)}
		</div>
	);
}

// ─── RoleEditorDrawer ───────────────────────────────────────────────────────

interface RoleEditorDrawerProps {
	tenantSlug: string;
	roleId: string | null;
	roles: Role[];
	onClose: () => void;
}

function RoleEditorDrawer({
	tenantSlug,
	roleId,
	roles,
	onClose }: RoleEditorDrawerProps) {
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
	const [isPending, startTransition] = useTransition();

	const createRole = useMutation(api.rbac.createRole);
	const updateRole = useMutation(api.rbac.updateRole);

	const isEditing = roleId !== null;

	// Load existing role data for editing
	React.useEffect(() => {
		if (isEditing && roleId) {
			const role = roles.find((r) => r._id === roleId);
			if (role) {
				setName(role.name);
				setDescription(role.description ?? "");
				setSelectedPermissions(role.permissions);
			}
		} else {
			setName("");
			setDescription("");
			setSelectedPermissions([]);
		}
	}, [isEditing, roleId, roles]);

	function togglePermission(perm: string) {
		setSelectedPermissions((prev) =>
			prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm],
		);
	}

	function handleSave() {
		if (!name.trim()) return;
		startTransition(async () => {
			if (isEditing && roleId) {
				await updateRole({
					tenantSlug,
					roleId: roleId as any,
					name: name.trim(),
					description: description.trim() || undefined,
					permissions: selectedPermissions });
			} else {
				await createRole({
					tenantSlug,
					name: name.trim(),
					description: description.trim() || undefined,
					permissions: selectedPermissions });
			}
			onClose();
		});
	}

	return (
		<div className="drawer-overlay" onClick={onClose}>
			<div
				className="drawer-panel"
				onClick={(e) => e.stopPropagation()}
				style={{ maxWidth: "480px" }}
			>
				<div className="drawer-header">
					<h2 className="drawer-title">
						{isEditing ? "Edit Role" : "Create Role"}
					</h2>
					<button
						type="button"
						onClick={onClose}
						className="drawer-close"
					>
						<X size={18} />
					</button>
				</div>

				<div className="drawer-body space-y-4">
					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							Role Name
						</label>
						<input
							type="text"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="e.g. Security Analyst"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							Description
						</label>
						<textarea
							value={description}
							onChange={(e) => setDescription(e.target.value)}
							placeholder="Optional description of this role"
							rows={2}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none"
						/>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Permissions
						</label>
						<div className="grid grid-cols-2 gap-2">
							{AVAILABLE_PERMISSIONS.map((perm) => {
								const isSelected = selectedPermissions.includes(perm);
								return (
									<button
										key={perm}
										type="button"
										onClick={() => togglePermission(perm)}
										className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs transition-colors ${
											isSelected
												? "border-[var(--signal)] bg-[var(--signal)]/10 text-[var(--signal)]"
												: "border-[var(--line)] bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:border-[var(--signal)]/40"
										}`}
									>
										{isSelected ? (
											<Check size={12} />
										) : (
											<div className="w-3 h-3 rounded border border-[var(--line)]" />
										)}
										<span className="truncate">{perm}</span>
									</button>
								);
							})}
						</div>
					</div>
				</div>

				<div className="drawer-footer">
					<button
						type="button"
						onClick={onClose}
						className="secondary-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Cancel
					</button>
					<button
						type="button"
						onClick={handleSave}
						disabled={isPending || !name.trim()}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						{isPending ? "Saving..." : isEditing ? "Update Role" : "Create Role"}
					</button>
				</div>
			</div>
		</div>
	);
}

// ─── DelegatedAdminSection ──────────────────────────────────────────────────

const DELEGABLE_PERMISSIONS = [
	{ id: "findings.manage", label: "Manage Findings", description: "Create, update, and close findings" },
	{ id: "scans.run", label: "Run Scans", description: "Trigger and configure security scans" },
	{ id: "reports.view", label: "View Reports", description: "Access security reports and dashboards" },
	{ id: "webhooks.manage", label: "Manage Webhooks", description: "Configure outbound webhook endpoints" },
] as const;

const DELEGATED_RESTRICTIONS = [
	"Manage billing or subscriptions",
	"Configure SSO settings",
	"Manage API keys",
	"Manage roles or other admins",
	"Delete workspace or transfer ownership",
];

type MemberDelegation = {
	memberId: string;
	userId: string;
	role: "owner" | "admin" | "member";
	email?: string;
	name?: string;
	delegatedPermissions?: string[];
};

interface DelegatedAdminSectionProps {
	tenantSlug: string;
}

function DelegatedAdminSection({ tenantSlug }: DelegatedAdminSectionProps) {
	const [editingUserId, setEditingUserId] = useState<string | null>(null);

	const members = useQuery(
		api.rbac.listMembersWithDelegations,
		{ tenantSlug },
	) as MemberDelegation[] | undefined;

	return (
		<>
			<div className="page-body mt-6">
				<div className="section-header mb-3">
					<h2 className="section-title">Delegated Permissions</h2>
					<p className="text-xs text-[var(--sea-ink-soft)] ml-2">
						Grant members limited admin capabilities without full admin access
					</p>
				</div>

				{members ? (
					<div className="space-y-2">
						{members
							.filter((m) => m.role !== "owner")
							.map((member) => (
								<div key={member.memberId} className="card card-sm">
									<div className="flex items-center justify-between gap-3">
										<div className="flex items-center gap-3 min-w-0">
											<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
												<UserCog size={14} className="text-[var(--sea-ink-soft)]" />
											</div>
											<div className="min-w-0">
												<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
													{member.name || member.email || "Unknown"}
												</p>
												<div className="flex gap-1.5 mt-1 flex-wrap">
													{(member.delegatedPermissions ?? []).length === 0 ? (
														<StatusPill label="no delegated permissions" tone="neutral" />
													) : (
														(member.delegatedPermissions ?? []).map((p) => (
															<StatusPill key={p} label={p} tone="info" />
														))
													)}
												</div>
											</div>
										</div>
										<button
											type="button"
											onClick={() => setEditingUserId(member.userId)}
											className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--signal)] hover:bg-[var(--signal)]/10 transition-colors"
											title="Edit delegated permissions"
										>
											<Pencil size={14} />
										</button>
									</div>
								</div>
							))}

						{members.filter((m) => m.role !== "owner").length === 0 && (
							<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
								<UserCog size={24} className="mb-2 opacity-40" />
								<p>No non-owner members to configure.</p>
							</div>
						)}
					</div>
				) : (
					<div className="space-y-2">
						{["a", "b"].map((k) => (
							<div key={k} className="loading-panel h-14 rounded-2xl" />
						))}
					</div>
				)}
			</div>

			{editingUserId && members && (
				<DelegatedPermissionsDrawer
					tenantSlug={tenantSlug}
					member={members.find((m) => m.userId === editingUserId)!}
					onClose={() => setEditingUserId(null)}
				/>
			)}
		</>
	);
}

interface DelegatedPermissionsDrawerProps {
	tenantSlug: string;
	member: {
		userId: string;
		role: string;
		email?: string;
		name?: string;
		delegatedPermissions?: string[];
	};
	onClose: () => void;
}

function DelegatedPermissionsDrawer({
	tenantSlug,
	member,
	onClose }: DelegatedPermissionsDrawerProps) {
	const [selected, setSelected] = useState<string[]>(member.delegatedPermissions ?? []);
	const [isPending, startTransition] = useTransition();
	const setDelegated = useMutation(api.rbac.setDelegatedPermissions);

	function toggle(id: string) {
		setSelected((prev) =>
			prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id],
		);
	}

	function handleSave() {
		startTransition(async () => {
			await setDelegated({
				tenantSlug,
				targetUserId: member.userId as any,
				permissions: selected });
			onClose();
		});
	}

	return (
		<div className="drawer-overlay" onClick={onClose}>
			<div
				className="drawer-panel"
				onClick={(e) => e.stopPropagation()}
				style={{ maxWidth: "520px" }}
			>
				<div className="drawer-header">
					<h2 className="drawer-title">
						Delegated Permissions — {member.name || member.email || "Member"}
					</h2>
					<button type="button" onClick={onClose} className="drawer-close">
						<X size={18} />
					</button>
				</div>

				<div className="drawer-body space-y-5">
					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Allowed Actions
						</label>
						<div className="space-y-2">
							{DELEGABLE_PERMISSIONS.map((perm) => {
								const isSelected = selected.includes(perm.id);
								return (
									<button
										key={perm.id}
										type="button"
										onClick={() => toggle(perm.id)}
										className={`w-full flex items-start gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors ${
											isSelected
												? "border-[var(--signal)] bg-[var(--signal)]/10"
												: "border-[var(--line)] bg-[var(--surface)] hover:border-[var(--signal)]/40"
										}`}
									>
										<div className="mt-0.5 flex-shrink-0">
											{isSelected ? (
												<Check size={14} className="text-[var(--signal)]" />
											) : (
												<div className="w-3.5 h-3.5 rounded border border-[var(--line)]" />
											)}
										</div>
										<div>
											<p className={`text-xs font-semibold ${isSelected ? "text-[var(--signal)]" : "text-[var(--sea-ink)]"}`}>
												{perm.label}
											</p>
											<p className="text-xs text-[var(--sea-ink-soft)]">{perm.description}</p>
										</div>
									</button>
								);
							})}
						</div>
					</div>

					<div>
						<p className="text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Always Restricted
						</p>
						<div className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2.5 space-y-1">
							{DELEGATED_RESTRICTIONS.map((r) => (
								<div key={r} className="flex items-center gap-2">
									<X size={11} className="text-[var(--danger)] flex-shrink-0" />
									<span className="text-xs text-[var(--sea-ink-soft)]">{r}</span>
								</div>
							))}
						</div>
					</div>
				</div>

				<div className="drawer-footer">
					<button
						type="button"
						onClick={onClose}
						className="secondary-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Cancel
					</button>
					<button
						type="button"
						onClick={handleSave}
						disabled={isPending}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						{isPending ? "Saving..." : "Save Permissions"}
					</button>
				</div>
			</div>
		</div>
	);
}

// Need React import for useEffect in drawer
import React from "react";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
