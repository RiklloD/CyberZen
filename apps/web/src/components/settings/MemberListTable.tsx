import { useState, useTransition } from "react";
import { useMutation } from "convex/react";
import { Trash2, UserCog } from "lucide-react";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import StatusPill from "../StatusPill";

type Member = {
	_id: Id<"tenantMembers">;
	userId: Id<"users">;
	role: "owner" | "admin" | "member";
	email?: string;
	name?: string;
	joinedAt?: number;
};

interface MemberListTableProps {
	members: Member[];
	tenantSlug: string;
	currentUserCanAdmin: boolean;
}

function roleTone(role: string) {
	if (role === "owner") return "warning" as const;
	if (role === "admin") return "info" as const;
	return "neutral" as const;
}

export default function MemberListTable({
	members,
	tenantSlug,
	currentUserCanAdmin }: MemberListTableProps) {
	const [isPending, startTransition] = useTransition();
	const [changingRole, setChangingRole] = useState<string | null>(null);

	const removeMember = useMutation(api.workspaceAuth.removeMember);
	const changeRole = useMutation(api.workspaceAuth.changeRole);

	function handleRemove(userId: Id<"users">) {
		startTransition(async () => {
			await removeMember({
				tenantSlug,
				memberUserId: userId });
		});
	}

	function handleChangeRole(userId: Id<"users">, newRole: "owner" | "admin" | "member") {
		setChangingRole(userId);
		startTransition(async () => {
			await changeRole({
				tenantSlug,
				memberUserId: userId,
				newRole });
			setChangingRole(null);
		});
	}

	return (
		<div className="space-y-2">
			{members.map((member) => (
				<div key={member._id} className="card card-sm">
					<div className="flex items-center justify-between gap-3">
						<div className="flex items-center gap-3 min-w-0">
							<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
								<UserCog size={14} className="text-[var(--sea-ink-soft)]" />
							</div>
							<div className="min-w-0">
								<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
									{member.name || member.email || "Unknown"}
								</p>
								{member.name && member.email && (
									<p className="text-xs text-[var(--sea-ink-soft)] truncate">
										{member.email}
									</p>
								)}
							</div>
						</div>

						<div className="flex items-center gap-2 flex-shrink-0">
							{currentUserCanAdmin && member.role !== "owner" ? (
								<select
									value={member.role}
									disabled={isPending || changingRole === member.userId}
									onChange={(e) =>
										handleChangeRole(
											member.userId,
											e.target.value as "owner" | "admin" | "member",
										)
									}
									className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
								>
									<option value="admin">Admin</option>
									<option value="member">Member</option>
								</select>
							) : (
								<StatusPill label={member.role} tone={roleTone(member.role)} />
							)}

							{currentUserCanAdmin && member.role !== "owner" && (
								<button
									type="button"
									disabled={isPending}
									onClick={() => handleRemove(member.userId)}
									className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
									title="Remove member"
								>
									<Trash2 size={14} />
								</button>
							)}
						</div>
					</div>
				</div>
			))}

			{members.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
					<UserCog size={24} className="mb-2 opacity-40" />
					<p>No members found in this workspace.</p>
				</div>
			)}
		</div>
	);
}
