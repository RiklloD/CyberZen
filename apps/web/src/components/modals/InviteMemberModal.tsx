import { useState, useTransition } from "react";
import { useMutation, useQuery } from "convex/react";
import { Mail } from "lucide-react";
import { api } from "../../lib/convex";
import { track } from "../../lib/analytics";

interface InviteMemberModalProps {
	open: boolean;
	tenantSlug: string;
	onClose: () => void;
}

export default function InviteMemberModal({
	open,
	tenantSlug,
	onClose }: InviteMemberModalProps) {
	const [email, setEmail] = useState("");
	const [role, setRole] = useState<"admin" | "member">("member");
	const [assignedRoleId, setAssignedRoleId] = useState<string>("");
	const [isPending, startTransition] = useTransition();
	const [result, setResult] = useState<{
		inviteUrl: string;
		tenantName: string;
	} | null>(null);

	const inviteMember = useMutation(api.workspaceAuth.inviteMember);

	// §6.11 — Fetch custom RBAC roles for the role dropdown
	const customRoles = useQuery(api.rbac.listRoles, {
		tenantSlug });

	if (!open) return null;

	function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!email.trim()) return;

		setResult(null);
		startTransition(async () => {
			const res = await inviteMember({
				tenantSlug,
				email: email.trim(),
				role,
				assignedRoleId: assignedRoleId || undefined });
			track("member.invited", {
				role,
				hasRoleId: Boolean(assignedRoleId) });
			setResult({ inviteUrl: res.inviteUrl, tenantName: res.tenantName });
			setEmail("");
		});
	}

	function handleBackdropClick(e: React.MouseEvent) {
		if (e.target === e.currentTarget) onClose();
	}

	function handleDone() {
		setResult(null);
		setRole("member");
		setAssignedRoleId("");
		onClose();
	}

	return (
		<div
			onClick={handleBackdropClick}
			style={{
				position: "fixed",
				inset: 0,
				zIndex: 50,
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				background: "rgba(0, 0, 0, 0.44)",
				backdropFilter: "blur(2px)" }}
		>
			<div
				className="card"
				style={{
					width: "min(520px, 92vw)",
					maxHeight: "90vh",
					overflowY: "auto" }}
			>
				<div className="flex items-center gap-2 mb-4">
					<Mail size={18} className="text-[var(--signal)]" />
					<h2 className="text-sm font-bold text-[var(--sea-ink)]">
						Invite Member
					</h2>
				</div>

				{result ? (
					<div className="space-y-3">
						<p className="text-xs text-[var(--success)]">
							Invitation created successfully for {result.tenantName}.
						</p>
						<div>
							<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1">
								Invite Link
							</label>
							<input
								readOnly
								value={result.inviteUrl}
								className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] font-mono"
								onClick={(e) => (e.target as HTMLInputElement).select()}
							/>
						</div>
						<div className="flex justify-end pt-2">
							<button
								type="button"
								onClick={handleDone}
								className="signal-button"
								style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
							>
								Done
							</button>
						</div>
					</div>
				) : (
					<form onSubmit={handleSubmit} className="space-y-4">
						<div>
							<label
								htmlFor="invite-email"
								className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
							>
								Email address *
							</label>
							<input
								id="invite-email"
								type="email"
								value={email}
								onChange={(e) => setEmail(e.target.value)}
								required
								placeholder="colleague@company.com"
								className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
							/>
						</div>

						<div>
							<label
								htmlFor="invite-role"
								className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
							>
								Workspace Role
							</label>
							<select
								id="invite-role"
								value={role}
								onChange={(e) => setRole(e.target.value as "admin" | "member")}
								className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
							>
								<option value="member">Member</option>
								<option value="admin">Admin</option>
							</select>
							<p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
								Members can view data. Admins can manage members and settings.
							</p>
						</div>

						{/* §6.11 — Custom RBAC Role Dropdown */}
						{customRoles && customRoles.length > 0 && (
							<div>
								<label
									htmlFor="invite-custom-role"
									className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
								>
									Custom Role (optional)
								</label>
								<select
									id="invite-custom-role"
									value={assignedRoleId}
									onChange={(e) => setAssignedRoleId(e.target.value)}
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
								>
									<option value="">None — use workspace role only</option>
									{customRoles.map((r: (typeof customRoles)[number]) => (
										<option key={r._id} value={r._id}>
											{r.name}
											{r.description ? ` — ${r.description}` : ""}
										</option>
									))}
								</select>
								<p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
									Assign a custom RBAC role with specific permissions on top of
									the workspace role.
								</p>
							</div>
						)}

						<div className="flex justify-end gap-2 pt-2">
							<button
								type="button"
								onClick={onClose}
								disabled={isPending}
								className="signal-button secondary-button"
								style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
							>
								Cancel
							</button>
							<button
								type="submit"
								disabled={isPending}
								className="signal-button"
								style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
							>
								{isPending ? "Inviting…" : "Send Invite"}
							</button>
						</div>
					</form>
				)}
			</div>
		</div>
	);
}
