import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "../../lib/clerk-compat";
import { useMutation, useQuery } from "convex/react";
import { Plus, Users, Trash2, Clock, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { useState, useTransition } from "react";
import MemberListTable from "../../components/settings/MemberListTable";
import InviteMemberModal from "../../components/modals/InviteMemberModal";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/team")({
	errorComponent: RouteErrorBoundary,
	component: TeamManagementPage,
});

function TeamManagementPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";
	const [inviteOpen, setInviteOpen] = useState(false);

	const members = useQuery(
		api.workspaceAuth.listMembers,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	const currentUser = useQuery(api.workspaceAuth.currentWorkspace, {
		authToken,
	});

	const currentWorkspace = currentUser?.workspaces?.find(
		(w: { tenantSlug: string; role: string }) => w.tenantSlug === TENANT,
	);
	const currentUserCanAdmin =
		currentWorkspace?.role === "owner" || currentWorkspace?.role === "admin";
	const currentUserIsOwner = currentWorkspace?.role === "owner";

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Users size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Team Management</h1>
						<p className="page-subtitle">
							Manage workspace members, roles, and invitations
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="section-header mb-3">
					<h2 className="section-title">Members</h2>
					{members && (
						<StatusPill
							label={`${members.length} member${members.length !== 1 ? "s" : ""}`}
							tone="neutral"
						/>
					)}
					{currentUserCanAdmin && (
						<button
							type="button"
							onClick={() => setInviteOpen(true)}
							className="signal-button ml-auto"
							style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
						>
							<Plus size={14} className="mr-1" />
							Invite
						</button>
					)}
				</div>

				{members ? (
					<MemberListTable
						members={members}
						authToken={authToken}
						tenantSlug={TENANT}
						currentUserCanAdmin={currentUserCanAdmin ?? false}
					/>
				) : (
					<div className="space-y-2">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-14 rounded-2xl" />
						))}
					</div>
				)}
			</div>

			{currentUserIsOwner && (
				<DeletionQueuePanel
					authToken={authToken}
					tenantSlug={TENANT}
				/>
			)}

			<InviteMemberModal
				open={inviteOpen}
				authToken={authToken}
				tenantSlug={TENANT}
				onClose={() => setInviteOpen(false)}
			/>
		</main>
	);
}

// ─── DeletionQueuePanel ──────────────────────────────────────────────────────

function statusIcon(status: string) {
	if (status === "scheduled") return <Clock size={14} className="text-[var(--sea-ink-soft)]" />;
	if (status === "executing") return <AlertTriangle size={14} className="text-[var(--signal)]" />;
	if (status === "completed") return <CheckCircle size={14} className="text-[var(--success,#22c55e)]" />;
	return <XCircle size={14} className="text-[var(--danger)]" />;
}

function statusTone(status: string): "neutral" | "info" | "warning" | "danger" {
	if (status === "scheduled") return "neutral";
	if (status === "executing") return "info";
	if (status === "completed") return "neutral";
	return "danger";
}

type DeletionEntry = {
	_id: string;
	entityType: "user" | "finding" | "tenant";
	entityId: string;
	requestedAt: number;
	scheduledAt: number;
	executedAt?: number;
	status: "scheduled" | "executing" | "completed" | "failed";
	error?: string;
};

interface DeletionQueuePanelProps {
	authToken: string;
	tenantSlug: string;
}

function DeletionQueuePanel({ authToken, tenantSlug }: DeletionQueuePanelProps) {
	const [isPending, startTransition] = useTransition();
	const queue = useQuery(
		api.deletionPipeline.listDeletionQueue,
		authToken ? { authToken, tenantSlug } : "skip",
	) as DeletionEntry[] | undefined;
	const cancelDeletion = useMutation(api.deletionPipeline.cancelDeletion);

	function handleCancel(queueId: string) {
		if (!confirm("Cancel this scheduled deletion? The data will be retained.")) return;
		startTransition(async () => {
			await cancelDeletion({ authToken, tenantSlug, queueId: queueId as any });
		});
	}

	return (
		<div className="page-body mt-6">
			<div className="section-header mb-3">
				<div className="flex items-center gap-2">
					<Trash2 size={16} className="text-[var(--danger)]" />
					<h2 className="section-title">Deletion Queue</h2>
				</div>
				{queue && (
					<StatusPill
						label={`${queue.filter((e) => e.status === "scheduled").length} pending`}
						tone="neutral"
					/>
				)}
			</div>

			{queue ? (
				queue.length === 0 ? (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Trash2 size={24} className="mb-2 opacity-40" />
						<p>No deletions scheduled.</p>
					</div>
				) : (
					<div className="space-y-2">
						{queue.map((entry) => {
							const scheduledDate = new Date(entry.scheduledAt);
							const daysUntil = Math.ceil(
								(entry.scheduledAt - Date.now()) / (1000 * 60 * 60 * 24),
							);
							return (
								<div key={entry._id} className="card card-sm">
									<div className="flex items-center justify-between gap-3">
										<div className="flex items-center gap-3 min-w-0">
											<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
												{statusIcon(entry.status)}
											</div>
											<div className="min-w-0">
												<div className="flex items-center gap-2">
													<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
														{entry.entityType} / {entry.entityId.slice(0, 16)}…
													</p>
													<StatusPill label={entry.status} tone={statusTone(entry.status)} />
												</div>
												<p className="text-xs text-[var(--sea-ink-soft)]">
													{entry.status === "scheduled"
														? `Executes ${scheduledDate.toLocaleDateString()} (${daysUntil > 0 ? `in ${daysUntil}d` : "overdue"})`
														: entry.executedAt
															? `Executed ${new Date(entry.executedAt).toLocaleDateString()}`
															: `Requested ${new Date(entry.requestedAt).toLocaleDateString()}`}
												</p>
												{entry.error && (
													<p className="text-xs text-[var(--danger)] truncate">{entry.error}</p>
												)}
											</div>
										</div>

										{entry.status === "scheduled" && (
											<button
												type="button"
												disabled={isPending}
												onClick={() => handleCancel(entry._id)}
												className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40 flex-shrink-0"
												title="Cancel deletion"
											>
												<XCircle size={14} />
											</button>
										)}
									</div>
								</div>
							);
						})}
					</div>
				)
			) : (
				<div className="space-y-2">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-14 rounded-2xl" />
					))}
				</div>
			)}
		</div>
	);
}
