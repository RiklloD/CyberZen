import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "@convex-dev/auth/react";
import { useMutation, useQuery } from "convex/react";
import {
	Globe,
	Laptop,
	Loader2,
	LogOut,
	Monitor,
	Smartphone,
	Tablet,
} from "lucide-react";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/sessions")({
	errorComponent: QueryErrorFallback,
	component: SessionsPage,
});

function deviceIcon(os?: string, ua?: string) {
	const str = (os ?? ua ?? "").toLowerCase();
	if (str.includes("android") || str.includes("ios") || str.includes("iphone"))
		return <Smartphone size={16} />;
	if (str.includes("ipad") || str.includes("tablet"))
		return <Tablet size={16} />;
	return <Monitor size={16} />;
}

function formatRelativeTime(ts: number) {
	const diffMs = Date.now() - ts;
	const diffMins = Math.floor(diffMs / 60000);
	if (diffMins < 1) return "Just now";
	if (diffMins < 60) return `${diffMins}m ago`;
	const diffHours = Math.floor(diffMins / 60);
	if (diffHours < 24) return `${diffHours}h ago`;
	const diffDays = Math.floor(diffHours / 24);
	return `${diffDays}d ago`;
}

function SessionsPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";
	const [revoking, setRevoking] = useState<string | null>(null);
	const [revokingAll, setRevokingAll] = useState(false);
	const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

	const sessions = useQuery(
		api.sessionManagement.listSessions,
		authToken ? { authToken } : "skip",
	);

	const revokeSession = useMutation(api.sessionManagement.revokeSession);
	const revokeAllOther = useMutation(
		api.sessionManagement.revokeAllOtherSessions,
	);

	function flash(text: string, ok: boolean) {
		setMsg({ text, ok });
		setTimeout(() => setMsg(null), 4000);
	}

	async function handleRevoke(id: string) {
		setRevoking(id);
		try {
			await revokeSession({
				authToken,
				userSessionId: id as any,
			});
			flash("Session revoked.", true);
		} catch (err) {
			flash(err instanceof Error ? err.message : "Failed to revoke.", false);
		} finally {
			setRevoking(null);
		}
	}

	async function handleRevokeAll() {
		setRevokingAll(true);
		try {
			const count = await revokeAllOther({ authToken });
			flash(`${count} other session${count === 1 ? "" : "s"} revoked.`, true);
		} catch (err) {
			flash(
				err instanceof Error ? err.message : "Failed to revoke sessions.",
				false,
			);
		} finally {
			setRevokingAll(false);
		}
	}

	const otherSessions = sessions?.filter((s) => !s.isCurrent) ?? [];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Laptop size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Active Sessions</h1>
						<p className="page-subtitle">
							Manage devices and sessions with access to your account
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-6">
				{msg && (
					<div
						className={`text-xs px-3 py-2 rounded-lg border ${msg.ok ? "text-[var(--success)] border-[var(--success)]" : "text-[var(--danger)] border-[var(--danger)]"}`}
					>
						{msg.text}
					</div>
				)}

				{sessions === undefined ? (
					<div className="space-y-3">
						{["a", "b"].map((k) => (
							<div key={k} className="loading-panel h-20 rounded-2xl" />
						))}
					</div>
				) : (
					<>
						<div className="card card-sm space-y-4">
							<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
								Sessions
							</h2>

							{sessions.length === 0 && (
								<p className="text-xs text-[var(--sea-ink-soft)]">
									No active sessions found.
								</p>
							)}

							<div className="space-y-2">
								{sessions.map((session) => (
									<div
										key={session._id}
										className={`flex items-center gap-3 rounded-xl p-3 border ${session.isCurrent ? "border-[var(--signal)] bg-[var(--signal-soft)]" : "border-[var(--line)] bg-[var(--surface)]"}`}
									>
										<div className="text-[var(--sea-ink-soft)]">
											{deviceIcon(
												session.deviceInfo.os,
												session.deviceInfo.userAgent,
											)}
										</div>

										<div className="flex-1 min-w-0">
											<div className="flex items-center gap-2">
												<span className="text-xs font-medium text-[var(--sea-ink)]">
													{session.deviceInfo.browser ?? "Unknown browser"}{" "}
													{session.deviceInfo.os
														? `on ${session.deviceInfo.os}`
														: ""}
												</span>
												{session.isCurrent && (
													<span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--signal)] text-white font-medium">
														Current
													</span>
												)}
											</div>
											<div className="flex items-center gap-3 mt-0.5">
												{session.ipAddress && (
													<span className="flex items-center gap-1 text-[11px] text-[var(--sea-ink-soft)]">
														<Globe size={10} />
														{session.ipAddress}
													</span>
												)}
												<span className="text-[11px] text-[var(--sea-ink-soft)]">
													Last seen {formatRelativeTime(session.lastSeenAt)}
												</span>
												<span className="text-[11px] text-[var(--sea-ink-soft)]">
													Created {formatRelativeTime(session.createdAt)}
												</span>
											</div>
										</div>

										{!session.isCurrent && (
											<button
												type="button"
												className="text-xs px-2.5 py-1 rounded-lg border border-[var(--danger)] text-[var(--danger)] hover:bg-red-50 transition-colors disabled:opacity-50"
												onClick={() => handleRevoke(session._id)}
												disabled={revoking === session._id}
											>
												{revoking === session._id ? (
													<Loader2 size={12} className="animate-spin" />
												) : (
													"Revoke"
												)}
											</button>
										)}
									</div>
								))}
							</div>
						</div>

						{otherSessions.length > 0 && (
							<div className="card card-sm">
								<h2 className="text-sm font-semibold text-[var(--sea-ink)] mb-2">
									Sign out everywhere else
								</h2>
								<p className="text-xs text-[var(--sea-ink-soft)] mb-4">
									Revoke all sessions except the current one. You'll remain
									signed in on this device.
								</p>
								<button
									type="button"
									className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-[var(--danger)] text-[var(--danger)] hover:bg-red-50 transition-colors disabled:opacity-50"
									onClick={handleRevokeAll}
									disabled={revokingAll}
								>
									{revokingAll ? (
										<Loader2 size={12} className="animate-spin" />
									) : (
										<LogOut size={12} />
									)}
									Sign out all other sessions ({otherSessions.length})
								</button>
							</div>
						)}
					</>
				)}
			</div>
		</main>
	);
}
