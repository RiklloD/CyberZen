import { createFileRoute } from "@tanstack/react-router";
import { Bell } from "lucide-react";
import { useMutation, useQuery } from "convex/react";
import { useAuthToken } from "../../lib/clerk-compat";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/notifications")({
	errorComponent: RouteErrorBoundary,
	component: NotificationSettingsPage,
});

const EVENT_TYPES = [
	{ type: "finding_critical", label: "Critical Findings" },
	{ type: "finding_high", label: "High Findings" },
	{ type: "gate_blocked", label: "Gate Blocked" },
	{ type: "gate_overridden", label: "Gate Overridden" },
	{ type: "exploit_validated", label: "Exploit Validated" },
	{ type: "pr_generated", label: "PR Generated" },
	{ type: "scan_completed", label: "Scan Completed" },
	{ type: "sla_breach", label: "SLA Breach" },
	{ type: "remediation_dispatched", label: "Remediation Dispatched" },
	{ type: "member_invited", label: "Member Invited" },
	{ type: "system", label: "System" },
] as const;

const CHANNELS = [
	{ channel: "in_app" as const, label: "In-App" },
	{ channel: "email" as const, label: "Email" },
	{ channel: "slack" as const, label: "Slack" },
] as const;

function NotificationSettingsPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken();

	const preferences = useQuery(api.notifications.getPreferences, {
		tenantSlug: TENANT,
	});

	const upsertPreference = useMutation(api.notifications.upsertPreference);

	function isEnabled(channel: string, type: string): boolean {
		const pref = preferences?.find(
			(p: { channel: string; type: string; enabled: boolean }) => p.channel === channel && p.type === type,
		);
		return pref?.enabled ?? true; // default to enabled
	}

	function toggle(channel: string, type: string) {
		const current = isEnabled(channel, type);
		upsertPreference({
			tenantSlug: TENANT,
			channel: channel as "in_app" | "email" | "slack",
			type,
			enabled: !current,
		});
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Bell size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Notification Preferences</h1>
						<p className="page-subtitle">
							Choose which events trigger notifications and through which channels
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="panel">
					{preferences === undefined && (
						<div className="p-6 text-sm text-[var(--sea-ink-soft)]">
							Loading preferences...
						</div>
					)}

					{preferences !== undefined && (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b border-[var(--line)]">
										<th className="px-4 py-3 text-left font-semibold text-[var(--sea-ink-soft)]">
											Event Type
										</th>
										{CHANNELS.map((ch) => (
											<th
												key={ch.channel}
												className="px-4 py-3 text-center font-semibold text-[var(--sea-ink-soft)]"
											>
												{ch.label}
											</th>
										))}
									</tr>
								</thead>
								<tbody>
									{EVENT_TYPES.map((evt) => (
										<tr
											key={evt.type}
											className="border-b border-[var(--line)]"
										>
											<td className="px-4 py-3 text-[var(--sea-ink)]">
												{evt.label}
											</td>
											{CHANNELS.map((ch) => (
												<td
													key={ch.channel}
													className="px-4 py-3 text-center"
												>
													<label className="inline-flex cursor-pointer items-center">
														<input
															type="checkbox"
															checked={isEnabled(
																ch.channel,
																evt.type,
															)}
															onChange={() =>
																toggle(
																	ch.channel,
																	evt.type,
																)
															}
															className="h-4 w-4 rounded border-[var(--line)] accent-[var(--signal)]"
														/>
													</label>
												</td>
											))}
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
			</div>
		</main>
	);
}
