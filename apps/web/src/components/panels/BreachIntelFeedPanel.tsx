import type { FunctionReturnType } from "convex/server";
import { useMutation } from "convex/react";
import { RefreshCw, Shield } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { disclosureTone, formatTimestamp } from "../../lib/utils";

type EscalationsData = NonNullable<
	FunctionReturnType<typeof api.dashboard.escalations>
>;
type OverviewDisclosure = EscalationsData["disclosures"][number];

export default function BreachIntelFeedPanel({
	disclosures,
	tenantSlug }: {
	disclosures: OverviewDisclosure[];
	tenantSlug: string;
}) {
	const [syncing, setSyncing] = useState(false);
	const [lastSyncResult, setLastSyncResult] = useState<string | null>(null);

	const runSync = useMutation(api.advisorySync.runManualSync);

	async function handleSync() {
		setSyncing(true);
		setLastSyncResult(null);
		try {
			await runSync({ tenantSlug });
			setLastSyncResult("Sync scheduled — new advisories will appear within a minute.");
		} catch (err) {
			setLastSyncResult(`Sync failed: ${err instanceof Error ? err.message : "Unknown error"}`);
		} finally {
			setSyncing(false);
		}
	}

	return (
		<div>
			<div className="section-header">
				<h2 className="section-title">Disclosure Watchlist</h2>
				<StatusPill
					label={`${disclosures.length} disclosures`}
					tone="neutral"
				/>
				<button
					type="button"
					onClick={handleSync}
					disabled={syncing}
					className="signal-button ml-auto"
					style={{ padding: "0.4rem 0.75rem", fontSize: "0.75rem" }}
				>
					<RefreshCw
						size={13}
						className={`mr-1 ${syncing ? "animate-spin" : ""}`}
					/>
					{syncing ? "Syncing…" : "Sync Now"}
				</button>
			</div>
			{lastSyncResult && (
				<p className="mb-2 text-xs text-[var(--sea-ink-soft)]">{lastSyncResult}</p>
			)}
			<div className="space-y-3">
				{disclosures.map((d: OverviewDisclosure) => (
					<div key={d._id} className="card card-sm">
						<div className="flex flex-wrap items-center gap-2">
							<StatusPill
								label={d.matchStatus}
								tone={disclosureTone(d.matchStatus)}
							/>
							<StatusPill
								label={d.severity}
								tone={
									d.severity === "critical"
										? "danger"
										: d.severity === "high"
											? "warning"
											: d.severity === "medium"
												? "info"
												: "neutral"
								}
							/>
							{d.exploitAvailable && (
								<StatusPill label="exploit available" tone="danger" />
							)}
						</div>
						<h3 className="mt-2 text-sm font-semibold text-[var(--sea-ink)]">
							{d.packageName}
						</h3>
						<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
							{d.sourceName}
							{d.repositoryName ? ` / ${d.repositoryName}` : ""} ·{" "}
							{d.sourceRef} · {formatTimestamp(d.publishedAt)}
						</p>
						<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
							{d.matchSummary}
						</p>
						{d.affectedVersions.length > 0 && (
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
								Affected: {d.affectedVersions.join(" ; ")}
							</p>
						)}
						{d.fixVersion && (
							<p className="mt-0.5 text-xs text-[var(--success)]">
								Fixed in: {d.fixVersion}
							</p>
						)}
					</div>
				))}
				{disclosures.length === 0 && (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Shield size={24} className="mb-2 opacity-40" />
						<p>No disclosures found for your current SBOM inventory.</p>
					</div>
				)}
			</div>
		</div>
	);
}
