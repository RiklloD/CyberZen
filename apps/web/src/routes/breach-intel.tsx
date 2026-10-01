import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { useMemo, useState } from "react";
import StatusPill from "../components/StatusPill";
import { PanelSkeleton } from "../components/panels/SharedPanelComponents";
import BreachIntelFeedPanel from "../components/panels/BreachIntelFeedPanel";
import EpssThreatIntelPanel from "../components/panels/EpssThreatIntelPanel";
import Tier3SignalsPanel from "../components/panels/Tier3SignalsPanel";
import { api } from "../lib/convex";
import { syncTone } from "../lib/utils";
import { absoluteTime, humanize, relativeTime } from "../lib/format";
import PageHeader from "../components/ui/PageHeader";
import Section from "../components/ui/Section";
import EmptyState from "../components/ui/EmptyState";
import { useTenantSlug } from "../lib/workspace";
import QueryErrorFallback from "../components/QueryErrorFallback";

export const Route = createFileRoute("/breach-intel")({
	errorComponent: QueryErrorFallback,
	component: BreachIntelPage });

type EscalationsData = NonNullable<
	FunctionReturnType<typeof api.dashboard.escalations>
>;
type OverviewAdvisoryRun =
	EscalationsData["advisoryAggregator"]["recentRuns"][number];
type OverviewAdvisorySource =
	EscalationsData["advisoryAggregator"]["sourceCoverage"][number];

function BreachIntelPage() {
	const TENANT = useTenantSlug();
	const escalations = useQuery(api.dashboard.escalations, { tenantSlug: TENANT });
	const epss = useQuery(api.epssIntel.getLatestEpssSnapshot);
	const tier3 = useQuery(api.tier3Intel.getRecentTier3Signals, { limit: 10 });

	const [selectedRepo, setSelectedRepo] = useState<string>("all");

	// Extract unique repo names from disclosures for the filter dropdown
	const repoNames = useMemo(() => {
		if (!escalations) return [];
		const names = new Set<string>();
		for (const d of escalations.disclosures) {
			if (d.repositoryName) names.add(d.repositoryName);
		}
		return Array.from(names).sort();
	}, [escalations]);

	if (!escalations) {
		return (
			<main className="page-body-padded">
				<PanelSkeleton count={3} />
			</main>
		);
	}

	const { advisoryAggregator } = escalations;

	// Filter disclosures by selected repository
	const filteredDisclosures =
		selectedRepo === "all"
			? escalations.disclosures
			: escalations.disclosures.filter(
					(d) => d.repositoryName === selectedRepo,
				);

	// Filter advisory sync runs by selected repository
	const filteredRuns =
		selectedRepo === "all"
			? advisoryAggregator.recentRuns
			: advisoryAggregator.recentRuns.filter(
					(run: OverviewAdvisoryRun) => run.repositoryName === selectedRepo,
				);

	return (
		<main>
			<PageHeader
				title="Breach intel"
				description={
					<>
						Advisories from GitHub, OSV and threat feeds, matched against your live SBOM ·{" "}
						{advisoryAggregator.recentMatchedDisclosures} matched
					</>
				}
				actions={
					repoNames.length > 0 && (
						<select
							aria-label="Repository"
							value={selectedRepo}
							onChange={(e) => setSelectedRepo(e.target.value)}
							className="input !w-auto"
						>
							<option value="all">All repositories</option>
							{repoNames.map((name) => (
								<option key={name} value={name}>
									{name}
								</option>
							))}
						</select>
					)
				}
			/>

			<div className="page-body">
				<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
					{/* Left: Disclosures */}
					<BreachIntelFeedPanel disclosures={filteredDisclosures} tenantSlug={TENANT} />

					{/* Right: Advisory aggregator + sources + threat intel */}
					<div className="space-y-4">
						{/* Advisory sync history */}
						<Section
							title="Advisory sync"
							description={
								advisoryAggregator.lastCompletedAt
									? `Last successful sync ${relativeTime(advisoryAggregator.lastCompletedAt)}`
									: "No successful sync yet"
							}
						>
							{filteredRuns.length === 0 ? (
								<div className="list">
									<EmptyState title="No sync runs yet" description="Advisory syncs run on a schedule and after every SBOM import." />
								</div>
							) : (
								<div className="list">
									{filteredRuns.map((run: OverviewAdvisoryRun) => (
										<SyncRunRow key={run._id} run={run} />
									))}
								</div>
							)}
						</Section>

						{/* Source coverage */}
						{advisoryAggregator.sourceCoverage.length > 0 && (
							<div>
								<h2 className="section-title mb-3">Source coverage</h2>
								<div className="list">
									<table className="data-table">
										<thead>
											<tr>
												<th>Source</th>
												<th>Tier</th>
												<th>Disclosures</th>
												<th>Matched</th>
											</tr>
										</thead>
										<tbody>
											{advisoryAggregator.sourceCoverage.map(
												(s: OverviewAdvisorySource) => (
													<tr key={s.sourceName}>
														<td className="font-medium">{s.sourceName}</td>
														<td>
															<StatusPill label={s.sourceTier} tone="info" />
														</td>
														<td>{s.disclosureCount}</td>
														<td>
															<StatusPill
																label={`${s.matchedCount}`}
																tone={
																	s.matchedCount > 0 ? "warning" : "neutral"
																}
															/>
														</td>
													</tr>
												),
											)}
										</tbody>
									</table>
								</div>
							</div>
						)}

						{/* EPSS Threat Intel */}
						{epss && <EpssThreatIntelPanel epss={epss} />}

						{/* Tier-3 Intel */}
						{tier3 && tier3.length > 0 && (
							<Tier3SignalsPanel signals={tier3} />
						)}
					</div>
				</div>
			</div>
		</main>
	);
}

function SyncRunRow({ run }: { run: OverviewAdvisoryRun }) {
	const [expanded, setExpanded] = useState(false);
	const failed = run.status === "failed";
	const tone = syncTone(run.status);
	return (
		<div className="list-row !items-start">
			<span
				className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
				style={{ background: `var(--${tone === "neutral" ? "text-3" : tone})` }}
			/>
			<div className="min-w-0 flex-1">
				<div className="flex items-center gap-2 text-[0.82rem]">
					<span className="font-medium">{run.repositoryName}</span>
					<span className="text-[var(--text-3)]">· {humanize(run.triggerType)}</span>
					<span className="ml-auto shrink-0 text-xs text-[var(--text-3)]" title={absoluteTime(run.startedAt)}>
						{relativeTime(run.startedAt)}
					</span>
				</div>
				<p className="text-xs text-[var(--text-3)]">
					{failed ? (
						<span className="text-[var(--danger)]">Sync failed</span>
					) : (
						<>
							{run.packageCount} packages · GitHub {run.githubImported}/{run.githubFetched} · OSV{" "}
							{run.osvImported}/{run.osvFetched}
						</>
					)}
					{run.reason && (
						<button
							type="button"
							className="ml-2 text-[var(--text-2)] underline-offset-2 hover:underline"
							onClick={() => setExpanded((v) => !v)}
						>
							{expanded ? "Hide details" : "Details"}
						</button>
					)}
				</p>
				{expanded && run.reason && (
					<pre className="mt-1.5 whitespace-pre-wrap break-words rounded-[var(--radius-sm)] bg-[var(--surface-2)] p-2 font-mono text-[0.7rem] text-[var(--text-2)]">
						{run.reason}
					</pre>
				)}
			</div>
		</div>
	);
}
