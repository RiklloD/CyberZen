import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Shield } from "lucide-react";
import StatusPill from "../components/StatusPill";
import { PanelSkeleton } from "../components/panels/SharedPanelComponents";
import BreachIntelFeedPanel from "../components/panels/BreachIntelFeedPanel";
import EpssThreatIntelPanel from "../components/panels/EpssThreatIntelPanel";
import Tier3SignalsPanel from "../components/panels/Tier3SignalsPanel";
import { api } from "../lib/convex";
import { formatTimestamp, syncTone } from "../lib/utils";
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

	if (!escalations) {
		return (
			<main className="page-body-padded">
				<PanelSkeleton count={3} />
			</main>
		);
	}

	const { disclosures, advisoryAggregator } = escalations;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Shield size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Breach Intel</h1>
						<p className="page-subtitle">
							{advisoryAggregator.recentImportedDisclosures} recent imports ·{" "}
							{advisoryAggregator.recentMatchedDisclosures} matched disclosures
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
					{/* Left: Disclosures */}
					<BreachIntelFeedPanel disclosures={disclosures} tenantSlug={TENANT} />

					{/* Right: Advisory aggregator + sources + threat intel */}
					<div className="space-y-4">
						{/* Advisory Aggregator */}
						<div>
							<div className="section-header mb-3">
								<h2 className="section-title">Advisory Aggregator</h2>
							</div>
							<div className="card card-sm mb-3">
								<div className="flex flex-wrap gap-2">
									<StatusPill
										label={`${advisoryAggregator.recentImportedDisclosures} imported`}
										tone="neutral"
									/>
									<StatusPill
										label={`${advisoryAggregator.recentMatchedDisclosures} matched`}
										tone={
											advisoryAggregator.recentMatchedDisclosures > 0
												? "warning"
												: "success"
										}
									/>
									{advisoryAggregator.lastCompletedAt && (
										<StatusPill
											label={`Last sync: ${formatTimestamp(advisoryAggregator.lastCompletedAt)}`}
											tone="neutral"
										/>
									)}
								</div>
							</div>

							<div className="space-y-2">
								{advisoryAggregator.recentRuns.map(
									(run: OverviewAdvisoryRun) => (
										<div key={run._id} className="card card-sm">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={run.status}
													tone={syncTone(run.status)}
												/>
												<StatusPill label={run.triggerType} tone="info" />
												<StatusPill
													label={`${run.packageCount} packages`}
													tone="neutral"
												/>
											</div>
											<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
												{run.repositoryName} · {formatTimestamp(run.startedAt)}
											</p>
											<div className="mt-1 flex flex-wrap gap-2 text-xs text-[var(--sea-ink-soft)]">
												<span>
													GitHub: {run.githubImported}/{run.githubFetched}
												</span>
												<span>
													OSV: {run.osvImported}/{run.osvFetched}
												</span>
											</div>
											{run.reason && (
												<p className="mt-0.5 text-xs text-[var(--warning)]">
													{run.reason}
												</p>
											)}
										</div>
									),
								)}
							</div>
						</div>

						{/* Source coverage */}
						{advisoryAggregator.sourceCoverage.length > 0 && (
							<div>
								<h2 className="section-title mb-3">Source Coverage</h2>
								<div className="card">
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
