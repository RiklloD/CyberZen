import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Shield } from "lucide-react";
import { api } from "../../convex/_generated/api";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import { disclosureTone, formatTimestamp, syncTone } from "../lib/utils";

export const Route = createFileRoute("/breach-intel")({ component: BreachIntelPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewDisclosure = OverviewData["disclosures"][number];
type OverviewAdvisoryRun = OverviewData["advisoryAggregator"]["recentRuns"][number];
type OverviewAdvisorySource = OverviewData["advisoryAggregator"]["sourceCoverage"][number];

const TENANT = TENANT_SLUG;

function BreachIntelPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const epss = useQuery(api.epssIntel.getLatestEpssSnapshot);
	const tier3 = useQuery(api.tier3Intel.getRecentTier3Signals, { limit: 10 });

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
					{["a", "b", "c"].map((k) => (
						<div key={k} className="loading-panel h-32 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { disclosures, advisoryAggregator } = overview;

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
					<div>
						<div className="section-header">
							<h2 className="section-title">Disclosure Watchlist</h2>
							<StatusPill label={`${disclosures.length} disclosures`} tone="neutral" />
						</div>
						<div className="space-y-3">
							{disclosures.map((d: OverviewDisclosure) => (
								<div key={d._id} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={d.matchStatus}
											tone={disclosureTone(d.matchStatus)}
										/>
										<StatusPill label={d.severity} tone={
											d.severity === "critical" ? "danger" :
											d.severity === "high" ? "warning" :
											d.severity === "medium" ? "info" : "neutral"
										} />
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
										tone={advisoryAggregator.recentMatchedDisclosures > 0 ? "warning" : "success"}
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
								{advisoryAggregator.recentRuns.map((run: OverviewAdvisoryRun) => (
									<div key={run._id} className="card card-sm">
										<div className="flex flex-wrap items-center gap-2">
											<StatusPill label={run.status} tone={syncTone(run.status)} />
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
											<span>GitHub: {run.githubImported}/{run.githubFetched}</span>
											<span>OSV: {run.osvImported}/{run.osvFetched}</span>
										</div>
										{run.reason && (
											<p className="mt-0.5 text-xs text-[var(--warning)]">{run.reason}</p>
										)}
									</div>
								))}
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
																tone={s.matchedCount > 0 ? "warning" : "neutral"}
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
						{epss && (
							<div>
								<h2 className="section-title mb-3">EPSS Threat Intel</h2>
								<div className="card card-sm">
									<div className="flex flex-wrap gap-2 mb-2">
										<StatusPill
											label={`${epss.enrichedCount} tracked CVEs`}
											tone="neutral"
										/>
										{epss.criticalRiskCount > 0 && (
											<StatusPill
												label={`${epss.criticalRiskCount} critical EPSS`}
												tone="danger"
											/>
										)}
										{epss.highRiskCount > 0 && (
											<StatusPill
												label={`${epss.highRiskCount} high EPSS`}
												tone="warning"
											/>
										)}
									</div>
									<p className="text-xs text-[var(--sea-ink-soft)]">{epss.summary}</p>
									{epss.topCves?.slice(0, 5).map((cve: { cveId: string; epssScore: number; packageName?: string }) => (
										<div key={cve.cveId} className="mt-2 flex flex-wrap items-center gap-2">
											<StatusPill
												label={cve.cveId}
												tone={cve.epssScore > 0.5 ? "danger" : cve.epssScore > 0.2 ? "warning" : "neutral"}
											/>
											<StatusPill
												label={`EPSS ${(cve.epssScore * 100).toFixed(1)}%`}
												tone="neutral"
											/>
											{cve.packageName && <StatusPill label={cve.packageName} tone="info" />}
										</div>
									))}
								</div>
							</div>
						)}

						{/* Tier-3 Intel */}
						{tier3 && tier3.length > 0 && (
							<div>
								<h2 className="section-title mb-3">Tier-3 Intel ({tier3.length} signals)</h2>
								<div className="space-y-2">
									{tier3.map((signal) => (
										<div key={signal._id} className="card card-sm">
											<div className="flex flex-wrap gap-1.5 mb-1">
												<StatusPill
													label={signal.threatLevel}
													tone={signal.threatLevel === "critical" || signal.threatLevel === "high" ? "danger" : signal.threatLevel === "medium" ? "warning" : "neutral"}
												/>
												<StatusPill label={signal.source} tone="info" />
												{signal.hasExploitKeywords && <StatusPill label="exploit" tone="danger" />}
												{signal.hasRansomwareKeywords && <StatusPill label="ransomware" tone="danger" />}
											</div>
											<p className="text-xs text-[var(--sea-ink-soft)] line-clamp-2">{signal.text}</p>
										</div>
									))}
								</div>
							</div>
						)}
					</div>
				</div>
			</div>
		</main>
	);
}
