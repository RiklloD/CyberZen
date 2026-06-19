import type { FunctionReturnType } from "convex/server";
import { GitCompare } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import CrossRepoFindingDetail from "./CrossRepoFindingDetail";

type SummaryData = NonNullable<
	FunctionReturnType<typeof api.crossRepoIntel.getTenantCrossRepoSummaryBySlug>
>;
type CrossRepoEvent = SummaryData["events"][number];

function severityCellTone(severity: string) {
	if (severity === "critical") return "danger";
	if (severity === "high") return "warning";
	if (severity === "medium") return "info";
	return "neutral";
}

export default function TenantCrossRepoPanel({
	summary }: {
	summary: SummaryData;
}) {
	const [selectedEvent, setSelectedEvent] = useState<CrossRepoEvent | null>(
		null,
	);

	const { events, totalPackagesTracked, totalAffectedRepoSlots, packagesWithSpread } =
		summary;

	// Build the repo-x-package heat-map matrix
	const uniqueRepos: string[] = Array.from(
		new Set(events.flatMap((e: CrossRepoEvent) => e.affectedRepositoryNames as string[])),
	);

	// For the matrix: map packageName → set of affected repo names
	const packageRepoMap = new Map<string, Set<string>>();
	for (const event of events) {
		const key = event.packageName;
		const set = packageRepoMap.get(key) ?? new Set<string>();
		for (const name of event.affectedRepositoryNames) {
			set.add(name);
		}
		packageRepoMap.set(key, set);
	}

	return (
		<div className="space-y-4">
			{/* KPI row */}
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<GitCompare size={14} />
						<span className="panel-label">Packages Tracked</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{totalPackagesTracked}
					</div>
				</div>
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<span className="panel-label">Packages with Spread</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{packagesWithSpread}
					</div>
					{packagesWithSpread > 0 && (
						<StatusPill label="cross-repo exposure" tone="danger" />
					)}
				</div>
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<span className="panel-label">Affected Repo Slots</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{totalAffectedRepoSlots}
					</div>
				</div>
				<div className="card card-sm">
					<div className="flex items-center gap-2 text-[var(--sea-ink-soft)] mb-2">
						<span className="panel-label">Unique Repos Exposed</span>
					</div>
					<div className="text-2xl font-bold text-[var(--sea-ink)]">
						{uniqueRepos.length}
					</div>
				</div>
			</div>

			{/* Heat-map matrix */}
			{events.length > 0 && (
				<div>
					<h3 className="section-title mb-3">
						Repo × Package Exposure Matrix
					</h3>
					<div className="card overflow-x-auto">
						<table className="data-table">
							<thead>
								<tr>
									<th>Package</th>
									<th>Severity</th>
									<th>Ecosystem</th>
									<th>Repos Affected</th>
									<th>Spread</th>
									<th>Computed</th>
									<th></th>
								</tr>
							</thead>
							<tbody>
								{events.map((event: CrossRepoEvent) => (
									<tr key={event._id}>
										<td className="font-medium text-[var(--sea-ink)]">
											{event.packageName}
										</td>
										<td>
											<StatusPill
												label={event.severity}
												tone={severityCellTone(event.severity)}
											/>
										</td>
										<td className="text-xs text-[var(--sea-ink-soft)]">
											{event.ecosystem}
										</td>
										<td>
											<StatusPill
												label={`${event.affectedRepositoryCount}/${event.totalRepositories}`}
												tone={
													event.affectedRepositoryCount > 0
														? "danger"
														: "success"
												}
											/>
										</td>
										<td className="text-xs text-[var(--sea-ink-soft)]">
											{event.affectedRepositoryNames.slice(0, 3).join(", ")}
											{event.affectedRepositoryNames.length > 3 &&
												` +${event.affectedRepositoryNames.length - 3} more`}
										</td>
										<td className="text-xs text-[var(--sea-ink-soft)]">
											{formatTimestamp(event.computedAt)}
										</td>
										<td>
											<button
												type="button"
												className="text-xs text-[var(--signal)] hover:underline"
												onClick={() =>
													setSelectedEvent(
														selectedEvent?._id === event._id
															? null
															: event,
													)
												}
											>
												{selectedEvent?._id === event._id
													? "Hide"
													: "Details"}
											</button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			)}

			{/* Visual matrix grid (repos x packages) */}
			{uniqueRepos.length > 0 && events.length > 0 && (
				<div>
					<h3 className="section-title mb-3">Exposure Heat Map</h3>
					<div className="card overflow-x-auto">
						<table className="data-table">
							<thead>
								<tr>
									<th>Repository</th>
									{events.slice(0, 8).map((e: CrossRepoEvent) => (
										<th
											key={e._id}
											className="text-[0.6rem] whitespace-nowrap"
											title={e.packageName}
										>
											{e.packageName.length > 12
												? `${e.packageName.slice(0, 12)}…`
												: e.packageName}
										</th>
									))}
								</tr>
							</thead>
							<tbody>
								{uniqueRepos.map((repoName) => (
									<tr key={repoName}>
										<td className="font-medium text-[var(--sea-ink)] whitespace-nowrap">
											{repoName}
										</td>
										{events.slice(0, 8).map((e: CrossRepoEvent) => {
											const isAffected =
												e.affectedRepositoryNames.includes(repoName);
											const impact = e.impacts?.find(
												(i: NonNullable<CrossRepoEvent["impacts"]>[number]) => i.repositoryName === repoName,
											);
											return (
												<td
													key={`${repoName}-${e._id}`}
													className="text-center"
													title={
														isAffected
															? `${repoName} uses ${e.packageName} (direct: ${impact?.directMatchCount ?? 0}, transitive: ${impact?.transitiveMatchCount ?? 0})`
															: `${repoName} not affected by ${e.packageName}`
													}
												>
													<span
														className={`inline-block w-6 h-6 rounded ${
															isAffected
																? e.severity === "critical"
																	? "bg-[var(--danger)]"
																	: e.severity === "high"
																		? "bg-[var(--warning)]"
																		: "bg-[rgba(30,157,154,0.5)]"
																: "bg-[rgba(130,122,110,0.1)]"
														}`}
													/>
												</td>
											);
										})}
									</tr>
								))}
							</tbody>
						</table>
					</div>
					{events.length > 8 && (
						<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
							Showing first 8 of {events.length} packages in heat map.
						</p>
					)}
				</div>
			)}

			{/* Drill-down detail */}
			{selectedEvent && (
				<CrossRepoFindingDetail event={selectedEvent} />
			)}

			{/* Empty state */}
			{events.length === 0 && (
				<div className="card text-center py-8">
					<GitCompare size={24} className="mx-auto mb-2 opacity-40" />
					<p className="text-[var(--sea-ink-soft)]">
						No cross-repo impact events detected yet. Events appear
						automatically when vulnerable packages are found across multiple
						repositories.
					</p>
				</div>
			)}
		</div>
	);
}
