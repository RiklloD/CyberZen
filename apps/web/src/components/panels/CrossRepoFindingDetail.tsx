import { GitBranch, Link2 } from "lucide-react";
import StatusPill from "../StatusPill";
import { formatTimestamp } from "../../lib/utils";

type Impact = {
	repositoryId: string;
	repositoryName: string;
	directMatchCount: number;
	transitiveMatchCount: number;
	matchedVersions: string[];
};

type CrossRepoEvent = {
	_id: string;
	packageName: string;
	normalizedPackageName: string;
	ecosystem: string;
	severity: string;
	totalRepositories: number;
	affectedRepositoryCount: number;
	affectedRepositoryNames: string[];
	impacts: Impact[];
	summary: string;
	computedAt: number;
};

function severityCellTone(severity: string) {
	if (severity === "critical") return "danger";
	if (severity === "high") return "warning";
	if (severity === "medium") return "info";
	return "neutral";
}

export default function CrossRepoFindingDetail({
	event,
}: {
	event: CrossRepoEvent;
}) {
	const {
		packageName,
		ecosystem,
		severity,
		totalRepositories,
		affectedRepositoryCount,
		affectedRepositoryNames,
		impacts,
		summary,
		computedAt,
	} = event;

	return (
		<div className="card">
			<div className="flex items-center gap-3 mb-4">
				<Link2 size={16} className="text-[var(--signal)]" />
				<h3 className="section-title mb-0">
					Cross-Repo Detail: {packageName}
				</h3>
			</div>

			{/* Summary pills */}
			<div className="flex flex-wrap gap-2 mb-3">
				<StatusPill label={severity} tone={severityCellTone(severity)} />
				<StatusPill label={ecosystem} tone="info" />
				<StatusPill
					label={`${affectedRepositoryCount} of ${totalRepositories} repos affected`}
					tone={affectedRepositoryCount > 0 ? "danger" : "success"}
				/>
				<StatusPill
					label={`Computed: ${formatTimestamp(computedAt)}`}
					tone="neutral"
				/>
			</div>

			<p className="text-sm text-[var(--sea-ink-soft)] mb-4">{summary}</p>

			{/* Per-repo impact breakdown */}
			{impacts && impacts.length > 0 && (
				<div>
					<h4 className="text-xs font-semibold text-[var(--sea-ink)] uppercase tracking-wider mb-2">
						Dependency Chain by Repository
					</h4>
					<table className="data-table">
						<thead>
							<tr>
								<th>Repository</th>
								<th>Direct</th>
								<th>Transitive</th>
								<th>Versions</th>
								<th>Risk</th>
							</tr>
						</thead>
						<tbody>
							{impacts.map((impact) => {
								return (
									<tr key={impact.repositoryId}>
										<td className="font-medium text-[var(--sea-ink)]">
											<GitBranch
												size={12}
												className="inline -mt-0.5 mr-1 text-[var(--sea-ink-soft)]"
											/>
											{impact.repositoryName}
										</td>
										<td>
											<StatusPill
												label={`${impact.directMatchCount}`}
												tone={
													impact.directMatchCount > 0
														? "danger"
														: "neutral"
												}
											/>
										</td>
										<td>
											<StatusPill
												label={`${impact.transitiveMatchCount}`}
												tone={
													impact.transitiveMatchCount > 0
														? "warning"
														: "neutral"
												}
											/>
										</td>
										<td className="text-xs text-[var(--sea-ink-soft)]">
											{impact.matchedVersions.length > 0
												? impact.matchedVersions.join(", ")
												: "—"}
										</td>
										<td>
											<StatusPill
												label={
													impact.directMatchCount > 0
														? "direct exposure"
														: impact.transitiveMatchCount > 0
															? "transitive only"
															: "clean"
												}
												tone={
													impact.directMatchCount > 0
														? "danger"
														: impact.transitiveMatchCount > 0
															? "warning"
															: "success"
												}
											/>
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}

			{/* Affected repos list */}
			{affectedRepositoryNames.length > 0 && (
				<div className="mt-3">
					<p className="text-xs text-[var(--sea-ink-soft)]">
						<span className="font-semibold">Lateral exposure path:</span>{" "}
						{affectedRepositoryNames.join(" → ")}
					</p>
				</div>
			)}
		</div>
	);
}
