import type { FunctionReturnType } from "convex/server";
import { ArrowDown, ArrowUp, Trophy } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type Report = NonNullable<
	FunctionReturnType<typeof api.executiveReportIntel.getExecutiveReport>
>;
type RepoSummary = Report["worstRepos"][number];

function gradeTone(
	grade: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (grade === "A" || grade === "B") return "success";
	if (grade === "C") return "warning";
	if (grade === "D") return "warning";
	return "danger";
}

function riskTone(
	risk: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (risk === "critical") return "danger";
	if (risk === "high") return "warning";
	if (risk === "medium") return "info";
	if (risk === "low") return "success";
	return "success";
}

function LeaderboardTable({
	repos,
	emptyLabel,
}: {
	repos: RepoSummary[];
	emptyLabel: string;
}) {
	if (repos.length === 0) {
		return (
			<p className="text-xs text-[var(--sea-ink-soft)] italic py-3">
				{emptyLabel}
			</p>
		);
	}
	return (
		<table className="data-table">
			<thead>
				<tr>
					<th>#</th>
					<th>Repository</th>
					<th>Score</th>
					<th>Grade</th>
					<th>Risk</th>
					<th>Top Risk</th>
				</tr>
			</thead>
			<tbody>
				{repos.map((r, i) => (
					<tr key={r.repositoryFullName}>
						<td className="text-[var(--sea-ink-soft)] font-medium">
							{i + 1}
						</td>
						<td className="font-mono text-xs">{r.repositoryFullName}</td>
						<td>
							<StatusPill
								label={`${r.compositeScore}/100`}
								tone={
									r.compositeScore >= 80
										? "success"
										: r.compositeScore >= 60
											? "warning"
											: "danger"
								}
							/>
						</td>
						<td>
							<StatusPill label={r.grade} tone={gradeTone(r.grade)} />
						</td>
						<td>
							<StatusPill
								label={r.riskLevel.toUpperCase()}
								tone={riskTone(r.riskLevel)}
							/>
						</td>
						<td className="text-xs text-[var(--sea-ink-soft)] max-w-[280px] truncate">
							{r.topRisk}
						</td>
					</tr>
				))}
			</tbody>
		</table>
	);
}

export default function ExecutiveRepoLeaderboard({
	worstRepos,
	bestRepos,
}: {
	worstRepos: RepoSummary[];
	bestRepos: RepoSummary[];
}) {
	return (
		<div className="grid gap-4 xl:grid-cols-2">
			<div className="card">
				<div className="flex items-center gap-2 mb-3">
					<ArrowDown size={14} className="text-[var(--danger)]" />
					<h3 className="section-title">Worst Performers</h3>
					<StatusPill label={`${worstRepos.length}`} tone="danger" />
				</div>
				<LeaderboardTable
					repos={worstRepos}
					emptyLabel="No scored repositories yet."
				/>
			</div>

			<div className="card">
				<div className="flex items-center gap-2 mb-3">
					<Trophy size={14} className="text-[var(--success)]" />
					<ArrowUp size={14} className="text-[var(--success)]" />
					<h3 className="section-title">Best Performers</h3>
					<StatusPill label={`${bestRepos.length}`} tone="success" />
				</div>
				<LeaderboardTable
					repos={bestRepos}
					emptyLabel="No scored repositories yet."
				/>
			</div>
		</div>
	);
}
