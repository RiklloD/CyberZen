import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { repositoryHealthTone } from "../../lib/utils";

type HealthScore = NonNullable<
	FunctionReturnType<
		typeof api.repositoryHealthIntel.getLatestRepositoryHealthScore
	>
>;

export default function RepositoryHealthScorePanel({
	healthScore,
}: {
	healthScore: HealthScore;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label">Repository Health</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`score ${healthScore.overallScore}`}
					tone={repositoryHealthTone(healthScore.overallScore)}
				/>
				<StatusPill
					label={`grade ${healthScore.overallGrade}`}
					tone={repositoryHealthTone(healthScore.overallScore)}
				/>
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{healthScore.summary}
			</p>
		</div>
	);
}
