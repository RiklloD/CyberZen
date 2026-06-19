import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type TrustScore = NonNullable<
	FunctionReturnType<
		typeof api.trustScoreIntel.getRepositoryTrustScoreSummary
	>
>;

export default function RepositoryTrustScorePanel({
	score }: {
	score: TrustScore;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label">Trust Score</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`score ${score.repositoryScore}`}
					tone={
						score.repositoryScore >= 70
							? "success"
							: score.repositoryScore >= 40
								? "warning"
								: "danger"
					}
				/>
				{score.untrustedCount > 0 && (
					<StatusPill
						label={`${score.untrustedCount} untrusted`}
						tone="danger"
					/>
				)}
				{score.vulnerableCount > 0 && (
					<StatusPill
						label={`${score.vulnerableCount} vulnerable`}
						tone="warning"
					/>
				)}
			</div>
		</div>
	);
}
