import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type GitIntegrity = NonNullable<
	FunctionReturnType<
		typeof api.gitIntegrityIntel.getLatestGitIntegrityScanBySlug
	>
>;

export default function GitIntegrityPanel({
	gitIntegrity,
}: {
	gitIntegrity: GitIntegrity;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Git Integrity</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={gitIntegrity.riskLevel}
					tone={
						gitIntegrity.riskLevel === "none" || gitIntegrity.riskLevel === "low"
							? "success"
							: gitIntegrity.riskLevel === "medium"
								? "warning"
								: "danger"
					}
				/>
				{gitIntegrity.criticalCount > 0 && (
					<StatusPill
						label={`${gitIntegrity.criticalCount} critical`}
						tone="danger"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{gitIntegrity.summary}
			</p>
		</div>
	);
}
