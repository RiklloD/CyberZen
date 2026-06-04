import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type CommitMsg = NonNullable<
	FunctionReturnType<
		typeof api.commitMessageIntel.getLatestCommitMessageScanBySlug
	>
>;

export default function CommitMessagePanel({ commitMsg }: { commitMsg: CommitMsg }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Commit Messages</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={commitMsg.riskLevel}
					tone={
						commitMsg.riskLevel === "none" || commitMsg.riskLevel === "low"
							? "success"
							: commitMsg.riskLevel === "medium"
								? "warning"
								: "danger"
					}
				/>
				{commitMsg.totalFindings > 0 && (
					<StatusPill
						label={`${commitMsg.totalFindings} findings`}
						tone="neutral"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{commitMsg.summary}
			</p>
		</div>
	);
}
