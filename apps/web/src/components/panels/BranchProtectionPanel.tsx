import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type BranchProtection = NonNullable<
	FunctionReturnType<
		typeof api.branchProtectionIntel.getLatestBranchProtectionBySlug
	>
>;

export default function BranchProtectionPanel({
	branchProtection }: {
	branchProtection: BranchProtection;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Branch Protection</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={branchProtection.riskLevel}
					tone={
						branchProtection.riskLevel === "critical" ||
						branchProtection.riskLevel === "high"
							? "danger"
							: branchProtection.riskLevel === "medium"
								? "warning"
								: "success"
					}
				/>
				{branchProtection.criticalCount > 0 && (
					<StatusPill
						label={`${branchProtection.criticalCount} critical`}
						tone="danger"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{branchProtection.summary}
			</p>
		</div>
	);
}
