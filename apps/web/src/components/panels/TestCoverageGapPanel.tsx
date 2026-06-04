import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type TestCoverage = NonNullable<
	FunctionReturnType<
		typeof api.testCoverageGapIntel.getLatestTestCoverageGapBySlug
	>
>;

export default function TestCoverageGapPanel({
	testCoverage,
}: {
	testCoverage: TestCoverage;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Test Coverage Gaps</p>
			<div className="flex flex-wrap gap-1.5">
				{testCoverage.totalFindings > 0 && (
					<StatusPill
						label={`${testCoverage.totalFindings} gaps`}
						tone="danger"
					/>
				)}
				{testCoverage.highCount > 0 && (
					<StatusPill
						label={`${testCoverage.highCount} high`}
						tone="warning"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{testCoverage.summary}
			</p>
		</div>
	);
}
