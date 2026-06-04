import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import {
	learningTrendTone,
	maturityTone,
	multiplierTone,
} from "../../lib/utils";

type LearningProfile = NonNullable<
	FunctionReturnType<typeof api.learningProfileIntel.getLatestLearningProfile>
>;

export default function LearningProfilePanel({
	profile,
}: {
	profile: LearningProfile;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Learning Profile</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`maturity ${profile.adaptedConfidenceScore}/100`}
					tone={maturityTone(profile.adaptedConfidenceScore)}
				/>
				<StatusPill
					label={profile.attackSurfaceTrend}
					tone={learningTrendTone(profile.attackSurfaceTrend)}
				/>
				{profile.recurringCount > 0 && (
					<StatusPill
						label={`${profile.recurringCount} recurring`}
						tone="warning"
					/>
				)}
				{profile.suppressedCount > 0 && (
					<StatusPill
						label={`${profile.suppressedCount} suppressed`}
						tone="neutral"
					/>
				)}
				{profile.successfulExploitPaths.length > 0 && (
					<StatusPill
						label={`${profile.successfulExploitPaths.length} exploit paths`}
						tone="danger"
					/>
				)}
			</div>
			{profile.vulnClassPatterns.slice(0, 3).map((p: LearningProfile["vulnClassPatterns"][number]) => (
				<div key={p.vulnClass} className="mt-1.5 flex flex-wrap gap-1.5">
					<StatusPill
						label={p.vulnClass.replaceAll("_", " ")}
						tone={multiplierTone(p.confidenceMultiplier)}
					/>
					<StatusPill
						label={`×${p.confidenceMultiplier} confidence`}
						tone={multiplierTone(p.confidenceMultiplier)}
					/>
				</div>
			))}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{profile.summary}
			</p>
		</div>
	);
}
