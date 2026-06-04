import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type AdversarialSummary = NonNullable<
	FunctionReturnType<typeof api.redBlueIntel.adversarialSummaryForRepository>
>;

export default function RedBlueAdversarialPanel({
	adversarialSummary,
	redAgentFindingCount,
}: {
	adversarialSummary: AdversarialSummary;
	redAgentFindingCount: number | null | undefined;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Red/Blue Adversarial Rounds</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={`${adversarialSummary.totalRounds} rounds`}
					tone="neutral"
				/>
				{adversarialSummary.redWins > 0 && (
					<StatusPill
						label={`Red ${adversarialSummary.redWins}W`}
						tone="danger"
					/>
				)}
				{adversarialSummary.blueWins > 0 && (
					<StatusPill
						label={`Blue ${adversarialSummary.blueWins}W`}
						tone="success"
					/>
				)}
				{adversarialSummary.draws > 0 && (
					<StatusPill
						label={`${adversarialSummary.draws} draws`}
						tone="neutral"
					/>
				)}
				{redAgentFindingCount != null && redAgentFindingCount > 0 && (
					<StatusPill
						label={`${redAgentFindingCount} escalated`}
						tone="warning"
					/>
				)}
			</div>
			<div className="mt-2 flex flex-wrap gap-1.5">
				<StatusPill
					label={`coverage ${adversarialSummary.avgAttackSurfaceCoverage}%`}
					tone={
						adversarialSummary.avgAttackSurfaceCoverage > 60
							? "warning"
							: "neutral"
					}
				/>
				<StatusPill
					label={`detection ${adversarialSummary.avgBlueDetectionScore}%`}
					tone={
						adversarialSummary.avgBlueDetectionScore > 70
							? "success"
							: "neutral"
					}
				/>
			</div>
			{adversarialSummary.latestRound && (
				<>
					<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
						Latest: {adversarialSummary.latestRound.redStrategySummary}
					</p>
					{adversarialSummary.latestRound.exploitChains
						.slice(0, 3)
						.map((chain: string, i: number) => (
							<p
								// biome-ignore lint/suspicious/noArrayIndexKey: exploit chains have no stable id
								key={i}
								className="mt-0.5 text-xs text-[var(--sea-ink-soft)]"
							>
								→ {chain}
							</p>
						))}
				</>
			)}
		</div>
	);
}
