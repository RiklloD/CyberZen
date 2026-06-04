import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { blastTierTone } from "../../lib/utils";

type BlastRadius = NonNullable<
	FunctionReturnType<
		typeof api.blastRadiusIntel.blastRadiusSummaryForRepository
	>
>;

export default function RepositoryBlastRadiusPanel({
	blastRadius,
}: {
	blastRadius: BlastRadius;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label">Blast Radius</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`max risk: ${blastRadius.maxRiskTier}`}
					tone={blastTierTone(blastRadius.maxRiskTier)}
				/>
				{blastRadius.totalReachableServices.length > 0 && (
					<StatusPill
						label={`${blastRadius.totalReachableServices.length} reachable services`}
						tone="neutral"
					/>
				)}
			</div>
			{blastRadius.topFindings.slice(0, 3).map((f: BlastRadius["topFindings"][number]) => (
				<div key={f.findingId} className="mt-1 flex flex-wrap gap-1.5">
					<StatusPill label={f.riskTier} tone={blastTierTone(f.riskTier)} />
					<StatusPill
						label={`score ${f.businessImpactScore}`}
						tone="neutral"
					/>
					<span className="text-xs text-[var(--sea-ink-soft)] truncate max-w-[200px]">
						{f.title}
					</span>
				</div>
			))}
		</div>
	);
}
