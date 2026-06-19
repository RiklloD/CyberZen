import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { blastTierTone } from "../../lib/utils";

type BlastRadiusData = NonNullable<
	FunctionReturnType<typeof api.blastRadiusIntel.getBlastRadius>
>;

export default function BlastRadiusPanel({
	blastRadius }: {
	blastRadius: BlastRadiusData;
}) {
	return (
		<div>
			<p className="panel-label mb-2">Blast Radius</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={blastRadius.riskTier}
					tone={blastTierTone(blastRadius.riskTier)}
				/>
				<StatusPill
					label={`impact ${blastRadius.businessImpactScore}`}
					tone="neutral"
				/>
				<StatusPill
					label={`depth ${blastRadius.attackPathDepth}`}
					tone="neutral"
				/>
			</div>
			{blastRadius.reachableServices.length > 0 && (
				<div className="mt-2 flex flex-wrap gap-1.5">
					{blastRadius.reachableServices.slice(0, 5).map((svc: string) => (
						<StatusPill key={svc} label={svc} tone="neutral" />
					))}
				</div>
			)}
			{blastRadius.exposedDataLayers.length > 0 && (
				<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
					Layers: {blastRadius.exposedDataLayers.join(", ")}
				</p>
			)}
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{blastRadius.summary}
			</p>
		</div>
	);
}
