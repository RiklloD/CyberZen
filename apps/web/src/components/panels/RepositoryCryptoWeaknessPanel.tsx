import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { supplyChainRiskTone } from "../../lib/utils";

type CryptoWeaknessData = NonNullable<
	FunctionReturnType<typeof api.cryptoWeaknessIntel.getLatestCryptoWeaknessScan>
>;

export interface RepositoryCryptoWeaknessPanelProps {
	data: CryptoWeaknessData;
}

export default function RepositoryCryptoWeaknessPanel({
	data }: RepositoryCryptoWeaknessPanelProps) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Crypto Weakness</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={data.overallRisk}
					tone={supplyChainRiskTone(data.overallRisk)}
				/>
				{data.criticalCount > 0 && (
					<StatusPill
						label={`${data.criticalCount} critical`}
						tone="danger"
					/>
				)}
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{data.summary}
			</p>
		</div>
	);
}
