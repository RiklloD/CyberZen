import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type Tier3Signal = FunctionReturnType<
	typeof api.tier3Intel.getRecentTier3Signals
>[number];

export default function Tier3SignalsPanel({
	signals }: {
	signals: Tier3Signal[];
}) {
	if (signals.length === 0) return null;

	return (
		<div>
			<h2 className="section-title mb-3">
				Tier-3 Intel ({signals.length} signals)
			</h2>
			<div className="space-y-2">
				{signals.map((signal) => (
					<div key={signal._id} className="card card-sm">
						<div className="flex flex-wrap gap-1.5 mb-1">
							<StatusPill
								label={signal.threatLevel}
								tone={
									signal.threatLevel === "critical" ||
									signal.threatLevel === "high"
										? "danger"
										: signal.threatLevel === "medium"
											? "warning"
											: "neutral"
								}
							/>
							<StatusPill label={signal.source} tone="info" />
							{signal.hasExploitKeywords && (
								<StatusPill label="exploit" tone="danger" />
							)}
							{signal.hasRansomwareKeywords && (
								<StatusPill label="ransomware" tone="danger" />
							)}
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)] line-clamp-2">
							{signal.text}
						</p>
					</div>
				))}
			</div>
		</div>
	);
}
