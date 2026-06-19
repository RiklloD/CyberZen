import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { priorityTierTone } from "../../lib/utils";

type RemediationQueue = NonNullable<
	FunctionReturnType<
		typeof api.remediationQueueIntel.getRemediationQueueForRepository
	>
>;

export default function RepositoryRemediationQueuePanel({
	remediationQueue }: {
	remediationQueue: RemediationQueue;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label">Remediation Queue</p>
			<div className="flex flex-wrap gap-1.5 mt-1">
				<StatusPill
					label={`${remediationQueue.summary.totalCandidates} in queue`}
					tone="neutral"
				/>
				{remediationQueue.summary.p0Count > 0 && (
					<StatusPill
						label={`P0: ${remediationQueue.summary.p0Count}`}
						tone="danger"
					/>
				)}
				{remediationQueue.summary.p1Count > 0 && (
					<StatusPill
						label={`P1: ${remediationQueue.summary.p1Count}`}
						tone="warning"
					/>
				)}
				{remediationQueue.summary.p2Count > 0 && (
					<StatusPill
						label={`P2: ${remediationQueue.summary.p2Count}`}
						tone="info"
					/>
				)}
			</div>
			{remediationQueue.queue.slice(0, 3).map((item: RemediationQueue["queue"][number]) => (
				<div key={item.findingId} className="mt-1.5 inset-panel">
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={item.priorityTier.toUpperCase()}
							tone={priorityTierTone(item.priorityTier)}
						/>
						<StatusPill
							label={`score ${item.priorityScore.toFixed(0)}`}
							tone="neutral"
						/>
					</div>
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)] truncate">
						{item.title}
					</p>
				</div>
			))}
		</div>
	);
}
