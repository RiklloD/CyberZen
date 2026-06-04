import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { severityTone } from "../../lib/utils";

type AgentMemory = NonNullable<
	FunctionReturnType<typeof api.agentMemory.getRepositoryMemory>
>;

export default function AgentMemoryPanel({ memory }: { memory: AgentMemory }) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Agent Memory</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={memory.dominantSeverity}
					tone={severityTone(memory.dominantSeverity)}
				/>
				<StatusPill
					label={`FP ${Math.round(memory.falsePositiveRate * 100)}%`}
					tone={memory.falsePositiveRate > 0.3 ? "warning" : "neutral"}
				/>
				<StatusPill
					label={`${memory.totalFindingsAnalyzed} analyzed`}
					tone="neutral"
				/>
			</div>
			{memory.recurringVulnClasses.slice(0, 2).map((vc: AgentMemory["recurringVulnClasses"][number]) => (
				<div key={vc.vulnClass} className="mt-1.5 flex flex-wrap gap-1.5">
					<StatusPill
						label={vc.vulnClass.replaceAll("_", " ")}
						tone="info"
					/>
					<span className="text-xs text-[var(--sea-ink-soft)]">
						{vc.count}× · avg severity{" "}
						{(vc.avgSeverityWeight * 100).toFixed(0)}%
					</span>
				</div>
			))}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{memory.summary}
			</p>
		</div>
	);
}
