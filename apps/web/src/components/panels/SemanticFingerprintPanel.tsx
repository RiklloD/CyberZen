import type { FunctionReturnType } from "convex/server";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type SemanticAnalysis = NonNullable<
	FunctionReturnType<typeof api.semanticFingerprintIntel.getLatestCodeAnalysis>
>;

export default function SemanticFingerprintPanel({
	analysis }: {
	analysis: SemanticAnalysis;
}) {
	return (
		<div className="card card-sm">
			<p className="panel-label mb-2">Semantic Fingerprint (this repo)</p>
			<p className="text-xs text-[var(--sea-ink-soft)] mb-2">
				Commit: <code>{analysis.commitSha.slice(0, 7)}</code> on{" "}
				{analysis.branch}
			</p>
			{analysis.topMatches.slice(0, 5).map((m: SemanticAnalysis["topMatches"][number]) => (
				<div
					key={m.patternId}
					className="flex flex-wrap items-center gap-1.5 mt-1"
				>
					<StatusPill
						label={m.severity}
						tone={
							m.severity === "critical"
								? "danger"
								: m.severity === "high"
									? "warning"
									: "neutral"
						}
					/>
					<span className="text-xs text-[var(--sea-ink-soft)] truncate">
						{m.vulnClass.replace(/_/g, " ")}
					</span>
					<span className="text-xs text-[var(--sea-ink-soft)] ml-auto">
						{(m.similarity * 100).toFixed(0)}%
					</span>
				</div>
			))}
			{analysis.topMatches.length === 0 && (
				<p className="text-xs text-[var(--success)]">
					No semantic matches above threshold
				</p>
			)}
		</div>
	);
}
