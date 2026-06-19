import type { FunctionReturnType } from "convex/server";
import { Filter } from "lucide-react";
import type { api } from "../../lib/convex";

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewFinding = OverviewData["findings"][number];

export const SEVERITY_LEVELS = [
	"all",
	"critical",
	"high",
	"medium",
	"low",
	"informational",
] as const;
export type SeverityFilter = (typeof SEVERITY_LEVELS)[number];

export default function FindingsSeverityFilterChips({
	findings,
	severityFilter,
	onChange }: {
	findings: OverviewFinding[];
	severityFilter: SeverityFilter;
	onChange: (level: SeverityFilter) => void;
}) {
	return (
		<div className="flex items-center gap-2 mb-4 flex-wrap">
			<Filter size={14} className="text-[var(--sea-ink-soft)]" />
			{SEVERITY_LEVELS.map((level) => {
				const count =
					level === "all"
						? findings.length
						: findings.filter(
								(f: OverviewFinding) => f.severity === level,
							).length;
				return (
					<button
						key={level}
						type="button"
						onClick={() => onChange(level)}
						className={`tab-btn ${severityFilter === level ? "is-active" : ""}`}
					>
						{level === "all"
							? "All"
							: level.charAt(0).toUpperCase() + level.slice(1)}
						{count > 0 && (
							<span className="ml-1.5 text-[var(--sea-ink-soft)]">
								({count})
							</span>
						)}
					</button>
				);
			})}
		</div>
	);
}
