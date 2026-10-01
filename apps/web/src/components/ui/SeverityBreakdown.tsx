import { Link } from "@tanstack/react-router";
import { SEVERITY_ORDER } from "../../lib/format";

type Counts = Record<(typeof SEVERITY_ORDER)[number], number>;

const LABELS: Record<string, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	informational: "Info",
};

/**
 * Stacked severity bar with a clickable legend. Each legend entry deep-links
 * into the findings list pre-filtered to that severity.
 */
export default function SeverityBreakdown({
	counts,
	linkToFindings = true,
	compact = false,
}: {
	counts: Counts;
	linkToFindings?: boolean;
	compact?: boolean;
}) {
	const total = SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0);
	const levels = SEVERITY_ORDER.filter((s) => s !== "informational" || counts[s] > 0);

	return (
		<div>
			<div
				className="sev-stack"
				role="img"
				aria-label={levels.map((s) => `${counts[s]} ${LABELS[s]}`).join(", ")}
			>
				{total === 0 ? (
					<span style={{ width: "100%", background: "var(--surface-3)" }} />
				) : (
					levels
						.filter((s) => counts[s] > 0)
						.map((s) => (
							<span
								key={s}
								data-sev={s}
								style={{ width: `${(counts[s] / total) * 100}%`, minWidth: 4 }}
							/>
						))
				)}
			</div>
			{!compact && (
				<div className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
					{levels.map((s) => {
						const body = (
							<>
								<span
									data-sev={s}
									className="h-2 w-2 rounded-[2px]"
									style={{ background: "var(--sev)" }}
								/>
								<span className="text-[var(--text-2)]">{LABELS[s]}</span>
								<span className="font-semibold tabular text-[var(--text)]">{counts[s]}</span>
							</>
						);
						return linkToFindings ? (
							<Link
								key={s}
								to="/findings"
								search={{ severity: s }}
								className="inline-flex items-center gap-1.5 text-[0.8rem] hover:opacity-80"
							>
								{body}
							</Link>
						) : (
							<span key={s} className="inline-flex items-center gap-1.5 text-[0.8rem]">
								{body}
							</span>
						);
					})}
				</div>
			)}
		</div>
	);
}
