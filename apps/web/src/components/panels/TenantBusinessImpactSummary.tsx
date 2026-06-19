import { Building, TrendingDown } from "lucide-react";
import StatusPill from "../StatusPill";

export interface TenantBusinessImpactSummaryProps {
	totalRepositories: number;
	assessedRepositories: number;
	levelDistribution: {
		critical: number;
		high: number;
		medium: number;
		low: number;
		minimal: number;
	};
	averageScore: number;
}

const LEVELS: {
	key: keyof TenantBusinessImpactSummaryProps["levelDistribution"];
	label: string;
	color: string;
	tone: "neutral" | "success" | "warning" | "danger" | "info";
}[] = [
	{ key: "critical", label: "Critical", color: "var(--danger)", tone: "danger" },
	{ key: "high", label: "High", color: "var(--warning)", tone: "warning" },
	{ key: "medium", label: "Medium", color: "var(--teal)", tone: "info" },
	{ key: "low", label: "Low", color: "var(--success)", tone: "success" },
	{
		key: "minimal",
		label: "Minimal",
		color: "var(--sea-ink-soft)",
		tone: "neutral" },
];

export default function TenantBusinessImpactSummary({
	totalRepositories,
	assessedRepositories,
	levelDistribution,
	averageScore }: TenantBusinessImpactSummaryProps) {
	const total = assessedRepositories || 1;

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<Building size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Tenant Business Impact</h3>
				</div>
				<div className="flex items-center gap-1.5">
					<StatusPill
						label={`${assessedRepositories}/${totalRepositories} assessed`}
						tone="neutral"
					/>
					<StatusPill label={`avg ${averageScore}`} tone="info" />
				</div>
			</div>

			<div className="mb-4">
				<p className="panel-label mb-1">Impact Distribution</p>
				<div className="flex h-4 w-full overflow-hidden rounded">
					{LEVELS.map((lvl) => {
						const count = levelDistribution[lvl.key];
						const pct = (count / total) * 100;
						if (pct === 0) return null;
						return (
							<div
								key={lvl.key}
								style={{ width: `${pct}%`, background: lvl.color }}
								title={`${lvl.label}: ${count}`}
							/>
						);
					})}
				</div>
			</div>

			<div className="grid gap-2 grid-cols-2 sm:grid-cols-5">
				{LEVELS.map((lvl) => (
					<div key={lvl.key} className="inset-panel text-center">
						<div className="text-[0.6rem] font-bold text-[var(--sea-ink-soft)] uppercase tracking-wider mb-1">
							{lvl.label}
						</div>
						<div className="text-2xl font-bold text-[var(--sea-ink)]">
							{levelDistribution[lvl.key]}
						</div>
						<div className="mt-1">
							<StatusPill
								label={
									levelDistribution[lvl.key] === 0
										? "none"
										: `${Math.round((levelDistribution[lvl.key] / total) * 100)}%`
								}
								tone={levelDistribution[lvl.key] === 0 ? "neutral" : lvl.tone}
							/>
						</div>
					</div>
				))}
			</div>

			{(levelDistribution.critical > 0 || levelDistribution.high > 0) && (
				<div className="mt-3 inset-panel border-l-2 border-[var(--danger)]">
					<div className="flex items-center gap-2">
						<TrendingDown size={12} className="text-[var(--danger)]" />
						<p className="text-xs text-[var(--sea-ink)]">
							<span className="font-bold">
								{levelDistribution.critical + levelDistribution.high}
							</span>{" "}
							repositor
							{levelDistribution.critical + levelDistribution.high === 1
								? "y carries"
								: "ies carry"}{" "}
							critical or high business impact — prioritise remediation here.
						</p>
					</div>
				</div>
			)}
		</div>
	);
}
