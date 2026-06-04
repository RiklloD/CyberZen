import type { FunctionReturnType } from "convex/server";
import {
	AlertTriangle,
	Building,
	DollarSign,
	GitBranch,
	Scale,
	Users,
} from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type Impact = NonNullable<
	FunctionReturnType<
		typeof api.businessImpactIntel.getLatestBusinessImpactBySlug
	>
>;

function impactTone(
	level: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (level === "critical") return "danger";
	if (level === "high") return "warning";
	if (level === "medium") return "info";
	if (level === "low") return "success";
	return "success";
}

function dimTone(
	score: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (score >= 70) return "danger";
	if (score >= 50) return "warning";
	if (score >= 25) return "info";
	return "success";
}

function RadialGauge({
	score,
	label,
	icon,
}: {
	score: number;
	label: string;
	icon: React.ReactNode;
}) {
	const r = 32;
	const c = 2 * Math.PI * r;
	const offset = c - (score / 100) * c;
	const colorVar =
		score >= 70
			? "var(--danger)"
			: score >= 50
				? "var(--warning)"
				: score >= 25
					? "var(--teal)"
					: "var(--success)";

	return (
		<div className="inset-panel text-center">
			<div className="mb-1 flex items-center justify-center gap-1.5 text-[var(--sea-ink-soft)]">
				{icon}
				<span className="text-[0.6rem] font-bold uppercase tracking-wider">
					{label}
				</span>
			</div>
			<svg width={80} height={80} aria-hidden className="mx-auto">
				<circle
					cx={40}
					cy={40}
					r={r}
					fill="none"
					stroke="var(--line)"
					strokeWidth={6}
				/>
				<circle
					cx={40}
					cy={40}
					r={r}
					fill="none"
					stroke={colorVar}
					strokeWidth={6}
					strokeLinecap="round"
					strokeDasharray={c}
					strokeDashoffset={offset}
					transform="rotate(-90 40 40)"
				/>
				<text
					x={40}
					y={40}
					textAnchor="middle"
					dominantBaseline="central"
					className="text-base font-bold"
					fill="var(--sea-ink)"
				>
					{score}
				</text>
			</svg>
		</div>
	);
}

function formatCurrency(amount: number): string {
	if (amount >= 1_000_000) return `$${(amount / 1_000_000).toFixed(1)}M`;
	if (amount >= 1_000) return `$${Math.round(amount / 1_000)}k`;
	return `$${amount}`;
}

export default function RepositoryBusinessImpactPanel({
	impact,
	repositoryFullName,
}: {
	impact: Impact;
	repositoryFullName: string;
}) {
	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-3 flex-wrap">
				<GitBranch size={14} className="text-[var(--signal)]" />
				<h3 className="section-title">{repositoryFullName}</h3>
				<StatusPill
					label={impact.impactLevel.toUpperCase()}
					tone={impactTone(impact.impactLevel)}
				/>
				<StatusPill label={`${impact.overallScore}/100`} tone="neutral" />
			</div>

			<div className="grid gap-2 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 mb-4">
				<RadialGauge
					score={impact.dataExposureScore}
					label="Data (Customer)"
					icon={<Users size={11} />}
				/>
				<RadialGauge
					score={impact.regulatoryExposureScore}
					label="Regulatory"
					icon={<Scale size={11} />}
				/>
				<RadialGauge
					score={impact.revenueImpactScore}
					label="Financial"
					icon={<DollarSign size={11} />}
				/>
				<RadialGauge
					score={impact.reputationScore}
					label="Brand"
					icon={<Building size={11} />}
				/>
				<RadialGauge
					score={impact.remediationCostScore}
					label="Operational"
					icon={<AlertTriangle size={11} />}
				/>
			</div>

			<div className="grid gap-2 sm:grid-cols-3 mb-4">
				<div className="inset-panel">
					<p className="panel-label mb-1">Records at Risk</p>
					<div className="text-lg font-bold text-[var(--sea-ink)]">
						{impact.estimatedRecordsAtRisk.toLocaleString()}
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Fine Exposure</p>
					<div className="text-sm font-bold text-[var(--sea-ink)]">
						{formatCurrency(impact.estimatedFineRangeMin)} –{" "}
						{formatCurrency(impact.estimatedFineRangeMax)}
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Remediation Cost</p>
					<div className="text-sm font-bold text-[var(--sea-ink)]">
						{formatCurrency(impact.estimatedRemediationCostMin)} –{" "}
						{formatCurrency(impact.estimatedRemediationCostMax)}
					</div>
				</div>
			</div>

			{impact.topExposures.length > 0 && (
				<div>
					<p className="panel-label mb-2">Top Exposures</p>
					<ul className="space-y-1 text-xs text-[var(--sea-ink)]">
						{impact.topExposures.map((exposure: string, i: number) => (
							<li
								// biome-ignore lint/suspicious/noArrayIndexKey: exposure strings are stable enough
								key={i}
								className="flex items-start gap-2"
							>
								<StatusPill
									label={`#${i + 1}`}
									tone={dimTone(impact.overallScore)}
								/>
								<span>{exposure}</span>
							</li>
						))}
					</ul>
				</div>
			)}
		</div>
	);
}
