import type { FunctionReturnType } from "convex/server";
import { Gauge, Info, AlertTriangle, TrendingUp, TrendingDown, Minus } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

export type DriftPostureData = NonNullable<
	FunctionReturnType<typeof api.driftPostureIntel.getLatestDriftPostureBySlug>
>;

export interface RepositoryDriftPosturePanelProps {
	report: DriftPostureData;
}

function gradeTone(
	grade: string,
): "success" | "info" | "warning" | "danger" | "neutral" {
	if (grade === "A") return "success";
	if (grade === "B") return "info";
	if (grade === "C") return "warning";
	if (grade === "D" || grade === "F") return "danger";
	return "neutral";
}

function trendIcon(trend: string) {
	if (trend === "improving") return <TrendingUp size={14} className="text-[var(--success)]" />;
	if (trend === "degrading") return <TrendingDown size={14} className="text-[var(--danger)]" />;
	return <Minus size={14} className="text-[var(--sea-ink-soft)]" />;
}

function trendLabel(trend: string): string {
	return trend.charAt(0).toUpperCase() + trend.slice(1);
}

/** SVG arc gauge for 0–100 drift posture score. */
function DriftScoreArc({ score, grade }: { score: number; grade: string }) {
	const radius = 54;
	const stroke = 8;
	const cx = 70;
	const cy = 70;
	const startAngle = 135;
	const endAngle = 405;
	const totalAngle = endAngle - startAngle;
	const fillAngle = startAngle + (score / 100) * totalAngle;

	const polarToCartesian = (angle: number) => {
		const rad = (angle * Math.PI) / 180;
		return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
	};

	const p1 = polarToCartesian(startAngle);
	const p2 = polarToCartesian(fillAngle);
	const p3 = polarToCartesian(endAngle);
	const largeArcFill = fillAngle - startAngle > 180 ? 1 : 0;

	const arcColor =
		grade === "A"
			? "var(--success)"
			: grade === "B"
				? "var(--signal)"
				: grade === "C"
					? "var(--warning)"
					: "var(--danger)";

	return (
		<svg viewBox="0 0 140 140" className="mx-auto" style={{ width: 160, height: 160 }}>
			{/* background arc */}
			<path
				d={`M ${p1.x} ${p1.y} A ${radius} ${radius} 0 1 1 ${p3.x} ${p3.y}`}
				fill="none"
				stroke="var(--border)"
				strokeWidth={stroke}
				strokeLinecap="round"
			/>
			{/* filled arc */}
			{score > 0 && (
				<path
					d={`M ${p1.x} ${p1.y} A ${radius} ${radius} 0 ${largeArcFill} 1 ${p2.x} ${p2.y}`}
					fill="none"
					stroke={arcColor}
					strokeWidth={stroke}
					strokeLinecap="round"
				/>
			)}
			{/* centre text */}
			<text
				x={cx}
				y={cy - 4}
				textAnchor="middle"
				className="fill-[var(--sea-ink)]"
				fontSize="28"
				fontWeight="700"
			>
				{score}
			</text>
			<text
				x={cx}
				y={cy + 16}
				textAnchor="middle"
				className="fill-[var(--sea-ink-soft)]"
				fontSize="10"
			>
				out of 100
			</text>
		</svg>
	);
}

export default function RepositoryDriftPosturePanel({
	report,
}: RepositoryDriftPosturePanelProps) {
	const {
		overallScore,
		overallGrade,
		trend,
		categoryScores,
		totalWorkstreamsScanned,
		criticalDriftCount,
		highDriftCount,
		topRisks,
		summary,
	} = report;

	return (
		<div className="space-y-4">
			{/* Score gauge + grade card */}
			<div className="card">
				<div className="flex items-center gap-2 mb-4">
					<Gauge size={16} className="text-[var(--signal)]" />
					<h3 className="section-title mb-0">Drift Posture Score</h3>
				</div>

				<div className="grid gap-4 md:grid-cols-[auto_1fr] items-center">
					<div className="flex flex-col items-center">
						<DriftScoreArc score={overallScore} grade={overallGrade} />
						<div className="flex items-center gap-2 mt-2">
							<StatusPill label={`Grade ${overallGrade}`} tone={gradeTone(overallGrade)} />
							<span className="inline-flex items-center gap-1 text-xs text-[var(--sea-ink-soft)]">
								{trendIcon(trend)}
								{trendLabel(trend)}
							</span>
						</div>
					</div>

					<div className="space-y-3">
						<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
							<Info size={14} className="mt-0.5 shrink-0" />
							<span>{summary}</span>
						</div>

						{/* Quick stats */}
						<div className="grid grid-cols-3 gap-3">
							<div className="text-center">
								<div className="text-lg font-bold text-[var(--sea-ink)]">
									{totalWorkstreamsScanned}
								</div>
								<div className="text-xs text-[var(--sea-ink-soft)]">Scanners</div>
							</div>
							<div className="text-center">
								<div className="text-lg font-bold text-[var(--danger)]">
									{criticalDriftCount}
								</div>
								<div className="text-xs text-[var(--sea-ink-soft)]">Critical</div>
							</div>
							<div className="text-center">
								<div className="text-lg font-bold text-[var(--warning)]">
									{highDriftCount}
								</div>
								<div className="text-xs text-[var(--sea-ink-soft)]">High</div>
							</div>
						</div>

						{/* Top risks */}
						{topRisks.length > 0 && (
							<div>
								<p className="text-xs font-bold text-[var(--sea-ink-soft)] mb-2 uppercase tracking-wider">
									Top Risks
								</p>
								<ul className="space-y-1.5">
									{topRisks.map((risk: string) => (
										<li
											key={risk}
											className="flex items-start gap-2 text-sm text-[var(--sea-ink)]"
										>
											<AlertTriangle size={13} className="mt-0.5 shrink-0 text-[var(--warning)]" />
											<span>{risk}</span>
										</li>
									))}
								</ul>
							</div>
						)}
					</div>
				</div>
			</div>

			{/* Category breakdown */}
			<div className="card">
				<div className="flex items-center gap-2 mb-4">
					<Gauge size={16} className="text-[var(--signal)]" />
					<h3 className="section-title mb-0">Category Breakdown</h3>
				</div>

				<div className="space-y-3">
					{categoryScores.map((cat: DriftPostureData["categoryScores"][number]) => {
						const barPercent = cat.score;
						const barColor =
							cat.grade === "A"
								? "var(--success)"
								: cat.grade === "B"
									? "var(--signal)"
									: cat.grade === "C"
										? "var(--warning)"
										: "var(--danger)";

						return (
							<div key={cat.category}>
								<div className="flex items-center justify-between mb-1">
									<span className="text-sm font-medium text-[var(--sea-ink)]">
										{cat.label}
									</span>
									<div className="flex items-center gap-2">
										<span className="text-xs text-[var(--sea-ink-soft)]">
											{cat.workstreamsScanned} scanners
										</span>
										<StatusPill
											label={`${cat.score}/100`}
											tone={
												cat.grade === "A"
													? "success"
													: cat.grade === "B"
														? "info"
														: cat.grade === "C"
															? "warning"
															: "danger"
											}
										/>
									</div>
								</div>
								<div className="w-full h-2 rounded-full bg-[var(--border)] overflow-hidden">
									<div
										className="h-full rounded-full transition-all duration-300"
										style={{
											width: `${barPercent}%`,
											backgroundColor: barColor,
										}}
									/>
								</div>
							</div>
						);
					})}
				</div>
			</div>
		</div>
	);
}
