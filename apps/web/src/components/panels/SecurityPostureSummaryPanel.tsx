import type { FunctionReturnType } from "convex/server";
import { Gauge, Info, ShieldCheck } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

export type PostureReport = NonNullable<
	FunctionReturnType<typeof api.securityPosture.getSecurityPostureReport>
>;

export interface SecurityPostureSummaryPanelProps {
	report: PostureReport;
}

function postureLevelTone(
	level: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (level === "excellent") return "success";
	if (level === "good") return "info";
	if (level === "fair") return "warning";
	if (level === "at_risk") return "warning";
	if (level === "critical") return "danger";
	return "neutral";
}

function postureLevelLabel(level: string): string {
	return level.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/** SVG arc gauge for 0–100 score. */
function ScoreArc({ score, level }: { score: number; level: string }) {
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
	const largeArcBg = 1;

	const arcColor =
		level === "excellent"
			? "var(--success)"
			: level === "good"
				? "var(--signal)"
				: level === "fair"
					? "var(--warning)"
					: level === "at_risk"
						? "var(--warning)"
						: "var(--danger)";

	return (
		<svg
			viewBox="0 0 140 140"
			className="mx-auto"
			style={{ width: 160, height: 160 }}
		>
			{/* background arc */}
			<path
				d={`M ${p1.x} ${p1.y} A ${radius} ${radius} 0 ${largeArcBg} 1 ${p3.x} ${p3.y}`}
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

export default function SecurityPostureSummaryPanel({
	report }: SecurityPostureSummaryPanelProps) {
	const { overallScore, postureLevel, topActions, summary } = report;

	return (
		<div className="space-y-4">
			<div className="card">
				<div className="flex items-center gap-2 mb-4">
					<Gauge size={16} className="text-[var(--signal)]" />
					<h3 className="section-title mb-0">Overall Posture Score</h3>
				</div>

				<div className="grid gap-4 md:grid-cols-[auto_1fr] items-center">
					<div className="flex flex-col items-center">
						<ScoreArc score={overallScore} level={postureLevel} />
						<StatusPill
							label={postureLevelLabel(postureLevel)}
							tone={postureLevelTone(postureLevel)}
						/>
					</div>

					<div className="space-y-3">
						<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
							<Info size={14} className="mt-0.5 shrink-0" />
							<span>{summary}</span>
						</div>

						{topActions.length > 0 && (
							<div>
								<p className="text-xs font-bold text-[var(--sea-ink-soft)] mb-2 uppercase tracking-wider">
									Priority Actions
								</p>
								<ul className="space-y-1.5">
									{topActions.map((action: string, idx: number) => (
										<li
											key={action}
											className="flex items-start gap-2 text-sm text-[var(--sea-ink)]"
										>
											<StatusPill label={`#${idx + 1}`} tone="warning" />
											<span>{action}</span>
										</li>
									))}
								</ul>
							</div>
						)}
					</div>
				</div>
			</div>

			<p className="text-xs text-[var(--sea-ink-soft)] flex items-center gap-1">
				<ShieldCheck size={12} />
				Repository: {report.repositoryFullName}
			</p>
		</div>
	);
}
