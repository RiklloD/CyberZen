import type { FunctionReturnType } from "convex/server";
import { BarChart3 } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

export type PostureReport = NonNullable<
	FunctionReturnType<typeof api.securityPosture.getSecurityPostureReport>
>;

export interface PosturePillarBreakdownProps {
	report: PostureReport;
}

interface Pillar {
	key: string;
	label: string;
	/** The max possible deduction (or bonus) for this pillar. */
	maxImpact: number;
	/** The actual deduction (negative) or bonus (positive) applied. */
	value: number | null;
	/** `null` = no data. */
	description: string;
	tone: "neutral" | "success" | "warning" | "danger" | "info";
}

function pillarTone(
	value: number | null,
	isBonus?: boolean,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (value === null) return "neutral";
	if (isBonus) {
		return value > 0 ? "success" : "neutral";
	}
	if (value === 0) return "success";
	if (value <= 5) return "info";
	if (value <= 15) return "warning";
	return "danger";
}

function formatImpact(value: number | null, isBonus?: boolean): string {
	if (value === null) return "No data";
	if (isBonus) return value > 0 ? `+${value} bonus` : "—";
	return value > 0 ? `−${value} pts` : "No penalty";
}

export default function PosturePillarBreakdown({
	report }: PosturePillarBreakdownProps) {
	const pillars: Pillar[] = [
		{
			key: "findings",
			label: "Open Findings",
			maxImpact: 50,
			value: report.findingPenalty,
			description: "Deduction based on open critical/high/medium/low findings",
			tone: pillarTone(report.findingPenalty) },
		{
			key: "attack-surface",
			label: "Attack Surface",
			maxImpact: 25,
			value: report.attackSurfacePenalty,
			description: "Deduction based on attack surface score and trend",
			tone: pillarTone(report.attackSurfacePenalty) },
		{
			key: "regulatory",
			label: "Regulatory Drift",
			maxImpact: 20,
			value: report.regulatoryPenalty,
			description: "Deduction based on compliance drift level across frameworks",
			tone: pillarTone(report.regulatoryPenalty) },
		{
			key: "red-blue",
			label: "Red / Blue Adversarial",
			maxImpact: 10,
			value: report.redAgentPenalty,
			description: "Deduction based on red agent win rate in adversarial rounds",
			tone: pillarTone(report.redAgentPenalty) },
		{
			key: "learning",
			label: "Learning Maturity",
			maxImpact: 5,
			value: report.learningBonus,
			description: "Bonus for adapted confidence score from learning profiles",
			tone: pillarTone(report.learningBonus, true) },
	];

	// Sort: penalties (highest first), then bonuses, then no-data
	const sorted = [...pillars].sort((a, b) => {
		const aVal = a.value ?? -1;
		const bVal = b.value ?? -1;
		return bVal - aVal;
	});

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-4">
				<BarChart3 size={16} className="text-[var(--signal)]" />
				<h3 className="section-title mb-0">Pillar Breakdown</h3>
			</div>

			<div className="space-y-4">
				{sorted.map((pillar) => {
					const isBonus = pillar.key === "learning";
					const barPercent =
						pillar.value !== null
							? isBonus
								? Math.min(100, (pillar.value / pillar.maxImpact) * 100)
								: Math.min(100, (pillar.value / pillar.maxImpact) * 100)
							: 0;

					const barColor =
						pillar.tone === "success"
							? "var(--success)"
							: pillar.tone === "danger"
								? "var(--danger)"
								: pillar.tone === "warning"
									? "var(--warning)"
									: pillar.tone === "info"
										? "var(--signal)"
										: "var(--border)";

					return (
						<div key={pillar.key}>
							<div className="flex items-center justify-between mb-1">
								<span className="text-sm font-medium text-[var(--sea-ink)]">
									{pillar.label}
								</span>
								<StatusPill
									label={formatImpact(pillar.value, isBonus)}
									tone={pillar.tone}
								/>
							</div>
							<div className="w-full h-2 rounded-full bg-[var(--border)] overflow-hidden">
								<div
									className="h-full rounded-full transition-all duration-300"
									style={{
										width: `${barPercent}%`,
										backgroundColor: barColor }}
								/>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
								{pillar.description}
							</p>
						</div>
					);
				})}
			</div>

			<div className="mt-4 pt-3 border-t border-[var(--border)]">
				<div className="flex items-center justify-between">
					<span className="text-sm font-bold text-[var(--sea-ink)]">
						Composite Score
					</span>
					<span className="text-lg font-bold text-[var(--sea-ink)]">
						{report.overallScore}/100
					</span>
				</div>
			</div>
		</div>
	);
}
