import type { FunctionReturnType } from "convex/server";
import { Award, GitBranch, Target } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type Assessment = NonNullable<
	FunctionReturnType<
		typeof api.maturityAssessmentIntel.getLatestMaturityAssessmentBySlug
	>
>;

const LEVEL_LABELS: Record<number, string> = {
	1: "Initial",
	2: "Managed",
	3: "Defined",
	4: "Quantitatively Managed",
	5: "Optimising",
};

function levelTone(
	level: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (level >= 5) return "success";
	if (level >= 4) return "success";
	if (level >= 3) return "info";
	if (level >= 2) return "warning";
	return "danger";
}

function LevelLadder({ current }: { current: number }) {
	return (
		<div className="flex items-center gap-1">
			{[1, 2, 3, 4, 5].map((lvl) => (
				<div
					key={lvl}
					className={`flex-1 h-2 rounded ${
						lvl <= current
							? lvl >= 4
								? "bg-[var(--success)]"
								: lvl >= 3
									? "bg-[var(--teal)]"
									: "bg-[var(--warning)]"
							: "bg-[var(--line)]"
					}`}
					title={`Level ${lvl} — ${LEVEL_LABELS[lvl]}`}
				/>
			))}
		</div>
	);
}

export default function RepositoryMaturityPanel({
	assessment,
	repositoryFullName,
}: {
	assessment: Assessment;
	repositoryFullName: string;
}) {
	const bottleneckDim = assessment.dimensions.find(
		(d: Assessment["dimensions"][number]) => d.dimension === assessment.bottleneck,
	);

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-3">
				<GitBranch size={14} className="text-[var(--signal)]" />
				<h3 className="section-title">{repositoryFullName}</h3>
				<StatusPill
					label={`Level ${assessment.overallLevel}`}
					tone={levelTone(assessment.overallLevel)}
				/>
				<StatusPill
					label={LEVEL_LABELS[assessment.overallLevel] ?? "Unknown"}
					tone="neutral"
				/>
				<StatusPill
					label={`${assessment.overallScore}/100`}
					tone="neutral"
				/>
			</div>

			<div className="mb-4">
				<p className="panel-label mb-1">CMMI Ladder</p>
				<LevelLadder current={assessment.overallLevel} />
				<div className="mt-1 flex justify-between text-[0.6rem] text-[var(--sea-ink-soft)] uppercase tracking-wider">
					<span>1 Initial</span>
					<span>2 Managed</span>
					<span>3 Defined</span>
					<span>4 Quant.</span>
					<span>5 Optimising</span>
				</div>
			</div>

			<div className="mb-4">
				<p className="panel-label mb-2">Dimensions Breakdown</p>
				<div className="grid gap-2">
					{assessment.dimensions.map((d: Assessment["dimensions"][number]) => (
						<div key={d.dimension} className="inset-panel">
							<div className="flex items-center justify-between mb-1">
								<span className="text-sm font-medium text-[var(--sea-ink)]">
									{d.label}
								</span>
								<div className="flex items-center gap-1.5">
									<StatusPill
										label={`L${d.level}`}
										tone={levelTone(d.level)}
									/>
									<StatusPill label={`${d.score}`} tone="neutral" />
								</div>
							</div>
							{d.gaps.length > 0 && (
								<ul className="mt-1 ml-3 list-disc text-xs text-[var(--sea-ink-soft)] space-y-0.5">
									{d.gaps.map((g: string, i: number) => (
										// biome-ignore lint/suspicious/noArrayIndexKey: gap strings have no stable id
										<li key={i}>{g}</li>
									))}
								</ul>
							)}
						</div>
					))}
				</div>
			</div>

			{bottleneckDim && (
				<div className="inset-panel mb-4 border-l-2 border-[var(--warning)]">
					<div className="flex items-center gap-2 mb-1">
						<Target size={12} className="text-[var(--warning)]" />
						<p className="panel-label">Bottleneck</p>
					</div>
					<p className="text-sm text-[var(--sea-ink)]">{bottleneckDim.label}</p>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						Lifting this dimension raises overall maturity.
					</p>
				</div>
			)}

			{assessment.advancementRoadmap.length > 0 && (
				<div>
					<div className="flex items-center gap-2 mb-2">
						<Award size={12} className="text-[var(--signal)]" />
						<p className="panel-label">Recommended Next Actions</p>
					</div>
					<ol className="ml-4 list-decimal text-xs text-[var(--sea-ink)] space-y-1">
						{assessment.advancementRoadmap.map((action: string, i: number) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: roadmap entries are user-facing strings
							<li key={i}>{action}</li>
						))}
					</ol>
				</div>
			)}
		</div>
	);
}
