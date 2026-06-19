import type { FunctionReturnType } from "convex/server";
import { TrendingUp } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type HistoryEntry = FunctionReturnType<
	typeof api.maturityAssessmentIntel.getMaturityAssessmentHistory
>[number];

function levelTone(
	level: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (level >= 5) return "success";
	if (level >= 4) return "success";
	if (level >= 3) return "info";
	if (level >= 2) return "warning";
	return "danger";
}

export default function MaturityProgressionTimeline({
	history }: {
	history: HistoryEntry[];
}) {
	if (history.length === 0) {
		return (
			<div className="card">
				<div className="flex items-center gap-2 mb-2">
					<TrendingUp size={14} className="text-[var(--sea-ink-soft)]" />
					<h3 className="section-title">Progression</h3>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)] italic">
					No historical assessments yet. Trigger a maturity assessment to start
					the timeline.
				</p>
			</div>
		);
	}

	// chronological order (oldest first)
	const ordered = [...history].reverse();

	const width = 480;
	const height = 80;
	const padding = 20;
	const innerW = width - padding * 2;
	const innerH = height - padding * 2;
	const stepX = ordered.length > 1 ? innerW / (ordered.length - 1) : 0;
	const points = ordered.map((h, i) => {
		const x = padding + i * stepX;
		const y = padding + innerH - ((h.overallScore - 0) / 100) * innerH;
		return { x, y, entry: h };
	});
	const path = points
		.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
		.join(" ");

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<TrendingUp size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Progression</h3>
				</div>
				<StatusPill label={`${history.length} assessments`} tone="neutral" />
			</div>

			<svg width={width} height={height} aria-hidden className="mb-3">
				<line
					x1={padding}
					y1={padding}
					x2={padding}
					y2={padding + innerH}
					stroke="var(--line)"
					strokeWidth={1}
				/>
				<line
					x1={padding}
					y1={padding + innerH}
					x2={padding + innerW}
					y2={padding + innerH}
					stroke="var(--line)"
					strokeWidth={1}
				/>
				<path d={path} stroke="var(--signal)" strokeWidth={1.5} fill="none" />
				{points.map((p) => (
					<circle
						key={p.entry._id}
						cx={p.x}
						cy={p.y}
						r={3}
						fill="var(--signal)"
					/>
				))}
			</svg>

			<div className="space-y-1.5">
				{ordered.map((h) => (
					<div
						key={h._id}
						className="flex items-center justify-between gap-2 text-xs"
					>
						<span className="text-[var(--sea-ink-soft)] min-w-[120px]">
							{formatTimestamp(h.assessedAt)}
						</span>
						<StatusPill
							label={`Level ${h.overallLevel}`}
							tone={levelTone(h.overallLevel)}
						/>
						<StatusPill label={`${h.overallScore}`} tone="neutral" />
						<span className="text-[var(--sea-ink-soft)] truncate flex-1">
							bottleneck: {h.bottleneck.replaceAll("_", " ")}
						</span>
					</div>
				))}
			</div>
		</div>
	);
}
