import type { FunctionReturnType } from "convex/server";
import { Activity } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type HistoryEntry = FunctionReturnType<
	typeof api.zeroDayDetectionIntel.getZeroDayDetectionHistory
>[number];

function scoreColor(score: number): string {
	if (score >= 70) return "var(--danger)";
	if (score >= 50) return "var(--warning)";
	if (score >= 25) return "var(--teal)";
	return "var(--success)";
}

function scoreTone(
	score: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (score >= 70) return "danger";
	if (score >= 50) return "warning";
	if (score >= 25) return "info";
	return "success";
}

export default function ZeroDaySignalGraph({
	history,
}: {
	history: HistoryEntry[];
}) {
	if (history.length === 0) {
		return (
			<div className="card">
				<div className="flex items-center gap-2 mb-3">
					<Activity size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Anomaly Signal History</h3>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)] italic">
					No historical anomaly data yet. Signal scores will appear here as
					scans complete.
				</p>
			</div>
		);
	}

	// Chronological order (oldest first)
	const ordered = [...history].reverse();

	// SVG sparkline dimensions
	const width = 480;
	const height = 100;
	const padding = 24;
	const innerW = width - padding * 2;
	const innerH = height - padding * 2;

	// Compute scale from anomaly scores (0–100)
	const maxScore = 100;
	const minScore = 0;

	const stepX =
		ordered.length > 1 ? innerW / (ordered.length - 1) : 0;

	const points = ordered.map((entry, i) => {
		const x = padding + i * stepX;
		const y =
			padding +
			innerH -
			((entry.anomalyScore - minScore) / (maxScore - minScore)) * innerH;
		return { x, y, entry };
	});

	const linePath = points
		.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
		.join(" ");

	// Area fill beneath the line
	const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${padding + innerH} L ${points[0].x.toFixed(1)} ${padding + innerH} Z`;

	const latestScore = ordered[ordered.length - 1].anomalyScore;
	const lineColor = scoreColor(latestScore);

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<Activity size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Anomaly Signal History</h3>
				</div>
				<div className="flex items-center gap-2">
					<StatusPill label={`${history.length} scans`} tone="neutral" />
					<StatusPill
						label={`latest ${latestScore.toFixed(0)}`}
						tone={scoreTone(latestScore)}
					/>
				</div>
			</div>

			<svg
				width={width}
				height={height}
				aria-label="Anomaly score over time"
				className="mb-3"
			>
				{/* Y-axis */}
				<line
					x1={padding}
					y1={padding}
					x2={padding}
					y2={padding + innerH}
					stroke="var(--line)"
					strokeWidth={1}
				/>
				{/* X-axis baseline */}
				<line
					x1={padding}
					y1={padding + innerH}
					x2={padding + innerW}
					y2={padding + innerH}
					stroke="var(--line)"
					strokeWidth={1}
				/>
				{/* Danger threshold at 70 */}
				{(() => {
					const thresholdY =
						padding +
						innerH -
						((70 - minScore) / (maxScore - minScore)) * innerH;
					return (
						<line
							x1={padding}
							y1={thresholdY}
							x2={padding + innerW}
							y2={thresholdY}
							stroke="var(--danger)"
							strokeWidth={0.5}
							strokeDasharray="4 4"
							opacity={0.5}
						/>
					);
				})()}

				{/* Area fill */}
				<path d={areaPath} fill={lineColor} opacity={0.08} />
				{/* Line */}
				<path d={linePath} stroke={lineColor} strokeWidth={1.5} fill="none" />
				{/* Data points */}
				{points.map((p) => (
					<circle
						key={p.entry._id}
						cx={p.x}
						cy={p.y}
						r={3}
						fill={scoreColor(p.entry.anomalyScore)}
						stroke="var(--bg)"
						strokeWidth={1.5}
					/>
				))}
			</svg>

			{/* Timeline entries */}
			<div className="space-y-1.5 max-h-48 overflow-y-auto">
				{ordered.map((entry) => (
					<div
						key={entry._id}
						className="flex items-center justify-between gap-2 text-xs"
					>
						<span className="text-[var(--sea-ink-soft)] min-w-[120px]">
							{formatTimestamp(entry.analyzedAt)}
						</span>
						<StatusPill
							label={`score ${entry.anomalyScore.toFixed(0)}`}
							tone={scoreTone(entry.anomalyScore)}
						/>
						{entry.findingCount > 0 && (
							<StatusPill
								label={`${entry.findingCount} findings`}
								tone={entry.findingCount > 3 ? "warning" : "neutral"}
							/>
						)}
						<span className="text-[var(--sea-ink-soft)] truncate flex-1">
							{entry.repositoryName}
						</span>
					</div>
				))}
			</div>
		</div>
	);
}
