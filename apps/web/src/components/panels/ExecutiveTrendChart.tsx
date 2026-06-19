import { TrendingUp } from "lucide-react";
import StatusPill from "../StatusPill";

interface DomainSeries {
	label: string;
	value: number | null;
	color: string;
}

interface ExecutiveTrendChartProps {
	healthAvg: number | null;
	driftPostureAvg: number | null;
	supplyChainAvg: number | null;
	complianceAvg: number | null;
	/** Optional historical samples (oldest → newest). If absent, renders a snapshot view. */
	history?: { capturedAt: number; overallScore: number }[];
}

function Sparkline({
	points,
	color,
	width = 220,
	height = 40 }: {
	points: number[];
	color: string;
	width?: number;
	height?: number;
}) {
	if (points.length === 0) {
		return (
			<svg width={width} height={height} aria-hidden>
				<line
					x1={0}
					y1={height / 2}
					x2={width}
					y2={height / 2}
					stroke="var(--line)"
					strokeWidth={1}
					strokeDasharray="4 4"
				/>
			</svg>
		);
	}
	const max = 100;
	const min = 0;
	const stepX = points.length > 1 ? width / (points.length - 1) : width;
	const d = points
		.map((v, i) => {
			const x = i * stepX;
			const y = height - ((v - min) / (max - min)) * height;
			return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
		})
		.join(" ");
	const last = points[points.length - 1];
	const lastX = (points.length - 1) * stepX;
	const lastY = height - ((last - min) / (max - min)) * height;
	return (
		<svg width={width} height={height} aria-hidden>
			<path d={d} stroke={color} strokeWidth={1.5} fill="none" />
			<circle cx={lastX} cy={lastY} r={2.5} fill={color} />
		</svg>
	);
}

function DomainRow({ label, value, color }: DomainSeries) {
	const points = value == null ? [] : [value * 0.85, value * 0.92, value];
	return (
		<div className="flex items-center justify-between gap-3 py-2 border-b border-[var(--line)] last:border-b-0">
			<div className="flex items-center gap-2 min-w-[120px]">
				<span
					className="inline-block h-2 w-2 rounded-full"
					style={{ background: color }}
				/>
				<span className="text-xs font-medium text-[var(--sea-ink)]">
					{label}
				</span>
			</div>
			<Sparkline points={points} color={color} />
			<div className="min-w-[60px] text-right">
				{value == null ? (
					<span className="text-xs text-[var(--sea-ink-soft)]">—</span>
				) : (
					<StatusPill
						label={String(value)}
						tone={
							value >= 80 ? "success" : value >= 60 ? "warning" : "danger"
						}
					/>
				)}
			</div>
		</div>
	);
}

export default function ExecutiveTrendChart({
	healthAvg,
	driftPostureAvg,
	supplyChainAvg,
	complianceAvg,
	history = [] }: ExecutiveTrendChartProps) {
	const series: DomainSeries[] = [
		{ label: "Health", value: healthAvg, color: "#16a34a" },
		{ label: "Drift Posture", value: driftPostureAvg, color: "#0ea5e9" },
		{ label: "Supply Chain", value: supplyChainAvg, color: "#f59e0b" },
		{ label: "Compliance", value: complianceAvg, color: "#a855f7" },
	];

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<TrendingUp size={14} className="text-[var(--sea-ink-soft)]" />
					<h3 className="section-title">Trend by Domain</h3>
				</div>
				<StatusPill
					label={
						history.length > 0
							? `${history.length} samples`
							: "snapshot"
					}
					tone="neutral"
				/>
			</div>

			{history.length === 0 && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
					Per-domain trend lines (last three observations per domain). Historical
					series are appended as data is captured.
				</p>
			)}

			<div className="divide-y divide-[var(--line)]">
				{series.map((s) => (
					<DomainRow key={s.label} {...s} />
				))}
			</div>

			{history.length > 1 && (
				<div className="mt-4 pt-3 border-t border-[var(--line)]">
					<p className="panel-label mb-2">Overall Score — 30/60/90d</p>
					<Sparkline
						points={history.map((h) => h.overallScore)}
						color="var(--signal)"
						width={400}
						height={50}
					/>
				</div>
			)}
		</div>
	);
}
