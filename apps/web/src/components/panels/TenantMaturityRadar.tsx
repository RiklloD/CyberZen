import { Radar } from "lucide-react";
import StatusPill from "../StatusPill";

export interface TenantMaturityRadarProps {
	totalRepositories: number;
	assessedRepositories: number;
	levelDistribution: {
		level1: number;
		level2: number;
		level3: number;
		level4: number;
		level5: number;
	};
	averageScore: number;
}

const LEVEL_META: { level: number; label: string; angle: number }[] = [
	{ level: 1, label: "Initial", angle: -90 },
	{ level: 2, label: "Managed", angle: -90 + 72 },
	{ level: 3, label: "Defined", angle: -90 + 144 },
	{ level: 4, label: "Quantitatively Managed", angle: -90 + 216 },
	{ level: 5, label: "Optimising", angle: -90 + 288 },
];

function polar(cx: number, cy: number, r: number, angleDeg: number) {
	const a = (angleDeg * Math.PI) / 180;
	return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}

export default function TenantMaturityRadar({
	totalRepositories,
	assessedRepositories,
	levelDistribution,
	averageScore }: TenantMaturityRadarProps) {
	const counts = [
		levelDistribution.level1,
		levelDistribution.level2,
		levelDistribution.level3,
		levelDistribution.level4,
		levelDistribution.level5,
	];
	const maxCount = Math.max(...counts, 1);
	const size = 260;
	const cx = size / 2;
	const cy = size / 2;
	const maxR = size / 2 - 32;

	const points = LEVEL_META.map((m, i) => {
		const r = (counts[i] / maxCount) * maxR;
		return polar(cx, cy, r, m.angle);
	});
	const polygon = points.map((p) => `${p.x},${p.y}`).join(" ");

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<Radar size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">CMMI Distribution</h3>
				</div>
				<div className="flex items-center gap-1.5">
					<StatusPill
						label={`${assessedRepositories}/${totalRepositories} assessed`}
						tone="neutral"
					/>
					<StatusPill label={`avg ${averageScore}`} tone="info" />
				</div>
			</div>

			<div className="flex items-center justify-center gap-6 flex-wrap">
				<svg width={size} height={size} aria-hidden>
					{[0.25, 0.5, 0.75, 1].map((scale) => (
						<polygon
							key={scale}
							points={LEVEL_META.map((m) => {
								const p = polar(cx, cy, maxR * scale, m.angle);
								return `${p.x},${p.y}`;
							}).join(" ")}
							fill="none"
							stroke="var(--line)"
							strokeWidth={1}
							strokeDasharray={scale === 1 ? "" : "3 3"}
						/>
					))}
					{LEVEL_META.map((m) => {
						const p = polar(cx, cy, maxR, m.angle);
						return (
							<line
								key={m.level}
								x1={cx}
								y1={cy}
								x2={p.x}
								y2={p.y}
								stroke="var(--line)"
								strokeWidth={1}
							/>
						);
					})}
					<polygon
						points={polygon}
						fill="rgba(158,255,100,0.18)"
						stroke="var(--signal)"
						strokeWidth={1.5}
					/>
					{points.map((p, i) => (
						<circle
							key={LEVEL_META[i].level}
							cx={p.x}
							cy={p.y}
							r={3}
							fill="var(--signal)"
						/>
					))}
					{LEVEL_META.map((m) => {
						const p = polar(cx, cy, maxR + 18, m.angle);
						return (
							<text
								key={m.level}
								x={p.x}
								y={p.y}
								textAnchor="middle"
								dominantBaseline="middle"
								className="text-[10px] font-bold"
								fill="var(--sea-ink-soft)"
							>
								L{m.level}
							</text>
						);
					})}
				</svg>

				<div className="space-y-2 min-w-[180px]">
					{LEVEL_META.map((m, i) => (
						<div
							key={m.level}
							className="flex items-center justify-between gap-3"
						>
							<div className="flex items-center gap-2">
								<span className="text-xs font-semibold text-[var(--sea-ink-soft)]">
									L{m.level}
								</span>
								<span className="text-xs text-[var(--sea-ink)]">{m.label}</span>
							</div>
							<StatusPill
								label={`${counts[i]}`}
								tone={
									counts[i] === 0
										? "neutral"
										: m.level >= 4
											? "success"
											: m.level === 3
												? "info"
												: m.level === 2
													? "warning"
													: "danger"
								}
							/>
						</div>
					))}
				</div>
			</div>
		</div>
	);
}
