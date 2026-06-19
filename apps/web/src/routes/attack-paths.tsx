import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Shield } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import QueryErrorFallback from "../components/QueryErrorFallback";
import { api } from "../lib/convex";
import type { Id } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

export const Route = createFileRoute("/attack-paths")({
	errorComponent: QueryErrorFallback,
	component: AttackPathsPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];
type OverviewFinding = OverviewData["findings"][number];

type GraphNode = {
	id: string;
	type: "package" | "service" | "data_store";
	label: string;
	version?: string;
	ecosystem?: string;
	vulnerabilityCount: number;
	severity?: string;
	isDirect?: boolean;
};
type GraphEdge = { from: string; to: string; type: string };
type GraphData = { nodes: GraphNode[]; edges: GraphEdge[] };

// ---------------------------------------------------------------------------
// Simple force-simulation positions (spring layout without D3)
// ---------------------------------------------------------------------------

type SimNode = GraphNode & { x: number; y: number; vx: number; vy: number };

function useForceLayout(
	nodes: GraphNode[],
	edges: GraphEdge[],
	width: number,
	height: number,
) {
	const [positions, setPositions] = useState<SimNode[]>([]);
	const tickRef = useRef(0);

	useEffect(() => {
		if (!nodes.length) return;

		// Initialise on a circle
		const sim: SimNode[] = nodes.map((n, i) => {
			const angle = (2 * Math.PI * i) / nodes.length;
			const r = Math.min(width, height) * 0.35;
			return {
				...n,
				x: width / 2 + r * Math.cos(angle),
				y: height / 2 + r * Math.sin(angle),
				vx: 0,
				vy: 0 };
		});

		const idxOf = (id: string) => sim.findIndex((n) => n.id === id);

		const tick = () => {
			const alpha = Math.max(0, 1 - tickRef.current / 120);
			if (alpha <= 0) {
				setPositions([...sim]);
				return;
			}
			tickRef.current++;

			// Repulsion between all pairs
			for (let i = 0; i < sim.length; i++) {
				for (let j = i + 1; j < sim.length; j++) {
					const dx = sim[j].x - sim[i].x;
					const dy = sim[j].y - sim[i].y;
					const dist = Math.sqrt(dx * dx + dy * dy) || 1;
					const force = (80 * 80) / (dist * dist);
					sim[i].vx -= (dx / dist) * force * alpha;
					sim[i].vy -= (dy / dist) * force * alpha;
					sim[j].vx += (dx / dist) * force * alpha;
					sim[j].vy += (dy / dist) * force * alpha;
				}
			}

			// Spring attraction along edges
			for (const edge of edges) {
				const si = idxOf(edge.from);
				const sj = idxOf(edge.to);
				if (si < 0 || sj < 0) continue;
				const dx = sim[sj].x - sim[si].x;
				const dy = sim[sj].y - sim[si].y;
				const dist = Math.sqrt(dx * dx + dy * dy) || 1;
				const target = 100;
				const stretch = (dist - target) * 0.05 * alpha;
				sim[si].vx += (dx / dist) * stretch;
				sim[si].vy += (dy / dist) * stretch;
				sim[sj].vx -= (dx / dist) * stretch;
				sim[sj].vy -= (dy / dist) * stretch;
			}

			// Center gravity
			for (const n of sim) {
				n.vx += (width / 2 - n.x) * 0.01 * alpha;
				n.vy += (height / 2 - n.y) * 0.01 * alpha;
			}

			// Integrate + dampen
			for (const n of sim) {
				n.vx *= 0.7;
				n.vy *= 0.7;
				n.x = Math.max(20, Math.min(width - 20, n.x + n.vx));
				n.y = Math.max(20, Math.min(height - 20, n.y + n.vy));
			}

			setPositions([...sim]);
			requestAnimationFrame(tick);
		};

		tickRef.current = 0;
		requestAnimationFrame(tick);
	}, [nodes, edges, width, height]);

	return positions;
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

function nodeColor(node: GraphNode, highlighted?: Set<string>): string {
	if (highlighted?.has(node.id)) {
		return node.vulnerabilityCount > 0 ? "#ef4444" : "#f97316";
	}
	if (node.vulnerabilityCount > 0) {
		const s = node.severity ?? "";
		if (s === "critical") return "#dc2626";
		if (s === "high") return "#ea580c";
		if (s === "medium") return "#ca8a04";
		return "#ef4444";
	}
	if (node.type === "service") return "#3b82f6";
	if (node.type === "data_store") return "#8b5cf6";
	return "#64748b";
}

function nodeRadius(node: GraphNode, edgeCount: number): number {
	return Math.max(8, Math.min(22, 8 + edgeCount * 2));
}

// ---------------------------------------------------------------------------
// SVG Graph component
// ---------------------------------------------------------------------------

function DependencyGraphSvg({
	graphData,
	highlighted,
	onNodeClick }: {
	graphData: GraphData;
	highlighted?: Set<string>;
	onNodeClick?: (id: string) => void;
}) {
	const W = 700;
	const H = 460;
	const positions = useForceLayout(graphData.nodes, graphData.edges, W, H);

	const edgeCounts = useMemo(() => {
		const counts = new Map<string, number>();
		for (const e of graphData.edges) {
			counts.set(e.from, (counts.get(e.from) ?? 0) + 1);
			counts.set(e.to, (counts.get(e.to) ?? 0) + 1);
		}
		return counts;
	}, [graphData.edges]);

	const posMap = useMemo(() => {
		const m = new Map<string, { x: number; y: number }>();
		for (const p of positions) m.set(p.id, { x: p.x, y: p.y });
		return m;
	}, [positions]);

	if (positions.length === 0) {
		return (
			<div
				className="loading-panel rounded-2xl"
				style={{ width: W, height: H }}
			/>
		);
	}

	return (
		<svg
			width={W}
			height={H}
			viewBox={`0 0 ${W} ${H}`}
			style={{ background: "var(--surface-card)", borderRadius: 12 }}
		>
			<defs>
				<marker
					id="arrowhead"
					markerWidth="8"
					markerHeight="6"
					refX="8"
					refY="3"
					orient="auto"
				>
					<polygon points="0 0, 8 3, 0 6" fill="#475569" />
				</marker>
			</defs>

			{/* Edges */}
			{graphData.edges.map((edge, i) => {
				const src = posMap.get(edge.from);
				const dst = posMap.get(edge.to);
				if (!src || !dst) return null;
				return (
					<line
						// biome-ignore lint/suspicious/noArrayIndexKey: static list
						key={i}
						x1={src.x}
						y1={src.y}
						x2={dst.x}
						y2={dst.y}
						stroke={
							highlighted?.has(edge.from) && highlighted?.has(edge.to)
								? "#f97316"
								: "#334155"
						}
						strokeWidth={highlighted?.has(edge.from) ? 2 : 1}
						strokeOpacity={0.6}
						markerEnd="url(#arrowhead)"
					/>
				);
			})}

			{/* Nodes */}
			{positions.map((node) => {
				const r = nodeRadius(node, edgeCounts.get(node.id) ?? 0);
				const color = nodeColor(node, highlighted);
				return (
					<g
						key={node.id}
						transform={`translate(${node.x},${node.y})`}
						style={{ cursor: onNodeClick ? "pointer" : "default" }}
						onClick={() => onNodeClick?.(node.id)}
					>
						<circle
							r={r}
							fill={color}
							fillOpacity={0.85}
							stroke={
								highlighted?.has(node.id) ? "#fff" : "transparent"
							}
							strokeWidth={2}
						/>
						<text
							textAnchor="middle"
							dy="0.35em"
							fontSize={9}
							fill="#fff"
							fontWeight={node.vulnerabilityCount > 0 ? "bold" : "normal"}
							style={{ pointerEvents: "none", userSelect: "none" }}
						>
							{node.label.length > 12
								? `${node.label.slice(0, 11)}…`
								: node.label}
						</text>
					</g>
				);
			})}
		</svg>
	);
}

// ---------------------------------------------------------------------------
// Legend
// ---------------------------------------------------------------------------

function GraphLegend() {
	const items = [
		{ color: "#dc2626", label: "Critical vuln" },
		{ color: "#ea580c", label: "High vuln" },
		{ color: "#ca8a04", label: "Medium/Low vuln" },
		{ color: "#3b82f6", label: "Service" },
		{ color: "#8b5cf6", label: "Data store" },
		{ color: "#64748b", label: "Package" },
	];
	return (
		<div className="flex flex-wrap gap-3 mt-3">
			{items.map(({ color, label }) => (
				<div key={label} className="flex items-center gap-1">
					<span
						style={{
							width: 10,
							height: 10,
							borderRadius: "50%",
							background: color,
							display: "inline-block" }}
					/>
					<span className="text-xs text-[var(--sea-ink-soft)]">{label}</span>
				</div>
			))}
		</div>
	);
}

// ---------------------------------------------------------------------------
// Blast radius score ring
// ---------------------------------------------------------------------------

function BlastRadiusRing({ score }: { score: number }) {
	const r = 44;
	const circ = 2 * Math.PI * r;
	const dash = (score / 100) * circ;
	const color =
		score >= 70 ? "#dc2626" : score >= 40 ? "#f97316" : "#eab308";

	return (
		<div className="flex flex-col items-center gap-1">
			<svg width={100} height={100}>
				<circle cx={50} cy={50} r={r} fill="none" stroke="#1e293b" strokeWidth={8} />
				<circle
					cx={50}
					cy={50}
					r={r}
					fill="none"
					stroke={color}
					strokeWidth={8}
					strokeDasharray={`${dash} ${circ - dash}`}
					strokeLinecap="round"
					transform="rotate(-90 50 50)"
				/>
				<text
					x={50}
					y={50}
					textAnchor="middle"
					dy="0.35em"
					fontSize={18}
					fontWeight="bold"
					fill={color}
				>
					{score}
				</text>
			</svg>
			<span className="text-xs text-[var(--sea-ink-soft)]">Blast Radius</span>
		</div>
	);
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function AttackPathsPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [activeTab, setActiveTab] = useState<
		"graph" | "blast-radius" | "critical-paths"
	>("graph");
	const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);
	const [selectedFindingId, setSelectedFindingId] =
		useState<Id<"findings"> | null>(null);
	const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

	const buildGraph = useMutation(api.attackPaths.buildDependencyGraph);
	const computePaths = useMutation(api.attackPaths.computeAttackPaths);

	const repos = overview?.repositories ?? [];
	const activeRepoId = (selectedRepoId ?? repos[0]?._id) as
		| Id<"repositories">
		| undefined;

	const vizData = useQuery(
		api.attackPaths.getAttackPathVisualization,
		activeRepoId ? { repositoryId: activeRepoId } : "skip",
	);

	const criticalPaths = useQuery(api.attackPaths.getCriticalPaths, {
		tenantSlug: TENANT });

	const findingAttackPath = useQuery(
		api.attackPaths.getAttackPathForFinding,
		selectedFindingId ? { findingId: selectedFindingId } : "skip",
	);

	const openFindings = (overview?.findings ?? []).filter(
		(f: OverviewFinding) =>
			f.status === "open" &&
			(f.severity === "critical" || f.severity === "high") &&
			(!activeRepoId || f.repositoryId === activeRepoId),
	) as OverviewFinding[];

	const graphData: GraphData = useMemo(() => {
		if (!vizData?.graph) return { nodes: [], edges: [] };
		try {
			return JSON.parse(vizData.graph) as GraphData;
		} catch {
			return { nodes: [], edges: [] };
		}
	}, [vizData]);

	const findingGraphData: GraphData = useMemo(() => {
		if (!findingAttackPath?.graph) return { nodes: [], edges: [] };
		try {
			return JSON.parse(findingAttackPath.graph) as GraphData;
		} catch {
			return { nodes: [], edges: [] };
		}
	}, [findingAttackPath]);

	// Highlighted nodes in blast radius view: vuln node + reachable targets
	const blastHighlighted = useMemo(() => {
		if (!findingAttackPath) return undefined;
		const set = new Set<string>();
		const selectedFinding = openFindings.find(
			(f) => f._id === selectedFindingId,
		);
		if (selectedFinding) {
			for (const pkg of selectedFinding.affectedPackages) set.add(pkg);
		}
		for (const t of findingAttackPath.reachableTargets) set.add(t);
		return set;
	}, [findingAttackPath, openFindings, selectedFindingId]);

	const handleBuildGraph = useCallback(async () => {
		if (!activeRepoId) return;
		await buildGraph({ repositoryId: activeRepoId });
	}, [buildGraph, activeRepoId]);

	const handleComputePaths = useCallback(
		async (findingId: Id<"findings">) => {
			await computePaths({ findingId });
		},
		[computePaths],
	);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="loading-panel h-16 rounded-2xl mb-4" />
				<div className="loading-panel h-96 rounded-2xl" />
			</main>
		);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Shield size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Attack Paths</h1>
						<p className="page-subtitle">
							Dependency graph · blast radius · critical attack paths
						</p>
					</div>
				</div>
			</div>

			<div className="page-body space-y-4">
				{/* Repository selector */}
				{repos.length > 1 && (
					<div className="tab-bar">
						{repos.map((r: OverviewRepository) => (
							<button
								key={r._id}
								type="button"
								className={`tab-item${selectedRepoId === r._id || (!selectedRepoId && r._id === repos[0]._id) ? " is-active" : ""}`}
								onClick={() => setSelectedRepoId(r._id)}
							>
								{r.name}
							</button>
						))}
					</div>
				)}

				{/* Feature tabs */}
				<div className="tab-bar">
					{(
						[
							["graph", "Dependency Graph"],
							["blast-radius", "Blast Radius"],
							["critical-paths", "Critical Paths"],
						] as const
					).map(([id, label]) => (
						<button
							key={id}
							type="button"
							className={`tab-item${activeTab === id ? " is-active" : ""}`}
							onClick={() => setActiveTab(id)}
						>
							{label}
						</button>
					))}
				</div>

				{/* ── Tab 1: Dependency Graph ─────────────────────────────── */}
				{activeTab === "graph" && (
					<div>
						<div className="flex items-center justify-between mb-3">
							<h2 className="section-title">Dependency Graph</h2>
							<button
								type="button"
								className="btn btn-sm btn-secondary"
								onClick={handleBuildGraph}
							>
								Build Graph
							</button>
						</div>

						{graphData.nodes.length === 0 ? (
							<div className="card card-sm text-center py-12">
								<p className="text-[var(--sea-ink-soft)] text-sm mb-3">
									No graph data yet. Click "Build Graph" to analyse the
									repository's dependency tree.
								</p>
								<button
									type="button"
									className="btn btn-primary"
									onClick={handleBuildGraph}
								>
									Build Dependency Graph
								</button>
							</div>
						) : (
							<>
								<div className="overflow-x-auto">
									<DependencyGraphSvg
										graphData={graphData}
										onNodeClick={setSelectedNodeId}
									/>
								</div>
								<GraphLegend />

								{selectedNodeId && (
									<div className="card card-sm mt-3">
										{(() => {
											const node = graphData.nodes.find(
												(n) => n.id === selectedNodeId,
											);
											if (!node) return null;
											return (
												<>
													<p className="panel-label mb-1">
														{node.label}
													</p>
													<div className="grid grid-cols-2 gap-2 text-xs text-[var(--sea-ink-soft)]">
														{node.version && (
															<span>
																<b className="text-[var(--sea-ink)]">
																	Version:
																</b>{" "}
																{node.version}
															</span>
														)}
														{node.ecosystem && (
															<span>
																<b className="text-[var(--sea-ink)]">
																	Ecosystem:
																</b>{" "}
																{node.ecosystem}
															</span>
														)}
														<span>
															<b className="text-[var(--sea-ink)]">
																Type:
															</b>{" "}
															{node.type}
														</span>
														<span>
															<b className="text-[var(--sea-ink)]">
																Vulnerabilities:
															</b>{" "}
															{node.vulnerabilityCount}
														</span>
													</div>
												</>
											);
										})()}
									</div>
								)}

								<div className="grid grid-cols-3 gap-3 mt-3">
									<div className="card card-sm text-center">
										<div className="text-2xl font-bold text-[var(--sea-ink)]">
											{graphData.nodes.length}
										</div>
										<div className="text-xs text-[var(--sea-ink-soft)] mt-1">
											Total Nodes
										</div>
									</div>
									<div className="card card-sm text-center">
										<div className="text-2xl font-bold text-[var(--signal)]">
											{
												graphData.nodes.filter(
													(n) => n.vulnerabilityCount > 0,
												).length
											}
										</div>
										<div className="text-xs text-[var(--sea-ink-soft)] mt-1">
											Vulnerable
										</div>
									</div>
									<div className="card card-sm text-center">
										<div className="text-2xl font-bold text-[var(--sea-ink)]">
											{graphData.edges.length}
										</div>
										<div className="text-xs text-[var(--sea-ink-soft)] mt-1">
											Dependencies
										</div>
									</div>
								</div>
							</>
						)}
					</div>
				)}

				{/* ── Tab 2: Blast Radius ─────────────────────────────────── */}
				{activeTab === "blast-radius" && (
					<div className="grid gap-4 xl:grid-cols-[1fr_1.5fr]">
						{/* Finding selector */}
						<div>
							<h2 className="section-title mb-3">
								Select Critical Finding
							</h2>
							{openFindings.length === 0 ? (
								<p className="text-xs text-[var(--sea-ink-soft)]">
									No critical or high findings currently open.
								</p>
							) : (
								<div className="space-y-2">
									{openFindings.slice(0, 15).map((f: OverviewFinding) => (
										<button
											key={f._id}
											type="button"
											className={`card card-sm w-full text-left transition-all${selectedFindingId === f._id ? " ring-2 ring-[var(--signal)]" : ""}`}
											onClick={async () => {
												setSelectedFindingId(f._id as Id<"findings">);
												await handleComputePaths(
													f._id as Id<"findings">,
												);
											}}
										>
											<div className="flex items-center justify-between mb-1">
												<span
													className={`text-xs font-semibold uppercase tracking-wide ${f.severity === "critical" ? "text-red-500" : "text-orange-500"}`}
												>
													{f.severity}
												</span>
												{findingAttackPath &&
													selectedFindingId === f._id && (
														<span className="text-xs font-bold text-red-500">
															BR:{" "}
															{findingAttackPath.blastRadius}/100
														</span>
													)}
											</div>
											<p className="text-xs text-[var(--sea-ink)] line-clamp-2">
												{f.title}
											</p>
											{f.affectedPackages.length > 0 && (
												<p className="text-xs text-[var(--sea-ink-soft)] mt-1 truncate">
													{f.affectedPackages.slice(0, 3).join(", ")}
												</p>
											)}
										</button>
									))}
								</div>
							)}
						</div>

						{/* Blast radius visualisation */}
						<div>
							{selectedFindingId && findingAttackPath ? (
								<>
									<div className="flex items-center gap-6 mb-4">
										<BlastRadiusRing
											score={findingAttackPath.blastRadius}
										/>
										<div className="space-y-2 flex-1">
											<div>
												<p className="panel-label mb-1">
													Reachable Targets
												</p>
												{findingAttackPath.reachableTargets.length ===
												0 ? (
													<p className="text-xs text-[var(--sea-ink-soft)]">
														None detected
													</p>
												) : (
													<div className="flex flex-wrap gap-1">
														{findingAttackPath.reachableTargets.map(
															(t) => (
																<span
																	key={t}
																	className="text-xs px-2 py-0.5 rounded-full bg-orange-500/15 text-orange-400"
																>
																	{t}
																</span>
															),
														)}
													</div>
												)}
											</div>
											<div>
												<p className="panel-label mb-1">Chokepoints</p>
												{findingAttackPath.chokePoints.length === 0 ? (
													<p className="text-xs text-[var(--sea-ink-soft)]">
														None identified
													</p>
												) : (
													<div className="flex flex-wrap gap-1">
														{findingAttackPath.chokePoints.map((c) => (
															<span
																key={c}
																className="text-xs px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400"
															>
																{c}
															</span>
														))}
													</div>
												)}
											</div>
										</div>
									</div>

									{findingGraphData.nodes.length > 0 ? (
										<>
											<p className="text-xs text-[var(--sea-ink-soft)] mb-2">
												<span className="text-red-500 font-semibold">
													Red
												</span>{" "}
												= vulnerable ·{" "}
												<span className="text-orange-500 font-semibold">
													Orange
												</span>{" "}
												= reachable
											</p>
											<div className="overflow-x-auto">
												<DependencyGraphSvg
													graphData={findingGraphData}
													highlighted={blastHighlighted}
												/>
											</div>
										</>
									) : (
										<p className="text-xs text-[var(--sea-ink-soft)]">
											Build the dependency graph first to see the
											visualisation.
										</p>
									)}
								</>
							) : (
								<div className="card card-sm flex items-center justify-center py-16 text-center">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										Select a finding on the left to compute its blast
										radius.
									</p>
								</div>
							)}
						</div>
					</div>
				)}

				{/* ── Tab 3: Critical Paths ──────────────────────────────── */}
				{activeTab === "critical-paths" && (
					<div>
						<h2 className="section-title mb-3">
							Top 10 Highest-Risk Attack Paths
						</h2>

						{!criticalPaths || criticalPaths.length === 0 ? (
							<div className="card card-sm text-center py-12">
								<p className="text-[var(--sea-ink-soft)] text-sm">
									No attack paths computed yet. Go to "Blast Radius" and
									analyse your critical findings.
								</p>
							</div>
						) : (
							<div className="space-y-3">
								{criticalPaths.map((path, rank) => {
									const finding = overview.findings.find(
										(f: OverviewFinding) => f._id === path.findingId,
									) as OverviewFinding | undefined;
									return (
										<div
											key={path._id}
											className="card card-sm flex gap-4 items-start"
										>
											{/* Rank badge */}
											<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface-raised)] flex items-center justify-center text-xs font-bold text-[var(--sea-ink-soft)]">
												#{rank + 1}
											</div>

											<div className="flex-1 min-w-0">
												<div className="flex items-center justify-between mb-1">
													<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
														{finding?.title ?? "Unknown finding"}
													</p>
													<BlastRadiusRing score={path.blastRadius} />
												</div>

												{finding && (
													<span
														className={`text-xs font-semibold uppercase tracking-wide mr-2 ${finding.severity === "critical" ? "text-red-500" : finding.severity === "high" ? "text-orange-500" : "text-yellow-500"}`}
													>
														{finding.severity}
													</span>
												)}

												{path.reachableTargets.length > 0 && (
													<div className="mt-2">
														<p className="panel-label mb-1">
															Reachable targets
														</p>
														<div className="flex flex-wrap gap-1">
															{path.reachableTargets
																.slice(0, 5)
																.map((t) => (
																	<span
																		key={t}
																		className="text-xs px-2 py-0.5 rounded-full bg-orange-500/15 text-orange-400"
																	>
																		{t}
																	</span>
																))}
														</div>
													</div>
												)}

												{path.chokePoints.length > 0 && (
													<div className="mt-2">
														<p className="panel-label mb-1">
															Chokepoints (fix to break path)
														</p>
														<div className="flex flex-wrap gap-1">
															{path.chokePoints.map((c) => (
																<span
																	key={c}
																	className="text-xs px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400"
																>
																	{c}
																</span>
															))}
														</div>
													</div>
												)}
											</div>
										</div>
									);
								})}
							</div>
						)}
					</div>
				)}
			</div>
		</main>
	);
}
