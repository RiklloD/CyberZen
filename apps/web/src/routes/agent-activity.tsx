import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { Bot, Brain, Shield, Crosshair, Eye, Zap, Activity, DollarSign, ChevronDown, ChevronRight, Code2, FileJson, Cpu, GraduationCap } from "lucide-react";
import { useState } from "react";
import HubTabs from "../components/HubTabs";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import type { Id } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/agent-activity")({
	errorComponent: RouteErrorBoundary,
	component: AgentsPage });

const AGENTS_TABS = [
	{ key: "agents", label: "AI Agent System", icon: Cpu, to: "/agent-activity" },
	{ key: "neural-memory", label: "Neural Memory", icon: Brain, to: "/neural-memory" },
	{ key: "learning", label: "Agents & Learning", icon: Bot, to: "/agents" },
];

function AgentsPage() {
	const TENANT = useTenantSlug();
	const agentTasks = useQuery(api.agentOrchestrator.getAgentTasksForTenant, {
		tenantSlug: TENANT,
		limit: 50 });
	const llmUsage = useQuery(api.agentOrchestrator.getLLMUsageForTenant, {
		tenantSlug: TENANT });
	const [activeTab, setActiveTab] = useState<
		"activity" | "remediation" | "redblue" | "prompt_injection" | "usage"
	>("activity");
	const [expandedTask, setExpandedTask] = useState<string | null>(null);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Bot size={24} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">AI Agent System</h1>
						<p className="page-subtitle">
							Autonomous LLM-powered security analysis · Remediation ·
							Exploit validation · Adversarial Red-Blue · Prompt injection
						</p>
					</div>
				</div>
			</div>

			<HubTabs tabs={AGENTS_TABS} activeKey="agents" />

			<div className="page-body">
				{/* Stats Row */}
				<div className="grid gap-4 mb-6 sm:grid-cols-2 lg:grid-cols-4">
					<StatCard
						icon={<Activity size={18} />}
						label="Total Agent Tasks"
						value={agentTasks?.length.toString() ?? "—"}
						sublabel={`${agentTasks?.filter((t) => t.status === "running").length ?? 0} running`}
					/>
					<StatCard
						icon={<Zap size={18} />}
						label="Completed"
						value={(agentTasks?.filter((t) => t.status === "completed").length ?? 0).toString()}
						sublabel={`${agentTasks?.filter((t) => t.status === "failed").length ?? 0} failed`}
					/>
					<StatCard
						icon={<Cpu size={18} />}
						label="LLM Calls"
						value={(llmUsage?.records.length ?? 0).toString()}
						sublabel={`${llmUsage?.totalTokens.toLocaleString() ?? 0} tokens`}
					/>
					<StatCard
						icon={<DollarSign size={18} />}
						label="Est. LLM Cost"
						value={`$${(llmUsage?.totalCostUsd ?? 0).toFixed(4)}`}
						sublabel="this period"
					/>
				</div>

				{/* Tabs */}
				<div className="tab-bar mb-5">
					<TabButton
						active={activeTab === "activity"}
						onClick={() => setActiveTab("activity")}
						icon={<Activity size={15} />}
						label="Agent Activity"
					/>
					<TabButton
						active={activeTab === "remediation"}
						onClick={() => setActiveTab("remediation")}
						icon={<Shield size={15} />}
						label="Remediation Proposals"
					/>
					<TabButton
						active={activeTab === "redblue"}
						onClick={() => setActiveTab("redblue")}
						icon={<Crosshair size={15} />}
						label="Red-Blue Adversarial"
					/>
					<TabButton
						active={activeTab === "prompt_injection"}
						onClick={() => setActiveTab("prompt_injection")}
						icon={<Eye size={15} />}
						label="Prompt Injection"
					/>
					<TabButton
						active={activeTab === "usage"}
						onClick={() => setActiveTab("usage")}
						icon={<DollarSign size={15} />}
						label="LLM Usage"
					/>
				</div>

				{/* Tab Content */}
				{activeTab === "activity" && (
					<AgentActivityPanel
						tasks={agentTasks ?? []}
						expandedTask={expandedTask}
						setExpandedTask={setExpandedTask}
					/>
				)}
				{activeTab === "remediation" && (
					<RemediationPanel tenantSlug={TENANT} />
				)}
				{activeTab === "redblue" && (
					<RedBluePanel tenantSlug={TENANT} />
				)}
				{activeTab === "prompt_injection" && (
					<PromptInjectionPanel tenantSlug={TENANT} />
				)}
				{activeTab === "usage" && <LLMUsagePanel usage={llmUsage} />}
			</div>
		</main>
	);
}

// ─── Agent Activity Panel ────────────────────────────────────────────────────

function AgentActivityPanel({
	tasks,
	expandedTask,
	setExpandedTask }: {
	tasks: Array<{
		_id: string;
		agentType: string;
		status: string;
		priority: string;
		inputSummary: string;
		outputSummary?: string;
		llmProvider?: string;
		llmModel?: string;
		tokenUsage?: { prompt: number; completion: number; total: number; costUsd: number };
		startedAt?: number;
		completedAt?: number;
		error?: string;
		trigger: string;
	}>;
	expandedTask: string | null;
	setExpandedTask: (id: string | null) => void;
}) {
	if (tasks.length === 0) {
		return (
			<div className="card p-8 text-center text-[var(--text-dim)]">
				<Bot size={32} className="mx-auto mb-3 opacity-50" />
				<p>No agent tasks yet. Agents activate automatically when findings are detected.</p>
				<p className="text-sm mt-2">
					You can also trigger agents manually from the Findings page or Repository pages.
				</p>
			</div>
		);
	}

	return (
		<div className="space-y-2">
			{tasks.map((task) => (
				<div key={task._id} className="card overflow-hidden">
					<button
						type="button"
						className="w-full flex items-center gap-3 p-4 text-left hover:bg-[var(--surface-soft)] transition-colors"
						onClick={() =>
							setExpandedTask(expandedTask === task._id ? null : task._id)
						}
					>
						{expandedTask === task._id ? (
							<ChevronDown size={16} className="text-[var(--text-dim)] shrink-0" />
						) : (
							<ChevronRight size={16} className="text-[var(--text-dim)] shrink-0" />
						)}
						<AgentTypeIcon type={task.agentType} />
						<div className="flex-1 min-w-0">
							<div className="flex items-center gap-2">
								<span className="font-medium text-sm">{task.agentType.replace(/_/g, " ")}</span>
								<StatusPill tone={taskStatusTone(task.status)}>{task.status}</StatusPill>
								<span className="text-xs text-[var(--text-dim)]">{task.trigger}</span>
							</div>
							<p className="text-xs text-[var(--text-dim)] truncate mt-0.5">
								{task.inputSummary}
							</p>
						</div>
						{task.completedAt && (
							<span className="text-xs text-[var(--text-dim)] shrink-0">
								{formatTimestamp(task.completedAt)}
							</span>
						)}
					</button>

					{expandedTask === task._id && (
						<div className="border-t border-[var(--line)] p-4 bg-[var(--surface-soft)]">
							{task.outputSummary && (
								<div className="mb-3">
									<h4 className="text-xs font-semibold text-[var(--text-dim)] mb-1">OUTPUT</h4>
									<p className="text-sm">{task.outputSummary}</p>
								</div>
							)}
							{task.error && (
								<div className="mb-3 p-3 rounded-lg bg-[var(--danger-bg,rgba(239,68,68,0.1))] border border-[var(--danger,rgba(239,68,68,0.3))]">
									<h4 className="text-xs font-semibold text-[var(--danger,red)] mb-1">ERROR</h4>
									<p className="text-sm font-mono">{task.error}</p>
								</div>
							)}
							{task.llmProvider && (
								<div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
									<div>
										<span className="text-[var(--text-dim)]">Provider:</span>{" "}
										<span className="font-mono">{task.llmProvider}</span>
									</div>
									<div>
										<span className="text-[var(--text-dim)]">Model:</span>{" "}
										<span className="font-mono">{task.llmModel}</span>
									</div>
									{task.tokenUsage && (
										<>
											<div>
												<span className="text-[var(--text-dim)]">Tokens:</span>{" "}
												{task.tokenUsage.total.toLocaleString()}
											</div>
											<div>
												<span className="text-[var(--text-dim)]">Cost:</span> $
												{task.tokenUsage.costUsd.toFixed(4)}
											</div>
										</>
									)}
								</div>
							)}
							<ReasoningLogViewer taskId={task._id as Id<"agentTasks">} />
						</div>
					)}
				</div>
			))}
		</div>
	);
}

// ─── Reasoning Log Viewer ────────────────────────────────────────────────────

function ReasoningLogViewer({ taskId }: { taskId: Id<"agentTasks"> }) {
	const log = useQuery(api.agentOrchestrator.getReasoningLog, { agentTaskId: taskId });
	const [showMessages, setShowMessages] = useState(false);

	if (!log) return null;

	return (
		<div className="mt-4 border-t border-[var(--line)] pt-3">
			<button
				type="button"
				className="flex items-center gap-2 text-xs text-[var(--signal)] hover:underline"
				onClick={() => setShowMessages(!showMessages)}
			>
				<FileJson size={13} />
				{showMessages ? "Hide" : "Show"} reasoning chain ({log.messages.length} messages)
			</button>

			{showMessages && (
				<div className="mt-3 space-y-2 max-h-96 overflow-y-auto">
					{log.messages.map((msg, i) => (
						<div
							key={i}
							className="p-3 rounded-lg bg-[var(--bg)] border border-[var(--line)] text-xs"
						>
							<div className="flex items-center gap-2 mb-1">
								<StatusPill tone={roleTone(msg.role)}>{msg.role}</StatusPill>
								<span className="text-[var(--text-dim)]">
									{formatTimestamp(msg.timestamp)}
								</span>
							</div>
							<pre className="whitespace-pre-wrap break-words font-mono text-[var(--text-dim)]">
								{msg.content.slice(0, 2000)}
								{msg.content.length > 2000 ? "\n... (truncated)" : ""}
							</pre>
						</div>
					))}
				</div>
			)}

			<div className="mt-2 text-xs text-[var(--text-dim)] flex gap-4">
				<span>Latency: {log.latencyMs}ms</span>
				<span>Tokens: {log.totalTokens}</span>
				<span>Cost: ${log.totalCostUsd.toFixed(4)}</span>
			</div>
		</div>
	);
}

// ─── Remediation Proposals Panel ────────────────────────────────────────────

function RemediationPanel({ tenantSlug }: { tenantSlug: string }) {
	const proposals = useQuery(api.agentOrchestrator.getRemediationProposalsForTenant, {
		tenantSlug,
		limit: 20 });

	if (!proposals || proposals.length === 0) {
		return (
			<div className="card p-8 text-center text-[var(--text-dim)]">
				<Shield size={32} className="mx-auto mb-3 opacity-50" />
				<p>No remediation proposals yet.</p>
				<p className="text-sm mt-2">
					Proposals are generated automatically when critical/high findings are detected.
				</p>
			</div>
		);
	}

	return (
		<div className="space-y-3">
			{proposals.map((p) => (
				<div key={p._id} className="card p-4">
					<div className="flex items-start justify-between mb-2">
						<div>
							<h3 className="font-medium text-sm">
								{p.vulnerabilityExplanation.slice(0, 100)}
							</h3>
							<div className="flex items-center gap-2 mt-1">
								<StatusPill tone={p.status === "pr_opened" ? "success" : p.status === "proposed" ? "info" : "neutral"}>
									{p.status}
								</StatusPill>
								<span className="text-xs text-[var(--text-dim)]">
									Confidence: {Math.round(p.confidence * 100)}%
								</span>
								{p.requiresArchitecturalChange && (
									<StatusPill tone="warning">Needs arch change</StatusPill>
								)}
							</div>
						</div>
						{p.prUrl && (
							<a
								href={p.prUrl}
								target="_blank"
								rel="noopener noreferrer"
								className="text-xs text-[var(--signal)] hover:underline shrink-0"
							>
								View PR →
							</a>
						)}
					</div>
					<p className="text-xs text-[var(--text-dim)] mt-2">{p.fixDescription}</p>
					{p.fixDiff && (
						<pre className="mt-2 p-3 rounded-lg bg-[var(--bg)] border border-[var(--line)] text-xs font-mono overflow-x-auto max-h-40">
							{p.fixDiff.slice(0, 1000)}
						</pre>
					)}
				</div>
			))}
		</div>
	);
}

// ─── Red-Blue Panel ──────────────────────────────────────────────────────────

function RedBluePanel({ tenantSlug }: { tenantSlug: string }) {
	const attacks = useQuery(api.agentOrchestrator.getRedTeamAttacksForTenant, {
		tenantSlug,
		limit: 30 });
	const rules = useQuery(api.agentOrchestrator.getBlueTeamRulesForTenant, {
		tenantSlug });

	return (
		<div className="space-y-6">
			<div>
				<h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
					<Crosshair size={16} className="text-[var(--danger,red)]" />
					Red Team Attacks ({attacks?.length ?? 0})
				</h3>
				{attacks && attacks.length > 0 ? (
					<div className="space-y-2">
						{attacks.map((a) => (
							<div key={a._id} className="card p-3">
								<div className="flex items-center gap-2 mb-1">
									<StatusPill tone={attackOutcomeTone(a.outcome)}>{a.outcome}</StatusPill>
									<span className="text-xs font-medium">Round {a.roundNumber}: {a.attackVector}</span>
									{a.targetEndpoint && (
										<span className="text-xs text-[var(--text-dim)]">{a.targetEndpoint}</span>
									)}
								</div>
								<p className="text-xs text-[var(--text-dim)] font-mono truncate">
									{a.payload.slice(0, 150)}
								</p>
							</div>
						))}
					</div>
				) : (
					<p className="text-sm text-[var(--text-dim)]">No Red Team attacks logged yet.</p>
				)}
			</div>

			<div>
				<h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
					<Shield size={16} className="text-[var(--signal)]" />
					Blue Team Detection Rules ({rules?.length ?? 0})
				</h3>
				{rules && rules.length > 0 ? (
					<div className="space-y-2">
						{rules.map((r) => (
							<div key={r._id} className="card p-3">
								<div className="flex items-center gap-2 mb-1">
									<StatusPill tone="info">{r.ruleType}</StatusPill>
									<span className="text-xs font-medium">{r.ruleName}</span>
									{r.effectiveness !== undefined && (
										<span className="text-xs text-[var(--text-dim)]">
											Effectiveness: {Math.round(r.effectiveness * 100)}%
										</span>
									)}
								</div>
								<pre className="text-xs font-mono text-[var(--text-dim)] mt-1 p-2 rounded bg-[var(--bg)] border border-[var(--line)] overflow-x-auto max-h-32">
									{r.ruleContent.slice(0, 500)}
								</pre>
							</div>
						))}
					</div>
				) : (
					<p className="text-sm text-[var(--text-dim)]">No detection rules generated yet.</p>
				)}
			</div>
		</div>
	);
}

// ─── Prompt Injection Panel ──────────────────────────────────────────────────

function PromptInjectionPanel({ tenantSlug }: { tenantSlug: string }) {
	const findings = useQuery(api.agentOrchestrator.getPromptInjectionFindingsForTenant, {
		tenantSlug });

	if (!findings || findings.length === 0) {
		return (
			<div className="card p-8 text-center text-[var(--text-dim)]">
				<Eye size={32} className="mx-auto mb-3 opacity-50" />
				<p>No prompt injection findings.</p>
				<p className="text-sm mt-2">
					Run a prompt injection scan from the repository page to detect LLM vulnerabilities.
				</p>
			</div>
		);
	}

	return (
		<div className="space-y-2">
			{findings.map((f) => (
				<div key={f._id} className="card p-4">
					<div className="flex items-center gap-2 mb-2">
						<StatusPill tone={severityToneLocal(f.outcome)}>{f.outcome}</StatusPill>
						<span className="text-xs font-medium">{f.vulnerabilityType}</span>
					</div>
					<p className="text-xs text-[var(--text-dim)] mb-1">
						<strong>Chain:</strong> {f.llmCallChain}
					</p>
					<p className="text-xs text-[var(--text-dim)] mb-1">
						<strong>Input source:</strong> {f.inputSource}
					</p>
					<pre className="text-xs font-mono p-2 rounded bg-[var(--bg)] border border-[var(--line)] mt-2 overflow-x-auto max-h-32">
						{f.payload.slice(0, 300)}
					</pre>
					{f.mitigationCode && (
						<div className="mt-2">
							<h4 className="text-xs font-semibold text-[var(--signal)] mb-1">Mitigation:</h4>
							<pre className="text-xs font-mono p-2 rounded bg-[var(--bg)] border border-[var(--line)] overflow-x-auto max-h-32">
								{f.mitigationCode.slice(0, 500)}
							</pre>
						</div>
					)}
				</div>
			))}
		</div>
	);
}

// ─── LLM Usage Panel ─────────────────────────────────────────────────────────

function LLMUsagePanel({
	usage }: {
	usage: { totalCostUsd: number; totalTokens: number; records: Array<Record<string, unknown>> } | undefined;
}) {
	if (!usage || usage.records.length === 0) {
		return (
			<div className="card p-8 text-center text-[var(--text-dim)]">
				<DollarSign size={32} className="mx-auto mb-3 opacity-50" />
				<p>No LLM usage recorded yet.</p>
			</div>
		);
	}

	// Aggregate by provider+model
	const byModel: Record<string, { cost: number; tokens: number; count: number }> = {};
	for (const r of usage.records) {
		const key = `${r.provider}/${r.model}`;
		if (!byModel[key]) byModel[key] = { cost: 0, tokens: 0, count: 0 };
		byModel[key].cost += r.estimatedCostUsd as number;
		byModel[key].tokens += (r.promptTokens as number) + (r.completionTokens as number);
		byModel[key].count += 1;
	}

	return (
		<div className="space-y-4">
			<div className="grid grid-cols-3 gap-4">
				<div className="card p-4 text-center">
					<div className="text-2xl font-bold">${usage.totalCostUsd.toFixed(4)}</div>
					<div className="text-xs text-[var(--text-dim)]">Total Cost</div>
				</div>
				<div className="card p-4 text-center">
					<div className="text-2xl font-bold">{usage.totalTokens.toLocaleString()}</div>
					<div className="text-xs text-[var(--text-dim)]">Total Tokens</div>
				</div>
				<div className="card p-4 text-center">
					<div className="text-2xl font-bold">{usage.records.length}</div>
					<div className="text-xs text-[var(--text-dim)]">LLM Calls</div>
				</div>
			</div>

			<h3 className="text-sm font-semibold">By Model</h3>
			<div className="card overflow-hidden">
				<table className="w-full text-sm">
					<thead className="bg-[var(--surface-soft)] text-xs text-[var(--text-dim)]">
						<tr>
							<th className="text-left p-3">Model</th>
							<th className="text-right p-3">Calls</th>
							<th className="text-right p-3">Tokens</th>
							<th className="text-right p-3">Cost</th>
						</tr>
					</thead>
					<tbody>
						{Object.entries(byModel).map(([model, data]) => (
							<tr key={model} className="border-t border-[var(--line)]">
								<td className="p-3 font-mono text-xs">{model}</td>
								<td className="p-3 text-right">{data.count}</td>
								<td className="p-3 text-right">{data.tokens.toLocaleString()}</td>
								<td className="p-3 text-right">${data.cost.toFixed(4)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

// ─── Helper Components ───────────────────────────────────────────────────────

function StatCard({
	icon,
	label,
	value,
	sublabel }: {
	icon: React.ReactNode;
	label: string;
	value: string;
	sublabel: string;
}) {
	return (
		<div className="card p-4">
			<div className="flex items-center gap-2 text-[var(--text-dim)] mb-1">
				{icon}
				<span className="text-xs">{label}</span>
			</div>
			<div className="text-xl font-bold">{value}</div>
			<div className="text-xs text-[var(--text-dim)]">{sublabel}</div>
		</div>
	);
}

function TabButton({
	active,
	onClick,
	icon,
	label }: {
	active: boolean;
	onClick: () => void;
	icon: React.ReactNode;
	label: string;
}) {
	return (
		<button
			type="button"
			className={`tab-btn ${active ? "is-active" : ""}`}
			onClick={onClick}
		>
			<span className="inline-flex items-center gap-1.5">
				{icon}
				{label}
			</span>
		</button>
	);
}

function AgentTypeIcon({ type }: { type: string }) {
	const icons: Record<string, React.ReactNode> = {
		remediation: <Shield size={16} className="text-[var(--signal)]" />,
		pr_generation: <Code2 size={16} className="text-[var(--signal)]" />,
		exploit_validation: <Crosshair size={16} className="text-[var(--danger,red)]" />,
		red_team: <Crosshair size={16} className="text-[var(--danger,red)]" />,
		blue_team: <Shield size={16} className="text-[var(--signal)]" />,
		blast_radius: <Brain size={16} className="text-[var(--signal)]" />,
		prompt_injection: <Eye size={16} className="text-[var(--warning,#f59e0b)]" />,
		surface_reduction: <Zap size={16} className="text-[var(--signal)]" />,
		regulatory_drift: <FileJson size={16} className="text-[var(--signal)]" /> };
	return icons[type] ?? <Bot size={16} className="text-[var(--text-dim)]" />;
}

function taskStatusTone(status: string): "success" | "warning" | "danger" | "info" | "neutral" {
	switch (status) {
		case "completed": return "success";
		case "running": return "info";
		case "failed": return "danger";
		case "queued": return "neutral";
		default: return "neutral";
	}
}

function roleTone(role: string): "success" | "warning" | "danger" | "info" | "neutral" {
	switch (role) {
		case "system": return "info";
		case "user": return "neutral";
		case "assistant": return "success";
		case "tool": return "warning";
		default: return "neutral";
	}
}

function attackOutcomeTone(outcome: string): "success" | "warning" | "danger" | "info" | "neutral" {
	switch (outcome) {
		case "success": return "danger";
		case "partial": return "warning";
		case "failure": return "success";
		default: return "neutral";
	}
}

function severityToneLocal(severity: string): "success" | "warning" | "danger" | "info" | "neutral" {
	switch (severity) {
		case "critical": return "danger";
		case "high": return "danger";
		case "medium": return "warning";
		case "low": return "info";
		default: return "neutral";
	}
}
