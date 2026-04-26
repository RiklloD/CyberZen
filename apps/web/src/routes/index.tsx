import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	AlertTriangle,
	Boxes,
	FlaskConical,
	GitMerge,
	ShieldCheck,
	Sparkles,
	Waypoints,
} from "lucide-react";
import { api } from "../../convex/_generated/api";
import StatusPill from "../components/StatusPill";
import { TENANT_SLUG } from "../lib/config";
import {
	formatTimestamp,
	severityTone,
	workflowTone,
} from "../lib/utils";

export const Route = createFileRoute("/")({ component: DashboardPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewFinding = OverviewData["findings"][number];
type OverviewWorkflow = OverviewData["workflows"][number];
type OverviewWorkflowTask = OverviewWorkflow["tasks"][number];
type OverviewGateDecision = OverviewData["ciGateEnforcement"]["recentDecisions"][number];

const SKELETONS = ["a", "b", "c", "d", "e"];

function DashboardPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT_SLUG });

	if (overview === undefined) {
		return (
			<main className="page-body-padded">
				<div className="stats-grid mb-6">
					{SKELETONS.map((id) => (
						<div key={id} className="loading-panel h-24 rounded-2xl" />
					))}
				</div>
				<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
					<div className="loading-panel h-64 rounded-2xl" />
					<div className="loading-panel h-64 rounded-2xl" />
				</div>
			</main>
		);
	}

	if (overview === null) {
		return (
			<main className="page-body-padded">
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl py-16">
					<ShieldCheck size={32} className="mb-3 opacity-30" />
					<p className="text-sm font-semibold text-[var(--sea-ink)] mb-1">No data</p>
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No workspace data found for this tenant.
					</p>
				</div>
			</main>
		);
	}

	const { tenant, stats, findings, workflows, ciGateEnforcement, repositories } = overview;

	return (
		<main>
			<div className="page-header">
				<div>
					<h1 className="page-title">{tenant.name}</h1>
					<p className="page-subtitle">
						{tenant.deploymentMode.replace(/_/g, " ")} · {tenant.currentPhase.replace(/_/g, " ")}
					</p>
				</div>
			</div>

			<div className="page-body">
				{/* Stats */}
				<div className="stats-grid">
					{[
						{ label: "Open findings", value: stats.openFindings, hint: "Unresolved risk", icon: AlertTriangle },
						{ label: "Critical / High", value: stats.criticalFindings, hint: "Merge blockers", icon: ShieldCheck },
						{ label: "Active workflows", value: stats.activeWorkflows, hint: "Queued or running", icon: Waypoints },
						{ label: "SBOM components", value: stats.sbomComponents, hint: "Known inventory", icon: Boxes },
						{ label: "Validated", value: stats.validatedFindings, hint: "Exploit-confirmed", icon: Sparkles },
					].map(({ label, value, hint, icon: Icon }) => (
						<div key={label} className="stat-card rise-in">
							<div className="flex items-center justify-between">
								<span className="stat-label">{label}</span>
								<span className="metric-icon"><Icon size={14} /></span>
							</div>
							<div className="stat-value">{value}</div>
							<p className="stat-hint">{hint}</p>
						</div>
					))}
				</div>

				{/* Repositories */}
				{repositories.length > 0 && (
					<>
						<div className="mb-4 flex items-center justify-between">
							<h2 className="section-title">Repositories</h2>
							<Link to="/repositories" className="text-xs font-semibold text-[var(--lagoon-deep)] hover:underline">
								View all →
							</Link>
						</div>
						<div className="repo-grid mb-6">
							{repositories.slice(0, 6).map((repo) => (
								<div key={repo._id} className="card card-sm">
									<div className="repo-header">
										<span className="repo-name">{repo.fullName}</span>
										<StatusPill
											label={repo.latestSnapshot ? "has SBOM" : "no SBOM"}
											tone={repo.latestSnapshot ? "success" : "neutral"}
										/>
									</div>
									{repo.latestSnapshot && (
										<div className="flex flex-wrap gap-1.5 mt-1">
											<StatusPill
												label={`${repo.latestSnapshot.previewComponents.length} components`}
												tone="neutral"
											/>
											{repo.latestSnapshot.vulnerablePreview.length > 0 && (
												<StatusPill
													label={`${repo.latestSnapshot.vulnerablePreview.length} vulnerable`}
													tone="danger"
												/>
											)}
										</div>
									)}
								</div>
							))}
						</div>
					</>
				)}

				{/* Main grid: findings + workflows */}
				<div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
					{/* Findings */}
					<div>
						<div className="mb-4 flex items-center justify-between">
							<h2 className="section-title">Open findings</h2>
							<div className="flex items-center gap-3">
								{findings.length > 0 && (
									<StatusPill label={`${findings.length} visible`} tone="warning" />
								)}
								<Link to="/findings" className="text-xs font-semibold text-[var(--lagoon-deep)] hover:underline">
									All findings →
								</Link>
							</div>
						</div>
						<div className="space-y-3">
							{findings.slice(0, 8).map((finding: OverviewFinding) => (
								<div key={finding._id} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill label={finding.severity} tone={severityTone(finding.severity)} />
										<StatusPill label={finding.source} tone="info" />
										<StatusPill
											label={finding.validationStatus}
											tone={finding.validationStatus === "validated" ? "success" : "warning"}
										/>
									</div>
									<h3 className="mt-2 text-sm font-semibold text-[var(--sea-ink)]">
										{finding.title}
									</h3>
									<div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--sea-ink-soft)]">
										<span>{finding.status.replace(/_/g, " ")}</span>
										<span>Confidence: {Math.round(finding.confidence * 100)}%</span>
										<span>{formatTimestamp(finding.createdAt)}</span>
									</div>
								</div>
							))}
							{findings.length === 0 && (
								<div className="empty-state">
									<ShieldCheck size={20} className="mb-2 opacity-30" />
									<p>No open findings.</p>
								</div>
							)}
						</div>
					</div>

					{/* Workflows + CI/CD */}
					<div className="space-y-4">
						{/* Workflows */}
						<div>
							<div className="mb-3 flex items-center justify-between">
							<h2 className="section-title">Recent workflows</h2>
							</div>
							<div className="space-y-3">
								{workflows.slice(0, 5).map((workflow: OverviewWorkflow) => (
									<div key={workflow._id} className="card card-sm">
										<div className="flex items-center justify-between gap-2">
											<span className="text-sm font-semibold text-[var(--sea-ink)]">
												{workflow.workflowType.replace(/_/g, " ")}
											</span>
											<StatusPill label={workflow.status} tone={workflowTone(workflow.status)} />
										</div>
										<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">{workflow.summary}</p>
										<div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--sea-ink-soft)]">
											<span>Priority: {workflow.priority}</span>
											<span>{workflow.completedTaskCount}/{workflow.totalTaskCount} tasks</span>
											{workflow.currentStage && (
												<span>{workflow.currentStage.replace(/_/g, " ")}</span>
											)}
										</div>
										<div className="mt-2 flex flex-wrap gap-1.5">
											{workflow.tasks.slice(0, 6).map((task: OverviewWorkflowTask) => (
												<StatusPill
													key={task._id}
													label={`${task.order + 1}. ${task.stage}`}
													tone={workflowTone(task.status)}
												/>
											))}
										</div>
									</div>
								))}
								{workflows.length === 0 && (
									<div className="empty-state">
										<Waypoints size={20} className="mb-2 opacity-30" />
										<p>No recent workflows.</p>
									</div>
								)}
							</div>
						</div>

						{/* CI/CD Gate summary */}
						<div>
							<div className="mb-3 flex items-center justify-between">
								<h2 className="section-title">
									<span className="inline-flex items-center gap-2">
										<GitMerge size={15} className="text-[var(--signal)]" />
										CI/CD Gate enforcement
									</span>
								</h2>
								<Link to="/ci-cd" className="text-xs font-semibold text-[var(--lagoon-deep)] hover:underline">
									Full view →
								</Link>
							</div>
							{ciGateEnforcement.blockedCount === 0 && ciGateEnforcement.approvedCount === 0 ? (
								<div className="empty-state">
									<GitMerge size={20} className="mb-2 opacity-30" />
									<p>No gate decisions yet.</p>
								</div>
							) : (
								<div className="card card-sm">
									<div className="flex flex-wrap gap-2 mb-3">
										<StatusPill
											label={`${ciGateEnforcement.blockedCount} blocked`}
											tone={ciGateEnforcement.blockedCount > 0 ? "danger" : "success"}
										/>
										<StatusPill
											label={`${ciGateEnforcement.approvedCount} approved`}
											tone="success"
										/>
										{ciGateEnforcement.overrideCount > 0 && (
											<StatusPill
												label={`${ciGateEnforcement.overrideCount} overridden`}
												tone="warning"
											/>
										)}
									</div>
									<div className="space-y-2">
										{ciGateEnforcement.recentDecisions.slice(0, 3).map((d: OverviewGateDecision) => (
											<div key={d._id} className="inset-panel">
												<div className="flex flex-wrap items-center gap-1.5">
													<StatusPill
														label={d.decision}
														tone={
															d.decision === "blocked"
																? "danger"
																: d.decision === "approved"
																	? "success"
																	: "warning"
														}
													/>
													<StatusPill label={d.stage.replace(/_/g, " ")} tone="neutral" />
												</div>
												<p className="mt-1.5 text-xs font-medium text-[var(--sea-ink)]">
													{d.findingTitle}
												</p>
												<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
													{d.repositoryName} · {formatTimestamp(d.createdAt)}
												</p>
											</div>
										))}
									</div>
								</div>
							)}
						</div>
					</div>
				</div>

				{/* Navigation cards */}
				<div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
					{[
						{ to: "/findings", label: "Findings", description: "Triage and review all security findings", icon: AlertTriangle },
						{ to: "/sbom", label: "SBOM Explorer", description: "Browse software bill of materials snapshots", icon: Boxes },
						{ to: "/breach-intel", label: "Breach Intel", description: "Advisory aggregator and disclosure watchlist", icon: ShieldCheck },
						{ to: "/supply-chain", label: "Supply Chain", description: "Supply chain posture and injection risk", icon: Waypoints },
						{ to: "/compliance", label: "Compliance", description: "Regulatory drift across SOC 2, GDPR, HIPAA", icon: ShieldCheck },
						{ to: "/remediation", label: "Remediation", description: "P0–P3 priority queue and auto-fix history", icon: Sparkles },
						{ to: "/agents", label: "Agents", description: "Red/Blue adversarial rounds and learning profiles", icon: FlaskConical },
						{ to: "/integrations", label: "Integrations", description: "Vendor trust, webhooks, and external tools", icon: Waypoints },
					].map(({ to, label, description, icon: Icon }) => (
						<Link
							key={to}
							to={to as "/findings"}
							className="card card-sm block no-underline group"
						>
							<div className="flex items-center gap-2 mb-1.5">
								<span className="metric-icon"><Icon size={14} /></span>
								<span className="text-sm font-semibold text-[var(--sea-ink)]">{label}</span>
							</div>
							<p className="text-xs text-[var(--sea-ink-soft)]">{description}</p>
						</Link>
					))}
				</div>
			</div>
		</main>
	);
}
