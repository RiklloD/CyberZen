import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	AlertTriangle,
	Boxes,
	FlaskConical,
	RadioTower,
	ShieldCheck,
	Sparkles,
	Waypoints,
} from "lucide-react";
import { useTransition } from "react";
import { env } from "#/env";
import { api } from "../../convex/_generated/api";
import StatusPill from "../components/StatusPill";

export const Route = createFileRoute("/")({ component: HomePage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewFinding = OverviewData["findings"][number];
type OverviewWorkflow = OverviewData["workflows"][number];
type OverviewWorkflowTask = OverviewWorkflow["tasks"][number];
type OverviewGateDecision = OverviewData["gateDecisions"][number];
type OverviewRepository = OverviewData["repositories"][number];
type OverviewDisclosure = OverviewData["disclosures"][number];
type OverviewAdvisoryAggregator = OverviewData["advisoryAggregator"];
type OverviewAdvisorySyncRun = OverviewAdvisoryAggregator["recentRuns"][number];
type OverviewAdvisorySource =
	OverviewAdvisoryAggregator["sourceCoverage"][number];
type OverviewSemanticFinding =
	OverviewData["semanticFingerprint"]["recentFindings"][number];
type OverviewExploitValidationRun =
	OverviewData["exploitValidation"]["recentRuns"][number];
type OverviewSnapshot = NonNullable<OverviewRepository["latestSnapshot"]>;
type OverviewComparison = NonNullable<OverviewSnapshot["comparison"]>;
type OverviewSnapshotComponent = OverviewSnapshot["previewComponents"][number];
type OverviewVulnerableComponent =
	OverviewSnapshot["vulnerablePreview"][number];
type OverviewUpdatedComponent = OverviewComparison["updatedPreview"][number];
type OverviewDiffComponent = OverviewComparison["addedPreview"][number];

const implementationTrack = [
	"Exercise the first real GitHub webhook delivery against the Convex HTTP endpoint",
	"Run the first live advisory bulk-sync pass against the hosted Convex deployment",
	"Exercise the first live end-to-end repository scan path",
	"Begin the CI/CD Gate Enforcement MVP",
];

const loadingSkeletonIds = [
	"skeleton-a",
	"skeleton-b",
	"skeleton-c",
	"skeleton-d",
	"skeleton-e",
	"skeleton-f",
];

function formatTimestamp(timestamp?: number) {
	if (!timestamp) {
		return "Not yet";
	}

	return new Intl.DateTimeFormat("en-CH", {
		month: "short",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
	}).format(timestamp);
}

function severityTone(severity: string) {
	if (severity === "critical" || severity === "high") {
		return "danger" as const;
	}

	if (severity === "medium") {
		return "warning" as const;
	}

	return "info" as const;
}

function workflowTone(status: string) {
	if (status === "completed") {
		return "success" as const;
	}

	if (status === "failed") {
		return "danger" as const;
	}

	if (status === "running") {
		return "info" as const;
	}

	return "warning" as const;
}

function disclosureTone(status: string) {
	if (status === "matched") {
		return "danger" as const;
	}

	if (status === "version_unknown" || status === "no_snapshot") {
		return "warning" as const;
	}

	if (status === "version_unaffected") {
		return "success" as const;
	}

	return "info" as const;
}

function taskTone(status: string) {
	return workflowTone(status);
}

function syncTone(status: string) {
	if (status === "failed") {
		return "danger" as const;
	}

	if (status === "skipped") {
		return "warning" as const;
	}

	return "success" as const;
}

function validationTone(status?: string) {
	if (status === "validated") {
		return "success" as const;
	}

	if (status === "likely_exploitable") {
		return "warning" as const;
	}

	if (status === "unexploitable") {
		return "info" as const;
	}

	return workflowTone(status || "queued");
}

function componentTone(layer: string, hasKnownVulnerabilities = false) {
	if (hasKnownVulnerabilities) {
		return "danger" as const;
	}

	if (layer === "direct") {
		return "success" as const;
	}

	if (layer === "build") {
		return "warning" as const;
	}

	return "info" as const;
}

function formatLayerLabel(layer: string) {
	if (layer === "ai_model") {
		return "AI model";
	}

	return layer.replace("_", " ");
}

function SetupState() {
	return (
		<main className="page-wrap px-4 pb-14 pt-10">
			<section className="hero-panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<p className="island-kicker mb-4">Configuration needed</p>
				<h1 className="display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
					The Sentinel control plane is scaffolded and ready. Convex just needs
					to be connected.
				</h1>
				<p className="mt-5 max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
					Run <code>bunx --bun convex init</code>, set
					<code> VITE_CONVEX_URL</code> and <code>CONVEX_DEPLOYMENT</code> in
					<code> .env.local</code>, then reload this page.
				</p>
				<div className="mt-8 flex flex-wrap gap-3">
					<Link to="/about" className="signal-button secondary-button">
						Review architecture decisions
					</Link>
					<a
						href="https://docs.convex.dev/quickstart/tanstack-start"
						target="_blank"
						rel="noreferrer"
						className="signal-button"
					>
						Open Convex quickstart
					</a>
				</div>
			</section>
		</main>
	);
}

function HomePage() {
	if (!env.VITE_CONVEX_URL) {
		return <SetupState />;
	}

	return <ConfiguredDashboard />;
}

function ConfiguredDashboard() {
	const overview = useQuery(api.dashboard.overview, {
		tenantSlug: "atlas-fintech",
	});
	const seedBaseline = useMutation(api.seed.seedBaseline);
	const ingestGithubPush = useMutation(api.events.ingestGithubPush);
	const simulateLatestWorkflowStep = useMutation(
		api.events.simulateLatestWorkflowStep,
	);
	const runLatestSemanticFingerprint = useMutation(
		api.events.runLatestSemanticFingerprint,
	);
	const runLatestExploitValidation = useMutation(
		api.events.runLatestExploitValidation,
	);
	const [isPending, startTransition] = useTransition();

	async function handleSeed() {
		await seedBaseline({});
	}

	function queueSamplePush() {
		startTransition(() => {
			void ingestGithubPush({
				tenantSlug: "atlas-fintech",
				repositoryFullName: "atlas-fintech/payments-api",
				branch: "main",
				commitSha: `manual-${Date.now().toString(36)}`,
				changedFiles: [
					"services/auth/jwt.py",
					"services/sbom/parser.py",
					"infra/github/workflows/scan.yml",
				],
			});
		});
	}

	function advanceWorkflow() {
		startTransition(() => {
			void simulateLatestWorkflowStep({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	function runSemanticFingerprint() {
		startTransition(() => {
			void runLatestSemanticFingerprint({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	function runExploitValidation() {
		startTransition(() => {
			void runLatestExploitValidation({
				tenantSlug: "atlas-fintech",
			});
		});
	}

	if (overview === null) {
		return (
			<main className="page-wrap px-4 pb-14 pt-10">
				<section className="hero-panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
					<p className="island-kicker mb-4">First-run workspace</p>
					<h1 className="display-title max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
						The app is wired. Seed the baseline Sentinel tenant to start shaping
						the runtime around real data.
					</h1>
					<p className="mt-5 max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
						This creates a tenant, repositories, workflow history, SBOM
						inventory, breach disclosures, findings, and gate decisions that
						match the Phase 1 path from the spec.
					</p>
					<div className="mt-8 flex flex-wrap gap-3">
						<button
							type="button"
							onClick={handleSeed}
							className="signal-button"
						>
							Seed baseline workspace
						</button>
						<Link to="/about" className="signal-button secondary-button">
							See the architecture rationale
						</Link>
					</div>
				</section>
			</main>
		);
	}

	if (overview === undefined) {
		return (
			<main className="page-wrap px-4 pb-14 pt-10">
				<section className="panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
					<p className="island-kicker mb-4">Loading control plane</p>
					<div className="grid gap-4 md:grid-cols-3">
						{loadingSkeletonIds.map((skeletonId) => (
							<div
								key={skeletonId}
								className="loading-panel h-28 rounded-3xl"
							/>
						))}
					</div>
				</section>
			</main>
		);
	}

	return (
		<main className="page-wrap px-4 pb-14 pt-10">
			<section className="hero-panel rise-in relative overflow-hidden rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<div className="halo halo-left" />
				<div className="halo halo-right" />
				<div className="flex flex-wrap items-start justify-between gap-5">
					<div className="max-w-3xl">
						<p className="island-kicker mb-3">Sentinel Phase 0 foundation</p>
						<h1 className="display-title mb-5 max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
							Build the cyber-intelligence spine first, then layer autonomy on
							top.
						</h1>
						<p className="max-w-2xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
							This dashboard is already anchored to the real domain model:
							events, workflow runs, SBOM snapshots, breach disclosures,
							findings, and gate decisions. That gives us a trustworthy place to
							plug GitHub, Python agents, and later sandbox execution into.
						</p>
					</div>
					<div className="panel-grid min-w-[280px] flex-1 rounded-[1.5rem] p-5">
						<div className="flex items-center justify-between">
							<span className="tiny-label">Tenant</span>
							<StatusPill label={overview.tenant.currentPhase} tone="info" />
						</div>
						<div className="mt-2 text-2xl font-semibold text-[var(--sea-ink)]">
							{overview.tenant.name}
						</div>
						<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
							Deployment: {overview.tenant.deploymentMode.replace("_", " ")}
						</p>
						<div className="mt-4 flex flex-wrap gap-2">
							<button
								type="button"
								onClick={handleSeed}
								className="signal-button secondary-button"
							>
								Re-check baseline
							</button>
							<button
								type="button"
								onClick={queueSamplePush}
								className="signal-button"
								disabled={isPending}
							>
								Queue sample push
							</button>
							<button
								type="button"
								onClick={advanceWorkflow}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Advance active workflow
							</button>
							<button
								type="button"
								onClick={runSemanticFingerprint}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run semantic fingerprint
							</button>
							<button
								type="button"
								onClick={runExploitValidation}
								className="signal-button secondary-button"
								disabled={isPending}
							>
								Run exploit validation
							</button>
						</div>
					</div>
				</div>
			</section>

			<section className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
				{[
					{
						label: "Open findings",
						value: overview.stats.openFindings,
						hint: "Current unresolved risk",
						icon: AlertTriangle,
					},
					{
						label: "Critical or high",
						value: overview.stats.criticalFindings,
						hint: "Potential merge blockers",
						icon: ShieldCheck,
					},
					{
						label: "Active workflows",
						value: overview.stats.activeWorkflows,
						hint: "Queued or running scans",
						icon: Waypoints,
					},
					{
						label: "SBOM components",
						value: overview.stats.sbomComponents,
						hint: "Latest known inventory size",
						icon: Boxes,
					},
					{
						label: "Validated findings",
						value: overview.stats.validatedFindings,
						hint: "Exploit-first confirmed",
						icon: Sparkles,
					},
				].map(({ label, value, hint, icon: Icon }, index) => (
					<article
						key={label}
						className="panel rise-in rounded-[1.35rem] p-5"
						style={{ animationDelay: `${index * 70 + 80}ms` }}
					>
						<div className="flex items-center justify-between">
							<span className="tiny-label">{label}</span>
							<span className="metric-icon">
								<Icon size={16} />
							</span>
						</div>
						<div className="mt-4 text-4xl font-semibold text-[var(--sea-ink)]">
							{value}
						</div>
						<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">{hint}</p>
					</article>
				))}
			</section>

			<section className="mt-8 grid gap-4 xl:grid-cols-[1.3fr_1fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<div className="flex items-center justify-between gap-3">
						<div>
							<p className="island-kicker mb-2">Open finding queue</p>
							<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
								Only the evidence-backed problems should survive to this layer.
							</h2>
						</div>
						<StatusPill
							label={`${overview.findings.length} visible`}
							tone="warning"
						/>
					</div>
					<div className="mt-5 space-y-4">
						{overview.findings.map((finding: OverviewFinding) => (
							<div key={finding._id} className="signal-row">
								<div className="flex flex-wrap items-center gap-2">
									<StatusPill
										label={finding.severity}
										tone={severityTone(finding.severity)}
									/>
									<StatusPill label={finding.source} tone="info" />
									<StatusPill
										label={finding.validationStatus}
										tone={
											finding.validationStatus === "validated"
												? "success"
												: "warning"
										}
									/>
								</div>
								<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
									{finding.title}
								</h3>
								<div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-[var(--sea-ink-soft)]">
									<span>Status: {finding.status.replace("_", " ")}</span>
									<span>
										Confidence: {Math.round(finding.confidence * 100)}%
									</span>
									<span>Raised: {formatTimestamp(finding.createdAt)}</span>
								</div>
							</div>
						))}
					</div>
				</article>

				<div className="space-y-4">
					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Workflow spine</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Recent runs
								</h2>
							</div>
							<StatusPill label="event driven" tone="info" />
						</div>
						<div className="mt-5 space-y-4">
							{overview.workflows.map((workflow: OverviewWorkflow) => (
								<div key={workflow._id} className="signal-row">
									<div className="flex items-center justify-between gap-4">
										<div className="text-lg font-semibold text-[var(--sea-ink)]">
											{workflow.workflowType.replace("_", " ")}
										</div>
										<StatusPill
											label={workflow.status}
											tone={workflowTone(workflow.status)}
										/>
									</div>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{workflow.summary}
									</p>
									<div className="mt-3 flex flex-wrap gap-4 text-sm text-[var(--sea-ink-soft)]">
										<span>Priority: {workflow.priority}</span>
										<span>
											Progress: {workflow.completedTaskCount}/
											{workflow.totalTaskCount}
										</span>
										<span>
											Stage:{" "}
											{workflow.currentStage
												? workflow.currentStage.replace("_", " ")
												: "Not started"}
										</span>
										<span>Started: {formatTimestamp(workflow.startedAt)}</span>
										<span>Ended: {formatTimestamp(workflow.completedAt)}</span>
									</div>
									<div className="mt-4 flex flex-wrap gap-2">
										{workflow.tasks.map((task: OverviewWorkflowTask) => (
											<StatusPill
												key={task._id}
												label={`${task.order + 1}. ${task.stage}`}
												tone={taskTone(task.status)}
											/>
										))}
									</div>
								</div>
							))}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Gate history</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Decision log
								</h2>
							</div>
							<RadioTower className="text-[var(--signal)]" size={18} />
						</div>
						<div className="mt-5 space-y-4">
							{overview.gateDecisions.map((decision: OverviewGateDecision) => (
								<div key={decision._id} className="signal-row">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={decision.decision}
											tone={
												decision.decision === "blocked"
													? "danger"
													: decision.decision === "approved"
														? "success"
														: "warning"
											}
										/>
										<StatusPill label={decision.stage} tone="neutral" />
									</div>
									<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
										{decision.justification || "No justification captured."}
									</p>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{decision.actorType} / {formatTimestamp(decision.createdAt)}
									</p>
								</div>
							))}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Semantic fingerprinting</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Changed-code matches now feed the exploit-first pipeline.
								</h2>
							</div>
							<StatusPill
								label={`${overview.semanticFingerprint.openCandidateCount} open`}
								tone={
									overview.semanticFingerprint.openCandidateCount > 0
										? "warning"
										: "success"
								}
							/>
						</div>
						<div className="mt-4 flex flex-wrap gap-2">
							<StatusPill
								label={`pending validation ${overview.semanticFingerprint.pendingValidationCount}`}
								tone="info"
							/>
							<StatusPill label="path-aware MVP" tone="neutral" />
						</div>
						<div className="mt-5 space-y-4">
							{overview.semanticFingerprint.recentFindings.map(
								(finding: OverviewSemanticFinding) => (
									<div key={finding._id} className="signal-row">
										<div className="flex flex-wrap items-center gap-2">
											<StatusPill
												label={finding.severity}
												tone={severityTone(finding.severity)}
											/>
											<StatusPill
												label={finding.validationStatus}
												tone={
													finding.validationStatus === "validated"
														? "success"
														: "warning"
												}
											/>
										</div>
										<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
											{finding.title}
										</h3>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											{finding.repositoryName} /{" "}
											{finding.vulnClass.replaceAll("_", " ")}
										</p>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Confidence {Math.round(finding.confidence * 100)}% /{" "}
											{formatTimestamp(finding.createdAt)}
										</p>
									</div>
								),
							)}
						</div>
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<div className="flex items-center justify-between gap-3">
							<div>
								<p className="island-kicker mb-2">Exploit validation</p>
								<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
									Local-first validation runs now classify which candidates stay
									open.
								</h2>
							</div>
							<FlaskConical className="text-[var(--signal)]" size={18} />
						</div>
						<div className="mt-4 flex flex-wrap gap-2">
							<StatusPill
								label={`pending ${overview.exploitValidation.pendingCount}`}
								tone={
									overview.exploitValidation.pendingCount > 0
										? "warning"
										: "success"
								}
							/>
							<StatusPill
								label={`validated ${overview.exploitValidation.validatedCount}`}
								tone="success"
							/>
							<StatusPill
								label={`likely exploitable ${overview.exploitValidation.likelyExploitableCount}`}
								tone="warning"
							/>
						</div>
						<div className="mt-5 space-y-4">
							{overview.exploitValidation.recentRuns.length > 0 ? (
								overview.exploitValidation.recentRuns.map(
									(run: OverviewExploitValidationRun) => (
										<div key={run._id} className="signal-row">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={run.status}
													tone={workflowTone(run.status)}
												/>
												{run.outcome ? (
													<StatusPill
														label={run.outcome.replaceAll("_", " ")}
														tone={validationTone(run.outcome)}
													/>
												) : null}
											</div>
											<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
												{run.findingTitle}
											</h3>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												{run.repositoryName} / confidence{" "}
												{Math.round(run.validationConfidence * 100)}%
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												{run.evidenceSummary}
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												Started {formatTimestamp(run.startedAt)} / finished{" "}
												{formatTimestamp(run.completedAt)}
											</p>
										</div>
									),
								)
							) : (
								<div className="signal-row">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										No validation runs recorded yet. Trigger the local-first
										validation path after queueing a semantic or breach finding.
									</p>
								</div>
							)}
						</div>
					</article>
				</div>
			</section>

			<section className="mt-8 grid gap-4 xl:grid-cols-[1.2fr_1fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<div className="flex items-center justify-between gap-3">
						<div>
							<p className="island-kicker mb-2">Repository inventory</p>
							<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
								The first operator-facing surface is already typed around real
								repos.
							</h2>
						</div>
						{overview.latestSnapshot ? (
							<StatusPill
								label={`SBOM ${overview.latestSnapshot.commitSha}`}
								tone="success"
							/>
						) : null}
					</div>
					<div className="mt-5 grid gap-4 md:grid-cols-2">
						{overview.repositories.map((repository: OverviewRepository) => (
							<div key={repository._id} className="signal-row h-full">
								<div className="flex items-center justify-between gap-3">
									<div>
										<h3 className="text-lg font-semibold text-[var(--sea-ink)]">
											{repository.name}
										</h3>
										<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
											{repository.provider} / {repository.primaryLanguage}
										</p>
									</div>
									<StatusPill label={repository.defaultBranch} tone="neutral" />
								</div>
								<div className="mt-4 space-y-2 text-sm text-[var(--sea-ink-soft)]">
									<div>
										Last scan: {formatTimestamp(repository.lastScannedAt)}
									</div>
									<div>Commit: {repository.latestCommitSha || "Unknown"}</div>
								</div>
								{repository.latestSnapshot ? (
									<div className="mt-4 rounded-2xl border border-[color:var(--line)]/70 bg-[var(--surface-strong)]/70 p-4">
										<div className="flex flex-wrap items-center gap-2">
											<StatusPill
												label={`${repository.latestSnapshot.totalComponents} components`}
												tone="success"
											/>
											<StatusPill
												label={repository.latestSnapshot.commitSha}
												tone="neutral"
											/>
										</div>
										<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
											Captured:{" "}
											{formatTimestamp(repository.latestSnapshot.capturedAt)}
										</p>
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Source manifests:{" "}
											{repository.latestSnapshot.sourceFiles.join(", ")}
										</p>
										<div className="mt-3 flex flex-wrap gap-2">
											{[
												{
													layer: "direct",
													count:
														repository.latestSnapshot.directDependencyCount,
												},
												{
													layer: "transitive",
													count:
														repository.latestSnapshot.transitiveDependencyCount,
												},
												{
													layer: "build",
													count: repository.latestSnapshot.buildDependencyCount,
												},
												{
													layer: "container",
													count:
														repository.latestSnapshot.containerDependencyCount,
												},
												{
													layer: "runtime",
													count:
														repository.latestSnapshot.runtimeDependencyCount,
												},
												{
													layer: "ai_model",
													count:
														repository.latestSnapshot.aiModelDependencyCount,
												},
											]
												.filter((entry) => entry.count > 0)
												.map(({ layer, count }) => (
													<StatusPill
														key={`${repository._id}-${layer}`}
														label={`${formatLayerLabel(String(layer))}: ${count}`}
														tone={
															layer === "direct"
																? "success"
																: layer === "build" || layer === "container"
																	? "warning"
																	: "info"
														}
													/>
												))}
											{repository.latestSnapshot.vulnerableComponentCount >
											0 ? (
												<StatusPill
													label={`vulnerable: ${repository.latestSnapshot.vulnerableComponentCount}`}
													tone="danger"
												/>
											) : null}
										</div>
										{repository.latestSnapshot.comparison ? (
											<div className="mt-3 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
												<div className="flex flex-wrap items-center gap-2">
													<StatusPill
														label={`+${repository.latestSnapshot.comparison.addedCount} added`}
														tone="success"
													/>
													<StatusPill
														label={`${repository.latestSnapshot.comparison.updatedCount} updated`}
														tone="warning"
													/>
													<StatusPill
														label={`-${repository.latestSnapshot.comparison.removedCount} removed`}
														tone="danger"
													/>
													{repository.latestSnapshot.comparison
														.vulnerableComponentDelta !== 0 ? (
														<StatusPill
															label={`vuln delta ${repository.latestSnapshot.comparison.vulnerableComponentDelta > 0 ? "+" : ""}${repository.latestSnapshot.comparison.vulnerableComponentDelta}`}
															tone={
																repository.latestSnapshot.comparison
																	.vulnerableComponentDelta > 0
																	? "danger"
																	: "success"
															}
														/>
													) : null}
												</div>
												<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
													Compared with{" "}
													{
														repository.latestSnapshot.comparison
															.previousCommitSha
													}{" "}
													from{" "}
													{formatTimestamp(
														repository.latestSnapshot.comparison
															.previousCapturedAt,
													)}
												</p>
												<div className="mt-3 space-y-2 text-sm text-[var(--sea-ink-soft)]">
													{repository.latestSnapshot.comparison.updatedPreview.map(
														(component: OverviewUpdatedComponent) => (
															<p
																key={`${repository._id}-update-${component.name}-${component.sourceFile}`}
															>
																Updated {component.name} in{" "}
																{component.sourceFile}:{" "}
																{component.previousVersion} to{" "}
																{component.nextVersion}
															</p>
														),
													)}
													{repository.latestSnapshot.comparison.addedPreview.map(
														(component: OverviewDiffComponent) => (
															<p
																key={`${repository._id}-add-${component.name}-${component.version}-${component.sourceFile}`}
															>
																Added {component.name}@{component.version} via{" "}
																{component.sourceFile}
															</p>
														),
													)}
													{repository.latestSnapshot.comparison.removedPreview.map(
														(component: OverviewDiffComponent) => (
															<p
																key={`${repository._id}-remove-${component.name}-${component.version}-${component.sourceFile}`}
															>
																Removed {component.name}@{component.version}{" "}
																from {component.sourceFile}
															</p>
														),
													)}
												</div>
											</div>
										) : null}
										{repository.latestSnapshot.vulnerablePreview.length > 0 ? (
											<div className="mt-3 rounded-2xl border border-[color:var(--danger)]/20 bg-[color:var(--danger)]/6 p-4">
												<div className="flex items-center justify-between gap-3">
													<p className="tiny-label">Vulnerable inventory</p>
													<StatusPill
														label={`${repository.latestSnapshot.vulnerableComponentCount} flagged`}
														tone="danger"
													/>
												</div>
												<div className="mt-3 space-y-2 text-sm text-[var(--sea-ink-soft)]">
													{repository.latestSnapshot.vulnerablePreview.map(
														(component: OverviewVulnerableComponent) => (
															<p
																key={`${repository._id}-vuln-${component.name}-${component.version}-${component.sourceFile}`}
															>
																{component.name}@{component.version} via{" "}
																{component.sourceFile} (
																{formatLayerLabel(component.layer)})
															</p>
														),
													)}
												</div>
											</div>
										) : null}
										<div className="mt-3 flex flex-wrap gap-2">
											{repository.latestSnapshot.previewComponents.map(
												(component: OverviewSnapshotComponent) => (
													<StatusPill
														key={`${repository._id}-${component.name}-${component.version}`}
														label={`${component.name}@${component.version}`}
														tone={componentTone(
															component.layer,
															component.hasKnownVulnerabilities,
														)}
													/>
												),
											)}
										</div>
									</div>
								) : (
									<p className="mt-4 text-sm text-[var(--sea-ink-soft)]">
										No SBOM snapshot imported for this repository yet.
									</p>
								)}
							</div>
						))}
					</div>
				</article>

				<div className="space-y-4">
					<article className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Breach intel aggregator</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Feed sync is now observable instead of disappearing behind backend
							actions.
						</h2>
						<div className="mt-5 flex flex-wrap gap-2">
							<StatusPill
								label={`recent disclosures ${overview.advisoryAggregator.recentImportedDisclosures}`}
								tone="info"
							/>
							<StatusPill
								label={`matched ${overview.advisoryAggregator.recentMatchedDisclosures}`}
								tone={
									overview.advisoryAggregator.recentMatchedDisclosures > 0
										? "danger"
										: "success"
								}
							/>
							{overview.advisoryAggregator.lastCompletedAt ? (
								<StatusPill
									label={`last sync ${formatTimestamp(overview.advisoryAggregator.lastCompletedAt)}`}
									tone="success"
								/>
							) : (
								<StatusPill label="no sync history yet" tone="warning" />
							)}
						</div>
						<div className="mt-5 space-y-4">
							{overview.advisoryAggregator.recentRuns.length > 0 ? (
								overview.advisoryAggregator.recentRuns.map(
									(run: OverviewAdvisorySyncRun) => (
										<div key={run._id} className="signal-row">
											<div className="flex flex-wrap items-center gap-2">
												<StatusPill
													label={run.status}
													tone={syncTone(run.status)}
												/>
												<StatusPill label={run.triggerType} tone="neutral" />
												<StatusPill
													label={`${run.packageCount} packages`}
													tone="info"
												/>
											</div>
											<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
												{run.repositoryName}
											</h3>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												GitHub fetched {run.githubFetched}, imported{" "}
												{run.githubImported}. OSV fetched {run.osvFetched},
												imported {run.osvImported}.
											</p>
											<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
												Started {formatTimestamp(run.startedAt)} / finished{" "}
												{formatTimestamp(run.completedAt)}
											</p>
											{run.reason ? (
												<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
													{run.reason}
												</p>
											) : null}
										</div>
									),
								)
							) : (
								<div className="signal-row">
									<p className="text-sm text-[var(--sea-ink-soft)]">
										No advisory sync runs have been recorded yet.
									</p>
								</div>
							)}
						</div>
						{overview.advisoryAggregator.sourceCoverage.length > 0 ? (
							<div className="mt-5 rounded-2xl border border-[color:var(--line)]/60 bg-[var(--surface)]/70 p-4">
								<p className="tiny-label">Recent source coverage</p>
								<div className="mt-3 space-y-3">
									{overview.advisoryAggregator.sourceCoverage.map(
										(source: OverviewAdvisorySource) => (
											<div key={`${source.sourceType}-${source.sourceTier}`}>
												<div className="flex flex-wrap items-center gap-2">
													<StatusPill
														label={source.sourceType.replaceAll("_", " ")}
														tone="neutral"
													/>
													<StatusPill
														label={source.sourceTier.replace("_", " ")}
														tone="info"
													/>
													<StatusPill
														label={`${source.disclosureCount} disclosures`}
														tone="info"
													/>
													<StatusPill
														label={`${source.matchedCount} matched`}
														tone={
															source.matchedCount > 0 ? "danger" : "success"
														}
													/>
												</div>
												<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
													{source.sourceName} / last published{" "}
													{formatTimestamp(source.lastPublishedAt)}
												</p>
											</div>
										),
									)}
								</div>
							</div>
						) : null}
					</article>

					<article className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Breach watchlist</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Feed-normalized disclosure intake is now version aware against
							live inventory.
						</h2>
						<div className="mt-5 space-y-4">
							{overview.disclosures.map((disclosure: OverviewDisclosure) => (
								<div key={disclosure._id} className="signal-row">
									<div className="flex flex-wrap items-center gap-2">
										<StatusPill
											label={disclosure.sourceType.replaceAll("_", " ")}
											tone="neutral"
										/>
										<StatusPill
											label={disclosure.sourceTier.replace("_", " ")}
											tone="info"
										/>
										<StatusPill
											label={disclosure.severity}
											tone={severityTone(disclosure.severity)}
										/>
										<StatusPill
											label={disclosure.matchStatus.replace("_", " ")}
											tone={disclosureTone(disclosure.matchStatus)}
										/>
										{disclosure.exploitAvailable ? (
											<StatusPill label="exploit available" tone="danger" />
										) : null}
									</div>
									<h3 className="mt-3 text-lg font-semibold text-[var(--sea-ink)]">
										{disclosure.packageName}
									</h3>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{disclosure.sourceName}
										{disclosure.repositoryName
											? ` / ${disclosure.repositoryName}`
											: ""}
										{" / "}
										{disclosure.sourceRef}
										{" / "}
										{formatTimestamp(disclosure.publishedAt)}
									</p>
									<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
										{disclosure.matchSummary}
									</p>
									{disclosure.affectedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Affected ranges: {disclosure.affectedVersions.join(" ; ")}
										</p>
									) : null}
									{disclosure.fixVersion ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Fixed in: {disclosure.fixVersion}
										</p>
									) : null}
									{disclosure.affectedMatchedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Affected installed versions:{" "}
											{disclosure.affectedMatchedVersions.join(", ")}
										</p>
									) : disclosure.matchedVersions.length > 0 ? (
										<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
											Observed installed versions:{" "}
											{disclosure.matchedVersions.join(", ")}
										</p>
									) : null}
								</div>
							))}
						</div>
					</article>
				</div>
			</section>

			<section className="mt-8 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Build track</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						The next four implementation moves are already constrained by the
						spec and the project tracker.
					</h2>
					<div className="mt-5 grid gap-3">
						{implementationTrack.map((step, index) => (
							<div key={step} className="timeline-step">
								<div className="timeline-index">{index + 1}</div>
								<p className="text-sm text-[var(--sea-ink)]">{step}</p>
							</div>
						))}
					</div>
				</article>

				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Why this shape</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Convex handles the control plane now so Python and Go can specialize
						later instead of carrying the whole platform on day one.
					</h2>
					<div className="mt-5 space-y-3 text-sm text-[var(--sea-ink-soft)]">
						<p>
							Convex is the system of record for tenants, workflows, findings,
							SBOM state, and operator UI data.
						</p>
						<p>
							Python remains the path for orchestration, embeddings, scraping,
							and exploit reasoning.
						</p>
						<p>
							Go still fits the event gateway and sandbox manager, but those are
							being staged behind stable contracts instead of guessed into
							existence.
						</p>
					</div>
					<div className="mt-5">
						<Link to="/about" className="signal-button secondary-button">
							Read the full foundation decision log
						</Link>
					</div>
				</article>
			</section>
		</main>
	);
}
