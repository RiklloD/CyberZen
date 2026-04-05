import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import {
	AlertTriangle,
	Boxes,
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

const implementationTrack = [
	"GitHub-first webhook intake with event dedupe and staged workflow routing",
	"Multi-ecosystem SBOM worker coverage with snapshot-to-snapshot diffing",
	"Version-aware breach normalization against the live SBOM graph",
	"Repository drilldowns and operator remediation surfaces",
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
						{overview.findings.map((finding) => (
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
							{overview.workflows.map((workflow) => (
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
										{workflow.tasks.map((task) => (
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
							{overview.gateDecisions.map((decision) => (
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
						{overview.repositories.map((repository) => (
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
														(component) => (
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
														(component) => (
															<p
																key={`${repository._id}-add-${component.name}-${component.version}-${component.sourceFile}`}
															>
																Added {component.name}@{component.version} via{" "}
																{component.sourceFile}
															</p>
														),
													)}
													{repository.latestSnapshot.comparison.removedPreview.map(
														(component) => (
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
										<div className="mt-3 flex flex-wrap gap-2">
											{repository.latestSnapshot.previewComponents.map(
												(component) => (
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

				<article className="panel rounded-[1.75rem] p-6">
					<p className="island-kicker mb-2">Breach watchlist</p>
					<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
						Feed-normalized disclosure intake is now version aware against live
						inventory.
					</h2>
					<div className="mt-5 space-y-4">
						{overview.disclosures.map((disclosure) => (
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
