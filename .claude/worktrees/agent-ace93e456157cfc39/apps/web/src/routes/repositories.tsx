import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { GitBranch } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import type { Id } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	attackSurfaceTone,
	blastTierTone,
	formatTimestamp,
	honeypotScoreTone,
	learningTrendTone,
	maturityTone,
	multiplierTone,
	priorityTierTone,
	repositoryHealthTone,
	slaComplianceTone,
	trendTone,
} from "../lib/utils";

export const Route = createFileRoute("/repositories")({ component: RepositoriesPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function RepositoriesPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selected, setSelected] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
					{["a", "b", "c"].map((k) => (
						<div key={k} className="loading-panel h-36 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { repositories } = overview;
	const selectedRepo = selected
		? repositories.find((r) => r._id === selected) ?? null
		: null;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<GitBranch size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Repositories</h1>
						<p className="page-subtitle">{repositories.length} repositories tracked</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Repository list */}
				<div className="repo-grid mb-6">
					{repositories.map((repo: OverviewRepository) => (
						<button
							key={repo._id}
							type="button"
							onClick={() =>
								setSelected(selected === repo._id ? null : repo._id)
							}
							className={`card card-sm text-left w-full ${
								selected === repo._id
									? "border-[rgba(158,255,100,0.4)] bg-[rgba(158,255,100,0.06)]"
									: ""
							}`}
						>
							<div className="repo-header">
								<span className="repo-name">{repo.fullName}</span>
								<StatusPill
									label={repo.latestSnapshot ? "SBOM active" : "no SBOM"}
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
									{repo.latestSnapshot.comparison && (
										<StatusPill
											label={`${repo.latestSnapshot.comparison.addedPreview.length} added`}
											tone="info"
										/>
									)}
								</div>
							)}
							<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
								{formatTimestamp(repo.latestSnapshot?.capturedAt)}
							</p>
						</button>
					))}
				</div>

				{/* Drill-down panel for selected repo */}
				{selectedRepo && (
					<RepositoryDrillDown
						tenantSlug={TENANT}
						repo={selectedRepo}
					/>
				)}

				{!selectedRepo && repositories.length > 0 && (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<GitBranch size={24} className="mb-2 opacity-40" />
						<p>Select a repository to view its full intelligence profile</p>
					</div>
				)}
			</div>
		</main>
	);
}

function RepositoryDrillDown({
	tenantSlug,
	repo,
}: {
	tenantSlug: string;
	repo: OverviewRepository;
}) {
	const repositoryId = repo._id as Id<"repositories">;
	const repositoryFullName = repo.fullName;

	const trustScore = useQuery(
		api.trustScoreIntel.getRepositoryTrustScoreSummary,
		{ tenantSlug, repositoryFullName },
	);
	const blastRadius = useQuery(
		api.blastRadiusIntel.blastRadiusSummaryForRepository,
		{ tenantSlug, repositoryFullName },
	);
	const attackSurface = useQuery(
		api.attackSurfaceIntel.getAttackSurfaceDashboard,
		{ tenantSlug, repositoryFullName },
	);
	const sla = useQuery(api.slaIntel.getSlaStatusForRepository, {
		repositoryId,
	});
	const remediationQueue = useQuery(
		api.remediationQueueIntel.getRemediationQueueForRepository,
		{ repositoryId },
	);
	const healthScore = useQuery(
		api.repositoryHealthIntel.getLatestRepositoryHealthScore,
		{ tenantSlug, repositoryFullName },
	);
	const learningProfile = useQuery(
		api.learningProfileIntel.getLatestLearningProfile,
		{ tenantSlug, repositoryFullName },
	);
	const honeypot = useQuery(api.honeypotIntel.getLatestHoneypotPlan, {
		tenantSlug,
		repositoryFullName,
	});
	const riskAcceptance = useQuery(
		api.riskAcceptanceIntel.getAcceptanceSummaryForRepository,
		{ repositoryId },
	);

	return (
		<div className="space-y-4">
			<div className="flex items-center gap-2 mb-1">
				<GitBranch size={14} className="text-[var(--signal)]" />
				<h2 className="text-base font-bold text-[var(--sea-ink)]">
					{repo.fullName}
				</h2>
			</div>

			<div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
				{/* Trust Score */}
				{trustScore && (
					<div className="card card-sm">
						<p className="panel-label">Trust Score</p>
					<div className="flex flex-wrap gap-1.5 mt-1">
						<StatusPill
							label={`score ${trustScore.repositoryScore}`}
							tone={trustScore.repositoryScore >= 70 ? "success" : trustScore.repositoryScore >= 40 ? "warning" : "danger"}
						/>
						{trustScore.untrustedCount > 0 && (
							<StatusPill label={`${trustScore.untrustedCount} untrusted`} tone="danger" />
						)}
						{trustScore.vulnerableCount > 0 && (
							<StatusPill label={`${trustScore.vulnerableCount} vulnerable`} tone="warning" />
						)}
					</div>
					</div>
				)}

				{/* Repository Health */}
				{healthScore && (
					<div className="card card-sm">
						<p className="panel-label">Repository Health</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`score ${healthScore.overallScore}`}
								tone={repositoryHealthTone(healthScore.overallScore)}
							/>
						<StatusPill
							label={`grade ${healthScore.overallGrade}`}
							tone={repositoryHealthTone(healthScore.overallScore)}
						/>
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{healthScore.summary}
						</p>
					</div>
				)}

				{/* Blast Radius */}
				{blastRadius && blastRadius.maxRiskTier !== "low" && (
					<div className="card card-sm">
						<p className="panel-label">Blast Radius</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`max risk: ${blastRadius.maxRiskTier}`}
								tone={blastTierTone(blastRadius.maxRiskTier)}
							/>
							{blastRadius.totalReachableServices.length > 0 && (
								<StatusPill
									label={`${blastRadius.totalReachableServices.length} reachable services`}
									tone="neutral"
								/>
							)}
						</div>
						{blastRadius.topFindings.slice(0, 3).map((f) => (
							<div key={f.findingId} className="mt-1 flex flex-wrap gap-1.5">
								<StatusPill label={f.riskTier} tone={blastTierTone(f.riskTier)} />
								<StatusPill label={`score ${f.businessImpactScore}`} tone="neutral" />
								<span className="text-xs text-[var(--sea-ink-soft)] truncate max-w-[200px]">
									{f.title}
								</span>
							</div>
						))}
					</div>
				)}

				{/* Attack Surface */}
				{attackSurface && (
					<div className="card card-sm">
						<p className="panel-label">Attack Surface</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`score ${attackSurface.snapshot.score}`}
								tone={attackSurfaceTone(attackSurface.snapshot.score)}
							/>
							<StatusPill
								label={attackSurface.snapshot.trend}
								tone={trendTone(attackSurface.snapshot.trend)}
							/>
							{attackSurface.snapshot.openCriticalCount > 0 && (
								<StatusPill
									label={`${attackSurface.snapshot.openCriticalCount} critical`}
									tone="danger"
								/>
							)}
						</div>
						{attackSurface.history.length > 1 && (
							<div className="mt-2 flex h-6 items-end gap-[2px]">
								{attackSurface.history.slice(-12).map((p, i) => (
									<div
										// biome-ignore lint/suspicious/noArrayIndexKey: history points have no stable id
										key={i}
										className="flex-1 rounded-sm bg-[var(--sea-ink-soft)]/25"
										style={{ height: `${Math.max(8, p.score)}%` }}
										title={`Score ${p.score}`}
									/>
								))}
							</div>
						)}
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{attackSurface.snapshot.summary}
						</p>
					</div>
				)}

				{/* SLA Enforcement */}
				{sla && sla.summary.totalTracked > 0 && (
					<div className="card card-sm">
						<p className="panel-label">SLA Enforcement</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`${Math.round(sla.summary.complianceRate * 100)}% compliant`}
								tone={slaComplianceTone(sla.summary.complianceRate)}
							/>
							{sla.summary.breachedSla > 0 && (
								<StatusPill label={`${sla.summary.breachedSla} breached`} tone="danger" />
							)}
							{sla.summary.approachingSla > 0 && (
								<StatusPill
									label={`${sla.summary.approachingSla} approaching`}
									tone="warning"
								/>
							)}
							{sla.summary.mttrHours !== null && (
								<StatusPill
									label={`MTTR ${Math.round(sla.summary.mttrHours)}h`}
									tone="neutral"
								/>
							)}
						</div>
					</div>
				)}

				{/* Remediation Queue */}
			{remediationQueue && remediationQueue.summary.totalCandidates > 0 && (
				<div className="card card-sm">
					<p className="panel-label">Remediation Queue</p>
					<div className="flex flex-wrap gap-1.5 mt-1">
						<StatusPill
							label={`${remediationQueue.summary.totalCandidates} in queue`}
							tone="neutral"
						/>
						{remediationQueue.summary.p0Count > 0 && (
							<StatusPill label={`P0: ${remediationQueue.summary.p0Count}`} tone="danger" />
						)}
						{remediationQueue.summary.p1Count > 0 && (
							<StatusPill label={`P1: ${remediationQueue.summary.p1Count}`} tone="warning" />
						)}
						{remediationQueue.summary.p2Count > 0 && (
							<StatusPill label={`P2: ${remediationQueue.summary.p2Count}`} tone="info" />
						)}
					</div>
					{remediationQueue.queue.slice(0, 3).map((item) => (
						<div key={item.findingId} className="mt-1.5 inset-panel">
							<div className="flex flex-wrap gap-1.5">
								<StatusPill
									label={item.priorityTier.toUpperCase()}
									tone={priorityTierTone(item.priorityTier)}
								/>
								<StatusPill
									label={`score ${item.priorityScore.toFixed(0)}`}
									tone="neutral"
								/>
							</div>
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)] truncate">
								{item.title}
							</p>
						</div>
					))}
				</div>
			)}

				{/* Learning Profile */}
				{learningProfile && (
					<div className="card card-sm">
						<p className="panel-label">Learning Profile</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`maturity ${learningProfile.adaptedConfidenceScore}/100`}
								tone={maturityTone(learningProfile.adaptedConfidenceScore)}
							/>
							<StatusPill
								label={`surface ${learningProfile.attackSurfaceTrend}`}
								tone={learningTrendTone(learningProfile.attackSurfaceTrend)}
							/>
							{learningProfile.recurringCount > 0 && (
								<StatusPill
									label={`${learningProfile.recurringCount} recurring`}
									tone="warning"
								/>
							)}
						</div>
						{learningProfile.vulnClassPatterns.slice(0, 2).map((p) => (
							<div key={p.vulnClass} className="mt-1 flex flex-wrap gap-1.5">
								<StatusPill
									label={p.vulnClass.replaceAll("_", " ")}
									tone={multiplierTone(p.confidenceMultiplier)}
								/>
								<StatusPill
									label={`×${p.confidenceMultiplier} confidence`}
									tone={multiplierTone(p.confidenceMultiplier)}
								/>
							</div>
						))}
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{learningProfile.summary}
						</p>
					</div>
				)}

				{/* Honeypot */}
				{honeypot && honeypot.totalProposals > 0 && (
					<div className="card card-sm">
						<p className="panel-label">Honeypot Plan</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill
								label={`${honeypot.totalProposals} proposals`}
								tone="neutral"
							/>
							{honeypot.endpointCount > 0 && (
								<StatusPill label={`${honeypot.endpointCount} endpoints`} tone="neutral" />
							)}
							{honeypot.tokenCount > 0 && (
								<StatusPill label={`${honeypot.tokenCount} tokens`} tone="neutral" />
							)}
						</div>
						{honeypot.proposals.slice(0, 2).map((p) => (
							<div key={p.path} className="mt-1 flex flex-wrap gap-1.5">
								<StatusPill
									label={`score ${p.attractivenessScore}`}
									tone={honeypotScoreTone(p.attractivenessScore)}
								/>
								<span className="font-mono text-xs text-[var(--sea-ink-soft)] truncate">
									{p.path}
								</span>
							</div>
						))}
					</div>
				)}

				{/* Risk Acceptances */}
				{riskAcceptance && riskAcceptance.totalActive > 0 && (
					<div className="card card-sm">
						<p className="panel-label">Risk Acceptances</p>
						<div className="flex flex-wrap gap-1.5 mt-1">
							<StatusPill label={`${riskAcceptance.totalActive} active`} tone="neutral" />
							{riskAcceptance.expiringSoon > 0 && (
								<StatusPill
									label={`${riskAcceptance.expiringSoon} expiring soon`}
									tone="warning"
								/>
							)}
							{riskAcceptance.permanent > 0 && (
								<StatusPill label={`${riskAcceptance.permanent} permanent`} tone="neutral" />
							)}
						</div>
					</div>
				)}
			</div>
		</div>
	);
}

