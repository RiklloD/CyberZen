import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
type LearningProfileData = NonNullable<FunctionReturnType<typeof api.learningProfileIntel.getLatestLearningProfile>>;
type VulnClassPattern = LearningProfileData["vulnClassPatterns"][number];
type HoneypotData = NonNullable<FunctionReturnType<typeof api.honeypotIntel.getLatestHoneypotPlan>>;
type HoneypotProposal = HoneypotData["proposals"][number];
import { GitBranch, Loader2, Rocket, Trash2 } from "lucide-react";
import { useState } from "react";
import RepositoryAttackSurfacePanel from "../components/panels/RepositoryAttackSurfacePanel";
import RepositoryBlastRadiusPanel from "../components/panels/RepositoryBlastRadiusPanel";
import RepositoryBusinessImpactPanel from "../components/panels/RepositoryBusinessImpactPanel";
import RepositoryTrustScorePanel from "../components/panels/RepositoryTrustScorePanel";
import RepositoryCloudBlastRadiusPanel from "../components/panels/RepositoryCloudBlastRadiusPanel";
import RepositoryHealthScorePanel from "../components/panels/RepositoryHealthScorePanel";
import RepositoryListPanel from "../components/panels/RepositoryListPanel";
import RepositoryRemediationQueuePanel from "../components/panels/RepositoryRemediationQueuePanel";
import RepositoryRiskAcceptancePanel from "../components/panels/RepositoryRiskAcceptancePanel";
import RepositorySlaPanel from "../components/panels/RepositorySlaPanel";
import RescanButton from "../components/RescanButton";
import StatusPill from "../components/StatusPill";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import {
	honeypotScoreTone,
	learningTrendTone,
	maturityTone,
	multiplierTone } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import QueryErrorFallback from "../components/QueryErrorFallback";

export const Route = createFileRoute("/repositories")({
	errorComponent: QueryErrorFallback,
	component: RepositoriesPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];

function RepositoriesPage() {
	const TENANT = useTenantSlug();
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
		? (repositories.find((r: OverviewRepository) => r._id === selected) ?? null)
		: null;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<GitBranch size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Repositories</h1>
						<p className="page-subtitle">
							{repositories.length} repositories tracked
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Repository list */}
				<RepositoryListPanel
					repos={repositories}
					selected={selected}
					onSelect={(id) =>
						setSelected(selected === id ? null : id)
					}
					tenantSlug={TENANT}
				/>

				{/* Drill-down panel for selected repo */}
				{selectedRepo && (
					<RepositoryDrillDown tenantSlug={TENANT} repo={selectedRepo} />
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
	repo }: {
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
		repositoryId });
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
		repositoryFullName });
	const riskAcceptance = useQuery(
		api.riskAcceptanceIntel.getAcceptanceSummaryForRepository,
		{ repositoryId },
	);
	const businessImpact = useQuery(
		api.businessImpactIntel.getLatestBusinessImpactBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const cloudBlast = useQuery(
		api.cloudBlastRadiusIntel.getCloudBlastRadiusBySlug,
		{ tenantSlug, repositoryFullName },
	);

	return (
		<div className="space-y-4">
			<div className="flex items-center gap-2 mb-1">
				<GitBranch size={14} className="text-[var(--signal)]" />
				<h2 className="text-base font-bold text-[var(--sea-ink)]">
					{repo.fullName}
				</h2>
				<div className="flex flex-wrap gap-1 ml-auto">
					<RescanButton
						scannerType="full_scan"
						tenantSlug={tenantSlug}
						repositoryFullName={repo.fullName}
						label="Full Re-scan"
					/>
					<RescanButton
						scannerType="secret_detection"
						tenantSlug={tenantSlug}
						repositoryFullName={repo.fullName}
					/>
					<RescanButton
						scannerType="iac_scan"
						tenantSlug={tenantSlug}
						repositoryFullName={repo.fullName}
					/>
					<RescanButton
						scannerType="cicd_scan"
						tenantSlug={tenantSlug}
						repositoryFullName={repo.fullName}
					/>
				</div>
			</div>

			<div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
				{/* Trust Score */}
				{trustScore && <RepositoryTrustScorePanel score={trustScore} />}

				{/* Repository Health */}
				{healthScore && (
					<RepositoryHealthScorePanel healthScore={healthScore} />
				)}

				{/* Blast Radius */}
				{blastRadius && blastRadius.maxRiskTier !== "low" && (
					<RepositoryBlastRadiusPanel blastRadius={blastRadius} />
				)}

				{/* Attack Surface */}
				{attackSurface && (
					<RepositoryAttackSurfacePanel attackSurface={attackSurface} />
				)}

				{/* SLA Enforcement */}
				{sla && sla.summary.totalTracked > 0 && (
					<RepositorySlaPanel sla={sla} />
				)}

				{/* Remediation Queue */}
				{remediationQueue && remediationQueue.summary.totalCandidates > 0 && (
					<RepositoryRemediationQueuePanel
						remediationQueue={remediationQueue}
					/>
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
						{learningProfile.vulnClassPatterns.slice(0, 2).map((p: VulnClassPattern) => (
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

			{/* Honeypot — always rendered so deploy/teardown CTAs stay accessible */}
			<div className="card card-sm">
					<p className="panel-label">Honeypot Plan</p>

					{/* §3.12 — Deploy / Teardown CTAs */}
					<HoneypotCtaButtons
						tenantSlug={tenantSlug}
						repositoryFullName={repositoryFullName}
						hasActiveHoneypots={!!honeypot && honeypot.totalProposals > 0}
					/>

					{honeypot && honeypot.totalProposals > 0 && (
					<>
					<div className="flex flex-wrap gap-1.5 mt-1">
						<StatusPill
							label={`${honeypot.totalProposals} proposals`}
							tone="neutral"
						/>
						{honeypot.endpointCount > 0 && (
							<StatusPill
								label={`${honeypot.endpointCount} endpoints`}
								tone="neutral"
							/>
						)}
						{honeypot.tokenCount > 0 && (
							<StatusPill
								label={`${honeypot.tokenCount} tokens`}
								tone="neutral"
							/>
						)}
					</div>
					{honeypot.proposals.slice(0, 2).map((p: HoneypotProposal) => (
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
					</>
					)}

					{!honeypot && (
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)] italic">
						No honeypot plan computed yet. Deploy to generate one.
					</p>
					)}
					</div>

					{/* Business Impact (full-width within grid) */}
				{businessImpact && (
					<div className="lg:col-span-2 xl:col-span-3">
						<RepositoryBusinessImpactPanel
							impact={businessImpact}
							repositoryFullName={repo.fullName}
						/>
					</div>
				)}

				{/* Cloud Blast Radius (full-width within grid) */}
				{cloudBlast && cloudBlast.providers.length > 0 && (
					<div className="lg:col-span-2 xl:col-span-3">
						<RepositoryCloudBlastRadiusPanel
							data={cloudBlast}
							repositoryFullName={repo.fullName}
						/>
					</div>
				)}

				{/* Risk Acceptances */}
				{riskAcceptance && riskAcceptance.totalActive > 0 && (
					<RepositoryRiskAcceptancePanel
						riskAcceptance={riskAcceptance}
						repositoryId={repositoryId}
					/>
				)}
			</div>
		</div>
	);
}

/**
 * §3.12 — Honeypot Deploy / Teardown CTAs.
 *
 * "Deploy" calls `api.honeypotIntel.deployHoneypot`.
 * "Teardown" calls `api.honeypotIntel.tearDownHoneypot`.
 * Both show a loading spinner while the mutation is in-flight.
 */
function HoneypotCtaButtons({
	tenantSlug,
	repositoryFullName,
	hasActiveHoneypots }: {
	tenantSlug: string;
	repositoryFullName: string;
	hasActiveHoneypots: boolean;
}) {
	const [deploying, setDeploying] = useState(false);
	const [tearingDown, setTearingDown] = useState(false);
	const [deployMsg, setDeployMsg] = useState<string | null>(null);
	const [teardownMsg, setTeardownMsg] = useState<string | null>(null);

	const deploy = useMutation(api.honeypotIntel.deployHoneypot);
	const teardown = useMutation(api.honeypotIntel.tearDownHoneypot);

	const handleDeploy = async () => {
		setDeploying(true);
		setDeployMsg(null);
		try {
			const res = await deploy({ tenantSlug, repositoryFullName });
			setDeployMsg(res.message);
		} catch (err) {
			setDeployMsg(err instanceof Error ? err.message : "Deploy failed");
		} finally {
			setDeploying(false);
		}
	};

	const handleTeardown = async () => {
		setTearingDown(true);
		setTeardownMsg(null);
		try {
			const res = await teardown({ tenantSlug, repositoryFullName });
			setTeardownMsg(res.message);
		} catch (err) {
			setTeardownMsg(err instanceof Error ? err.message : "Teardown failed");
		} finally {
			setTearingDown(false);
		}
	};

	return (
		<div className="mt-2 flex flex-wrap items-center gap-2">
			<button
				type="button"
				className="signal-button inline-flex items-center gap-1.5 text-xs"
				onClick={handleDeploy}
				disabled={deploying}
			>
				{deploying ? (
					<Loader2 size={12} className="animate-spin" />
				) : (
					<Rocket size={12} />
				)}
				{deploying ? "Deploying…" : "Deploy"}
			</button>

			<button
				type="button"
				className="signal-button secondary-button inline-flex items-center gap-1.5 text-xs"
				onClick={handleTeardown}
				disabled={tearingDown || !hasActiveHoneypots}
			>
				{tearingDown ? (
					<Loader2 size={12} className="animate-spin" />
				) : (
					<Trash2 size={12} />
				)}
				{tearingDown ? "Tearing down…" : "Teardown"}
			</button>

			{deployMsg && (
				<span className="text-xs text-[var(--success)]">{deployMsg}</span>
			)}
			{teardownMsg && (
				<span className="text-xs text-[var(--warning)]">{teardownMsg}</span>
			)}
		</div>
	);
}
