import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { GitMerge } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import { formatTimestamp } from "../lib/utils";

export const Route = createFileRoute("/ci-cd")({ component: CiCdPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewGateDecision = OverviewData["ciGateEnforcement"]["recentDecisions"][number];
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function CiCdPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-40 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { ciGateEnforcement, repositories } = overview;
	const activeRepo =
		selectedRepo
			? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
			: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<GitMerge size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">CI / CD Gates</h1>
						<p className="page-subtitle">
							Policy-driven gate enforcement · {ciGateEnforcement.blockedCount} blocked ·{" "}
							{ciGateEnforcement.approvedCount} approved
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
					{/* Left: Gate summary + recent decisions */}
					<div>
						{/* Summary stats */}
						<div className="card mb-4">
							<p className="panel-label mb-2">Gate Summary</p>
							<div className="flex flex-wrap gap-2">
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
						</div>

						{/* Recent decisions */}
						<h2 className="section-title mb-3">Recent Decisions</h2>
						<div className="space-y-3">
							{ciGateEnforcement.recentDecisions.map((d: OverviewGateDecision) => (
								<div key={d._id} className="card card-sm">
									<div className="flex flex-wrap items-center gap-2">
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
										<StatusPill
											label={d.actorId.replace(/_/g, " ")}
											tone="info"
										/>
									</div>
									<h3 className="mt-2 text-sm font-semibold text-[var(--sea-ink)]">
										{d.findingTitle}
									</h3>
									<p className="mt-0.5 text-xs text-[var(--sea-ink-soft)]">
										{d.repositoryName} · {formatTimestamp(d.createdAt)}
									</p>
									{d.justification && (
										<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
											{d.justification}
										</p>
									)}
									{d.expiresAt && (
										<p className="mt-0.5 text-xs text-[var(--warning)]">
											Expires: {formatTimestamp(d.expiresAt)}
										</p>
									)}
								</div>
							))}
							{ciGateEnforcement.recentDecisions.length === 0 && (
								<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
									<p>No gate decisions recorded yet.</p>
								</div>
							)}
						</div>
					</div>

					{/* Right: Per-repo CI/CD intelligence */}
					<div>
						{repositories.length > 1 && (
							<div className="tab-bar mb-4">
								{repositories.map((r: OverviewRepository) => (
									<button
										key={r._id}
										type="button"
										className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
										onClick={() => setSelectedRepo(r._id)}
									>
										{r.fullName.split("/").pop()}
									</button>
								))}
							</div>
						)}
						{activeRepo && (
							<RepoCiCdIntelligence
								tenantSlug={TENANT}
								repositoryFullName={activeRepo.fullName}
							/>
						)}
					</div>
				</div>
			</div>
		</main>
	);
}

function RepoCiCdIntelligence({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const cicdScan = useQuery(api.cicdScanIntel.getLatestCicdScan, {
		tenantSlug,
		repositoryFullName,
	});
	const branchProtection = useQuery(
		api.branchProtectionIntel.getLatestBranchProtectionBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const buildConfig = useQuery(
		api.buildConfigIntel.getLatestBuildConfigScanBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const commitMsg = useQuery(
		api.commitMessageIntel.getLatestCommitMessageScanBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const gitIntegrity = useQuery(
		api.gitIntegrityIntel.getLatestGitIntegrityScanBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const highRisk = useQuery(
		api.highRiskChangeIntel.getLatestHighRiskChangeScanBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const depLock = useQuery(
		api.depLockIntel.getLatestDepLockVerifyScanBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const testCoverage = useQuery(
		api.testCoverageGapIntel.getLatestTestCoverageGapBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const iacScan = useQuery(api.iacScanIntel.getLatestIacScan, {
		tenantSlug,
		repositoryFullName,
	});

	return (
		<div className="grid gap-3 sm:grid-cols-2">
			{cicdScan && (
				<div className="card card-sm">
					<p className="panel-label mb-2">CI/CD Pipeline Scan</p>
					<div className="flex flex-wrap gap-1.5">
					<StatusPill
						label={cicdScan.overallRisk}
						tone={
							cicdScan.overallRisk === "critical" || cicdScan.overallRisk === "high"
								? "danger"
								: cicdScan.overallRisk === "medium"
									? "warning"
									: "success"
						}
					/>
					{cicdScan.totalFindings > 0 && (
						<StatusPill label={`${cicdScan.totalFindings} issues`} tone="warning" />
					)}
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{cicdScan.summary}</p>
				</div>
			)}

			{branchProtection && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Branch Protection</p>
					<div className="flex flex-wrap gap-1.5">
					<StatusPill
						label={branchProtection.riskLevel}
						tone={
							branchProtection.riskLevel === "critical" || branchProtection.riskLevel === "high"
								? "danger"
								: branchProtection.riskLevel === "medium"
									? "warning"
									: "success"
						}
					/>
					{branchProtection.criticalCount > 0 && (
						<StatusPill
							label={`${branchProtection.criticalCount} critical`}
							tone="danger"
						/>
					)}
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
						{branchProtection.summary}
					</p>
				</div>
			)}

			{buildConfig && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Build Config</p>
					<div className="flex flex-wrap gap-1.5">
						<StatusPill
							label={buildConfig.riskLevel}
							tone={
								buildConfig.riskLevel === "critical" || buildConfig.riskLevel === "high"
									? "danger"
									: buildConfig.riskLevel === "medium"
										? "warning"
										: "success"
							}
						/>
					{buildConfig.totalFindings > 0 && (
						<StatusPill
							label={`${buildConfig.totalFindings} issues`}
							tone="warning"
						/>
					)}
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{buildConfig.summary}</p>
				</div>
			)}

			{commitMsg && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Commit Messages</p>
					<div className="flex flex-wrap gap-1.5">
					<StatusPill
						label={commitMsg.riskLevel}
						tone={commitMsg.riskLevel === "none" || commitMsg.riskLevel === "low" ? "success" : commitMsg.riskLevel === "medium" ? "warning" : "danger"}
					/>
					{commitMsg.totalFindings > 0 && (
						<StatusPill
							label={`${commitMsg.totalFindings} findings`}
							tone="neutral"
						/>
					)}
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{commitMsg.summary}</p>
				</div>
			)}

			{gitIntegrity && (
				<div className="card card-sm">
					<p className="panel-label mb-2">Git Integrity</p>
					<div className="flex flex-wrap gap-1.5">
					<StatusPill
						label={gitIntegrity.riskLevel}
						tone={
							gitIntegrity.riskLevel === "none" || gitIntegrity.riskLevel === "low"
								? "success"
								: gitIntegrity.riskLevel === "medium"
									? "warning"
									: "danger"
						}
					/>
					{gitIntegrity.criticalCount > 0 && (
						<StatusPill
							label={`${gitIntegrity.criticalCount} critical`}
							tone="danger"
						/>
					)}
					</div>
					<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{gitIntegrity.summary}</p>
				</div>
			)}

			{highRisk && (
					<div className="card card-sm">
						<p className="panel-label mb-2">High-Risk Changes</p>
						<div className="flex flex-wrap gap-1.5">
							{highRisk.criticalCount > 0 && (
								<StatusPill
									label={`${highRisk.criticalCount} critical`}
									tone="danger"
								/>
							)}
							{highRisk.highCount > 0 && (
								<StatusPill
									label={`${highRisk.highCount} high`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{highRisk.summary}</p>
					</div>
				)}

				{depLock && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Dependency Lock</p>
						<div className="flex flex-wrap gap-1.5">
							{depLock.criticalCount > 0 && (
								<StatusPill
									label={`${depLock.criticalCount} critical discrepancies`}
									tone="danger"
								/>
							)}
							{depLock.highCount > 0 && (
								<StatusPill
									label={`${depLock.highCount} high`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{depLock.summary}</p>
					</div>
				)}

				{testCoverage && (
					<div className="card card-sm">
						<p className="panel-label mb-2">Test Coverage Gaps</p>
						<div className="flex flex-wrap gap-1.5">
					{testCoverage.totalFindings > 0 && (
						<StatusPill
							label={`${testCoverage.totalFindings} gaps`}
							tone="danger"
						/>
					)}
							{testCoverage.highCount > 0 && (
								<StatusPill
									label={`${testCoverage.highCount} high`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{testCoverage.summary}</p>
					</div>
				)}

				{iacScan && (
					<div className="card card-sm">
						<p className="panel-label mb-2">IaC Security</p>
						<div className="flex flex-wrap gap-1.5">
							{iacScan.criticalCount > 0 && (
								<StatusPill
									label={`${iacScan.criticalCount} critical issues`}
									tone="danger"
								/>
							)}
							{iacScan.highCount > 0 && (
								<StatusPill
									label={`${iacScan.highCount} high`}
									tone="warning"
								/>
							)}
						</div>
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">{iacScan.summary}</p>
					</div>
				)}
		</div>
	);
}

