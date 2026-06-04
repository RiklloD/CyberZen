import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import type { Id } from "../../convex/_generated/dataModel";
import { GitMerge } from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import GateDecisionListPanel from "../components/panels/GateDecisionListPanel";
import GateDecisionDetailDrawer from "../components/panels/GateDecisionDetailDrawer";
import RepositoryCicdScanPanel from "../components/panels/RepositoryCicdScanPanel";
import BranchProtectionPanel from "../components/panels/BranchProtectionPanel";
import BuildConfigPanel from "../components/panels/BuildConfigPanel";
import CommitMessagePanel from "../components/panels/CommitMessagePanel";
import GitIntegrityPanel from "../components/panels/GitIntegrityPanel";
import HighRiskChangePanel from "../components/panels/HighRiskChangePanel";
import DepLockPanel from "../components/panels/DepLockPanel";
import TestCoverageGapPanel from "../components/panels/TestCoverageGapPanel";
import RepositoryIacScanPanel from "../components/panels/RepositoryIacScanPanel";
import { api } from "../lib/convex";
import { formatTimestamp } from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/ci-cd")({ errorComponent: RouteErrorBoundary, component: CiCdPage });

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewGateDecision =
	OverviewData["ciGateEnforcement"]["recentDecisions"][number];
type OverviewRepository = OverviewData["repositories"][number];

function CiCdPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState<"overview" | "gate-decisions">("overview");
	const [selectedDecisionId, setSelectedDecisionId] = useState<string | null>(null);

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
	const activeRepo = selectedRepo
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
							Policy-driven gate enforcement · {ciGateEnforcement.blockedCount}{" "}
							blocked · {ciGateEnforcement.approvedCount} approved
						</p>
					</div>
				</div>
			</div>

			{/* Tab bar */}
			<div className="tab-bar mb-4">
				<button
					type="button"
					className={`tab-btn ${activeTab === "overview" ? "is-active" : ""}`}
					onClick={() => setActiveTab("overview")}
				>
					Overview
				</button>
				<button
					type="button"
					className={`tab-btn ${activeTab === "gate-decisions" ? "is-active" : ""}`}
					onClick={() => setActiveTab("gate-decisions")}
				>
					Gate Decisions
				</button>
			</div>

			{activeTab === "overview" ? (
				<OverviewTab
					TENANT={TENANT}
					ciGateEnforcement={ciGateEnforcement}
					repositories={repositories}
					activeRepo={activeRepo}
					selectedRepo={selectedRepo}
					setSelectedRepo={setSelectedRepo}
				/>
			) : (
				<GateDecisionsTab
					tenantSlug={TENANT}
					activeRepo={activeRepo}
					selectedDecisionId={selectedDecisionId}
					onSelectDecision={setSelectedDecisionId}
					onOverride={() => setSelectedDecisionId(null)}
				/>
			)}
		</main>
	);
}

/* -------------------------------------------------------------------------- */
/* Overview Tab — original CI/CD page content                                 */
/* -------------------------------------------------------------------------- */

function OverviewTab({
	TENANT,
	ciGateEnforcement,
	repositories,
	activeRepo,
	selectedRepo: _selectedRepo,
	setSelectedRepo,
}: {
	TENANT: string;
	ciGateEnforcement: OverviewData["ciGateEnforcement"];
	repositories: OverviewData["repositories"];
	activeRepo: OverviewRepository | undefined;
	selectedRepo: string | null;
	setSelectedRepo: (id: string | null) => void;
}) {
	return (
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
								tone={
									ciGateEnforcement.blockedCount > 0 ? "danger" : "success"
								}
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
						{ciGateEnforcement.recentDecisions.map(
							(d: OverviewGateDecision) => (
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
										<StatusPill
											label={d.stage.replace(/_/g, " ")}
											tone="neutral"
										/>
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
							),
						)}
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
	);
}

/* -------------------------------------------------------------------------- */
/* Gate Decisions Tab — §1.17                                                 */
/* -------------------------------------------------------------------------- */

function GateDecisionsTab({
	tenantSlug,
	activeRepo,
	selectedDecisionId,
	onSelectDecision,
	onOverride,
}: {
	tenantSlug: string;
	activeRepo: OverviewRepository | undefined;
	selectedDecisionId: string | null;
	onSelectDecision: (id: string | null) => void;
	onOverride?: () => void;
}) {
	const decisions = useQuery(
		api.gateEnforcement.listGateDecisionsForRepository,
		activeRepo
			? { tenantSlug, repositoryFullName: activeRepo.fullName }
			: "skip",
	);

	const decisionDetail = useQuery(
		api.gateEnforcement.getGateDecisionDetail,
		selectedDecisionId
			? { gateDecisionId: selectedDecisionId as Id<"gateDecisions"> }
			: "skip",
	);

	return (
		<div className="page-body">
			<div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
				<GateDecisionListPanel
					decisions={decisions}
					selectedId={selectedDecisionId}
					onSelect={onSelectDecision}
				/>
				<GateDecisionDetailDrawer detail={decisionDetail} onOverride={onOverride} />
			</div>
		</div>
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
	const depLock = useQuery(api.depLockIntel.getLatestDepLockVerifyScanBySlug, {
		tenantSlug,
		repositoryFullName,
	});
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
			{cicdScan && <RepositoryCicdScanPanel scan={cicdScan} />}
			{branchProtection && (
				<BranchProtectionPanel branchProtection={branchProtection} />
			)}
			{buildConfig && <BuildConfigPanel buildConfig={buildConfig} />}
			{commitMsg && <CommitMessagePanel commitMsg={commitMsg} />}
			{gitIntegrity && <GitIntegrityPanel gitIntegrity={gitIntegrity} />}
			{highRisk && <HighRiskChangePanel highRisk={highRisk} />}
			{depLock && <DepLockPanel depLock={depLock} />}
			{testCoverage && <TestCoverageGapPanel testCoverage={testCoverage} />}
			{iacScan && <RepositoryIacScanPanel iacScan={iacScan} />}
		</div>
	);
}
