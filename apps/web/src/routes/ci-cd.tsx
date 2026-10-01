import { createFileRoute, Link } from "@tanstack/react-router";
import { BookOpen, GitPullRequestArrow } from "lucide-react";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import type { Id } from "../../convex/_generated/dataModel";
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
import { absoluteTime, humanize, relativeTime } from "../lib/format";
import PageHeader from "../components/ui/PageHeader";
import Section from "../components/ui/Section";
import EmptyState from "../components/ui/EmptyState";
import RepoPicker, { useSelectedRepo } from "../components/ui/RepoPicker";
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
	const [activeTab, setActiveTab] = useState<"overview" | "gate-decisions">("overview");
	const [selectedDecisionId, setSelectedDecisionId] = useState<string | null>(null);
	const repositories: OverviewRepository[] = overview?.repositories ?? [];
	const [activeRepo, selectRepo] = useSelectedRepo(repositories);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="skeleton mb-6 h-8 w-56" />
				<div className="skeleton h-72" />
			</main>
		);
	}

	const { ciGateEnforcement } = overview;
	const decisionCount =
		ciGateEnforcement.blockedCount + ciGateEnforcement.approvedCount + ciGateEnforcement.overrideCount;

	return (
		<main>
			<PageHeader
				title="CI/CD gates"
				description="Policy checks that block risky changes before they merge or deploy"
				actions={
					<>
						<RepoPicker repositories={repositories} active={activeRepo} onSelect={selectRepo} />
						<Link to="/docs/github-integration" className="btn">
							<BookOpen size={14} />
							Set up GitHub Action
						</Link>
					</>
				}
			>
				<div className="kpi-strip">
					<div className="kpi">
						<span className="kpi-label">Blocked</span>
						<span
							className="kpi-value block"
							style={ciGateEnforcement.blockedCount > 0 ? { color: "var(--danger)" } : undefined}
						>
							{ciGateEnforcement.blockedCount}
						</span>
						<span className="kpi-hint block">Changes stopped by policy</span>
					</div>
					<div className="kpi">
						<span className="kpi-label">Passed</span>
						<span className="kpi-value block">{ciGateEnforcement.approvedCount}</span>
						<span className="kpi-hint block">Cleared all checks</span>
					</div>
					<div className="kpi">
						<span className="kpi-label">Overridden</span>
						<span
							className="kpi-value block"
							style={ciGateEnforcement.overrideCount > 0 ? { color: "var(--warning)" } : undefined}
						>
							{ciGateEnforcement.overrideCount}
						</span>
						<span className="kpi-hint block">Merged despite a block</span>
					</div>
				</div>
			</PageHeader>

			<div className="hub-tabs">
				<button
					type="button"
					className={`hub-tab ${activeTab === "overview" ? "is-active" : ""}`}
					onClick={() => setActiveTab("overview")}
				>
					Overview
				</button>
				<button
					type="button"
					className={`hub-tab ${activeTab === "gate-decisions" ? "is-active" : ""}`}
					onClick={() => setActiveTab("gate-decisions")}
				>
					Decision log
					<span className="tab-count">{decisionCount}</span>
				</button>
			</div>

			{activeTab === "overview" ? (
				<div className="page-body">
					<div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
						<Section title="Recent decisions">
							{ciGateEnforcement.recentDecisions.length === 0 ? (
								<div className="list">
									<EmptyState
										icon={GitPullRequestArrow}
										title="No gate decisions yet"
										description="Add the CyberZen GitHub Action to your workflow and every pull request gets a pass/block verdict here."
										actions={
											<Link to="/docs/github-integration" className="btn btn-primary">
												Set up GitHub Action
											</Link>
										}
									/>
								</div>
							) : (
								<div className="list">
									{ciGateEnforcement.recentDecisions.map((d: OverviewGateDecision) => (
										<div key={d._id} className="list-row !items-start">
											<StatusPill
												label={d.decision === "approved" ? "Passed" : d.decision}
												tone={d.decision === "blocked" ? "danger" : d.decision === "approved" ? "success" : "warning"}
											/>
											<div className="min-w-0 flex-1">
												<p className="truncate text-[0.84rem] font-medium">{d.findingTitle}</p>
												<p className="truncate text-xs text-[var(--text-3)]">
													{d.repositoryName} · {humanize(d.stage)} · {humanize(d.actorId)}
												</p>
												{d.justification && (
													<p className="mt-0.5 text-xs text-[var(--text-2)]">“{d.justification}”</p>
												)}
												{d.expiresAt && (
													<p className="mt-0.5 text-xs text-[var(--warning)]">
														Override expires {relativeTime(d.expiresAt)}
													</p>
												)}
											</div>
											<span className="shrink-0 text-xs text-[var(--text-3)]" title={absoluteTime(d.createdAt)}>
												{relativeTime(d.createdAt)}
											</span>
										</div>
									))}
								</div>
							)}
						</Section>

						<Section
							title="Pipeline checks"
							description={activeRepo ? `Latest results for ${activeRepo.fullName}` : undefined}
						>
							{activeRepo ? (
								<RepoCiCdIntelligence tenantSlug={TENANT} repositoryFullName={activeRepo.fullName} />
							) : (
								<div className="list">
									<EmptyState title="No repositories" description="Add a repository to see its pipeline checks." />
								</div>
							)}
						</Section>
					</div>
				</div>
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
/* Gate Decisions Tab — §1.17                                                 */
/* -------------------------------------------------------------------------- */

function GateDecisionsTab({
	tenantSlug,
	activeRepo,
	selectedDecisionId,
	onSelectDecision,
	onOverride }: {
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
	repositoryFullName }: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const cicdScan = useQuery(api.cicdScanIntel.getLatestCicdScan, {
		tenantSlug,
		repositoryFullName });
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
		repositoryFullName });
	const testCoverage = useQuery(
		api.testCoverageGapIntel.getLatestTestCoverageGapBySlug,
		{ tenantSlug, repositoryFullName },
	);
	const iacScan = useQuery(api.iacScanIntel.getLatestIacScan, {
		tenantSlug,
		repositoryFullName });

	const results = [cicdScan, branchProtection, buildConfig, commitMsg, gitIntegrity, highRisk, depLock, testCoverage, iacScan];
	if (results.some((r) => r === undefined)) {
		return (
			<div className="grid gap-3 sm:grid-cols-2">
				{[1, 2, 3, 4].map((k) => (
					<div key={k} className="skeleton h-32" />
				))}
			</div>
		);
	}
	if (results.every((r) => !r)) {
		return (
			<div className="list">
				<EmptyState
					title="No pipeline checks yet"
					description="Checks run on each push and pull request once the repository has been scanned."
				/>
			</div>
		);
	}

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
