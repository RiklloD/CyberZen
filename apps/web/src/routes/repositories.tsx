import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	ArrowLeft,
	ArrowRight,
	CheckCircle2,
	FolderGit2,
	Loader2,
	MoreHorizontal,
	Plus,
	RefreshCw,
	Rocket,
	Trash2,
	Unplug,
} from "lucide-react";
import { useCallback, useRef, useState } from "react";
import AddRepositoryModal from "../components/AddRepositoryModal";
import FindingListRow from "../components/FindingListRow";
import RepositoryAttackSurfacePanel from "../components/panels/RepositoryAttackSurfacePanel";
import RepositoryBlastRadiusPanel from "../components/panels/RepositoryBlastRadiusPanel";
import RepositoryBusinessImpactPanel from "../components/panels/RepositoryBusinessImpactPanel";
import RepositoryCloudBlastRadiusPanel from "../components/panels/RepositoryCloudBlastRadiusPanel";
import RepositoryHealthScorePanel from "../components/panels/RepositoryHealthScorePanel";
import RepositoryRemediationQueuePanel from "../components/panels/RepositoryRemediationQueuePanel";
import RepositoryRiskAcceptancePanel from "../components/panels/RepositoryRiskAcceptancePanel";
import RepositorySlaPanel from "../components/panels/RepositorySlaPanel";
import RepositoryTrustScorePanel from "../components/panels/RepositoryTrustScorePanel";
import QueryErrorFallback from "../components/QueryErrorFallback";
import RescanButton from "../components/RescanButton";
import StatusPill from "../components/StatusPill";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import Section from "../components/ui/Section";
import SeverityBreakdown from "../components/ui/SeverityBreakdown";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { countBySeverity, type FindingRow, groupFindings, isOpen } from "../lib/findings";
import { absoluteTime, humanize, plural, relativeTime } from "../lib/format";
import { useDismiss } from "../lib/useDismiss";
import {
	honeypotScoreTone,
	learningTrendTone,
	maturityTone,
	multiplierTone,
} from "../lib/utils";
import { useTenantSlug } from "../lib/workspace";

type Tab = "findings" | "dependencies" | "posture" | "deception";
const TABS: { value: Tab; label: string }[] = [
	{ value: "findings", label: "Findings" },
	{ value: "dependencies", label: "Dependencies" },
	{ value: "posture", label: "Posture" },
	{ value: "deception", label: "Deception" },
];

export const Route = createFileRoute("/repositories")({
	errorComponent: QueryErrorFallback,
	component: RepositoriesPage,
	validateSearch: (search: Record<string, unknown>): { repo?: string; tab?: Tab } => ({
		repo: typeof search.repo === "string" ? search.repo : undefined,
		tab: TABS.some((t) => t.value === search.tab) ? (search.tab as Tab) : undefined,
	}),
});

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];
type InventoryComponent = {
	name: string;
	version: string;
	ecosystem: string;
	layer: string;
	sourceFile: string;
	hasKnownVulnerabilities: boolean;
};
type DiffComponent = Omit<InventoryComponent, "hasKnownVulnerabilities">;
type VersionChange = Omit<DiffComponent, "version"> & { previousVersion: string; nextVersion: string };

function RepositoriesPage() {
	const tenantSlug = useTenantSlug();
	const search = Route.useSearch();
	const overview = useQuery(api.dashboard.overview, { tenantSlug });
	const findingRows = useQuery(api.findings.list, { tenantSlug, limit: 200 }) as
		| FindingRow[]
		| undefined;
	const [showAddModal, setShowAddModal] = useState(false);

	if (!overview || findingRows === undefined) {
		return (
			<main className="page-body-padded">
				<div className="skeleton mb-6 h-8 w-56" />
				<div className="skeleton h-72" />
			</main>
		);
	}

	const repositories: OverviewRepository[] = overview.repositories;
	const open = findingRows.filter(isOpen);
	const selected = search.repo ? repositories.find((r) => r._id === search.repo) : undefined;

	return (
		<main>
			{showAddModal && (
				<AddRepositoryModal tenantSlug={tenantSlug} onClose={() => setShowAddModal(false)} />
			)}
			{selected ? (
				<RepositoryDetail
					repo={selected}
					tenantSlug={tenantSlug}
					findings={open.filter((f) => f.repositoryId === selected._id)}
					tab={search.tab ?? "findings"}
				/>
			) : (
				<>
					<PageHeader
						title="Repositories"
						description={`${plural(repositories.length, "repository", "repositories")} monitored`}
						actions={
							<button type="button" className="btn btn-primary" onClick={() => setShowAddModal(true)}>
								<Plus size={14} />
								Add repository
							</button>
						}
					/>
					<div className="page-body">
						{repositories.length === 0 ? (
							<div className="list">
								<EmptyState
									icon={FolderGit2}
									title="No repositories yet"
									description="Connect a GitHub repository. CyberZen builds its SBOM, runs 40+ scanners and keeps watching for new advisories."
									actions={
										<button type="button" className="btn btn-primary" onClick={() => setShowAddModal(true)}>
											<Plus size={14} />
											Add repository
										</button>
									}
								/>
							</div>
						) : (
							<RepositoryTable repositories={repositories} openFindings={open} tenantSlug={tenantSlug} />
						)}
					</div>
				</>
			)}
		</main>
	);
}

// ── List ────────────────────────────────────────────────────────────────

function RepositoryTable({
	repositories,
	openFindings,
	tenantSlug,
}: {
	repositories: OverviewRepository[];
	openFindings: FindingRow[];
	tenantSlug: string;
}) {
	const navigate = useNavigate({ from: "/repositories" });
	const rows = repositories
		.map((repo) => {
			const findings = openFindings.filter((f) => f.repositoryId === repo._id);
			return { repo, findings, counts: countBySeverity(findings) };
		})
		.sort(
			(a, b) =>
				b.counts.critical - a.counts.critical ||
				b.counts.high - a.counts.high ||
				b.findings.length - a.findings.length,
		);

	return (
		<div className="list overflow-visible">
			<table className="data-table">
				<thead>
					<tr>
						<th>Repository</th>
						<th className="w-[30%]">Open findings</th>
						<th className="text-right">Vulnerable deps</th>
						<th className="text-right">Last scan</th>
						<th className="w-10" />
					</tr>
				</thead>
				<tbody>
					{rows.map(({ repo, findings, counts }) => (
						<tr
							key={repo._id}
							className="cursor-pointer"
							onClick={() => void navigate({ search: { repo: repo._id } })}
						>
							<td data-label="Repository">
								<span className="font-medium">{repo.fullName}</span>
								<div className="text-xs text-[var(--text-3)]">
									{[repo.primaryLanguage, repo.defaultBranch, humanize(repo.provider)]
										.filter(Boolean)
										.join(" · ")}
								</div>
							</td>
							<td data-label="Open findings">
								<div className="flex items-center gap-3">
									<span className="w-6 text-right font-semibold tabular">{findings.length}</span>
									<div className="flex-1">
										<SeverityBreakdown counts={counts} compact linkToFindings={false} />
									</div>
								</div>
							</td>
							<td data-label="Vulnerable deps" className="text-right tabular">
								{repo.latestSnapshot ? (
									<>
										<span
											className={
												repo.latestSnapshot.vulnerableComponentCount > 0
													? "font-medium text-[var(--danger)]"
													: "text-[var(--text-3)]"
											}
										>
											{repo.latestSnapshot.vulnerableComponentCount}
										</span>
										<span className="text-[var(--text-3)]"> / {repo.latestSnapshot.totalComponents}</span>
									</>
								) : (
									<span className="text-[var(--text-3)]">No SBOM</span>
								)}
							</td>
							<td
								data-label="Last scan"
								className="text-right text-[var(--text-2)] tabular"
								title={absoluteTime(repo.lastScannedAt)}
							>
								{repo.lastScannedAt ? relativeTime(repo.lastScannedAt) : "Never"}
							</td>
							<td onClick={(e) => e.stopPropagation()}>
								<RepoActionsMenu repositoryFullName={repo.fullName} tenantSlug={tenantSlug} />
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function RepoActionsMenu({
	repositoryFullName,
	tenantSlug,
	align = "right",
}: {
	repositoryFullName: string;
	tenantSlug: string;
	align?: "right" | "left";
}) {
	const [open, setOpen] = useState(false);
	const [status, setStatus] = useState<string | null>(null);
	const ref = useRef<HTMLDivElement>(null);
	const close = useCallback(() => setOpen(false), []);
	useDismiss(ref, open, close);
	const disconnect = useMutation(api.repositories.disconnect);
	const reconnect = useMutation(api.repositories.reconnect);

	async function run(label: string, fn: () => Promise<unknown>) {
		setStatus(label);
		try {
			await fn();
			close();
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Failed");
			return;
		}
		setStatus(null);
	}

	return (
		<div ref={ref} className="relative inline-block">
			<button
				type="button"
				className="icon-button"
				onClick={() => setOpen((v) => !v)}
				aria-label="Repository actions"
				aria-expanded={open}
			>
				<MoreHorizontal size={15} />
			</button>
			{open && (
				<div className={`menu top-[calc(100%+4px)] ${align === "right" ? "right-0" : "left-0"}`} role="menu">
					<div className="menu-label">Run scanner</div>
					<RescanButton variant="menu" scannerType="secret_detection" tenantSlug={tenantSlug} repositoryFullName={repositoryFullName} label="Secrets" />
					<RescanButton variant="menu" scannerType="iac_scan" tenantSlug={tenantSlug} repositoryFullName={repositoryFullName} label="Infrastructure as code" />
					<RescanButton variant="menu" scannerType="cicd_scan" tenantSlug={tenantSlug} repositoryFullName={repositoryFullName} label="CI/CD pipelines" />
					<RescanButton variant="menu" scannerType="crypto_weakness" tenantSlug={tenantSlug} repositoryFullName={repositoryFullName} label="Crypto weaknesses" />
					<div className="menu-sep" />
					<button
						type="button"
						className="menu-item"
						disabled={!!status}
						onClick={() => run("reconnect", () => reconnect({ tenantSlug, repositoryFullName }))}
					>
						<RefreshCw size={14} />
						Reconnect
					</button>
					<button
						type="button"
						className="menu-item is-danger"
						disabled={!!status}
						onClick={() => {
							if (window.confirm(`Stop monitoring ${repositoryFullName}? Existing findings are kept.`)) {
								void run("disconnect", () => disconnect({ tenantSlug, repositoryFullName }));
							}
						}}
					>
						<Unplug size={14} />
						Disconnect
					</button>
					{status && status !== "reconnect" && status !== "disconnect" && (
						<p className="px-2 py-1 text-xs text-[var(--danger)]">{status}</p>
					)}
				</div>
			)}
		</div>
	);
}

// ── Detail ──────────────────────────────────────────────────────────────

function RepositoryDetail({
	repo,
	tenantSlug,
	findings,
	tab,
}: {
	repo: OverviewRepository;
	tenantSlug: string;
	findings: FindingRow[];
	tab: Tab;
}) {
	const navigate = useNavigate({ from: "/repositories" });
	const counts = countBySeverity(findings);
	const snapshot = repo.latestSnapshot;

	return (
		<>
			<PageHeader
				title={
					<span className="flex items-center gap-2">
						<Link to="/repositories" className="icon-button -ml-2" aria-label="All repositories">
							<ArrowLeft size={16} />
						</Link>
						{repo.fullName}
					</span>
				}
				description={
					<>
						{[repo.primaryLanguage, `${repo.defaultBranch} branch`, humanize(repo.provider)]
							.filter(Boolean)
							.join(" · ")}
						{" · "}
						<span title={absoluteTime(repo.lastScannedAt)}>
							{repo.lastScannedAt ? `scanned ${relativeTime(repo.lastScannedAt)}` : "never scanned"}
						</span>
					</>
				}
				actions={
					<>
						<RescanButton
							variant="primary"
							scannerType="full_scan"
							tenantSlug={tenantSlug}
							repositoryFullName={repo.fullName}
							label="Run full scan"
						/>
						<RepoActionsMenu repositoryFullName={repo.fullName} tenantSlug={tenantSlug} />
					</>
				}
			>
				<div className="kpi-strip">
					<div className="kpi">
						<span className="kpi-label">Open findings</span>
						<span className="kpi-value block">{findings.length}</span>
						<span className="kpi-hint block">
							<span className="text-[var(--sev-critical)]">{counts.critical + counts.high}</span> critical or high
						</span>
					</div>
					<div className="kpi">
						<span className="kpi-label">Vulnerable dependencies</span>
						<span
							className="kpi-value block"
							style={snapshot?.vulnerableComponentCount ? { color: "var(--danger)" } : undefined}
						>
							{snapshot?.vulnerableComponentCount ?? 0}
						</span>
						<span className="kpi-hint block">of {snapshot?.totalComponents ?? 0} components</span>
					</div>
					<div className="kpi">
						<span className="kpi-label">Direct / transitive</span>
						<span className="kpi-value block">
							{snapshot?.directDependencyCount ?? 0}
							<span className="text-[var(--text-3)]"> / {snapshot?.transitiveDependencyCount ?? 0}</span>
						</span>
						<span className="kpi-hint block">dependencies</span>
					</div>
					<div className="kpi">
						<span className="kpi-label">Since last snapshot</span>
						<span className="kpi-value block">
							{snapshot?.comparison ? snapshot.comparison.changedComponentCount : "—"}
						</span>
						<span className="kpi-hint block">
							{snapshot?.comparison
								? `+${snapshot.comparison.addedCount} −${snapshot.comparison.removedCount} ~${snapshot.comparison.updatedCount}`
								: "No previous snapshot"}
						</span>
					</div>
				</div>
			</PageHeader>

			<div className="hub-tabs">
				{TABS.map((t) => (
					<button
						key={t.value}
						type="button"
						className={`hub-tab ${tab === t.value ? "is-active" : ""}`}
						onClick={() =>
							void navigate({
								search: (prev) => ({ ...prev, tab: t.value === "findings" ? undefined : t.value }),
								replace: true,
							})
						}
					>
						{t.label}
						{t.value === "findings" && <span className="tab-count">{findings.length}</span>}
					</button>
				))}
			</div>

			<div className="page-body">
				{tab === "findings" && <RepoFindingsTab repo={repo} findings={findings} />}
				{tab === "dependencies" && <RepoDependenciesTab repo={repo} />}
				{tab === "posture" && <RepoPostureTab repo={repo} tenantSlug={tenantSlug} />}
				{tab === "deception" && <RepoDeceptionTab repo={repo} tenantSlug={tenantSlug} />}
			</div>
		</>
	);
}

function RepoFindingsTab({ repo, findings }: { repo: OverviewRepository; findings: FindingRow[] }) {
	const navigate = useNavigate();
	const groups = groupFindings(findings);
	if (groups.length === 0) {
		return (
			<div className="list">
				<EmptyState
					icon={CheckCircle2}
					title="No open findings"
					description="Run a full scan to re-check this repository against every scanner."
				/>
			</div>
		);
	}
	return (
		<Section
			title="Open findings"
			description="Ranked by fix priority"
			actions={
				<Link to="/findings" search={{ repo: repo._id }} className="section-link">
					Open in Findings
					<ArrowRight size={13} />
				</Link>
			}
		>
			<div className="list">
				{groups.map((g) => (
					<FindingListRow
						key={g.key}
						group={g}
						showRepo={false}
						onOpen={() => void navigate({ to: "/findings", search: { id: g.lead._id, repo: repo._id } })}
					/>
				))}
			</div>
		</Section>
	);
}

function ComponentList({ items, empty }: { items: InventoryComponent[]; empty: string }) {
	if (items.length === 0) {
		return <p className="text-xs text-[var(--text-3)]">{empty}</p>;
	}
	return (
		<div className="list">
			{items.map((c) => (
				<div key={`${c.name}@${c.version}:${c.sourceFile}`} className="list-row !py-2">
					<span className="min-w-0 flex-1">
						<span className="font-mono text-[0.8rem]">
							{c.name}
							<span className="text-[var(--text-3)]">@{c.version}</span>
						</span>
						<span className="block truncate text-xs text-[var(--text-3)]">{c.sourceFile}</span>
					</span>
					<span className="badge">{humanize(c.ecosystem)}</span>
					<span className="badge">{humanize(c.layer)}</span>
				</div>
			))}
		</div>
	);
}

function RepoDependenciesTab({ repo }: { repo: OverviewRepository }) {
	const snapshot = repo.latestSnapshot;
	if (!snapshot) {
		return (
			<div className="list">
				<EmptyState
					icon={FolderGit2}
					title="No SBOM yet"
					description="Run a full scan to build the software bill of materials for this repository."
				/>
			</div>
		);
	}
	const layers = [
		["Direct", snapshot.directDependencyCount],
		["Transitive", snapshot.transitiveDependencyCount],
		["Build", snapshot.buildDependencyCount],
		["Container", snapshot.containerDependencyCount],
		["Runtime", snapshot.runtimeDependencyCount],
		["AI models", snapshot.aiModelDependencyCount],
	] as const;
	const cmp = snapshot.comparison;

	return (
		<div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
			<div className="min-w-0">
				<Section
					title="Vulnerable components"
					description={`${snapshot.vulnerableComponentCount} with known vulnerabilities`}
					actions={
						<Link to="/sbom" className="section-link">
							Full SBOM
							<ArrowRight size={13} />
						</Link>
					}
				>
					<ComponentList items={snapshot.vulnerablePreview} empty="No known-vulnerable components." />
				</Section>
				{cmp && (cmp.addedPreview.length > 0 || cmp.updatedPreview.length > 0 || cmp.removedPreview.length > 0) && (
					<Section
						title="Changes since last snapshot"
						description={`Compared to ${cmp.previousCommitSha.slice(0, 7)} · ${relativeTime(cmp.previousCapturedAt)}`}
					>
						<div className="list">
							{cmp.addedPreview.map((c: DiffComponent) => (
								<div key={`a-${c.name}`} className="list-row !py-2 text-[0.8rem]">
									<span className="badge" data-tone="success">Added</span>
									<span className="font-mono">{c.name}@{c.version}</span>
								</div>
							))}
							{cmp.updatedPreview.map((c: VersionChange) => (
								<div key={`u-${c.name}`} className="list-row !py-2 text-[0.8rem]">
									<span className="badge" data-tone="info">Updated</span>
									<span className="font-mono">
										{c.name} <span className="text-[var(--text-3)]">{c.previousVersion} →</span> {c.nextVersion}
									</span>
								</div>
							))}
							{cmp.removedPreview.map((c: DiffComponent) => (
								<div key={`r-${c.name}`} className="list-row !py-2 text-[0.8rem]">
									<span className="badge">Removed</span>
									<span className="font-mono text-[var(--text-3)] line-through">{c.name}@{c.version}</span>
								</div>
							))}
						</div>
					</Section>
				)}
			</div>
			<aside>
				<Section title="Inventory">
					<div className="list">
						<div className="list-row justify-between text-[0.82rem]">
							<span className="text-[var(--text-2)]">Total components</span>
							<span className="font-semibold tabular">{snapshot.totalComponents}</span>
						</div>
						{layers.map(([label, value]) => (
							<div key={label} className="list-row justify-between !py-2 text-[0.82rem]">
								<span className="text-[var(--text-2)]">{label}</span>
								<span className="tabular">{value}</span>
							</div>
						))}
					</div>
				</Section>
				<Section title="Manifests" description={`Snapshot of ${snapshot.commitSha.slice(0, 7)} · ${relativeTime(snapshot.capturedAt)}`}>
					<div className="flex flex-wrap gap-1.5">
						{snapshot.sourceFiles.map((f: string) => (
							<span key={f} className="badge font-mono">{f}</span>
						))}
					</div>
				</Section>
			</aside>
		</div>
	);
}

type LearningProfileData = NonNullable<FunctionReturnType<typeof api.learningProfileIntel.getLatestLearningProfile>>;
type VulnClassPattern = LearningProfileData["vulnClassPatterns"][number];

function RepoPostureTab({ repo, tenantSlug }: { repo: OverviewRepository; tenantSlug: string }) {
	const repositoryId = repo._id as Id<"repositories">;
	const repositoryFullName = repo.fullName;
	const trustScore = useQuery(api.trustScoreIntel.getRepositoryTrustScoreSummary, { tenantSlug, repositoryFullName });
	const blastRadius = useQuery(api.blastRadiusIntel.blastRadiusSummaryForRepository, { tenantSlug, repositoryFullName });
	const attackSurface = useQuery(api.attackSurfaceIntel.getAttackSurfaceDashboard, { tenantSlug, repositoryFullName });
	const sla = useQuery(api.slaIntel.getSlaStatusForRepository, { repositoryId });
	const remediationQueue = useQuery(api.remediationQueueIntel.getRemediationQueueForRepository, { repositoryId });
	const healthScore = useQuery(api.repositoryHealthIntel.getLatestRepositoryHealthScore, { tenantSlug, repositoryFullName });
	const learningProfile = useQuery(api.learningProfileIntel.getLatestLearningProfile, { tenantSlug, repositoryFullName });
	const riskAcceptance = useQuery(api.riskAcceptanceIntel.getAcceptanceSummaryForRepository, { repositoryId });
	const businessImpact = useQuery(api.businessImpactIntel.getLatestBusinessImpactBySlug, { tenantSlug, repositoryFullName });
	const cloudBlast = useQuery(api.cloudBlastRadiusIntel.getCloudBlastRadiusBySlug, { tenantSlug, repositoryFullName });

	const loading = [trustScore, healthScore, attackSurface, sla].some((q) => q === undefined);
	const nothing =
		!loading &&
		!trustScore &&
		!healthScore &&
		!attackSurface &&
		!(blastRadius && blastRadius.maxRiskTier !== "low") &&
		!(sla && sla.summary.totalTracked > 0) &&
		!learningProfile &&
		!businessImpact;

	if (loading) {
		return (
			<div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
				{[1, 2, 3].map((k) => (
					<div key={k} className="skeleton h-40" />
				))}
			</div>
		);
	}
	if (nothing) {
		return (
			<div className="list">
				<EmptyState
					title="No posture data yet"
					description="Posture scores are computed after the first full scan completes."
				/>
			</div>
		);
	}

	return (
		<div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
			{trustScore && <RepositoryTrustScorePanel score={trustScore} />}
			{healthScore && <RepositoryHealthScorePanel healthScore={healthScore} />}
			{blastRadius && blastRadius.maxRiskTier !== "low" && <RepositoryBlastRadiusPanel blastRadius={blastRadius} />}
			{attackSurface && <RepositoryAttackSurfacePanel attackSurface={attackSurface} />}
			{sla && sla.summary.totalTracked > 0 && <RepositorySlaPanel sla={sla} />}
			{remediationQueue && remediationQueue.summary.totalCandidates > 0 && (
				<RepositoryRemediationQueuePanel remediationQueue={remediationQueue} />
			)}
			{learningProfile && (
				<div className="card card-sm">
					<p className="panel-label">Learning profile</p>
					<div className="mt-1 flex flex-wrap gap-1.5">
						<StatusPill
							label={`Maturity ${learningProfile.adaptedConfidenceScore}/100`}
							tone={maturityTone(learningProfile.adaptedConfidenceScore)}
						/>
						<StatusPill
							label={`Surface ${learningProfile.attackSurfaceTrend}`}
							tone={learningTrendTone(learningProfile.attackSurfaceTrend)}
						/>
						{learningProfile.recurringCount > 0 && (
							<StatusPill label={`${learningProfile.recurringCount} recurring`} tone="warning" />
						)}
					</div>
					{learningProfile.vulnClassPatterns.slice(0, 2).map((p: VulnClassPattern) => (
						<div key={p.vulnClass} className="mt-1.5 flex flex-wrap gap-1.5">
							<StatusPill label={p.vulnClass} tone={multiplierTone(p.confidenceMultiplier)} />
							<StatusPill
								label={`×${p.confidenceMultiplier} confidence`}
								tone={multiplierTone(p.confidenceMultiplier)}
							/>
						</div>
					))}
					<p className="mt-2 text-xs text-[var(--text-2)]">{learningProfile.summary}</p>
				</div>
			)}
			{riskAcceptance && riskAcceptance.totalActive > 0 && (
				<RepositoryRiskAcceptancePanel riskAcceptance={riskAcceptance} repositoryId={repositoryId} />
			)}
			{businessImpact && (
				<div className="lg:col-span-2 xl:col-span-3">
					<RepositoryBusinessImpactPanel impact={businessImpact} repositoryFullName={repo.fullName} />
				</div>
			)}
			{cloudBlast && cloudBlast.providers.length > 0 && (
				<div className="lg:col-span-2 xl:col-span-3">
					<RepositoryCloudBlastRadiusPanel data={cloudBlast} repositoryFullName={repo.fullName} />
				</div>
			)}
		</div>
	);
}

type HoneypotData = NonNullable<FunctionReturnType<typeof api.honeypotIntel.getLatestHoneypotPlan>>;
type HoneypotProposal = HoneypotData["proposals"][number];

function RepoDeceptionTab({ repo, tenantSlug }: { repo: OverviewRepository; tenantSlug: string }) {
	const repositoryFullName = repo.fullName;
	const honeypot = useQuery(api.honeypotIntel.getLatestHoneypotPlan, { tenantSlug, repositoryFullName });
	const deploy = useMutation(api.honeypotIntel.deployHoneypot);
	const teardown = useMutation(api.honeypotIntel.tearDownHoneypot);
	const [busy, setBusy] = useState<"deploy" | "teardown" | null>(null);
	const [message, setMessage] = useState<{ text: string; tone: "success" | "danger" } | null>(null);
	const hasActive = !!honeypot && honeypot.totalProposals > 0;

	async function run(kind: "deploy" | "teardown") {
		setBusy(kind);
		setMessage(null);
		try {
			const res = await (kind === "deploy" ? deploy : teardown)({ tenantSlug, repositoryFullName });
			setMessage({ text: res.message, tone: "success" });
		} catch (err) {
			setMessage({ text: err instanceof Error ? err.message : `${humanize(kind)} failed`, tone: "danger" });
		} finally {
			setBusy(null);
		}
	}

	return (
		<Section
			title="Honeypot plan"
			description="Decoy endpoints and canary tokens placed where an attacker would look first. Any hit is a high-signal intrusion alert."
			actions={
				<>
					<button type="button" className="btn btn-primary" disabled={!!busy} onClick={() => run("deploy")}>
						{busy === "deploy" ? <Loader2 size={13} className="animate-spin" /> : <Rocket size={13} />}
						{hasActive ? "Redeploy" : "Deploy honeypots"}
					</button>
					<button type="button" className="btn" disabled={!!busy || !hasActive} onClick={() => run("teardown")}>
						{busy === "teardown" ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
						Tear down
					</button>
				</>
			}
		>
			{message && (
				<div className="callout mb-3" data-tone={message.tone}>
					{message.text}
				</div>
			)}
			{honeypot === undefined ? (
				<div className="skeleton h-32" />
			) : !hasActive ? (
				<div className="list">
					<EmptyState title="No honeypots deployed" description="Deploy to generate a plan tailored to this repository's routes and secrets." />
				</div>
			) : (
				<div className="list">
					<div className="list-row gap-2 text-xs text-[var(--text-2)]">
						<span>{plural(honeypot.totalProposals, "proposal")}</span>
						{honeypot.endpointCount > 0 && <span>· {plural(honeypot.endpointCount, "endpoint")}</span>}
						{honeypot.tokenCount > 0 && <span>· {plural(honeypot.tokenCount, "token")}</span>}
					</div>
					{honeypot.proposals.map((p: HoneypotProposal) => (
						<div key={p.path} className="list-row !py-2">
							<span className="flex-1 truncate font-mono text-[0.8rem]">{p.path}</span>
							<StatusPill label={`Attractiveness ${p.attractivenessScore}`} tone={honeypotScoreTone(p.attractivenessScore)} />
						</div>
					))}
				</div>
			)}
		</Section>
	);
}
