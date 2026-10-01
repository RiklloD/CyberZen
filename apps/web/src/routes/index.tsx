import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	ArrowRight,
	CheckCircle2,
	FolderGit2,
	GitPullRequestArrow,
	Package,
	Plus,
	ShieldAlert,
	Zap,
} from "lucide-react";
import { useState } from "react";
import ActivityFeed from "../components/ActivityFeed";
import AddRepositoryModal from "../components/AddRepositoryModal";
import FindingListRow from "../components/FindingListRow";
import QueryErrorFallback from "../components/QueryErrorFallback";
import SetupChecklist from "../components/SetupChecklist";
import EmptyState from "../components/ui/EmptyState";
import PageHeader from "../components/ui/PageHeader";
import Section from "../components/ui/Section";
import SeverityBreakdown from "../components/ui/SeverityBreakdown";
import SilentBoundary from "../components/ui/SilentBoundary";
import { api } from "../lib/convex";
import {
	countBySeverity,
	type FindingRow,
	groupFindings,
	isExploitable,
	isOpen,
} from "../lib/findings";
import { absoluteTime, plural, relativeTime } from "../lib/format";
import { useTenantSlug } from "../lib/workspace";

export const Route = createFileRoute("/")({
	errorComponent: QueryErrorFallback,
	component: OverviewPage,
});

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];
type GateDecision = OverviewData["ciGateEnforcement"]["recentDecisions"][number];

function OverviewPage() {
	const tenantSlug = useTenantSlug();
	const navigate = useNavigate();
	const overview = useQuery(api.dashboard.overview, { tenantSlug });
	const findingRows = useQuery(api.findings.list, { tenantSlug, limit: 200 }) as
		| FindingRow[]
		| undefined;
	const [showAddRepo, setShowAddRepo] = useState(false);

	if (overview === undefined || findingRows === undefined) {
		return <OverviewSkeleton />;
	}

	if (overview === null) {
		return (
			<main className="page-body-padded">
				<EmptyState
					icon={ShieldAlert}
					title="No workspace yet"
					description="Create a workspace, connect GitHub and add a repository to get your first security report."
					actions={
						<Link to="/onboarding" className="btn btn-primary">
							Start onboarding
						</Link>
					}
					bordered
				/>
			</main>
		);
	}

	const { tenant, stats, repositories, ciGateEnforcement } = overview;
	const open = findingRows.filter(isOpen);
	const severity = countBySeverity(open);
	const urgent = severity.critical + severity.high;
	const exploitable = open.filter(isExploitable).length;
	const fixable = open.filter((f) => !!f.fixVersion).length;
	const groups = groupFindings(open);
	const lastScan = Math.max(0, ...repositories.map((r: OverviewRepository) => r.lastScannedAt ?? 0));

	const openFinding = (f: FindingRow) =>
		void navigate({ to: "/findings", search: { id: f._id } });

	return (
		<main>
			<PageHeader
				title={tenant.name}
				description={
					<>
						{plural(repositories.length, "repository", "repositories")} monitored
						{lastScan > 0 && (
							<span title={absoluteTime(lastScan)}> · last scan {relativeTime(lastScan)}</span>
						)}
					</>
				}
				actions={
					<button type="button" className="btn" onClick={() => setShowAddRepo(true)}>
						<Plus size={14} />
						Add repository
					</button>
				}
			/>

			{showAddRepo && (
				<AddRepositoryModal tenantSlug={tenantSlug} onClose={() => setShowAddRepo(false)} />
			)}

			<div className="page-body">
				{/* ── Posture headline ─────────────────────────────────────── */}
				<div className="mb-7 grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
					<div className="card flex flex-col gap-5 !p-5">
						<div className="flex flex-wrap items-start justify-between gap-4">
							<div>
								<p className="text-[0.8rem] text-[var(--text-2)]">Security posture</p>
								<p className="mt-1 text-[1.35rem] font-semibold leading-tight tracking-[-0.02em]">
									{urgent > 0 ? (
										<>
											<span className="text-[var(--sev-critical)]">{urgent}</span>{" "}
											critical or high {urgent === 1 ? "finding needs" : "findings need"} attention
										</>
									) : open.length > 0 ? (
										<>No critical or high findings open</>
									) : (
										<>All clear. No open findings</>
									)}
								</p>
							</div>
							{urgent > 0 && (
								<Link
									to="/findings"
									search={{ severity: "urgent" }}
									className="btn btn-primary"
								>
									Triage now
									<ArrowRight size={14} />
								</Link>
							)}
						</div>
						<SeverityBreakdown counts={severity} />
					</div>

					<div className="kpi-strip is-2col">
						<Kpi
							to="/findings"
							search={{ exploitable: true }}
							icon={<Zap size={13} />}
							label="Exploitable"
							value={exploitable}
							hint="Confirmed in sandbox"
							tone={exploitable > 0 ? "danger" : undefined}
						/>
						<Kpi
							to="/findings"
							search={{ fixable: true }}
							icon={<CheckCircle2 size={13} />}
							label="Fix available"
							value={fixable}
							hint="Known patched version"
						/>
						<Kpi
							to="/ci-cd"
							icon={<GitPullRequestArrow size={13} />}
							label="Gates blocked"
							value={ciGateEnforcement.blockedCount}
							hint={`${ciGateEnforcement.approvedCount} approved recently`}
							tone={ciGateEnforcement.blockedCount > 0 ? "warning" : undefined}
						/>
						<Kpi
							to="/supply-chain"
							icon={<Package size={13} />}
							label="Components"
							value={stats.sbomComponents}
							hint="In latest SBOM"
						/>
					</div>
				</div>

				<div className="grid gap-x-6 xl:grid-cols-[minmax(0,1fr)_340px]">
					<div className="min-w-0">
						{/* ── Fix first ──────────────────────────────────────── */}
						<Section
							title="Fix first"
							description="Open findings ranked by severity, exploitability and fix availability"
							actions={
								<Link to="/findings" className="section-link">
									All {open.length} findings
									<ArrowRight size={13} />
								</Link>
							}
						>
							{groups.length === 0 ? (
								<div className="list">
									<EmptyState
										icon={CheckCircle2}
										title="Nothing to fix right now"
										description="New findings from scans, breach intel and agents land here, ranked by risk."
									/>
								</div>
							) : (
								<div className="list">
									{groups.slice(0, 7).map((g) => (
										<FindingListRow key={g.key} group={g} onOpen={() => openFinding(g.lead)} />
									))}
								</div>
							)}
						</Section>

						{/* ── Repositories ───────────────────────────────────── */}
						<Section
							title="Repositories"
							actions={
								<Link to="/repositories" className="section-link">
									Manage
									<ArrowRight size={13} />
								</Link>
							}
						>
							{repositories.length === 0 ? (
								<div className="list">
									<EmptyState
										icon={FolderGit2}
										title="No repositories yet"
										description="Add a repository to build its SBOM and run the first scan."
										actions={
											<button
												type="button"
												className="btn btn-primary"
												onClick={() => setShowAddRepo(true)}
											>
												<Plus size={14} />
												Add repository
											</button>
										}
									/>
								</div>
							) : (
								<RepositoryRiskTable repositories={repositories} openFindings={open} />
							)}
						</Section>
					</div>

					<aside className="min-w-0">
						<SilentBoundary>
							<div className="section">
								<SetupChecklist
									repositoryCount={repositories.length}
									scannedRepositoryCount={
										repositories.filter((r: OverviewRepository) => r.lastScannedAt || r.latestSnapshot).length
									}
									gateDecisionCount={
										ciGateEnforcement.blockedCount +
										ciGateEnforcement.approvedCount +
										ciGateEnforcement.overrideCount
									}
								/>
							</div>
						</SilentBoundary>

						<Section title="Recent activity">
							<ActivityFeed />
						</Section>

						{ciGateEnforcement.recentDecisions.length > 0 && (
							<Section
								title="Gate decisions"
								actions={
									<Link to="/ci-cd" className="section-link">
										View all
										<ArrowRight size={13} />
									</Link>
								}
							>
								<div className="list">
									{ciGateEnforcement.recentDecisions.slice(0, 4).map((d: GateDecision) => (
										<div key={d._id} className="list-row !items-start">
											<span
												className="badge mt-0.5 shrink-0"
												data-tone={
													d.decision === "blocked"
														? "danger"
														: d.decision === "approved"
															? "success"
															: "warning"
												}
											>
												{d.decision === "blocked"
													? "Blocked"
													: d.decision === "approved"
														? "Passed"
														: "Overridden"}
											</span>
											<div className="min-w-0 flex-1">
												<p className="truncate text-[0.82rem]">{d.findingTitle}</p>
												<p className="text-xs text-[var(--text-3)]">
													{d.repositoryName} · {relativeTime(d.createdAt)}
												</p>
											</div>
										</div>
									))}
								</div>
							</Section>
						)}
					</aside>
				</div>
			</div>
		</main>
	);
}

function Kpi({
	to,
	search,
	icon,
	label,
	value,
	hint,
	tone,
}: {
	to: string;
	search?: Record<string, unknown>;
	icon: React.ReactNode;
	label: string;
	value: number;
	hint: string;
	tone?: "danger" | "warning";
}) {
	return (
		<Link
			to={to as "/"}
			search={search as never}
			className="kpi"
		>
			<span className="kpi-label">
				{icon}
				{label}
			</span>
			<span
				className="kpi-value block"
				style={tone ? { color: `var(--${tone})` } : undefined}
			>
				{value.toLocaleString()}
			</span>
			<span className="kpi-hint block">{hint}</span>
		</Link>
	);
}

function RepositoryRiskTable({
	repositories,
	openFindings,
}: {
	repositories: OverviewRepository[];
	openFindings: FindingRow[];
}) {
	const byRepo = new Map<string, FindingRow[]>();
	for (const f of openFindings) {
		const list = byRepo.get(f.repositoryId) ?? [];
		list.push(f);
		byRepo.set(f.repositoryId, list);
	}
	const rows = repositories
		.map((repo) => {
			const findings = byRepo.get(repo._id) ?? [];
			return { repo, findings, counts: countBySeverity(findings) };
		})
		.sort(
			(a, b) =>
				b.counts.critical - a.counts.critical ||
				b.counts.high - a.counts.high ||
				b.findings.length - a.findings.length,
		);

	return (
		<div className="list overflow-x-auto">
			<table className="data-table">
				<thead>
					<tr>
						<th>Repository</th>
						<th className="w-[28%]">Open findings</th>
						<th className="text-right">Vulnerable deps</th>
						<th className="text-right">Last scan</th>
					</tr>
				</thead>
				<tbody>
					{rows.map(({ repo, findings, counts }) => (
						<tr key={repo._id}>
							<td data-label="Repository">
								<Link
									to="/repositories"
									search={{ repo: repo._id }}
									className="font-medium text-[var(--text)] hover:underline"
								>
									{repo.fullName}
								</Link>
								<div className="text-xs text-[var(--text-3)]">
									{repo.primaryLanguage} · {repo.defaultBranch}
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
									<span
										className={
											repo.latestSnapshot.vulnerableComponentCount > 0
												? "font-medium text-[var(--danger)]"
												: "text-[var(--text-3)]"
										}
									>
										{repo.latestSnapshot.vulnerableComponentCount}
										<span className="text-[var(--text-3)] font-normal">
											{" "}
											/ {repo.latestSnapshot.totalComponents}
										</span>
									</span>
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
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function OverviewSkeleton() {
	return (
		<main className="page-body-padded">
			<div className="skeleton mb-2 h-7 w-56" />
			<div className="skeleton mb-7 h-4 w-72" />
			<div className="mb-7 grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
				<div className="skeleton h-40" />
				<div className="skeleton h-40" />
			</div>
			<div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
				<div className="skeleton h-96" />
				<div className="skeleton h-96" />
			</div>
		</main>
	);
}
