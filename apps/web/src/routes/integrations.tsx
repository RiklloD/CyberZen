import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "@convex-dev/auth/react";
import { useAction, useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { CheckCircle, Loader2, MessageSquare, Plug, XCircle } from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import ObservabilityIntelPanel from "../components/panels/ObservabilityIntelPanel";
import SiemIntelPanel from "../components/panels/SiemIntelPanel";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/integrations")({
	errorComponent: RouteErrorBoundary,
	component: IntegrationsPage,
});

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewRepository = OverviewData["repositories"][number];
type CatalogEntry = NonNullable<FunctionReturnType<typeof api.integrations.listIntegrationCatalog>>[number];
type VendorEntry = NonNullable<FunctionReturnType<typeof api.vendorTrust.listVendorsBySlug>>[number];
type MarketplaceItem = NonNullable<FunctionReturnType<typeof api.communityMarketplace.listContributions>>[number];
type IntegrationStatus = NonNullable<FunctionReturnType<typeof api.integrations.listIntegrationStatusForTenant>>[number];
type GamificationData = NonNullable<FunctionReturnType<typeof api.gamificationIntel.getLatestGamification>>;
type LeaderboardEntry = GamificationData["repositoryLeaderboard"][number];

function IntegrationsPage() {
	const TENANT = useTenantSlug();
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const vendors = useQuery(api.vendorTrust.listVendorsBySlug, {
		tenantSlug: TENANT,
	});
	const marketplace = useQuery(api.communityMarketplace.listContributions, {
		limit: 12,
	});
	const catalog = useQuery(api.integrations.listIntegrationCatalog);
	const integrationStatus = useQuery(api.integrations.listIntegrationStatusForTenant, {
		tenantSlug: TENANT,
	});
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState<"main" | "observability" | "siem">("main");

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3 sm:grid-cols-2">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-40 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const { repositories } = overview;
	const activeRepo = selectedRepo
		? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
		: repositories[0];

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Plug size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Integrations</h1>
						<p className="page-subtitle">
							Vendor trust · Webhooks · Community marketplace
						</p>
					</div>
				</div>
			</div>

			{/* Tab bar */}
			<div className="flex gap-1 border-b border-[var(--line)] pb-0">
				<button
					type="button"
					className={`tab-btn ${activeTab === "main" ? "is-active" : ""}`}
					onClick={() => setActiveTab("main")}
				>
					Integrations
				</button>
				<button
					type="button"
					className={`tab-btn ${activeTab === "observability" ? "is-active" : ""}`}
					onClick={() => setActiveTab("observability")}
				>
					Observability
				</button>
				<button
					type="button"
					className={`tab-btn ${activeTab === "siem" ? "is-active" : ""}`}
					onClick={() => setActiveTab("siem")}
				>
					SIEM
				</button>
			</div>

			{activeTab === "observability" ? (
				<ObservabilityTab tenantSlug={TENANT} />
			) : activeTab === "siem" ? (
				<SiemTab repositories={repositories} />
			) : (
			<div className="page-body space-y-5">
				{/* ChatOps — Slack Integration */}
				<div>
					<h2 className="section-title mb-3">ChatOps</h2>
					<SlackIntegrationCard tenantSlug={TENANT} />
				</div>

				{/* Webhook Settings — live from integrationCatalog (spec §5.4) */}
				<div>
					<h2 className="section-title mb-3">Webhook Configuration</h2>
					<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
						{(catalog ?? []).map((entry: CatalogEntry) => {
							const isOutbound = !entry.webhookPathTemplate;
							return (
								<div key={entry.slug} className="card card-sm">
									<div className="flex items-center justify-between mb-1.5">
										<span className="text-sm font-semibold text-[var(--sea-ink)]">
											{entry.label}
										</span>
										<StatusPill
											label={isOutbound ? "outbound" : "inbound"}
											tone={isOutbound ? "info" : "neutral"}
										/>
									</div>
									<p className="text-xs font-mono text-[var(--sea-ink-soft)]">
										{entry.envVarName}
									</p>
									{entry.webhookPathTemplate && (
										<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
											Endpoint: <code>{entry.webhookPathTemplate}</code>
										</p>
									)}
								</div>
							);
						})}
					</div>
				</div>

				{/* Vendor Trust */}
				{vendors && vendors.length > 0 && (
					<div>
						<h2 className="section-title mb-3">
							Vendor Trust ({vendors.length} vendors)
						</h2>
						<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
							{vendors.map((vendor: VendorEntry) => (
								<div key={vendor._id} className="card card-sm">
									<div className="flex items-start justify-between gap-2">
										<span className="text-sm font-semibold text-[var(--sea-ink)]">
											{vendor.name}
										</span>
										<StatusPill
											label={`risk ${vendor.latestRisk?.riskScore ?? "—"}`}
											tone={
												vendor.latestRisk?.riskLevel === "critical" ||
												vendor.latestRisk?.riskLevel === "high"
													? "danger"
													: vendor.latestRisk?.riskLevel === "medium"
														? "warning"
														: "success"
											}
										/>
									</div>
									<div className="mt-1.5 flex flex-wrap gap-1.5">
										<StatusPill label={vendor.category} tone="info" />
										{vendor.latestRisk?.breachDetected && (
											<StatusPill label="known breach" tone="danger" />
										)}
										{vendor.latestRisk?.riskLevel &&
											vendor.latestRisk.riskLevel !== "trusted" &&
											vendor.latestRisk.riskLevel !== "low" && (
												<StatusPill
													label={vendor.latestRisk.recommendation}
													tone={
														vendor.latestRisk.riskLevel === "critical" ||
														vendor.latestRisk.riskLevel === "high"
															? "danger"
															: "warning"
													}
												/>
											)}
									</div>
									{vendor.latestRisk?.breachSummary && (
										<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
											{vendor.latestRisk.breachSummary}
										</p>
									)}
								</div>
							))}
						</div>
					</div>
				)}

				{/* Per-repo gamification */}
				{repositories.length > 0 && (
					<div>
						<div className="flex items-center justify-between mb-3">
							<h2 className="section-title">Repository Gamification</h2>
							{repositories.length > 1 && (
								<div className="flex gap-1">
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
						</div>
						{activeRepo && (
							<RepoGamification
								tenantSlug={TENANT}
								repositoryFullName={activeRepo.fullName}
							/>
						)}
					</div>
				)}

				{/* Community Marketplace */}
				{marketplace && marketplace.length > 0 && (
					<div>
						<h2 className="section-title mb-3">
							Community Marketplace ({marketplace.length} integrations)
						</h2>
						<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
							{marketplace.map((item: MarketplaceItem) => (
								<CommunityContributionCard
									key={`${item.title}-${item.createdAt}`}
									item={item}
								/>
							))}
						</div>
					</div>
				)}

				{/* Integration overview — live from integrationCatalog + integrationStatus (spec §5.4) */}
				<div>
					<h2 className="section-title mb-3">Integration Status</h2>
					<div className="card">
						<table className="data-table">
							<thead>
								<tr>
									<th>Integration</th>
									<th>Category</th>
									<th>Direction</th>
									<th>Env Variable</th>
									<th>Health</th>
								</tr>
							</thead>
							<tbody>
								{(catalog ?? []).map((entry: CatalogEntry) => {
									const status = (integrationStatus ?? []).find(
										(s: IntegrationStatus) => s.integrationSlug === entry.slug,
									);
									const isOutbound = !entry.webhookPathTemplate;
									const healthTone =
										status?.health === "healthy"
											? "success"
											: status?.health === "degraded"
												? "warning"
												: "danger";
									return (
										<tr key={entry.slug}>
											<td className="font-medium">{entry.label}</td>
											<td className="text-[var(--sea-ink-soft)]">
												{entry.category.toUpperCase()}
											</td>
											<td className="text-[var(--sea-ink-soft)]">
												{isOutbound ? "outbound" : "inbound"}
											</td>
											<td>
												<code className="text-xs text-[var(--teal)]">
													{entry.envVarName}
												</code>
											</td>
											<td>
												<StatusPill
													label={status?.health ?? "offline"}
													tone={healthTone}
												/>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				</div>
			</div>
			)}
		</main>
	);
}

function ObservabilityTab({ tenantSlug }: { tenantSlug: string }) {
	const intel = useQuery(api.observabilityIntel.getLatestObservabilityIntel, {
		tenantSlug,
	});

	if (!intel) {
		return (
			<div className="page-body space-y-5">
				<div className="loading-panel h-40 rounded-2xl" />
			</div>
		);
	}

	return (
		<div className="page-body space-y-5">
			<ObservabilityIntelPanel intel={intel} />
		</div>
	);
}

function SiemTab({
	repositories,
}: {
	repositories: OverviewRepository[];
}) {
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
	const activeRepo = selectedRepo
		? repositories.find((r) => r._id === selectedRepo)
		: repositories[0];

	const latestPush = useQuery(
		api.siemIntel.getLatestSiemPush,
		activeRepo ? { repositoryId: activeRepo._id as any } : "skip",
	);
	const pushHistory = useQuery(
		api.siemIntel.getSiemPushHistory,
		activeRepo ? { repositoryId: activeRepo._id as any } : "skip",
	);

	if (repositories.length === 0) {
		return (
			<div className="page-body space-y-5">
				<div className="card card-sm">
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No repositories found. Add a repository to enable SIEM push.
					</p>
				</div>
			</div>
		);
	}

	return (
		<div className="page-body space-y-5">
			{/* Repo selector */}
			{repositories.length > 1 && (
				<div className="flex gap-1">
					{repositories.map((r) => (
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

			{!latestPush && !pushHistory ? (
				<div className="loading-panel h-40 rounded-2xl" />
			) : (
				<SiemIntelPanel
					latestPush={latestPush}
					history={pushHistory}
					repositoryId={activeRepo!._id}
				/>
			)}
		</div>
	);
}

function RepoGamification({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const gamification = useQuery(api.gamificationIntel.getLatestGamification, {
		tenantSlug,
	});

	if (!gamification) return null;

	const repoEntry =
		gamification.repositoryLeaderboard.find(
			(r: LeaderboardEntry) => r.repositoryName === repositoryFullName.split("/").pop(),
		) ?? gamification.repositoryLeaderboard[0];

	return (
		<div className="card card-sm">
			{repoEntry && (
				<div className="flex flex-wrap gap-2 mb-2">
					<StatusPill label={`score ${repoEntry.currentScore}`} tone="info" />
					<StatusPill label={`rank #${repoEntry.rank}`} tone="neutral" />
					{repoEntry.badge && (
						<StatusPill label={repoEntry.badge} tone="success" />
					)}
					<StatusPill
						label={repoEntry.trend}
						tone={
							repoEntry.trend === "improving"
								? "success"
								: repoEntry.trend === "stable"
									? "neutral"
									: "warning"
						}
					/>
				</div>
			)}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
				{gamification.summary}
			</p>
		</div>
	);
}

// ── Slack ChatOps integration card (Sprint 4B) ──────────────────────────────

const SLACK_ALERT_EVENTS = [
	{ key: "critical_finding", label: "Critical finding detected" },
	{ key: "sla_breach", label: "SLA breach" },
	{ key: "gate_block", label: "Gate blocked" },
	{ key: "new_exploit", label: "New exploit published" },
] as const;

function SlackIntegrationCard({ tenantSlug }: { tenantSlug: string }) {
	const authToken = useAuthToken();
	const integration = useQuery(
		api.slack.getSlackIntegration,
		authToken ? { authToken, tenantSlug } : "skip",
	);
	const initiateOAuth = useMutation(api.slack.initiateSlackOAuth);
	const configureAlerts = useMutation(api.slack.configureSlackAlerts);
	const disconnect = useMutation(api.slack.disconnectSlack);
	const sendTest = useAction(api.slack.sendTestSlackNotification);

	const [connecting, setConnecting] = useState(false);
	const [disconnecting, setDisconnecting] = useState(false);
	const [testing, setTesting] = useState(false);
	const [saving, setSaving] = useState(false);
	const [testResult, setTestResult] = useState<"ok" | "err" | null>(null);

	// local alert config state
	const [channel, setChannel] = useState("");
	const [selectedEvents, setSelectedEvents] = useState<string[]>([
		"critical_finding",
		"sla_breach",
	]);
	const [minSeverity, setMinSeverity] = useState<"critical" | "high" | "medium" | "low">("high");
	const [configDirty, setConfigDirty] = useState(false);

	// sync from remote once loaded
	const syncedRef = useState(false);
	if (integration?.isActive && !syncedRef[0] && !configDirty) {
		if (integration.configuredChannels) setChannel(integration.configuredChannels);
		if (integration.alertConfig) {
			const cfg = integration.alertConfig as { events?: string[]; minSeverity?: string };
			if (cfg.events) setSelectedEvents(cfg.events);
			if (cfg.minSeverity) setMinSeverity(cfg.minSeverity as typeof minSeverity);
		}
		syncedRef[1](true);
	}

	const handleConnect = async () => {
		if (!authToken) return;
		setConnecting(true);
		try {
			const { oauthUrl } = await initiateOAuth({ authToken, tenantSlug });
			window.location.href = oauthUrl;
		} catch {
			setConnecting(false);
		}
	};

	const handleDisconnect = async () => {
		if (!authToken) return;
		setDisconnecting(true);
		try {
			await disconnect({ authToken, tenantSlug });
		} finally {
			setDisconnecting(false);
		}
	};

	const handleSave = async () => {
		if (!authToken) return;
		setSaving(true);
		try {
			await configureAlerts({
				authToken,
				tenantSlug,
				channel,
				events: selectedEvents,
				minSeverity,
			});
			setConfigDirty(false);
		} finally {
			setSaving(false);
		}
	};

	const handleTest = async () => {
		if (!authToken || !channel) return;
		setTesting(true);
		setTestResult(null);
		try {
			await sendTest({ authToken, tenantSlug, channel });
			setTestResult("ok");
		} catch {
			setTestResult("err");
		} finally {
			setTesting(false);
			setTimeout(() => setTestResult(null), 4000);
		}
	};

	const toggleEvent = (key: string) => {
		setConfigDirty(true);
		setSelectedEvents((prev) =>
			prev.includes(key) ? prev.filter((e) => e !== key) : [...prev, key],
		);
	};

	if (integration === undefined) {
		return <div className="loading-panel h-32 rounded-2xl" />;
	}

	return (
		<div className="card card-sm">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<MessageSquare size={16} className="text-[var(--signal)]" />
					<span className="text-sm font-semibold text-[var(--sea-ink)]">
						Slack
					</span>
					{integration?.isActive ? (
						<StatusPill label="connected" tone="success" />
					) : (
						<StatusPill label="not connected" tone="neutral" />
					)}
				</div>
				{integration?.isActive ? (
					<button
						type="button"
						onClick={handleDisconnect}
						disabled={disconnecting}
						className="btn secondary-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
					>
						{disconnecting ? <Loader2 size={12} className="animate-spin" /> : <XCircle size={12} />}
						Disconnect
					</button>
				) : (
					<button
						type="button"
						onClick={handleConnect}
						disabled={connecting}
						className="btn signal-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
					>
						{connecting ? <Loader2 size={12} className="animate-spin" /> : <MessageSquare size={12} />}
						Connect Slack
					</button>
				)}
			</div>

			{integration?.isActive && (
				<>
					{integration.teamName && (
						<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
							Connected to workspace:{" "}
							<span className="font-medium text-[var(--sea-ink)]">
								{integration.teamName}
							</span>
						</p>
					)}

					<div className="space-y-3">
						{/* Channel */}
						<div>
							<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
								Alert channel
							</label>
							<div className="flex gap-2">
								<input
									type="text"
									value={channel}
									onChange={(e) => {
										setChannel(e.target.value);
										setConfigDirty(true);
									}}
									placeholder="#security-alerts"
									className="input-field text-xs flex-1"
								/>
								<button
									type="button"
									onClick={handleTest}
									disabled={testing || !channel}
									className="btn secondary-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
								>
									{testing ? (
										<Loader2 size={12} className="animate-spin" />
									) : testResult === "ok" ? (
										<CheckCircle size={12} className="text-green-500" />
									) : testResult === "err" ? (
										<XCircle size={12} className="text-red-500" />
									) : null}
									Test
								</button>
							</div>
						</div>

						{/* Alert events */}
						<div>
							<label className="text-xs font-medium text-[var(--sea-ink)] mb-1.5 block">
								Alert on
							</label>
							<div className="flex flex-wrap gap-2">
								{SLACK_ALERT_EVENTS.map(({ key, label }) => (
									<label
										key={key}
										className="flex items-center gap-1.5 text-xs text-[var(--sea-ink-soft)] cursor-pointer"
									>
										<input
											type="checkbox"
											checked={selectedEvents.includes(key)}
											onChange={() => toggleEvent(key)}
											className="rounded"
										/>
										{label}
									</label>
								))}
							</div>
						</div>

						{/* Min severity */}
						<div>
							<label className="text-xs font-medium text-[var(--sea-ink)] mb-1 block">
								Minimum severity
							</label>
							<select
								value={minSeverity}
								onChange={(e) => {
									setMinSeverity(e.target.value as typeof minSeverity);
									setConfigDirty(true);
								}}
								className="input-field text-xs"
							>
								<option value="critical">Critical only</option>
								<option value="high">High and above</option>
								<option value="medium">Medium and above</option>
								<option value="low">All severities</option>
							</select>
						</div>

						<button
							type="button"
							onClick={handleSave}
							disabled={saving || !configDirty}
							className="btn signal-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
						>
							{saving && <Loader2 size={12} className="animate-spin" />}
							Save configuration
						</button>
					</div>

					{/* Slash command docs */}
					<div className="mt-4 pt-3 border-t border-[var(--line)]">
						<p className="text-xs font-medium text-[var(--sea-ink)] mb-2">
							Slash commands
						</p>
						<div className="space-y-1">
							{[
								["/cyberzen status", "Get security posture summary"],
								["/cyberzen critical", "List top critical findings"],
								["/cyberzen score", "Show current security score"],
							].map(([cmd, desc]) => (
								<div key={cmd} className="flex items-center gap-2">
									<code className="text-xs bg-[var(--surface-2)] px-1.5 py-0.5 rounded font-mono text-[var(--teal)]">
										{cmd}
									</code>
									<span className="text-xs text-[var(--sea-ink-soft)]">{desc}</span>
								</div>
							))}
						</div>
					</div>
				</>
			)}

			{!integration?.isActive && (
				<p className="text-xs text-[var(--sea-ink-soft)]">
					Connect your Slack workspace to receive security alerts and use slash
					commands directly in your team channels.
				</p>
			)}
		</div>
	);
}

// ── Community contribution card with accept/reject CTAs (spec §3.6) ────────

function CommunityContributionCard({ item }: { item: MarketplaceItem }) {
	const accept = useMutation(api.communityMarketplace.acceptContribution);
	const reject = useMutation(api.communityMarketplace.rejectContribution);
	const [acting, setActing] = useState(false);

	const canModerate =
		item.status === "pending" || item.status === "under_review";

	const handleAccept = async () => {
		setActing(true);
		try {
			await accept({
				contributionId: item._id as Id<"communityContributions">,
			});
		} catch {
			/* optimistic — mutation will refresh list */
		} finally {
			setActing(false);
		}
	};

	const handleReject = async () => {
		setActing(true);
		try {
			await reject({
				contributionId: item._id as Id<"communityContributions">,
			});
		} catch {
			/* optimistic — mutation will refresh list */
		} finally {
			setActing(false);
		}
	};

	return (
		<div className="card card-sm">
			<div className="flex items-start justify-between gap-2">
				<span className="text-sm font-semibold text-[var(--sea-ink)]">
					{item.title}
				</span>
				<StatusPill label={item.type} tone="info" />
			</div>
			<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{item.description}
			</p>
			<div className="mt-1.5 flex flex-wrap gap-1.5">
				<StatusPill
					label={item.status}
					tone={
						item.status === "approved"
							? "success"
							: item.status === "under_review"
								? "warning"
								: item.status === "rejected"
									? "danger"
									: "neutral"
					}
				/>
				{item.upvoteCount > 0 && (
					<StatusPill
						label={`${item.upvoteCount} upvotes`}
						tone="neutral"
					/>
				)}
			</div>
			{canModerate && (
				<div className="mt-2 flex gap-1.5">
					<button
						type="button"
						onClick={handleAccept}
						disabled={acting}
						className="btn signal-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
						title="Accept contribution"
					>
						<CheckCircle size={12} />
						Accept
					</button>
					<button
						type="button"
						onClick={handleReject}
						disabled={acting}
						className="btn secondary-button inline-flex items-center gap-1 text-xs disabled:opacity-50"
						title="Reject contribution"
					>
						<XCircle size={12} />
						Reject
					</button>
				</div>
			)}
		</div>
	);
}
