import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Plug } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";

export const Route = createFileRoute("/integrations")({ component: IntegrationsPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];

const TENANT = TENANT_SLUG;

function IntegrationsPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const vendors = useQuery(api.vendorTrust.listVendorsBySlug, {
		tenantSlug: TENANT,
	});
	const marketplace = useQuery(
		api.communityMarketplace.listContributions,
		{ limit: 12 },
	);
	const [selectedRepo, setSelectedRepo] = useState<string | null>(null);

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
	const activeRepo =
		selectedRepo
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

			<div className="page-body space-y-5">
				{/* Webhook Settings */}
				<div>
					<h2 className="section-title mb-3">Webhook Configuration</h2>
					<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
						{[
							{ label: "GitHub", envVar: "GITHUB_WEBHOOK_SECRET", path: "/webhooks/github" },
							{ label: "GitLab", envVar: "GITLAB_WEBHOOK_SECRET", path: "/webhooks/gitlab" },
							{ label: "Jenkins", envVar: "JENKINS_WEBHOOK_SECRET", path: "/webhooks/jenkins" },
							{ label: "CircleCI", envVar: "CIRCLECI_WEBHOOK_SECRET", path: "/webhooks/circleci" },
							{ label: "Buildkite", envVar: "BUILDKITE_WEBHOOK_TOKEN", path: "/webhooks/buildkite" },
							{ label: "Azure DevOps", envVar: "AZURE_DEVOPS_WEBHOOK_SECRET", path: "/webhooks/azure-devops" },
							{ label: "Bitbucket", envVar: "BITBUCKET_WEBHOOK_SECRET", path: "/webhooks/bitbucket" },
							{ label: "Slack", envVar: "SLACK_WEBHOOK_URL", path: "outbound" },
							{ label: "PagerDuty", envVar: "PAGERDUTY_ROUTING_KEY", path: "outbound" },
							{ label: "Jira", envVar: "JIRA_API_TOKEN", path: "outbound" },
							{ label: "Linear", envVar: "LINEAR_API_KEY", path: "outbound" },
							{ label: "Datadog", envVar: "DATADOG_API_KEY", path: "outbound" },
							{ label: "OpsGenie", envVar: "OPSGENIE_API_KEY", path: "outbound" },
						].map(({ label, envVar, path }) => (
							<div key={label} className="card card-sm">
								<div className="flex items-center justify-between mb-1.5">
									<span className="text-sm font-semibold text-[var(--sea-ink)]">
										{label}
									</span>
									<StatusPill
										label={path === "outbound" ? "outbound" : "inbound"}
										tone={path === "outbound" ? "info" : "neutral"}
									/>
								</div>
								<p className="text-xs font-mono text-[var(--sea-ink-soft)]">
									{envVar}
								</p>
								{path !== "outbound" && (
									<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
										Endpoint: <code>{path}</code>
									</p>
								)}
							</div>
						))}
					</div>
				</div>

				{/* Vendor Trust */}
				{vendors && vendors.length > 0 && (
					<div>
						<h2 className="section-title mb-3">
							Vendor Trust ({vendors.length} vendors)
						</h2>
						<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
							{vendors.map((vendor) => (
								<div key={vendor._id} className="card card-sm">
									<div className="flex items-start justify-between gap-2">
										<span className="text-sm font-semibold text-[var(--sea-ink)]">
											{vendor.name}
										</span>
								<StatusPill
										label={`risk ${vendor.latestRisk?.riskScore ?? "—"}`}
										tone={
											vendor.latestRisk?.riskLevel === "critical" || vendor.latestRisk?.riskLevel === "high"
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
									{vendor.latestRisk?.riskLevel && vendor.latestRisk.riskLevel !== "trusted" && vendor.latestRisk.riskLevel !== "low" && (
										<StatusPill
											label={vendor.latestRisk.recommendation}
											tone={vendor.latestRisk.riskLevel === "critical" || vendor.latestRisk.riskLevel === "high" ? "danger" : "warning"}
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
						{marketplace.map((item, idx) => (
							<div key={`${item.title}-${idx}`} className="card card-sm">
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
							</div>
						))}
						</div>
					</div>
				)}

			{/* Integration overview */}
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
							</tr>
						</thead>
						<tbody>
							{[
								{ label: "GitHub", category: "VCS", path: "inbound + outbound", envVar: "GITHUB_TOKEN" },
								{ label: "Slack", category: "Notifications", path: "outbound", envVar: "SLACK_WEBHOOK_URL" },
								{ label: "Jira", category: "Ticketing", path: "outbound", envVar: "JIRA_API_TOKEN" },
								{ label: "Linear", category: "Ticketing", path: "outbound", envVar: "LINEAR_API_KEY" },
								{ label: "Datadog", category: "Observability", path: "inbound", envVar: "DATADOG_API_KEY" },
								{ label: "PagerDuty", category: "Alerting", path: "outbound", envVar: "PAGERDUTY_ROUTING_KEY" },
								{ label: "OpenAI", category: "AI", path: "outbound", envVar: "OPENAI_API_KEY" },
							].map((row) => (
								<tr key={row.label}>
									<td className="font-medium">{row.label}</td>
									<td className="text-[var(--sea-ink-soft)]">{row.category}</td>
									<td className="text-[var(--sea-ink-soft)]">{row.path}</td>
									<td><code className="text-xs text-[var(--teal)]">{row.envVar}</code></td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</div>
			</div>
		</main>
	);
}

function RepoGamification({
	tenantSlug,
	repositoryFullName,
}: {
	tenantSlug: string;
	repositoryFullName: string;
}) {
	const gamification = useQuery(
		api.gamificationIntel.getLatestGamification,
		{ tenantSlug },
	);

	if (!gamification) return null;

	const repoEntry = gamification.repositoryLeaderboard.find(
		(r) => r.repositoryName === repositoryFullName.split("/").pop(),
	) ?? gamification.repositoryLeaderboard[0];

	return (
		<div className="card card-sm">
			{repoEntry && (
				<div className="flex flex-wrap gap-2 mb-2">
					<StatusPill
						label={`score ${repoEntry.currentScore}`}
						tone="info"
					/>
					<StatusPill label={`rank #${repoEntry.rank}`} tone="neutral" />
					{repoEntry.badge && (
						<StatusPill label={repoEntry.badge} tone="success" />
					)}
					<StatusPill
						label={repoEntry.trend}
						tone={repoEntry.trend === "improving" ? "success" : repoEntry.trend === "stable" ? "neutral" : "warning"}
					/>
				</div>
			)}
			<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">{gamification.summary}</p>
		</div>
	);
}

