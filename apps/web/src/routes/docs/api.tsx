import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import { useState } from "react";
import {
	BookOpen,
	ChevronDown,
	ChevronRight,
	Copy,
	Download,
	Github,
	Play,
} from "lucide-react";
import StatusPill from "../../components/StatusPill";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
import { api } from "../../lib/convex";

export const Route = createFileRoute("/docs/api")({
	errorComponent: RouteErrorBoundary,
	component: ApiDocsPage,
});

// Minimal JSON-to-YAML serializer for OpenAPI spec download.
function jsonToYaml(obj: unknown, indent = 0): string {
	const pad = "  ".repeat(indent);
	if (obj === null || obj === undefined) return `${pad}null`;
	if (typeof obj === "string") {
		const needsQuote = obj.includes(":") || obj.includes("#") || obj.includes("\n");
		return needsQuote ? `"${obj.replace(/"/g, '\\"')}"` : obj;
	}
	if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
	if (Array.isArray(obj)) {
		if (obj.length === 0) return "[]";
		return obj.map((item) => `${pad}- ${jsonToYaml(item, indent + 1).trimStart()}`).join("\n");
	}
	if (typeof obj === "object") {
		const entries = Object.entries(obj as Record<string, unknown>);
		if (entries.length === 0) return "{}";
		return entries
			.map(([k, v]) => {
				const valStr = jsonToYaml(v, indent + 1);
				const isComplex = typeof v === "object" && v !== null;
				return isComplex
					? `${pad}${k}:\n${valStr}`
					: `${pad}${k}: ${valStr}`;
			})
			.join("\n");
	}
	return String(obj);
}

// ─── OpenAPI-style endpoint catalog ──────────────────────────────────────────

interface ApiEndpoint {
	method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
	path: string;
	summary: string;
	description: string;
	auth: "bearer" | "apikey" | "none";
	requestBody?: string;
	responseExample: string;
	statusCodes: { code: number; description: string }[];
}

const API_ENDPOINTS: ApiEndpoint[] = [
	{
		method: "GET",
		path: "/api/v1/findings",
		summary: "List findings",
		description:
			"Retrieve a paginated list of security findings for the authenticated tenant. Supports filtering by severity, status, repository, and date range.",
		auth: "bearer",
		responseExample: JSON.stringify(
			{
				data: [
					{
						id: "fnd_abc123",
						severity: "critical",
						status: "open",
						title: "SQL Injection in auth middleware",
						repository: "acme/api-server",
						createdAt: "2026-05-15T10:30:00Z",
					},
				],
				pagination: { cursor: null, hasMore: false },
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK — findings returned" },
			{ code: 401, description: "Unauthorized — invalid or missing token" },
			{ code: 403, description: "Forbidden — insufficient permissions" },
		],
	},
	{
		method: "GET",
		path: "/api/v1/findings/:id",
		summary: "Get finding by ID",
		description:
			"Retrieve a single finding with full detail including blast radius, affected files, and reasoning log.",
		auth: "bearer",
		responseExample: JSON.stringify(
			{
				id: "fnd_abc123",
				severity: "critical",
				status: "open",
				title: "SQL Injection in auth middleware",
				repository: "acme/api-server",
				summary: "User input concatenated into SQL query without parameterization.",
				confidence: 0.95,
				businessImpactScore: 82,
				affectedFiles: ["src/middleware/auth.ts"],
				affectedPackages: ["pg@8.11.3"],
				blastRadiusSummary: "Exposes entire user table; PII leak potential.",
				createdAt: "2026-05-15T10:30:00Z",
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "Finding not found" },
		],
	},
	{
		method: "POST",
		path: "/api/v1/findings/:id/triage",
		summary: "Triage a finding",
		description:
			"Apply a triage action to a finding: mark as false positive, accept risk, snooze, or resolve.",
		auth: "bearer",
		requestBody: JSON.stringify(
			{
				action: "false_positive",
				reason: "Verified as test fixture, not exploitable in production.",
			},
			null,
			2,
		),
		responseExample: JSON.stringify(
			{ ok: true, findingId: "fnd_abc123", newStatus: "false_positive" },
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "Triage applied" },
			{ code: 400, description: "Invalid action" },
			{ code: 409, description: "Conflict — already triaged" },
		],
	},
	{
		method: "GET",
		path: "/api/v1/repositories",
		summary: "List repositories",
		description:
			"List all connected repositories with health scores, trust scores, and last-scan timestamps.",
		auth: "bearer",
		responseExample: JSON.stringify(
			{
				data: [
					{
						id: "repo_xyz",
						fullName: "acme/api-server",
						healthScore: 78,
						trustScore: 82,
						lastScannedAt: "2026-05-15T08:00:00Z",
					},
				],
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 401, description: "Unauthorized" },
		],
	},
	{
		method: "POST",
		path: "/api/v1/repositories/:id/scan",
		summary: "Trigger scan",
		description:
			"Dispatch an on-demand security scan for a specific repository. Returns the workflow run ID.",
		auth: "bearer",
		requestBody: JSON.stringify(
			{ scannerTypes: ["dependency", "sast", "iac"], branch: "main" },
			null,
			2,
		),
		responseExample: JSON.stringify(
			{ ok: true, workflowRunId: "wr_789", status: "queued" },
			null,
			2,
		),
		statusCodes: [
			{ code: 202, description: "Scan queued" },
			{ code: 429, description: "Rate limited — scan already running" },
		],
	},
	{
		method: "GET",
		path: "/api/v1/executive-report",
		summary: "Get executive report",
		description:
			"Retrieve the latest tenant-wide executive security report with KPIs, trends, and repo leaderboard.",
		auth: "bearer",
		responseExample: JSON.stringify(
			{
				generatedAt: "2026-05-15T12:00:00Z",
				openCritical: 3,
				mttr: "4.2 days",
				gateBlockRate: 0.12,
				domainAverages: {
					healthAvg: 76,
					driftPostureAvg: 82,
					supplyChainAvg: 71,
					complianceAvg: 88,
				},
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "No report generated yet" },
		],
	},
	{
		method: "GET",
		path: "/api/v1/compliance/evidence",
		summary: "List compliance evidence",
		description:
			"Retrieve collected compliance evidence artifacts grouped by framework (SOC2, GDPR, HIPAA, PCI-DSS, NIS2).",
		auth: "bearer",
		responseExample: JSON.stringify(
			{
				frameworks: [
					{
						framework: "SOC2",
						controlCount: 42,
						collected: 38,
						missing: 4,
					},
				],
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 401, description: "Unauthorized" },
		],
	},
	{
		method: "GET",
		path: "/api/v1/exports/findings.csv",
		summary: "Export findings as CSV",
		description:
			"Download all findings matching the given filters as a CSV file. Supports query params: severity, status, repositoryId, from, to.",
		auth: "apikey",
		responseExample: "id,severity,status,title,repository,createdAt\nfnd_abc123,critical,open,SQL Injection...,acme/api-server,2026-05-15",
		statusCodes: [
			{ code: 200, description: "CSV file download" },
			{ code: 401, description: "Unauthorized" },
		],
	},
	{
		method: "POST",
		path: "/api/v1/webhooks/outgoing",
		summary: "Register outgoing webhook",
		description:
			"Create a new outgoing webhook endpoint for real-time event delivery (finding.created, gate.blocked, etc.).",
		auth: "bearer",
		requestBody: JSON.stringify(
			{
				url: "https://hooks.slack.com/services/T00/B00/xxx",
				eventTypes: ["finding.created", "gate.blocked"],
				secret: "whsec_abc123",
			},
			null,
			2,
		),
		responseExample: JSON.stringify(
			{ ok: true, webhookId: "wh_def456" },
			null,
			2,
		),
		statusCodes: [
			{ code: 201, description: "Webhook created" },
			{ code: 400, description: "Invalid URL or event types" },
		],
	}, // FIX: C5 — missing closing `},` for previous object entry
	{
		method: "GET",
		path: "/api/v1/status",
		summary: "System health check",
		description: "Public endpoint returning system health status.",
		auth: "none",
		responseExample: JSON.stringify(
			{
				status: "healthy",
				version: "2.4.0",
				services: {
					api: "healthy",
					scanner: "healthy",
					ingestion: "degraded",
				},
			},
			null,
			2,
		),
		statusCodes: [{ code: 200, description: "OK" }],
	},
	{
		method: "GET",
		path: "/api/sbom/export",
		summary: "Export SBOM snapshot",
		description:
			"Download an SBOM snapshot in CycloneDX or SPDX format. Requires a snapshotId query parameter and optional format parameter (cyclonedx, spdx).",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				bomFormat: "CycloneDX",
				specVersion: "1.5",
				components: [
					{ name: "fastapi", version: "0.117.1", purl: "pkg:pypi/fastapi@0.117.1" },
				],
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "SBOM exported successfully" },
			{ code: 400, description: "Missing snapshotId or invalid format" },
			{ code: 404, description: "Snapshot not found" },
		],
	},
	{
		method: "GET",
		path: "/api/reports/security-posture",
		summary: "Get security posture report",
		description:
			"Returns a unified SecurityPostureReport for the requested repository, aggregating findings, attack surface, regulatory drift, red/blue rounds, and learning profile into a single 0–100 score.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				repository: "acme/api-server",
				postureScore: 78,
				postureLevel: "moderate",
				pillars: {
					findings: { score: 72, drag: "3 critical open" },
					attackSurface: { score: 81 },
					regulatory: { score: 85 },
					redBlue: { score: 70 },
					learning: { score: 88 },
				},
				priorityActions: ["Resolve 3 critical findings in payments-api"],
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 400, description: "Missing tenantSlug or repositoryFullName" },
			{ code: 404, description: "Repository not found" },
		],
	},
	{
		method: "GET",
		path: "/api/attack-surface/score/history",
		summary: "Get attack surface history",
		description:
			"Returns the latest attack surface snapshot and the last 20 score history data points for sparkline rendering.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				repository: "acme/api-server",
				currentScore: 65,
				history: [
					{ at: "2026-05-14T10:00:00Z", score: 62 },
					{ at: "2026-05-15T10:00:00Z", score: 65 },
				],
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "Repository not found" },
		],
	},
	{
		method: "GET",
		path: "/api/reports/compliance",
		summary: "Get compliance report",
		description:
			"Returns the latest regulatory drift snapshot with per-framework scores (SOC2, GDPR, HIPAA, PCI-DSS, NIS2), drift level, and gap counts.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				repository: "acme/api-server",
				frameworks: {
					soc2: { score: 88, driftLevel: "low", gaps: 2 },
					gdpr: { score: 91, driftLevel: "none", gaps: 0 },
				},
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "No compliance data for repository" },
		],
	},
	{
		method: "GET",
		path: "/api/reports/adversarial",
		summary: "Get adversarial simulation summary",
		description:
			"Returns an adversarial simulation summary: win/loss/draw counts, exploit chain samples, and average detection scores.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				repository: "acme/api-server",
				redWins: 4,
				blueWins: 7,
				draws: 2,
				avgDetectionScore: 0.83,
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "No adversarial data for repository" },
		],
	},
	{
		method: "GET",
		path: "/api/blast-radius",
		summary: "Get blast radius for finding",
		description:
			"Returns the blast radius snapshot for a specific finding, including reachable services, exposed data layers, attack path depth, and business impact score.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				findingId: "fnd_abc123",
				reachableServices: ["payments-api", "auth-gateway"],
				exposedDataLayers: ["user_pii", "transaction_history"],
				attackPathDepth: 3,
				businessImpactScore: 84,
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "No blast radius data for finding" },
		],
	},
	{
		method: "GET",
		path: "/api/sbom",
		summary: "Get latest SBOM snapshot",
		description:
			"Returns the latest SBOM snapshot for a repository with component counts, layer breakdown, and vulnerable-component preview.",
		auth: "apikey",
		responseExample: JSON.stringify(
			{
				repository: "acme/api-server",
				totalComponents: 112,
				layers: { direct: 14, transitive: 61, container: 21 },
				vulnerableCount: 1,
			},
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "OK" },
			{ code: 404, description: "No SBOM snapshot found" },
		],
	},
	{
		method: "PATCH",
		path: "/api/findings/status",
		summary: "Update finding status",
		description:
			"Operator-facing status update for a finding. Body: { findingId, newStatus, reason? }. Fires a finding.resolved webhook when status transitions to 'resolved'.",
		auth: "apikey",
		requestBody: JSON.stringify(
			{
				findingId: "fnd_abc123",
				newStatus: "resolved",
				reason: "Patched in v2.10.2",
			},
			null,
			2,
		),
		responseExample: JSON.stringify(
			{ ok: true, findingId: "fnd_abc123", previousStatus: "open", newStatus: "resolved" },
			null,
			2,
		),
		statusCodes: [
			{ code: 200, description: "Status updated" },
			{ code: 400, description: "Invalid newStatus or missing findingId" },
			{ code: 404, description: "Finding not found" },
		],
	},
	{
		method: "POST",
		path: "/webhooks/github",
		summary: "GitHub webhook ingest",
		description:
			"Receives GitHub push and pull request events. Validates X-Hub-Signature-256 HMAC. Routes events into the ingestion pipeline for scanning.",
		auth: "none",
		statusCodes: [
			{ code: 200, description: "Event accepted and routed" },
			{ code: 400, description: "Missing X-GitHub-Event header" },
			{ code: 401, description: "Invalid signature" },
		],
		responseExample: JSON.stringify(
			{ status: "accepted", eventId: "evt_123", deduped: false },
			null,
			2,
		),
	},
];

// ─── Page ────────────────────────────────────────────────────────────────────

function ApiDocsPage() {
	const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
	const [filter, setFilter] = useState("");
	const openApiSpec = useQuery(api.apiDocs.getOpenApiSpec, {});

	const filtered = filter
		? API_ENDPOINTS.filter(
				(e) =>
					e.path.toLowerCase().includes(filter.toLowerCase()) ||
					e.summary.toLowerCase().includes(filter.toLowerCase()) ||
					e.method.includes(filter.toUpperCase()),
			)
		: API_ENDPOINTS;

	function downloadSpec(format: "json" | "yaml") {
		if (!openApiSpec) return;
		const content =
			format === "json"
				? JSON.stringify(openApiSpec, null, 2)
				: jsonToYaml(openApiSpec)
		const blob = new Blob([content], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `cyberzen-openapi.${format}`;
		a.click();
		URL.revokeObjectURL(url);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<BookOpen size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">API Documentation</h1>
						<p className="page-subtitle">
							REST API reference · {API_ENDPOINTS.length} endpoints
						</p>
					</div>
				</div>
				<div className="flex items-center gap-2">
					<Link
						to="/docs/github-integration"
						className="signal-button secondary-button flex items-center gap-1.5 text-xs"
					>
						<Github size={12} />
						GitHub Action
					</Link>
					<button
						type="button"
						onClick={() => downloadSpec("json")}
						disabled={!openApiSpec}
						className="signal-button secondary-button flex items-center gap-1.5 text-xs disabled:opacity-50"
					>
						<Download size={12} />
						OpenAPI JSON
					</button>
					<button
						type="button"
						onClick={() => downloadSpec("yaml")}
						disabled={!openApiSpec}
						className="signal-button secondary-button flex items-center gap-1.5 text-xs disabled:opacity-50"
					>
						<Download size={12} />
						OpenAPI YAML
					</button>
				</div>
			</div>

			<div className="page-body space-y-4">
				{/* Search */}
				<div className="flex items-center gap-3">
					<input
						type="text"
						placeholder="Filter endpoints… (e.g. findings, POST)"
						value={filter}
						onChange={(e) => setFilter(e.target.value)}
						className="flex-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
					/>
					<StatusPill
						label={`${filtered.length} endpoint${filtered.length !== 1 ? "s" : ""}`}
						tone="neutral"
					/>
				</div>

				{/* Authentication guide */}
				<div className="card">
					<h3 className="text-sm font-semibold text-[var(--sea-ink)] mb-2">
						Authentication
					</h3>
					<div className="space-y-2">
						<div className="rounded-lg bg-[var(--surface-soft)] p-3">
							<p className="text-xs font-medium text-[var(--sea-ink)] mb-1">
								Bearer Token
							</p>
							<code className="text-[10px] font-mono text-[var(--sea-ink-soft)]">
								Authorization: Bearer &lt;your-session-token&gt;
							</code>
						</div>
						<div className="rounded-lg bg-[var(--surface-soft)] p-3">
							<p className="text-xs font-medium text-[var(--sea-ink)] mb-1">
								API Key
							</p>
							<code className="text-[10px] font-mono text-[var(--sea-ink-soft)]">
								X-API-Key: czk_&lt;prefix&gt;_&lt;secret&gt;
							</code>
						</div>
					</div>
				</div>

				{/* Endpoint list */}
				<ApiEndpointList
					endpoints={filtered}
					expandedIndex={expandedIndex}
					onToggle={(i) =>
						setExpandedIndex(expandedIndex === i ? null : i)
					}
				/>
			</div>
		</main>
	);
}

// ─── Endpoint list component ─────────────────────────────────────────────────

function ApiEndpointList({
	endpoints,
	expandedIndex,
	onToggle,
}: {
	endpoints: ApiEndpoint[];
	expandedIndex: number | null;
	onToggle: (index: number) => void;
}) {
	return (
		<div className="space-y-2">
			{endpoints.map((ep, i) => (
				<ApiEndpointDetail
					key={`${ep.method}-${ep.path}`}
					endpoint={ep}
					isExpanded={expandedIndex === i}
					onToggle={() => onToggle(i)}
				/>
			))}
			{endpoints.length === 0 && (
				<div className="card">
					<p className="text-xs text-[var(--sea-ink-soft)]">
						No endpoints match your filter.
					</p>
				</div>
			)}
		</div>
	);
}

// ─── Single endpoint detail ──────────────────────────────────────────────────

function ApiEndpointDetail({
	endpoint,
	isExpanded,
	onToggle,
}: {
	endpoint: ApiEndpoint;
	isExpanded: boolean;
	onToggle: () => void;
}) {
	const methodColor: Record<string, string> = {
		GET: "text-[var(--success)]",
		POST: "text-blue-500",
		PUT: "text-amber-500",
		PATCH: "text-amber-500",
		DELETE: "text-[var(--danger)]",
	};

	const methodBg: Record<string, string> = {
		GET: "bg-emerald-50",
		POST: "bg-blue-50",
		PUT: "bg-amber-50",
		PATCH: "bg-amber-50",
		DELETE: "bg-red-50",
	};

	return (
		<div className="card">
			<button
				type="button"
				onClick={onToggle}
				className="w-full flex items-center gap-3 text-left"
			>
				<span
					className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${methodBg[endpoint.method] ?? ""} ${methodColor[endpoint.method] ?? ""}`}
				>
					{endpoint.method}
				</span>
				<code className="text-xs font-mono text-[var(--sea-ink)] flex-1">
					{endpoint.path}
				</code>
				<span className="text-xs text-[var(--sea-ink-soft)] hidden sm:block">
					{endpoint.summary}
				</span>
				{isExpanded ? (
					<ChevronDown size={14} className="text-[var(--sea-ink-soft)]" />
				) : (
					<ChevronRight size={14} className="text-[var(--sea-ink-soft)]" />
				)}
			</button>

			{isExpanded && (
				<div className="mt-4 space-y-4">
					<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
						{endpoint.description}
					</p>

					<div className="flex items-center gap-2">
						<span className="text-[10px] font-medium text-[var(--sea-ink-soft)]">
							Auth:
						</span>
						<StatusPill
							label={endpoint.auth === "none" ? "None" : endpoint.auth}
							tone={endpoint.auth === "none" ? "neutral" : "success"}
						/>
					</div>

					{/* Status codes */}
					<div>
						<h4 className="text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Status Codes
						</h4>
						<div className="space-y-1">
							{endpoint.statusCodes.map((sc) => (
								<div
									key={sc.code}
									className="flex items-center gap-2 text-xs"
								>
									<code className="font-mono font-medium text-[var(--sea-ink)]">
										{sc.code}
									</code>
									<span className="text-[var(--sea-ink-soft)]">
										{sc.description}
									</span>
								</div>
							))}
						</div>
					</div>

					{/* Request body */}
					{endpoint.requestBody && (
						<div>
							<h4 className="text-xs font-semibold text-[var(--sea-ink)] mb-2">
								Request Body
							</h4>
							<pre className="rounded-lg bg-[var(--surface-soft)] border border-[var(--line)] p-3 text-[10px] font-mono text-[var(--sea-ink)] overflow-x-auto">
								{endpoint.requestBody}
							</pre>
						</div>
					)}

					{/* Response example */}
					<div>
						<div className="flex items-center justify-between mb-2">
							<h4 className="text-xs font-semibold text-[var(--sea-ink)]">
								Response Example
							</h4>
							<button
								type="button"
								onClick={() => {
									navigator.clipboard.writeText(endpoint.responseExample);
								}}
								className="text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
							>
								<Copy size={12} />
							</button>
						</div>
						<pre className="rounded-lg bg-[var(--surface-soft)] border border-[var(--line)] p-3 text-[10px] font-mono text-[var(--sea-ink)] overflow-x-auto">
							{endpoint.responseExample}
						</pre>
					</div>

					{/* Try it */}
					<ApiTryItPanel endpoint={endpoint} />
				</div>
			)}
		</div>
	);
}

// ─── Try it panel ────────────────────────────────────────────────────────────

function ApiTryItPanel({ endpoint }: { endpoint: ApiEndpoint }) {
	const baseUrl = window.location.origin;

	return (
		<div className="rounded-lg border border-dashed border-[var(--line)] p-3">
			<div className="flex items-center gap-2 mb-2">
				<Play size={12} className="text-[var(--signal)]" />
				<h4 className="text-xs font-semibold text-[var(--sea-ink)]">
					Try it
				</h4>
			</div>
			<pre className="text-[10px] font-mono text-[var(--sea-ink-soft)] overflow-x-auto">
				{`curl -X ${endpoint.method} ${baseUrl}${endpoint.path} \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json"${
		endpoint.requestBody
			? ` \\\n  -d '${endpoint.requestBody.split("\n").join("")}'`
			: ""
	}`}
			</pre>
		</div>
	);
}
