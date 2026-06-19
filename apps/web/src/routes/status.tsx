import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import {
	Activity,
	CheckCircle2,
	AlertTriangle,
	XCircle,
	Wrench,
	ChevronDown,
	ChevronUp,
} from "lucide-react";
import { useState } from "react";
import { api } from "../lib/convex";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/status")({
	errorComponent: RouteErrorBoundary,
	component: StatusPage,
});

function StatusPage() {
	const health = useQuery(api.health.getServiceHealth);
	const incidents = useQuery(api.health.getIncidentHistory, { limit: 20 });
	const overall = useQuery(api.health.getOverallStatus);

	return (
		<main style={{ maxWidth: "900px", margin: "0 auto", padding: "2rem 1rem" }}>
			{/* Header */}
			<div className="text-center mb-8">
				<div className="flex items-center justify-center gap-2 mb-2">
					<Activity size={24} className="text-[var(--signal)]" />
					<h1 className="text-2xl font-bold text-[var(--sea-ink)]">CyberZen Status</h1>
				</div>
				<p className="text-sm text-[var(--sea-ink-soft)]">
					Real-time service health and incident tracking
				</p>
			</div>

			{/* Overall Status Banner */}
			<div className="mb-6">
				<OverallStatusBanner
					status={overall?.status ?? null}
					activeIncidents={overall?.activeIncidents ?? 0}
					lastUpdated={overall?.lastUpdated ?? null}
				/>
			</div>

			{/* Service Health Grid */}
			<div className="mb-8">
				<h2 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">Service Health</h2>
				{!health ? (
					<div className="space-y-2">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-12 rounded-xl" />
						))}
					</div>
				) : (
					<div className="space-y-2">
						{health.services.map((service: any) => (
							<ServiceHealthRow key={service.slug} service={service} />
						))}
					</div>
				)}
			</div>

			{/* Incident History */}
			<div>
				<h2 className="text-sm font-semibold text-[var(--sea-ink)] mb-3">Incident History</h2>
				{!incidents ? (
					<div className="space-y-2">
						{["a", "b"].map((k) => (
							<div key={k} className="loading-panel h-16 rounded-xl" />
						))}
					</div>
				) : incidents.length === 0 ? (
					<div className="card card-sm p-4 text-center">
						<CheckCircle2 size={20} className="mx-auto mb-1 text-[var(--success)]" />
						<p className="text-sm text-[var(--sea-ink-soft)]">No incidents recorded</p>
					</div>
				) : (
					<div className="space-y-2">
						{incidents.map((incident: any) => (
							<IncidentHistoryRow key={incident._id} incident={incident} />
						))}
					</div>
				)}
			</div>
		</main>
	);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function OverallStatusBanner({
	status,
	activeIncidents,
	lastUpdated,
}: {
	status: string | null;
	activeIncidents: number;
	lastUpdated: number | null;
}) {
	const statusConfig: Record<string, { icon: any; label: string; color: string; bg: string }> = {
		operational: { icon: CheckCircle2, label: "All Systems Operational", color: "var(--success)", bg: "var(--success)" },
		degraded: { icon: AlertTriangle, label: "Degraded Performance", color: "var(--warning)", bg: "var(--warning)" },
		maintenance: { icon: Wrench, label: "Maintenance in Progress", color: "var(--signal)", bg: "var(--signal)" },
		outage: { icon: XCircle, label: "Service Outage", color: "var(--danger)", bg: "var(--danger)" },
	};

	const resolved = statusConfig[status ?? "operational"] ?? statusConfig.operational;
	const Icon = resolved.icon;

	return (
		<div
			className="card p-5 text-center"
			style={{
				borderColor: resolved.color,
				borderWidth: "2px",
			}}
		>
			<Icon size={28} className="mx-auto mb-2" style={{ color: resolved.color }} />
			<p className="text-lg font-semibold text-[var(--sea-ink)]">{resolved.label}</p>
			{activeIncidents > 0 && (
				<p className="text-sm text-[var(--sea-ink-soft)] mt-1">
					{activeIncidents} active incident{activeIncidents !== 1 ? "s" : ""}
				</p>
			)}
			{lastUpdated && (
				<p className="text-xs text-[var(--sea-ink-soft)] mt-2">
					Last updated: {new Date(lastUpdated).toLocaleString()}
				</p>
			)}
		</div>
	);
}

function ServiceHealthRow({ service }: { service: any }) {
	const statusIcons: Record<string, any> = {
		operational: CheckCircle2,
		degraded: AlertTriangle,
		maintenance: Wrench,
		outage: XCircle,
	};

	const statusColors: Record<string, string> = {
		operational: "var(--success)",
		degraded: "var(--warning)",
		maintenance: "var(--signal)",
		outage: "var(--danger)",
	};

	const Icon = statusIcons[service.status] ?? CheckCircle2;
	const color = statusColors[service.status] ?? "var(--success)";

	return (
		<div className="card card-sm">
			<div className="flex items-center justify-between gap-3 px-1">
				<div className="flex items-center gap-3">
					<Icon size={16} style={{ color }} />
					<span className="text-sm font-medium text-[var(--sea-ink)]">{service.name}</span>
				</div>
				<div className="flex items-center gap-3">
					{service.latencyMs !== null && (
						<span className="text-xs text-[var(--sea-ink-soft)]">{service.latencyMs}ms</span>
					)}
					<span
						className="text-xs font-medium px-2 py-0.5 rounded-full"
						style={{
							backgroundColor: `${color}15`,
							color,
						}}
					>
						{service.status.replace("_", " ")}
					</span>
				</div>
			</div>
		</div>
	);
}

function IncidentHistoryRow({ incident }: { incident: any }) {
	const [expanded, setExpanded] = useState(false);

	const statusColors: Record<string, string> = {
		investigating: "var(--danger)",
		identified: "var(--warning)",
		monitoring: "var(--signal)",
		resolved: "var(--success)",
	};

	const severityBadge: Record<string, string> = {
		minor: "Minor",
		major: "Major",
		critical: "Critical",
	};

	const color = statusColors[incident.status] ?? "var(--neutral)";

	return (
		<div className="card card-sm">
			<button
				type="button"
				className="w-full flex items-center justify-between gap-3 px-1"
				onClick={() => setExpanded(!expanded)}
			>
				<div className="flex items-center gap-3 min-w-0">
					<div
						className="w-2 h-2 rounded-full flex-shrink-0"
						style={{ backgroundColor: color }}
					/>
					<span className="text-sm font-medium text-[var(--sea-ink)] truncate">
						{incident.title}
					</span>
					<span className="text-xs text-[var(--sea-ink-soft)]">
						{new Date(incident.startedAt).toLocaleDateString()}
					</span>
				</div>
				<div className="flex items-center gap-2 flex-shrink-0">
					<span
						className="text-xs font-medium px-2 py-0.5 rounded-full"
						style={{ backgroundColor: `${color}15`, color }}
					>
						{incident.status}
					</span>
					{expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
				</div>
			</button>

			{expanded && (
				<div className="mt-2 pt-2 border-t border-[var(--line)]">
					<p className="text-sm text-[var(--sea-ink-soft)]">{incident.message}</p>
					<div className="flex gap-2 mt-2 text-xs text-[var(--sea-ink-soft)]">
						<span>Service: {incident.service}</span>
						<span>•</span>
						<span>Severity: {severityBadge[incident.severity] ?? incident.severity}</span>
						{incident.resolvedAt && (
							<>
								<span>•</span>
								<span>Resolved: {new Date(incident.resolvedAt).toLocaleString()}</span>
							</>
						)}
					</div>
				</div>
			)}
		</div>
	);
}
