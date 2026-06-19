import type { FunctionReturnType } from "convex/server";
import { AlertTriangle, Eye, GitBranch, Zap } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type Detection = NonNullable<
	FunctionReturnType<
		typeof api.zeroDayDetectionIntel.getLatestZeroDayDetectionBySlug
	>
>;

type Finding = Detection["findings"][number];

function confidenceTone(
	score: number,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (score >= 80) return "danger";
	if (score >= 60) return "warning";
	if (score >= 40) return "info";
	return "neutral";
}

function severityTone(
	level: string,
): "neutral" | "success" | "warning" | "danger" | "info" {
	if (level === "critical") return "danger";
	if (level === "high") return "warning";
	if (level === "medium") return "info";
	return "neutral";
}

function FindingRow({ finding }: { finding: Finding }) {
	return (
		<div className="card card-sm">
			<div className="flex flex-wrap items-center gap-2 mb-2">
				<StatusPill
					label={finding.anomalyType.replace(/_/g, " ")}
					tone={severityTone(finding.severity)}
				/>
				<StatusPill
					label={`${finding.confidenceScore.toFixed(0)}% confidence`}
					tone={confidenceTone(finding.confidenceScore)}
				/>
				<StatusPill label={finding.severity} tone={severityTone(finding.severity)} />
				{finding.investigated ? (
					<StatusPill label="investigated" tone="success" />
				) : (
					<StatusPill label="requires investigation" tone="warning" />
				)}
			</div>

			<h4 className="text-sm font-semibold text-[var(--sea-ink)] mb-1">
				{finding.title}
			</h4>

			<p className="text-xs text-[var(--sea-ink-soft)] mb-2">
				{finding.description}
			</p>

			<div className="flex flex-wrap gap-1.5 text-xs text-[var(--sea-ink-soft)]">
				{finding.filePath && (
					<span className="inline-flex items-center gap-1">
						<GitBranch size={10} />
						{finding.filePath}
						{finding.lineRange && `:${finding.lineRange}`}
					</span>
				)}
				{finding.packageName && (
					<span>
						{finding.packageName}
						{finding.packageVersion && `@${finding.packageVersion}`}
					</span>
				)}
				<span>· {formatTimestamp(finding.detectedAt)}</span>
			</div>

			{finding.anomalyFlags.length > 0 && (
				<div className="flex flex-wrap gap-1.5 mt-2">
					{finding.anomalyFlags.map((flag: string) => (
						<StatusPill key={flag} label={flag.replace(/_/g, " ")} tone="info" />
					))}
				</div>
			)}
		</div>
	);
}

export default function RepositoryZeroDayDetectionPanel({
	detection,
	repositoryFullName }: {
	detection: Detection;
	repositoryFullName: string;
}) {
	const totalFindings = detection.findings.length;
	const criticalCount = detection.findings.filter(
		(f: Finding) => f.severity === "critical" || f.severity === "high",
	).length;
	const uninvestigated = detection.findings.filter((f: Finding) => !f.investigated).length;
	const avgConfidence =
		totalFindings > 0
			? detection.findings.reduce((sum: number, f: Finding) => sum + f.confidenceScore, 0) /
				totalFindings
			: 0;

	return (
		<div className="card">
			<div className="flex items-center gap-2 mb-3 flex-wrap">
				<Eye size={14} className="text-[var(--signal)]" />
				<h3 className="section-title">{repositoryFullName}</h3>
				<StatusPill label={`${totalFindings} findings`} tone="neutral" />
				{criticalCount > 0 && (
					<StatusPill label={`${criticalCount} critical`} tone="danger" />
				)}
				{uninvestigated > 0 && (
					<StatusPill
						label={`${uninvestigated} uninvestigated`}
						tone="warning"
					/>
				)}
			</div>

			{/* Summary row */}
			<div className="grid gap-2 sm:grid-cols-3 mb-4">
				<div className="inset-panel">
					<p className="panel-label mb-1">Avg Confidence</p>
					<div className="flex items-center gap-2">
						<Zap size={14} className="text-[var(--signal)]" />
						<span className="text-lg font-bold text-[var(--sea-ink)]">
							{avgConfidence.toFixed(0)}%
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Anomaly Score</p>
					<div className="flex items-center gap-2">
						<AlertTriangle size={14} className="text-[var(--warning)]" />
						<span className="text-lg font-bold text-[var(--sea-ink)]">
							{detection.overallAnomalyScore.toFixed(0)}
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Last Scan</p>
					<div className="text-sm font-medium text-[var(--sea-ink)]">
						{formatTimestamp(detection.analyzedAt)}
					</div>
				</div>
			</div>

			{/* Findings list */}
			{detection.summary && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
					{detection.summary}
				</p>
			)}

			<div className="space-y-2">
				{detection.findings.map((finding: Finding) => (
					<FindingRow key={finding._id} finding={finding} />
				))}
			</div>

			{totalFindings === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl mt-2">
					<Eye size={24} className="mb-2 opacity-40" />
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No anomalous patterns detected. Zero-day analysis is running
						continuously in the background.
					</p>
				</div>
			)}
		</div>
	);
}
