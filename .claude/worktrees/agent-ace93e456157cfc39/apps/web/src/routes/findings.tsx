import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { AlertTriangle, Filter } from "lucide-react";
import { useState, useTransition } from "react";
import { api } from "../lib/convex";
import type { Id } from "../lib/convex";
import { TENANT_SLUG } from "../lib/config";
import StatusPill from "../components/StatusPill";
import {
	blastTierTone,
	formatTimestamp,
	priorityTierTone,
	severityTone,
} from "../lib/utils";

export const Route = createFileRoute("/findings")({ component: FindingsPage });

type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewFinding = OverviewData["findings"][number];

const TENANT = TENANT_SLUG;
const SEVERITY_LEVELS = ["all", "critical", "high", "medium", "low", "informational"] as const;
type SeverityFilter = (typeof SEVERITY_LEVELS)[number];

function FindingsPage() {
	const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
	const [selected, setSelected] = useState<string | null>(null);

	if (!overview) {
		return (
			<main className="page-body-padded">
				<div className="grid gap-3">
					{["a", "b", "c", "d"].map((k) => (
						<div key={k} className="loading-panel h-24 rounded-2xl" />
					))}
				</div>
			</main>
		);
	}

	const findings = overview.findings.filter(
		(f: OverviewFinding) =>
			severityFilter === "all" || f.severity === severityFilter,
	);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<AlertTriangle size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Findings</h1>
						<p className="page-subtitle">
							{overview.findings.length} total open findings ·{" "}
							{overview.stats.criticalFindings} critical/high
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Filter bar */}
				<div className="flex items-center gap-2 mb-4 flex-wrap">
					<Filter size={14} className="text-[var(--sea-ink-soft)]" />
					{SEVERITY_LEVELS.map((level) => {
						const count =
							level === "all"
								? overview.findings.length
								: overview.findings.filter((f: OverviewFinding) => f.severity === level)
										.length;
						return (
							<button
								key={level}
								type="button"
								onClick={() => setSeverityFilter(level)}
								className={`tab-btn ${severityFilter === level ? "is-active" : ""}`}
							>
								{level === "all" ? "All" : level.charAt(0).toUpperCase() + level.slice(1)}
								{count > 0 && (
									<span className="ml-1.5 text-[var(--sea-ink-soft)]">({count})</span>
								)}
							</button>
						);
					})}
				</div>

				{/* Findings list */}
				<div className="space-y-3">
					{findings.map((finding: OverviewFinding) => (
						<div key={finding._id}>
							<button
								type="button"
								onClick={() =>
									setSelected(selected === finding._id ? null : finding._id)
								}
								className={`card card-sm w-full text-left ${
									selected === finding._id
										? "border-[rgba(158,255,100,0.35)]"
										: ""
								}`}
							>
								<div className="flex flex-wrap items-center gap-2">
									<StatusPill
										label={finding.severity}
										tone={severityTone(finding.severity)}
									/>
									<StatusPill label={finding.source} tone="info" />
									<StatusPill
										label={finding.validationStatus}
										tone={
											finding.validationStatus === "validated"
												? "success"
												: finding.validationStatus === "likely_exploitable"
													? "warning"
													: "neutral"
										}
									/>
									<StatusPill
										label={finding.status.replace(/_/g, " ")}
										tone={finding.status === "open" ? "danger" : "neutral"}
									/>
								</div>
								<h3 className="mt-2 text-sm font-semibold text-[var(--sea-ink)]">
									{finding.title}
								</h3>
								<div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--sea-ink-soft)]">
									<span>Confidence: {Math.round(finding.confidence * 100)}%</span>
									<span>Raised: {formatTimestamp(finding.createdAt)}</span>
								</div>
							</button>
							{selected === finding._id && (
								<FindingDetailPanel
									findingId={finding._id as Id<"findings">}
									finding={finding}
								/>
							)}
						</div>
					))}
					{findings.length === 0 && (
						<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
							<AlertTriangle size={24} className="mb-2 opacity-40" />
							<p>No findings match the current filter.</p>
						</div>
					)}
				</div>
			</div>
		</main>
	);
}

function FindingDetailPanel({
	findingId,
	finding,
}: {
	findingId: Id<"findings">;
	finding: OverviewFinding;
}) {
	const blastRadius = useQuery(api.blastRadiusIntel.getBlastRadius, {
		findingId,
	});
	const triageMutation = useMutation(api.findingTriage.markFalsePositive);
	const [isPending, startTransition] = useTransition();

	function handleFalsePositive() {
		startTransition(() => {
			void triageMutation({
				findingId,
				note: "Marked false positive via operator dashboard",
			});
		});
	}

	return (
		<div className="mt-2 card border-l-2 border-l-[var(--lagoon)] rounded-tl-none rounded-bl-none">
			<div className="grid gap-4 sm:grid-cols-2">
				{/* Blast Radius */}
				{blastRadius && (
					<div>
						<p className="panel-label mb-2">Blast Radius</p>
						<div className="flex flex-wrap gap-1.5">
							<StatusPill
								label={blastRadius.riskTier}
								tone={blastTierTone(blastRadius.riskTier)}
							/>
							<StatusPill
								label={`impact ${blastRadius.businessImpactScore}`}
								tone="neutral"
							/>
							<StatusPill
								label={`depth ${blastRadius.attackPathDepth}`}
								tone="neutral"
							/>
						</div>
						{blastRadius.reachableServices.length > 0 && (
							<div className="mt-2 flex flex-wrap gap-1.5">
								{blastRadius.reachableServices.slice(0, 5).map((svc) => (
									<StatusPill key={svc} label={svc} tone="neutral" />
								))}
							</div>
						)}
						{blastRadius.exposedDataLayers.length > 0 && (
							<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
								Layers: {blastRadius.exposedDataLayers.join(", ")}
							</p>
						)}
						<p className="mt-1.5 text-xs text-[var(--sea-ink-soft)]">
							{blastRadius.summary}
						</p>
					</div>
				)}

				{/* Triage Actions */}
				<div>
					<p className="panel-label mb-2">Triage</p>
					<div className="space-y-2">
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">Status:</span>{" "}
							{finding.status.replace(/_/g, " ")}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">Validation:</span>{" "}
							{finding.validationStatus}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">Source:</span>{" "}
							{finding.source}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">Confidence:</span>{" "}
							{Math.round(finding.confidence * 100)}%
						</div>
						<div className="mt-3 flex flex-wrap gap-2">
							<button
								type="button"
								onClick={handleFalsePositive}
								disabled={isPending}
								className="signal-button secondary-button"
								style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
							>
								Mark false positive
							</button>
						</div>
					</div>
				</div>
			</div>

			{/* Remediation Queue entry for this finding */}
			<FindingRemediationEntry findingId={findingId} />
		</div>
	);
}

function FindingRemediationEntry({ findingId }: { findingId: Id<"findings"> }) {
	const repos = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
	const firstRepo = repos?.repositories[0];
	const queue = useQuery(
		api.remediationQueueIntel.getRemediationQueueForRepository,
		firstRepo ? { repositoryId: firstRepo._id as Id<"repositories"> } : "skip",
	);

	if (!queue) return null;
	const entry = queue.queue.find(
		(i: { findingId: string }) => i.findingId === (findingId as string),
	);
	if (!entry) return null;

	return (
		<div className="mt-3 pt-3 border-t border-[var(--line)]">
			<p className="panel-label mb-1.5">Remediation Priority</p>
			<div className="flex flex-wrap gap-1.5">
				<StatusPill
					label={(entry.priorityTier as string).toUpperCase()}
					tone={priorityTierTone(entry.priorityTier as string)}
				/>
				<StatusPill
					label={`priority score ${(entry.priorityScore as number).toFixed(0)}`}
					tone="neutral"
				/>
			</div>
			{Array.isArray(entry.priorityRationale) && (entry.priorityRationale as string[]).length > 0 && (
				<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
					{(entry.priorityRationale as string[])[0]}
				</p>
			)}
		</div>
	);
}

