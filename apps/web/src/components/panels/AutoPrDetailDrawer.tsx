import { useMutation } from "convex/react";
import {
	CheckCircle2,
	ExternalLink,
	GitBranch,
	GitMerge,
	Merge,
	Package,
	ShieldCheck,
	XCircle } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import type { PrProposal } from "./AutoPrFeedPanel";

function prStatusTone(
	status: string,
): "success" | "warning" | "danger" | "neutral" | "info" {
	switch (status) {
		case "merged":
			return "success";
		case "open":
			return "info";
		case "draft":
			return "warning";
		case "failed":
			return "danger";
		case "closed":
			return "neutral";
		default:
			return "neutral";
	}
}

function validationStatusTone(
	status: string | undefined,
): "success" | "warning" | "danger" | "neutral" {
	if (!status) return "neutral";
	if (status === "exploited" || status === "likely_exploitable") return "danger";
	if (status === "not_exploitable") return "success";
	if (status === "pending" || status === "running") return "warning";
	return "neutral";
}

export default function AutoPrDetailDrawer({
	proposal,
	onClose }: {
	proposal: PrProposal;
	onClose: () => void;
}) {
	const [acting, setActing] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const markMerged = useMutation(api.prGeneration.markPrMerged);
	const markClosed = useMutation(api.prGeneration.markPrClosed);

	async function handleMerge() {
		setActing(true);
		setError(null);
		try {
			await markMerged({ proposalId: proposal._id as Id<"prProposals"> });
		} catch (e) {
			setError(e instanceof Error ? e.message : "Failed to mark as merged");
		} finally {
			setActing(false);
		}
	}

	async function handleClose() {
		setActing(true);
		setError(null);
		try {
			await markClosed({ proposalId: proposal._id as Id<"prProposals"> });
		} catch (e) {
			setError(e instanceof Error ? e.message : "Failed to mark as closed");
		} finally {
			setActing(false);
		}
	}

	return (
		<div className="card">
			{/* Header */}
			<div className="flex items-start justify-between gap-2 mb-4">
				<div className="min-w-0">
					<div className="flex flex-wrap items-center gap-2 mb-1">
						<StatusPill
							label={proposal.status}
							tone={prStatusTone(proposal.status)}
						/>
						{proposal.prNumber != null && (
							<span className="text-xs font-mono text-[var(--sea-ink-soft)]">
								PR #{proposal.prNumber}
							</span>
						)}
					</div>
					<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
						{proposal.prTitle}
					</h3>
				</div>
				<button
					type="button"
					className="shrink-0 text-xs text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)] transition-colors"
					onClick={onClose}
				>
					✕
				</button>
			</div>

			{/* Branch info */}
			<div className="mb-4 inset-panel p-3 rounded-lg space-y-2">
				<div className="flex items-center gap-2 text-xs">
					<GitBranch size={12} className="text-[var(--signal)] shrink-0" />
					<span className="font-mono text-[var(--sea-ink)]">
						{proposal.proposedBranch}
					</span>
				</div>
				{proposal.targetPackage && (
					<div className="flex items-center gap-2 text-xs">
						<Package size={12} className="text-[var(--signal)] shrink-0" />
						<span className="text-[var(--sea-ink)]">
							{proposal.targetPackage}
							{proposal.targetEcosystem && (
								<span className="text-[var(--sea-ink-soft)]">
									{" "}
									({proposal.targetEcosystem})
								</span>
							)}
						</span>
					</div>
				)}
				{proposal.currentVersion && proposal.fixVersion && (
					<div className="text-xs text-[var(--sea-ink-soft)] pl-5">
						{proposal.currentVersion} → {proposal.fixVersion}
					</div>
				)}
			</div>

			{/* Sandbox validation status */}
			<div className="mb-4">
				<div className="flex items-center gap-2 mb-2">
					<ShieldCheck size={12} className="text-[var(--signal)]" />
					<span className="text-xs font-semibold text-[var(--sea-ink)] uppercase tracking-wider">
						Sandbox Validation
					</span>
				</div>
				<div className="inset-panel p-3 rounded-lg">
					{proposal.validationStatus ? (
						<div className="flex items-center gap-2">
							<StatusPill
								label={proposal.validationStatus}
								tone={validationStatusTone(proposal.validationStatus)}
							/>
							{proposal.findingSeverity && (
								<StatusPill
									label={proposal.findingSeverity}
									tone={
										proposal.findingSeverity === "critical"
											? "danger"
											: proposal.findingSeverity === "high"
												? "warning"
												: "neutral"
									}
								/>
							)}
						</div>
					) : (
						<p className="text-xs text-[var(--sea-ink-soft)] italic">
							No validation run recorded for this finding yet.
						</p>
					)}
				</div>
			</div>

			{/* Full reasoning chain / PR body */}
			<div className="mb-4">
				<div className="flex items-center gap-2 mb-2">
					<CheckCircle2 size={12} className="text-[var(--signal)]" />
					<span className="text-xs font-semibold text-[var(--sea-ink)] uppercase tracking-wider">
						Reasoning Chain
					</span>
				</div>
				<div className="inset-panel p-3 rounded-lg max-h-48 overflow-y-auto">
					{proposal.prBody ? (
						<pre className="text-xs text-[var(--sea-ink-soft)] whitespace-pre-wrap break-words font-sans">
							{proposal.prBody}
						</pre>
					) : (
						<p className="text-xs text-[var(--sea-ink-soft)] italic">
							No reasoning body attached to this proposal.
						</p>
					)}
				</div>
			</div>

			{/* Fix summary */}
			{proposal.fixSummary && (
				<div className="mb-4">
					<div className="flex items-center gap-2 mb-2">
						<GitMerge size={12} className="text-[var(--signal)]" />
						<span className="text-xs font-semibold text-[var(--sea-ink)] uppercase tracking-wider">
							Fix Summary
						</span>
					</div>
					<div className="inset-panel p-3 rounded-lg">
						<p className="text-xs text-[var(--sea-ink-soft)]">
							{proposal.fixSummary}
						</p>
					</div>
				</div>
			)}

			{/* Timestamps */}
			<div className="mb-4 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--sea-ink-soft)]">
				<span>Created: {formatTimestamp(proposal.createdAt)}</span>
				{proposal.submittedAt && (
					<span>Submitted: {formatTimestamp(proposal.submittedAt)}</span>
				)}
				{proposal.mergedAt && (
					<span>Merged: {formatTimestamp(proposal.mergedAt)}</span>
				)}
				{proposal.mergedBy && (
					<span>by {proposal.mergedBy}</span>
				)}
			</div>

			{/* Error display */}
			{proposal.status === "failed" && proposal.githubError && (
				<div className="mb-4 inset-panel p-3 rounded-lg border border-[rgba(220,38,38,0.2)]">
					<p className="text-xs text-[var(--danger)] font-semibold mb-1">
						GitHub Error
					</p>
					<p className="text-xs text-[var(--danger)] break-words">
						{proposal.githubError}
					</p>
				</div>
			)}

			{/* Action error */}
			{error && (
				<div className="mb-3 inset-panel p-3 rounded-lg border border-[rgba(220,38,38,0.2)]">
					<p className="text-xs text-[var(--danger)]">{error}</p>
				</div>
			)}

			{/* CTAs */}
			<div className="flex flex-wrap items-center gap-2 pt-3 border-t border-[var(--line)]">
				{proposal.prUrl && (
					<a
						href={proposal.prUrl}
						target="_blank"
						rel="noopener noreferrer"
						className="inline-flex items-center gap-1.5 rounded-lg border border-[rgba(130,122,110,0.22)] bg-[rgba(130,122,110,0.07)] px-3 py-1.5 text-xs font-semibold text-[var(--sea-ink)] hover:bg-[rgba(130,122,110,0.14)] transition-colors"
					>
						<ExternalLink size={12} />
						View on GitHub
					</a>
				)}
				{proposal.status === "open" && (
					<>
						<button
							type="button"
							className="inline-flex items-center gap-1.5 rounded-lg border border-[rgba(5,150,105,0.26)] bg-[rgba(5,150,105,0.08)] px-3 py-1.5 text-xs font-semibold text-[var(--success)] hover:bg-[rgba(5,150,105,0.18)] transition-colors disabled:opacity-50"
							disabled={acting}
							onClick={handleMerge}
						>
							<Merge size={12} />
							Mark Merged
						</button>
						<button
							type="button"
							className="inline-flex items-center gap-1.5 rounded-lg border border-[rgba(130,122,110,0.22)] bg-[rgba(130,122,110,0.07)] px-3 py-1.5 text-xs font-semibold text-[var(--sea-ink-soft)] hover:bg-[rgba(130,122,110,0.14)] transition-colors disabled:opacity-50"
							disabled={acting}
							onClick={handleClose}
						>
							<XCircle size={12} />
							Close PR
						</button>
					</>
				)}
			</div>
		</div>
	);
}
