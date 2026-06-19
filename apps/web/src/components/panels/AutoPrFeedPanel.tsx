import type { FunctionReturnType } from "convex/server";
import { GitPullRequest } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type PrProposal = NonNullable<
	FunctionReturnType<
		typeof api.prGeneration.listGeneratedPrsForRepository
	>
>[number];

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

function fixTypeLabel(t: string): string {
	switch (t) {
		case "version_bump":
			return "Version Bump";
		case "patch":
			return "Patch";
		case "config_change":
			return "Config Change";
		case "manual":
			return "Manual";
		default:
			return t;
	}
}

export default function AutoPrFeedPanel({
	proposals,
	onSelect,
	selectedId,
	repositoryFullName }: {
	proposals: PrProposal[];
	onSelect: (proposal: PrProposal) => void;
	selectedId: string | null;
	repositoryFullName: string;
}) {
	if (proposals.length === 0) {
		return (
			<div className="card">
				<div className="flex items-center gap-2 mb-3">
					<GitPullRequest size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Auto-PR History</h3>
				</div>
				<p className="text-xs text-[var(--sea-ink-soft)] italic">
					No auto-generated PRs yet for {repositoryFullName}. PRs will appear
					here once the remediation engine dispatches fixes.
				</p>
			</div>
		);
	}

	// Status summary counts
	const statusCounts = proposals.reduce(
		(acc, p) => {
			acc[p.status] = (acc[p.status] || 0) + 1;
			return acc;
		},
		{} as Record<string, number>,
	);

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3">
				<div className="flex items-center gap-2">
					<GitPullRequest size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">Auto-PR History</h3>
				</div>
				<div className="flex items-center gap-2">
					<StatusPill label={`${proposals.length} total`} tone="neutral" />
					{statusCounts["open"] > 0 && (
						<StatusPill
							label={`${statusCounts["open"]} open`}
							tone="info"
						/>
					)}
					{statusCounts["merged"] > 0 && (
						<StatusPill
							label={`${statusCounts["merged"]} merged`}
							tone="success"
						/>
					)}
					{statusCounts["failed"] > 0 && (
						<StatusPill
							label={`${statusCounts["failed"]} failed`}
							tone="danger"
						/>
					)}
				</div>
			</div>

			<div className="space-y-2 max-h-[32rem] overflow-y-auto">
				{proposals.map((proposal) => (
					<button
						key={proposal._id}
						type="button"
						className={`w-full text-left card card-sm cursor-pointer transition-colors hover:bg-[rgba(130,122,110,0.05)] ${
							selectedId === proposal._id
								? "ring-1 ring-[var(--signal)]"
								: ""
						}`}
						onClick={() => onSelect(proposal)}
					>
						{/* Row 1: Status + Fix type + PR number */}
						<div className="flex flex-wrap items-center gap-2">
							<StatusPill
								label={proposal.status}
								tone={prStatusTone(proposal.status)}
							/>
							<StatusPill
								label={fixTypeLabel(proposal.fixType)}
								tone="neutral"
							/>
							{proposal.prNumber != null && (
								<span className="text-xs font-mono text-[var(--sea-ink-soft)]">
									#{proposal.prNumber}
								</span>
							)}
						</div>

						{/* Row 2: PR Title */}
						<h4 className="mt-1.5 text-sm font-semibold text-[var(--sea-ink)] truncate">
							{proposal.prTitle}
						</h4>

						{/* Row 3: Branch + Package + Version */}
						<div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-[var(--sea-ink-soft)]">
							<span className="font-mono">
								{proposal.proposedBranch.length > 36
									? `…${proposal.proposedBranch.slice(-36)}`
									: proposal.proposedBranch}
							</span>
							{proposal.targetPackage && (
								<span>
									{proposal.targetPackage}
									{proposal.currentVersion && proposal.fixVersion && (
										<>
											{" "}
											{proposal.currentVersion} → {proposal.fixVersion}
										</>
									)}
								</span>
							)}
						</div>

						{/* Row 4: Reasoning summary (first 140 chars) */}
						{proposal.fixSummary && (
							<p className="mt-1 text-xs text-[var(--sea-ink-soft)] line-clamp-2">
								{proposal.fixSummary.length > 140
									? `${proposal.fixSummary.slice(0, 140)}…`
									: proposal.fixSummary}
							</p>
						)}

						{/* Row 5: Finding title + timestamp */}
						<div className="mt-1.5 flex items-center justify-between gap-2 text-xs">
							{proposal.findingTitle && (
								<span className="text-[var(--sea-ink-soft)] truncate">
									Finding: {proposal.findingTitle}
								</span>
							)}
							<span className="shrink-0 text-[var(--sea-ink-soft)]">
								{formatTimestamp(proposal.createdAt)}
							</span>
						</div>

						{/* Error indicator for failed PRs */}
						{proposal.status === "failed" && proposal.githubError && (
							<p className="mt-1 text-xs text-[var(--danger)] truncate">
								{proposal.githubError.length > 120
									? `${proposal.githubError.slice(0, 120)}…`
									: proposal.githubError}
							</p>
						)}
					</button>
				))}
			</div>
		</div>
	);
}

export type { PrProposal };
