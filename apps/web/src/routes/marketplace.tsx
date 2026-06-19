import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "convex/react";
import {
	Store,
	ThumbsUp,
	ThumbsDown,
	Filter,
} from "lucide-react";
import { useState } from "react";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

export const Route = createFileRoute("/marketplace")({
	errorComponent: RouteErrorBoundary,
	component: MarketplacePage,
});

const STATUS_OPTIONS = ["pending", "under_review", "approved", "rejected"] as const;

function MarketplacePage() {
	const [typeFilter, setTypeFilter] = useState<"fingerprint" | "detection_rule" | undefined>(undefined);
	const [statusFilter, setStatusFilter] = useState<string | undefined>("approved");
	const [vulnClassFilter] = useState<string | undefined>(undefined);

	const contributions = useQuery(api.communityMarketplace.listContributions, {
		type: typeFilter,
		status: statusFilter as any,
		vulnClass: vulnClassFilter,
		limit: 50,
	});

	const stats = useQuery(api.communityMarketplace.getMarketplaceStats);
	const topContributors = useQuery(api.communityMarketplace.getTopContributors, { limit: 5 });

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Store size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Integration Marketplace</h1>
						<p className="page-subtitle">
							Community-driven detection rules, fingerprints, and integrations
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Stats Row */}
				{stats && (
					<div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
						<StatCard label="Total Contributions" value={stats.total} />
						<StatCard label="Approved" value={stats.approved} />
						<StatCard label="Pending Review" value={stats.pending} />
						<StatCard label="Contributors" value={topContributors?.length ?? 0} />
					</div>
				)}

				{/* Filters */}
				<div className="flex flex-wrap items-center gap-2 mb-4">
					<div className="flex items-center gap-1.5">
						<Filter size={14} className="text-[var(--sea-ink-soft)]" />
						<span className="text-xs text-[var(--sea-ink-soft)]">Filters:</span>
					</div>

					{/* Type filter chips */}
					<button
						type="button"
						onClick={() => setTypeFilter(undefined)}
						className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
							typeFilter === undefined
								? "bg-[var(--signal)] text-white"
								: "bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:bg-[var(--signal)]/10"
						}`}
					>
						All Types
					</button>
					<button
						type="button"
						onClick={() => setTypeFilter("fingerprint")}
						className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
							typeFilter === "fingerprint"
								? "bg-[var(--signal)] text-white"
								: "bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:bg-[var(--signal)]/10"
						}`}
					>
						Fingerprints
					</button>
					<button
						type="button"
						onClick={() => setTypeFilter("detection_rule")}
						className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
							typeFilter === "detection_rule"
								? "bg-[var(--signal)] text-white"
								: "bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:bg-[var(--signal)]/10"
						}`}
					>
						Detection Rules
					</button>

					<div className="w-px h-5 bg-[var(--line)]" />

					{/* Status filter */}
					{STATUS_OPTIONS.map((s) => (
						<button
							key={s}
							type="button"
							onClick={() => setStatusFilter(statusFilter === s ? undefined : s)}
							className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
								statusFilter === s
									? "bg-[var(--signal)] text-white"
									: "bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:bg-[var(--signal)]/10"
							}`}
						>
							{s.replace("_", " ")}
						</button>
					))}
				</div>

				{/* Contributions List */}
				{!contributions ? (
					<div className="space-y-2">
						{["a", "b", "c", "d"].map((k) => (
							<div key={k} className="loading-panel h-20 rounded-2xl" />
						))}
					</div>
				) : contributions.length === 0 ? (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Store size={24} className="mb-2 opacity-40" />
						<p>No contributions match your filters.</p>
					</div>
				) : (
					<div className="space-y-2">
						{contributions.map((c: any) => (
							<ContributionCard key={c._id} contribution={c} />
						))}
					</div>
				)}

				{/* Top Contributors */}
				{topContributors && topContributors.length > 0 && (
					<div className="mt-8">
						<h2 className="section-title mb-3">Top Contributors</h2>
						<div className="grid grid-cols-1 md:grid-cols-3 gap-3">
							{topContributors.map((tc: any) => (
								<div key={tc.tenantId} className="card card-sm flex items-center gap-3">
									<div className="w-8 h-8 rounded-full bg-[var(--signal)]/10 flex items-center justify-center text-[var(--signal)] font-semibold text-sm">
										{tc.approvedCount}
									</div>
									<div>
										<p className="text-sm font-semibold text-[var(--sea-ink)]">{tc.tenantSlug}</p>
										<p className="text-xs text-[var(--sea-ink-soft)]">
											{tc.approvedCount} approved contribution{tc.approvedCount !== 1 ? "s" : ""}
										</p>
									</div>
								</div>
							))}
						</div>
					</div>
				)}
			</div>
		</main>
	);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatCard({
	label,
	value,
}: {
	label: string;
	value: number;
}) {
	return (
		<div className="card card-sm p-4">
			<p className="text-2xl font-bold text-[var(--sea-ink)]">{value}</p>
			<p className="text-xs text-[var(--sea-ink-soft)]">{label}</p>
		</div>
	);
}

function ContributionCard({ contribution: c }: { contribution: any }) {
	const netScore = (c.upvoteCount ?? 0) - (c.downvoteCount ?? 0);

	const severityTone = (sev: string) => {
		switch (sev) {
			case "critical": return "danger";
			case "high": return "warning";
			case "medium": return "neutral";
			default: return "neutral";
		}
	};

	const statusTone = (status: string) => {
		switch (status) {
			case "approved": return "success";
			case "pending": return "warning";
			case "rejected": return "danger";
			case "under_review": return "neutral";
			default: return "neutral";
		}
	};

	return (
		<div className="card card-sm">
			<div className="flex items-start justify-between gap-3">
				<div className="min-w-0 flex-1">
					<div className="flex items-center gap-2 mb-1">
						<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">{c.title}</p>
						<StatusPill label={c.type === "fingerprint" ? "Fingerprint" : "Rule"} tone="neutral" />
						<StatusPill label={c.severity} tone={severityTone(c.severity) as any} />
						<StatusPill label={c.status.replace("_", " ")} tone={statusTone(c.status) as any} />
					</div>
					<p className="text-xs text-[var(--sea-ink-soft)] line-clamp-2 mb-1">{c.description}</p>
					<div className="flex items-center gap-3 text-xs text-[var(--sea-ink-soft)]">
						<span className="font-medium text-[var(--signal)]">{c.vulnClass}</span>
						<span>•</span>
						<span className="flex items-center gap-1">
							<ThumbsUp size={10} /> {c.upvoteCount ?? 0}
						</span>
						<span className="flex items-center gap-1">
							<ThumbsDown size={10} /> {c.downvoteCount ?? 0}
						</span>
						<span>•</span>
						<span>Net: {netScore > 0 ? "+" : ""}{netScore}</span>
						<span>•</span>
						<span>{new Date(c.createdAt).toLocaleDateString()}</span>
					</div>
				</div>
			</div>
		</div>
	);
}
