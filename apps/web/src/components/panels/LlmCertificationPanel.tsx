import type { FunctionReturnType } from "convex/server";
import { Award, CheckCircle2, Clock, RefreshCw, ShieldAlert, XCircle } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type CertReport = NonNullable<
	FunctionReturnType<
		typeof api.llmCertificationIntel.getLatestCertificationReport
	>
>;

type CertPath = CertReport["paths"][number];

function certStatusTone(
	status: string,
): "success" | "warning" | "danger" | "neutral" {
	if (status === "certified") return "success";
	if (status === "pending") return "warning";
	if (status === "uncertified") return "danger";
	return "neutral";
}

function CertPathRow({ path }: { path: CertPath }) {
	return (
		<div className="card card-sm">
			<div className="flex flex-wrap items-center gap-2 mb-1.5">
				<StatusPill label={path.status} tone={certStatusTone(path.status)} />
				<StatusPill
					label={`${(path.confidence * 100).toFixed(0)}% confidence`}
					tone={path.confidence >= 0.8 ? "success" : path.confidence >= 0.5 ? "warning" : "danger"}
				/>
				<StatusPill label={path.modelVersion} tone="neutral" />
			</div>

			<h4 className="text-sm font-semibold text-[var(--sea-ink)]">
				{path.label}
			</h4>

			<div className="flex flex-wrap gap-1.5 mt-1.5 text-xs text-[var(--sea-ink-soft)]">
				{path.lastCertifiedAt ? (
					<span className="inline-flex items-center gap-1">
						<CheckCircle2 size={10} />
						Last certified {formatTimestamp(path.lastCertifiedAt)}
					</span>
				) : (
					<span className="inline-flex items-center gap-1">
						<Clock size={10} />
						Not yet certified
					</span>
				)}
			</div>

			{path.failureReasons.length > 0 && (
				<div className="mt-2 space-y-0.5">
					{path.failureReasons.map((reason: string, i: number) => (
						<p
							// biome-ignore lint/suspicious/noArrayIndexKey: failure reasons have no stable id
							key={i}
							className="text-xs text-[var(--danger)] flex items-center gap-1"
						>
							<XCircle size={10} className="shrink-0" />
							{reason}
						</p>
					))}
				</div>
			)}
		</div>
	);
}

function overallStatusIcon(status: string) {
	if (status === "certified")
		return <ShieldAlert size={16} className="text-[var(--success)]" />;
	if (status === "uncertified")
		return <ShieldAlert size={16} className="text-[var(--danger)]" />;
	return <ShieldAlert size={16} className="text-[var(--warning)]" />;
}

export default function LlmCertificationPanel({
	report,
	onReCert,
}: {
	report: CertReport;
	onReCert?: () => void;
}) {
	const certifiedCount = report.paths.filter((p: CertPath) => p.status === "certified").length;
	const uncertifiedCount = report.paths.filter((p: CertPath) => p.status === "uncertified").length;
	const pendingCount = report.paths.filter((p: CertPath) => p.status === "pending").length;

	return (
		<div className="card">
			<div className="flex items-center justify-between mb-3 flex-wrap gap-2">
				<div className="flex items-center gap-2">
					<Award size={14} className="text-[var(--signal)]" />
					<h3 className="section-title">LLM Certification</h3>
					{overallStatusIcon(report.overallStatus)}
				</div>

				{onReCert && (
					<button
						type="button"
						onClick={onReCert}
						className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-transparent px-3 py-1.5 text-xs font-medium text-[var(--sea-ink)] transition-colors hover:bg-[rgba(130,122,110,0.08)]"
					>
						<RefreshCw size={12} />
						Re-certify
					</button>
				)}
			</div>

			{/* Summary stats */}
			<div className="grid gap-2 sm:grid-cols-4 mb-4">
				<div className="inset-panel">
					<p className="panel-label mb-1">Total Paths</p>
					<span className="text-lg font-bold text-[var(--sea-ink)]">
						{report.totalPaths}
					</span>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Certified</p>
					<div className="flex items-center gap-1.5">
						<CheckCircle2 size={14} className="text-[var(--success)]" />
						<span className="text-lg font-bold text-[var(--success)]">
							{certifiedCount}
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Uncertified</p>
					<div className="flex items-center gap-1.5">
						<XCircle size={14} className="text-[var(--danger)]" />
						<span className="text-lg font-bold text-[var(--danger)]">
							{uncertifiedCount}
						</span>
					</div>
				</div>
				<div className="inset-panel">
					<p className="panel-label mb-1">Pending</p>
					<div className="flex items-center gap-1.5">
						<Clock size={14} className="text-[var(--warning)]" />
						<span className="text-lg font-bold text-[var(--warning)]">
							{pendingCount}
						</span>
					</div>
				</div>
			</div>

			{/* Status pills */}
			<div className="flex flex-wrap gap-2 mb-3">
				<StatusPill
					label={report.overallStatus}
					tone={certStatusTone(report.overallStatus)}
				/>
				{report.certifiedAt && (
					<StatusPill
						label={`last cert ${formatTimestamp(report.certifiedAt)}`}
						tone="neutral"
					/>
				)}
			</div>

			{report.summary && (
				<p className="text-xs text-[var(--sea-ink-soft)] mb-3">
					{report.summary}
				</p>
			)}

			{/* Per-path details */}
			<div className="space-y-2">
				{report.paths.map((path: CertPath) => (
					<CertPathRow key={path.pathId} path={path} />
				))}
			</div>

			{report.paths.length === 0 && (
				<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl mt-2">
					<Award size={24} className="mb-2 opacity-40" />
					<p className="text-sm text-[var(--sea-ink-soft)]">
						No LLM-using code paths detected in this repository.
					</p>
				</div>
			)}
		</div>
	);
}
