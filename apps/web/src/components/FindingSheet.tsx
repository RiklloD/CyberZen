import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	BellOff,
	Check,
	ChevronDown,
	ChevronUp,
	Copy,
	ExternalLink,
	FileCode2,
	GitPullRequest,
	Loader2,
	RotateCcw,
	ShieldCheck,
	ShieldOff,
	X,
	Zap,
} from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import type { Id } from "../lib/convex";
import { api } from "../lib/convex";
import type { FindingRow } from "../lib/findings";
import { isOpen } from "../lib/findings";
import { absoluteTime, humanize, relativeTime } from "../lib/format";
import { blastTierTone } from "../lib/utils";
import AcceptRiskModal from "./modals/AcceptRiskModal";
import SnoozeFindingModal from "./modals/SnoozeFindingModal";
import {
	FindingRemediationEntry,
	GeneratePrButton,
	RemediationPlaybookSection,
	SecurityEducationSection,
	ThreatIntelSection,
} from "./panels/FindingDetailDrawer";
import StatusPill from "./StatusPill";
import SeverityBadge from "./ui/SeverityBadge";

type FindingDetail = NonNullable<FunctionReturnType<typeof api.findings.get>>;
type PrProposal = FindingDetail["prProposals"][number];
type GateDecision = FindingDetail["gateDecisions"][number];

const STATUS_TONE: Record<string, "danger" | "info" | "success" | "neutral" | "warning"> = {
	open: "danger",
	pr_opened: "info",
	merged: "success",
	resolved: "success",
	accepted_risk: "warning",
	false_positive: "neutral",
	ignored: "neutral",
	snoozed: "neutral",
};

/**
 * Right-hand sheet for triaging a single finding. Ordered by the questions
 * a responder asks: what is it → where → can it be exploited → how to fix.
 */
export default function FindingSheet({
	findingId,
	occurrences,
	onSelect,
	onClose,
	onPrev,
	onNext,
}: {
	findingId: Id<"findings">;
	/** Other findings in the same group (identical title + repo). */
	occurrences?: FindingRow[];
	onSelect?: (id: Id<"findings">) => void;
	onClose: () => void;
	onPrev?: () => void;
	onNext?: () => void;
}) {
	const finding = useQuery(api.findings.get, { findingId });
	const blastRadius = useQuery(api.blastRadiusIntel.getBlastRadius, { findingId });
	const markFalsePositive = useMutation(api.findingTriage.markFalsePositive);
	const applyTriage = useMutation(api.findingTriage.applyTriageAction);
	const [busy, setBusy] = useState<string | null>(null);
	const [modal, setModal] = useState<"snooze" | "accept" | null>(null);
	const [copied, setCopied] = useState(false);

	useEffect(() => {
		function onKey(e: KeyboardEvent) {
			const tag = (e.target as HTMLElement)?.tagName;
			if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || modal) return;
			if (e.key === "Escape") onClose();
			if (e.key === "j" || e.key === "ArrowDown") onNext?.();
			if (e.key === "k" || e.key === "ArrowUp") onPrev?.();
		}
		document.addEventListener("keydown", onKey);
		return () => document.removeEventListener("keydown", onKey);
	}, [onClose, onNext, onPrev, modal]);

	async function run(label: string, fn: () => Promise<unknown>) {
		setBusy(label);
		try {
			await fn();
		} finally {
			setBusy(null);
		}
	}

	function copyLink() {
		const url = new URL(window.location.href);
		url.searchParams.set("id", findingId);
		void navigator.clipboard.writeText(url.toString()).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1500);
		});
	}

	const latestValidation = finding?.validationRuns[0];
	const latestPr = finding?.prProposals[0];

	return (
		<div className="drawer-overlay" onMouseDown={onClose}>
			<aside
				className="drawer-panel !w-[min(680px,100vw)]"
				onMouseDown={(e) => e.stopPropagation()}
				aria-label="Finding details"
			>
				{finding === undefined ? (
					<div className="space-y-3 p-5">
						<div className="skeleton h-5 w-24" />
						<div className="skeleton h-7 w-3/4" />
						<div className="skeleton h-40" />
					</div>
				) : finding === null ? (
					<div className="p-5">
						<p className="text-sm text-[var(--text-2)]">This finding no longer exists.</p>
					</div>
				) : (
					<>
						{/* Header */}
						<div className="border-b border-[var(--line)] px-5 pt-4 pb-3.5">
							<div className="flex items-center gap-2">
								<SeverityBadge severity={finding.severity} />
								<StatusPill label={finding.status} tone={STATUS_TONE[finding.status] ?? "neutral"} />
								<div className="ml-auto flex items-center gap-0.5">
									<button type="button" className="icon-button" onClick={onPrev} disabled={!onPrev} title="Previous (k)">
										<ChevronUp size={15} />
									</button>
									<button type="button" className="icon-button" onClick={onNext} disabled={!onNext} title="Next (j)">
										<ChevronDown size={15} />
									</button>
									<button type="button" className="icon-button" onClick={copyLink} title="Copy link">
										{copied ? <Check size={15} /> : <Copy size={15} />}
									</button>
									<button type="button" className="icon-button" onClick={onClose} title="Close (Esc)">
										<X size={15} />
									</button>
								</div>
							</div>
							<h2 className="mt-2.5 text-[1.05rem] font-semibold leading-snug tracking-[-0.01em]">
								{finding.title}
							</h2>
							<p className="mt-1 text-xs text-[var(--text-3)]">
								<span className="font-mono">{finding.repository.fullName}</span> · {humanize(finding.source)} ·{" "}
								<span title={absoluteTime(finding.createdAt)}>found {relativeTime(finding.createdAt)}</span>
							</p>

							{/* Actions */}
							<div className="mt-3.5 flex flex-wrap items-center gap-2">
								{isOpen(finding) ? (
									<>
										{latestPr?.prUrl ? (
											<a href={latestPr.prUrl} target="_blank" rel="noopener noreferrer" className="btn btn-primary">
												<GitPullRequest size={13} />
												View fix PR
											</a>
										) : (
											<GeneratePrButton findingId={findingId} />
										)}
										<button
											type="button"
											className="btn"
											disabled={!!busy}
											onClick={() =>
												run("fp", () =>
													markFalsePositive({ findingId, note: "Marked false positive from findings triage" }),
												)
											}
										>
											{busy === "fp" ? <Loader2 size={13} className="animate-spin" /> : <ShieldOff size={13} />}
											False positive
										</button>
										<button type="button" className="btn" onClick={() => setModal("accept")}>
											<ShieldCheck size={13} />
											Accept risk
										</button>
										<button type="button" className="btn" onClick={() => setModal("snooze")}>
											<BellOff size={13} />
											Snooze
										</button>
									</>
								) : (
									<button
										type="button"
										className="btn"
										disabled={!!busy}
										onClick={() => run("reopen", () => applyTriage({ findingId, action: "reopen" }))}
									>
										{busy === "reopen" ? <Loader2 size={13} className="animate-spin" /> : <RotateCcw size={13} />}
										Reopen
									</button>
								)}
							</div>
						</div>

						{/* Body */}
						<div className="drawer-body space-y-6">
							{finding.summary && (
								<p className="text-[0.85rem] leading-relaxed text-[var(--text-2)]">{finding.summary}</p>
							)}

							<dl className="grid grid-cols-2 gap-px overflow-hidden rounded-[var(--radius)] border border-[var(--line)] bg-[var(--line)] sm:grid-cols-4">
								<Fact label="Exploitability">
									{finding.validationStatus === "validated" ? (
										<span className="inline-flex items-center gap-1 text-[var(--danger)]">
											<Zap size={12} /> Confirmed
										</span>
									) : (
										humanize(finding.validationStatus)
									)}
								</Fact>
								<Fact label="Confidence">{Math.round(finding.confidence * 100)}%</Fact>
								<Fact label="Business impact">{finding.businessImpactScore}/100</Fact>
								<Fact label="Class">{humanize(finding.vulnClass)}</Fact>
							</dl>

							{occurrences && occurrences.length > 1 && (
								<SheetSection title={`Occurrences (${occurrences.length})`}>
									<div className="list max-h-48 overflow-y-auto">
										{occurrences.map((o, i) => (
											<button
												key={o._id}
												type="button"
												className={`list-row !py-1.5 ${o._id === findingId ? "is-selected" : ""}`}
												onClick={() => onSelect?.(o._id)}
											>
												<span className="w-6 text-xs text-[var(--text-3)] tabular">{i + 1}</span>
												<span className="flex-1 truncate text-xs">
													{o.affectedPackages[0] ?? o.summary ?? o.title}
												</span>
												<span className="text-xs text-[var(--text-3)]">{relativeTime(o.createdAt)}</span>
											</button>
										))}
									</div>
								</SheetSection>
							)}

							{(finding.affectedFiles.length > 0 ||
								finding.affectedPackages.length > 0 ||
								finding.affectedServices.length > 0) && (
								<SheetSection title="Where">
									<div className="space-y-2">
										{finding.affectedFiles.length > 0 && (
											<div className="list">
												{finding.affectedFiles.slice(0, 8).map((file: string) => (
													<div key={file} className="list-row !py-1.5">
														<FileCode2 size={13} className="shrink-0 text-[var(--text-3)]" />
														<span className="truncate font-mono text-xs">{file}</span>
													</div>
												))}
												{finding.affectedFiles.length > 8 && (
													<div className="list-row !py-1.5 text-xs text-[var(--text-3)]">
														+{finding.affectedFiles.length - 8} more files
													</div>
												)}
											</div>
										)}
										<TagList label="Packages" items={finding.affectedPackages} mono />
										<TagList label="Services" items={finding.affectedServices} />
									</div>
								</SheetSection>
							)}

							{finding.disclosure && (
								<SheetSection title="Advisory">
									<div className="inset-panel space-y-1.5 text-[0.8rem]">
										<div className="flex flex-wrap items-center gap-2">
											<a
												href={advisoryUrl(finding.disclosure.sourceRef)}
												target="_blank"
												rel="noopener noreferrer"
												className="inline-flex items-center gap-1 font-mono text-xs"
											>
												{finding.disclosure.sourceRef}
												<ExternalLink size={11} />
											</a>
											<span className="text-xs text-[var(--text-3)]">via {finding.disclosure.sourceName}</span>
											{finding.disclosure.exploitAvailable && (
												<StatusPill label="Public exploit" tone="danger" />
											)}
										</div>
										<p className="text-[var(--text-2)]">
											<span className="font-mono">{finding.disclosure.packageName}</span>
											{finding.disclosure.matchedVersions.length > 0 && (
												<> @ {finding.disclosure.matchedVersions.join(", ")}</>
											)}
											{finding.disclosure.affectedVersions.length > 0 && (
												<span className="text-[var(--text-3)]">
													{" "}
													· affected {finding.disclosure.affectedVersions.join(", ")}
												</span>
											)}
										</p>
										{finding.disclosure.fixVersion && (
											<p className="text-[var(--success)]">
												Upgrade to <span className="font-mono">{finding.disclosure.fixVersion}</span> to fix
											</p>
										)}
									</div>
								</SheetSection>
							)}

							{(latestValidation || blastRadius) && (
								<SheetSection title="Impact">
									<div className="space-y-2">
										{latestValidation && (
											<div className="inset-panel text-[0.8rem]">
												<div className="mb-1 flex items-center gap-2">
													<span className="font-medium">Sandbox validation</span>
													<StatusPill
														label={latestValidation.outcome ?? latestValidation.status}
														tone={
															latestValidation.outcome === "validated"
																? "danger"
																: latestValidation.outcome === "likely_exploitable"
																	? "warning"
																	: "neutral"
														}
													/>
													<span className="ml-auto text-xs text-[var(--text-3)]">
														{relativeTime(latestValidation.startedAt)}
													</span>
												</div>
												<p className="text-[var(--text-2)]">{latestValidation.evidenceSummary}</p>
												{latestValidation.reproductionHint && (
													<p className="mt-1 font-mono text-xs text-[var(--text-3)]">
														{latestValidation.reproductionHint}
													</p>
												)}
											</div>
										)}
										{blastRadius && (
											<div className="inset-panel text-[0.8rem]">
												<div className="mb-1 flex flex-wrap items-center gap-2">
													<span className="font-medium">Blast radius</span>
													<StatusPill label={blastRadius.riskTier} tone={blastTierTone(blastRadius.riskTier)} />
													<span className="text-xs text-[var(--text-3)]">
														depth {blastRadius.attackPathDepth} · impact {blastRadius.businessImpactScore}
													</span>
												</div>
												<p className="text-[var(--text-2)]">{finding.blastRadiusSummary}</p>
												{blastRadius.reachableServices.length > 0 && (
													<div className="mt-1.5 flex flex-wrap gap-1">
														{blastRadius.reachableServices.slice(0, 6).map((svc: string) => (
															<span key={svc} className="badge">
																{svc}
															</span>
														))}
													</div>
												)}
											</div>
										)}
									</div>
								</SheetSection>
							)}

							<SheetSection title="Fix">
								<div className="space-y-2">
									{finding.prProposals.length > 0 && (
										<div className="list">
											{finding.prProposals.map((pr: PrProposal) => (
												<div key={pr._id} className="list-row">
													<GitPullRequest size={13} className="shrink-0 text-[var(--text-3)]" />
													<span className="min-w-0 flex-1">
														<span className="block truncate text-[0.8rem]">{pr.prTitle}</span>
														<span className="block truncate text-xs text-[var(--text-3)]">
															{pr.fixSummary}
														</span>
													</span>
													<StatusPill
														label={pr.status}
														tone={pr.status === "merged" ? "success" : pr.status === "failed" ? "danger" : "info"}
													/>
													{pr.prUrl && (
														<a href={pr.prUrl} target="_blank" rel="noopener noreferrer" className="icon-button">
															<ExternalLink size={13} />
														</a>
													)}
												</div>
											))}
										</div>
									)}
									<FindingRemediationEntry findingId={findingId} repositoryId={finding.repository._id} />
									<RemediationPlaybookSection findingId={findingId} />
								</div>
							</SheetSection>

							<ThreatIntelSection findingId={findingId} />

							{finding.gateDecisions.length > 0 && (
								<SheetSection title="Gate decisions">
									<div className="list">
										{finding.gateDecisions.map((d: GateDecision) => (
											<div key={d._id} className="list-row !py-2 text-[0.8rem]">
												<StatusPill
													label={d.decision}
													tone={d.decision === "blocked" ? "danger" : d.decision === "approved" ? "success" : "warning"}
												/>
												<span className="flex-1 truncate text-[var(--text-2)]">
													{humanize(d.stage)}
													{d.justification ? ` · ${d.justification}` : ""}
												</span>
												<span className="text-xs text-[var(--text-3)]">{relativeTime(d.createdAt)}</span>
											</div>
										))}
									</div>
								</SheetSection>
							)}

							{finding.regulatoryImplications.length > 0 && (
								<SheetSection title="Compliance">
									<TagList items={finding.regulatoryImplications} />
								</SheetSection>
							)}

							<SecurityEducationSection findingType={finding.vulnClass} findingId={findingId} />
						</div>
					</>
				)}
			</aside>

			{modal === "snooze" && (
				<div onMouseDown={(e) => e.stopPropagation()}>
					<SnoozeFindingModal findingId={findingId} onClose={() => setModal(null)} />
				</div>
			)}
			<div onMouseDown={(e) => e.stopPropagation()}>
				<AcceptRiskModal findingId={findingId} open={modal === "accept"} onClose={() => setModal(null)} />
			</div>
		</div>
	);
}

function advisoryUrl(ref: string) {
	if (ref.startsWith("GHSA-")) return `https://github.com/advisories/${ref}`;
	if (ref.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${ref}`;
	return `https://osv.dev/vulnerability/${ref}`;
}

function SheetSection({ title, children }: { title: string; children: ReactNode }) {
	return (
		<section>
			<h3 className="mb-2 text-xs font-medium text-[var(--text-3)]">{title}</h3>
			{children}
		</section>
	);
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
	return (
		<div className="bg-[var(--surface)] px-3 py-2.5">
			<dt className="text-[0.7rem] text-[var(--text-3)]">{label}</dt>
			<dd className="mt-0.5 truncate text-[0.82rem] font-medium">{children}</dd>
		</div>
	);
}

function TagList({ label, items, mono = false }: { label?: string; items: string[]; mono?: boolean }) {
	if (items.length === 0) return null;
	return (
		<div className="flex flex-wrap items-center gap-1.5">
			{label && <span className="mr-1 text-xs text-[var(--text-3)]">{label}</span>}
			{items.slice(0, 12).map((item) => (
				<span key={item} className={`badge ${mono ? "font-mono" : ""}`}>
					{item}
				</span>
			))}
			{items.length > 12 && <span className="text-xs text-[var(--text-3)]">+{items.length - 12}</span>}
		</div>
	);
}
