import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import {
	BookOpen,
	Check,
	ChevronDown,
	ChevronUp,
	Clock,
	ExternalLink,
	Loader2,
	Shield,
	Wrench,
} from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { Id } from "../../lib/convex";
import { api } from "../../lib/convex";
import { formatTimestamp, priorityTierTone } from "../../lib/utils";
import { useAuthToken } from "../../lib/clerk-compat";
import { useTenantSlug } from "../../lib/workspace";
import BlastRadiusPanel from "./BlastRadiusPanel";
import FindingTriageActionBar from "./FindingTriageActionBar";

type OverviewData = NonNullable<
	FunctionReturnType<typeof api.dashboard.overview>
>;
type OverviewFinding = OverviewData["findings"][number];

export default function FindingDetailDrawer({
	findingId,
	finding,
}: {
	findingId: Id<"findings">;
	finding: OverviewFinding;
}) {
	const blastRadius = useQuery(api.blastRadiusIntel.getBlastRadius, {
		findingId,
	});

	return (
		<div className="mt-2 card border-l-2 border-l-[var(--lagoon)] rounded-tl-none rounded-bl-none">
			<div className="grid gap-4 sm:grid-cols-2">
				{/* Blast Radius */}
				{blastRadius && <BlastRadiusPanel blastRadius={blastRadius} />}

				{/* Triage Actions */}
				<div>
					<p className="panel-label mb-2">Triage</p>
					<div className="space-y-2">
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">
								Status:
							</span>{" "}
							{finding.status.replace(/_/g, " ")}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">
								Validation:
							</span>{" "}
							{finding.validationStatus}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">
								Source:
							</span>{" "}
							{finding.source}
						</div>
						<div className="text-xs text-[var(--sea-ink-soft)]">
							<span className="font-semibold text-[var(--sea-ink)]">
								Confidence:
							</span>{" "}
							{Math.round(finding.confidence * 100)}%
						</div>
						<FindingTriageActionBar findingId={findingId} />
					</div>
				</div>
			</div>

			{/* §3.10 — Generate PR CTA */}
			<GeneratePrButton findingId={findingId} />

			{/* Remediation Queue entry for this finding */}
			<FindingRemediationEntry findingId={findingId} />

			{/* D2 — Threat Intelligence */}
			<ThreatIntelSection findingId={findingId} />

			{/* D6 — Security Education */}
			<SecurityEducationSection
				findingType={finding.vulnClass}
				findingId={findingId}
			/>

			{/* D3 — Remediation Playbook */}
			<RemediationPlaybookSection findingId={findingId} />
		</div>
	);
}

/**
 * §3.10 — Generate PR button for an individual finding.
 * Calls `api.prGeneration.generatePrForFinding` action, shows a spinner,
 * then displays the PR link when the proposal is created.
 */
function GeneratePrButton({ findingId }: { findingId: Id<"findings"> }) {
	const generatePr = useMutation(api.prGeneration.generatePrForFinding);
	const [loading, setLoading] = useState(false);
	const [result, setResult] = useState<{
		status?: string;
		prUrl?: string;
		message: string;
	} | null>(null);
	const [error, setError] = useState<string | null>(null);

	const handleGenerate = async () => {
		setLoading(true);
		setError(null);
		setResult(null);
		try {
			const res = await generatePr({ findingId });
			setResult(res);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Failed to generate PR");
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="mt-3 pt-3 border-t border-[var(--line)]">
			<p className="panel-label mb-2">PR Generation</p>

			{!result && !error && (
				<button
					type="button"
					onClick={handleGenerate}
					disabled={loading}
					className="signal-button"
					style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
				>
					{loading ? (
						<>
							<Loader2 size={12} className="animate-spin inline mr-1.5" />
							Generating PR…
						</>
					) : (
						"Generate PR"
					)}
				</button>
			)}

			{loading && (
				<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
					Analyzing finding and preparing fix proposal…
				</p>
			)}

			{result && (
				<div className="mt-1 flex flex-wrap items-center gap-2">
					<StatusPill
						label={result.status === "open" ? "✅ PR Opened" : result.status === "draft" ? "📝 Draft" : result.status ?? "Created"}
						tone={result.status === "open" ? "success" : result.status === "failed" ? "danger" : "neutral"}
					/>
					{result.prUrl && (
						<a
							href={result.prUrl}
							target="_blank"
							rel="noopener noreferrer"
							className="inline-flex items-center gap-1 text-xs font-medium text-[var(--signal)] hover:underline"
						>
							<ExternalLink size={11} />
							View PR
						</a>
					)}
					{!result.prUrl && (
						<span className="text-xs text-[var(--sea-ink-soft)]">
							{result.message}
						</span>
					)}
				</div>
			)}

			{error && (
				<div className="mt-1 flex items-center gap-2">
					<span className="text-xs text-[var(--danger)]">{error}</span>
					<button
						type="button"
						onClick={handleGenerate}
						className="signal-button secondary-button"
						style={{ padding: "0.25rem 0.6rem", fontSize: "0.72rem" }}
					>
						Retry
					</button>
				</div>
			)}
		</div>
	);
}

function ThreatIntelSection({ findingId }: { findingId: Id<"findings"> }) {
	const intelList = useQuery(api.threatIntelligence.getThreatIntelForFinding, {
		findingId,
	});

	if (!intelList || intelList.length === 0) return null;

	const isActivelyExploited = intelList.some(
		(i) => i.intel.source === "cisa_kev",
	);

	return (
		<div className="mt-3 pt-3 border-t border-[var(--line)]">
			<div className="flex items-center gap-2 mb-2">
				<Shield size={13} className="text-[var(--signal)]" />
				<p className="panel-label">Threat Intelligence</p>
				{isActivelyExploited && (
					<span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
						Exploited in Wild
					</span>
				)}
			</div>

			<div className="space-y-2">
				{intelList.slice(0, 3).map((item) => {
					const iocs = (() => {
						try {
							return JSON.parse(item.intel.iocs) as {
								ips?: string[];
								domains?: string[];
								hashes?: string[];
							};
						} catch {
							return {};
						}
					})();

					const sourceLabel =
						item.intel.source === "cisa_kev"
							? "CISA KEV"
							: item.intel.source === "otx"
								? "AlienVault OTX"
								: item.intel.source.toUpperCase();

					const sourceUrl =
						item.intel.source === "cisa_kev"
							? `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
							: item.intel.source === "otx"
								? `https://otx.alienvault.com/pulse/${item.intel.externalId}`
								: undefined;

					return (
						<div
							key={item._id}
							className="card card-sm"
						>
							<div className="flex items-start justify-between gap-2 mb-1">
								<p className="text-xs font-semibold text-[var(--sea-ink)] line-clamp-2 flex-1">
									{item.intel.title}
								</p>
								<span className="text-xs px-1.5 py-0.5 rounded bg-[var(--surface-raised)] text-[var(--sea-ink-soft)] whitespace-nowrap">
									{sourceLabel}
								</span>
							</div>

							<p className="text-xs text-[var(--sea-ink-soft)] line-clamp-2 mb-2">
								{item.intel.description}
							</p>

							<div className="flex flex-wrap gap-1 mb-1">
								{item.intel.cves.slice(0, 3).map((cve) => (
									<span
										key={cve}
										className="text-xs px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-mono"
									>
										{cve}
									</span>
								))}
								{item.intel.threatActors.slice(0, 2).map((actor) => (
									<span
										key={actor}
										className="text-xs px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400"
									>
										{actor}
									</span>
								))}
							</div>

							{(iocs.ips?.length || iocs.domains?.length) ? (
								<div className="text-xs text-[var(--sea-ink-soft)] mb-1">
									<span className="font-semibold text-[var(--sea-ink)]">IOCs:</span>{" "}
									{[
										...(iocs.ips?.slice(0, 2) ?? []),
										...(iocs.domains?.slice(0, 2) ?? []),
									].join(", ")}
								</div>
							) : null}

							<div className="flex items-center justify-between">
								<span className="text-xs text-[var(--sea-ink-soft)]">
									{formatTimestamp(item.intel.publishedAt)}
								</span>
								{sourceUrl && (
									<a
										href={sourceUrl}
										target="_blank"
										rel="noopener noreferrer"
										className="inline-flex items-center gap-1 text-xs text-[var(--signal)] hover:underline"
									>
										<ExternalLink size={10} />
										Source
									</a>
								)}
							</div>
						</div>
					);
				})}
			</div>
		</div>
	);
}

function SecurityEducationSection({
	findingType,
}: {
	findingType: string;
	findingId: Id<"findings">;
}) {
	const TENANT = useTenantSlug();
	const [open, setOpen] = useState(false);
	const [markedRead, setMarkedRead] = useState(false);

	const content = useQuery(api.securityEducation.getEducationContent, {
		findingType,
	});
	const trackView = useMutation(api.securityEducation.trackEducationView);

	if (!content) return null;

	const resources: { title: string; url: string }[] = (() => {
		try {
			return JSON.parse(content.resources);
		} catch {
			return [];
		}
	})();

	async function handleMarkRead() {
		if (markedRead || !content) return;
		await trackView({
			findingType,
			contentId: content._id,
			tenantSlug: TENANT,
		});
		setMarkedRead(true);
	}

	return (
		<div className="mt-3 pt-3 border-t border-[var(--line)]">
			<button
				type="button"
				onClick={() => {
					setOpen((v) => !v);
					if (!open) handleMarkRead();
				}}
				className="flex items-center gap-2 w-full text-left group"
			>
				<BookOpen size={13} className="text-[var(--signal)] shrink-0" />
				<span className="panel-label flex-1 group-hover:text-[var(--signal)] transition-colors">
					Learn About This Vulnerability
				</span>
				<span className="text-xs px-1.5 py-0.5 rounded-full bg-[var(--signal-soft)] text-[var(--signal)] font-medium">
					{content.vulnerabilityClass}
				</span>
				{open ? (
					<ChevronUp size={13} className="text-[var(--sea-ink-soft)] shrink-0" />
				) : (
					<ChevronDown
						size={13}
						className="text-[var(--sea-ink-soft)] shrink-0"
					/>
				)}
			</button>

			{open && (
				<div className="mt-3 space-y-3">
					{/* Why it matters */}
					<div className="card card-sm bg-amber-500/5 border-amber-500/20">
						<p className="text-xs font-semibold text-[var(--sea-ink)] mb-1">
							Why it matters
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
							{content.whyItMatters}
						</p>
					</div>

					{/* Attack scenario */}
					<div className="card card-sm bg-red-500/5 border-red-500/20">
						<p className="text-xs font-semibold text-red-400 mb-1">
							Attack scenario
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed font-mono">
							{content.attackScenario}
						</p>
					</div>

					{/* Secure coding guidelines */}
					<div className="card card-sm">
						<p className="text-xs font-semibold text-[var(--sea-ink)] mb-1">
							Secure coding guidelines
						</p>
						<p className="text-xs text-[var(--sea-ink-soft)] leading-relaxed">
							{content.secureCodingGuidelines}
						</p>
					</div>

					{/* Prevention checklist */}
					<div>
						<p className="text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Prevention checklist
						</p>
						<ul className="space-y-1.5">
							{content.preventionChecklist.map((item: string, i: number) => (
								<li key={i} className="flex items-start gap-2">
									<Check
										size={11}
										className="text-green-500 shrink-0 mt-0.5"
									/>
									<span className="text-xs text-[var(--sea-ink-soft)]">
										{item}
									</span>
								</li>
							))}
						</ul>
					</div>

					{/* Resources */}
					{resources.length > 0 && (
						<div>
							<p className="text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
								Further reading
							</p>
							<div className="flex flex-wrap gap-2">
								{resources.map((r) => (
									<a
										key={r.url}
										href={r.url}
										target="_blank"
										rel="noopener noreferrer"
										className="inline-flex items-center gap-1 text-xs text-[var(--signal)] hover:underline"
									>
										<ExternalLink size={10} />
										{r.title}
									</a>
								))}
							</div>
						</div>
					)}

					{/* Mark as read */}
					<div className="flex justify-end">
						<button
							type="button"
							onClick={handleMarkRead}
							disabled={markedRead}
							className={`signal-button secondary-button flex items-center gap-1.5 text-xs py-1 px-3 ${
								markedRead ? "opacity-60 cursor-default" : ""
							}`}
						>
							{markedRead ? (
								<>
									<Check size={11} className="text-green-500" />
									Marked as read
								</>
							) : (
								"Mark as Read"
							)}
						</button>
					</div>
				</div>
			)}
		</div>
	);
}

// ---------------------------------------------------------------------------
// D3 — Remediation Playbook Section
// ---------------------------------------------------------------------------

type PlaybookStep = {
	title: string;
	description: string;
	codeBefore?: string;
	codeAfter?: string;
	language?: string;
};

function difficultyTone(diff: string) {
	return diff === "easy"
		? "success"
		: diff === "hard"
			? "danger"
			: "neutral";
}

function RemediationPlaybookSection({
	findingId,
}: {
	findingId: Id<"findings">;
}) {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken();
	const [open, setOpen] = useState(false);
	const [generating, setGenerating] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [markingUsed, setMarkingUsed] = useState(false);
	const [marked, setMarked] = useState<"used" | "effective" | null>(null);

	const playbook = useQuery(
		api.remediationPlaybooks.getPlaybookForFinding,
		authToken
			? { authToken, tenantSlug: TENANT, findingId }
			: "skip",
	);
	const generate = useMutation(api.remediationPlaybooks.generatePlaybook);
	const markUsed = useMutation(api.remediationPlaybooks.markPlaybookUsed);
	const stats = useQuery(
		api.remediationPlaybooks.getPlaybookEffectivenessStats,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	const steps: PlaybookStep[] = playbook?.steps
		? (() => {
				try { return JSON.parse(playbook.steps) as PlaybookStep[]; } catch { return []; }
			})()
		: [];

	async function handleGenerate() {
		if (!authToken) return;
		setGenerating(true);
		setError(null);
		try {
			await generate({ authToken, tenantSlug: TENANT, findingId });
		} catch (e) {
			setError(e instanceof Error ? e.message : "Failed to generate playbook");
		} finally {
			setGenerating(false);
		}
	}

	async function handleMark(wasEffective: boolean) {
		if (!authToken || !playbook) return;
		setMarkingUsed(true);
		try {
			await markUsed({
				authToken,
				tenantSlug: TENANT,
				playbookId: playbook._id,
				wasEffective,
			});
			setMarked(wasEffective ? "effective" : "used");
		} finally {
			setMarkingUsed(false);
		}
	}

	return (
		<div className="mt-3 pt-3 border-t border-[var(--line)]">
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				className="flex items-center gap-2 w-full text-left group"
			>
				<Wrench size={13} className="text-[var(--signal)] shrink-0" />
				<span className="panel-label flex-1 group-hover:text-[var(--signal)] transition-colors">
					Remediation Playbook
				</span>
				{playbook && (
					<>
						<span className="flex items-center gap-1 text-xs text-[var(--sea-ink-soft)]">
							<Clock size={11} />
							{playbook.estimatedTime}
						</span>
						<StatusPill
							label={playbook.difficulty}
							tone={difficultyTone(playbook.difficulty)}
						/>
					</>
				)}
				{open ? (
					<ChevronUp size={13} className="text-[var(--sea-ink-soft)] shrink-0" />
				) : (
					<ChevronDown size={13} className="text-[var(--sea-ink-soft)] shrink-0" />
				)}
			</button>

			{/* Effectiveness stats banner */}
			{stats && stats.used > 0 && (
				<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
					{stats.effectivenessRate}% of playbooks successfully resolve findings
					({stats.effective}/{stats.used} used)
				</p>
			)}

			{open && (
				<div className="mt-3 space-y-3">
					{/* Generate CTA */}
					{!playbook && (
						<div>
							{error && (
								<p className="text-xs text-[var(--danger)] mb-2">{error}</p>
							)}
							<button
								type="button"
								onClick={handleGenerate}
								disabled={generating}
								className="signal-button"
								style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
							>
								{generating ? (
									<>
										<Loader2 size={12} className="animate-spin inline mr-1.5" />
										Generating…
									</>
								) : (
									"Generate Playbook"
								)}
							</button>
						</div>
					)}

					{/* Playbook content */}
					{playbook && (
						<>
							{/* Prerequisites */}
							{playbook.prerequisites.length > 0 && (
								<div className="card card-sm bg-[var(--surface-raised)]">
									<p className="text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
										Prerequisites
									</p>
									<ul className="space-y-1">
										{playbook.prerequisites.map((p, i) => (
											<li
												key={i}
												className="flex items-start gap-1.5 text-xs text-[var(--sea-ink-soft)]"
											>
												<span className="mt-0.5 text-[var(--signal)]">•</span>
												{p}
											</li>
										))}
									</ul>
								</div>
							)}

							{/* Steps */}
							<div className="space-y-3">
								{steps.map((step, i) => (
									<div key={i} className="card card-sm">
										<p className="text-xs font-semibold text-[var(--sea-ink)] mb-1">
											Step {i + 1}: {step.title}
										</p>
										<p className="text-xs text-[var(--sea-ink-soft)] mb-2 leading-relaxed">
											{step.description}
										</p>
										{(step.codeBefore || step.codeAfter) && (
											<div className="space-y-1.5">
												{step.codeBefore && (
													<div>
														<p className="text-xs text-red-400 font-semibold mb-0.5">
															Before
														</p>
														<pre className="text-xs bg-red-500/8 border border-red-500/20 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-[var(--sea-ink-soft)]">
															{step.codeBefore}
														</pre>
													</div>
												)}
												{step.codeAfter && (
													<div>
														<p className="text-xs text-green-400 font-semibold mb-0.5">
															After
														</p>
														<pre className="text-xs bg-green-500/8 border border-green-500/20 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all text-[var(--sea-ink-soft)]">
															{step.codeAfter}
														</pre>
													</div>
												)}
											</div>
										)}
									</div>
								))}
							</div>

							{/* Verification steps */}
							{playbook.verificationSteps.length > 0 && (
								<div className="card card-sm bg-green-500/5 border-green-500/20">
									<p className="text-xs font-semibold text-green-400 mb-1.5">
										Verification Steps
									</p>
									<ul className="space-y-1">
										{playbook.verificationSteps.map((step, i) => (
											<li
												key={i}
												className="flex items-start gap-1.5 text-xs text-[var(--sea-ink-soft)]"
											>
												<Check
													size={11}
													className="text-green-500 shrink-0 mt-0.5"
												/>
												{step}
											</li>
										))}
									</ul>
								</div>
							)}

							{/* Mark as used */}
							{!marked && (
								<div className="flex items-center gap-2 pt-1">
									<button
										type="button"
										onClick={() => handleMark(false)}
										disabled={markingUsed}
										className="signal-button secondary-button text-xs py-1 px-3"
									>
										Mark as Used
									</button>
									<button
										type="button"
										onClick={() => handleMark(true)}
										disabled={markingUsed}
										className="signal-button text-xs py-1 px-3"
									>
										{markingUsed ? (
											<Loader2 size={11} className="animate-spin inline" />
										) : (
											"✅ This Fixed It"
										)}
									</button>
								</div>
							)}
							{marked && (
								<p className="text-xs text-green-400 flex items-center gap-1">
									<Check size={11} />
									{marked === "effective"
										? "Marked as effective — great work!"
										: "Marked as used"}
								</p>
							)}
						</>
					)}
				</div>
			)}
		</div>
	);
}

function FindingRemediationEntry({ findingId }: { findingId: Id<"findings"> }) {
	const TENANT = useTenantSlug();
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
			{Array.isArray(entry.priorityRationale) &&
				(entry.priorityRationale as string[]).length > 0 && (
					<p className="mt-1 text-xs text-[var(--sea-ink-soft)]">
						{(entry.priorityRationale as string[])[0]}
					</p>
				)}
		</div>
	);
}
