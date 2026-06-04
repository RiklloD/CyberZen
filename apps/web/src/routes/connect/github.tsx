import { createFileRoute } from "@tanstack/react-router";
import { Github, CheckCircle2, ArrowRight, Loader2, GitBranch, Search } from "lucide-react";
import { useQuery } from "convex/react";
import { useState } from "react";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";
import { track } from "../../lib/analytics";

export const Route = createFileRoute("/connect/github")({
	errorComponent: RouteErrorBoundary,
	component: GitHubConnectWizard,
});

type WizardStep = "install" | "select-repos" | "initial-scan" | "complete";

function GitHubConnectWizard() {
	const TENANT = useTenantSlug();
	const [step, setStep] = useState<WizardStep>("install");
	const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());
	const [repoFilter, setRepoFilter] = useState("");
	const [scanTriggered, setScanTriggered] = useState(false);

	// Available repos after app install (simulated)
	const repositories = useQuery(api.dashboard.overview, { tenantSlug: TENANT });

	const steps: { key: WizardStep; label: string; num: number }[] = [
		{ key: "install", label: "Install App", num: 1 },
		{ key: "select-repos", label: "Select Repositories", num: 2 },
		{ key: "initial-scan", label: "Initial Scan", num: 3 },
		{ key: "complete", label: "Complete", num: 4 },
	];

	function stepIndex(s: WizardStep) {
		return steps.findIndex((st) => st.key === s);
	}

	function toggleRepo(name: string) {
		setSelectedRepos((prev) => {
			const next = new Set(prev);
			if (next.has(name)) {
				next.delete(name);
			} else {
				next.add(name);
			}
			return next;
		});
	}

	const repoList = (repositories as any)?.repositorySummaries ?? [];
	const filteredRepos = repoFilter
		? repoList.filter((r: any) =>
				(r.fullName ?? r.name ?? "").toLowerCase().includes(repoFilter.toLowerCase()),
			)
		: repoList;

	function handleSimulateInstall() {
		// In production this would redirect to GitHub App install URL
		setStep("select-repos");
	}

	function handleConfirmRepos() {
		if (selectedRepos.size === 0) return;
		track("repo.connected", {
			provider: "github",
			repositoryCount: selectedRepos.size,
		});
		setStep("initial-scan");
	}

	function handleStartScan() {
		setScanTriggered(true);
		track("scan.triggered", {
			scannerSlug: "initial-onboarding-scan",
			triggerType: "manual",
		});
		// Simulate scan start
		setTimeout(() => {
			setStep("complete");
		}, 2000);
	}

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Github size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">Connect GitHub</h1>
						<p className="page-subtitle">
							Install the CyberZen GitHub App and connect your repositories
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* Progress Steps */}
				<div className="flex items-center gap-2 mb-8">
					{steps.map((s, i) => {
						const isActive = step === s.key;
						const isDone = stepIndex(step) > i;
						return (
							<div key={s.key} className="flex items-center gap-2">
								{i > 0 && (
									<div
										className={`h-px w-8 ${
											isDone ? "bg-[var(--signal)]" : "bg-[var(--line)]"
										}`}
									/>
								)}
								<div
									className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
										isActive
											? "bg-[rgba(158,255,100,0.15)] text-[var(--signal)] border border-[var(--signal)]"
											: isDone
												? "bg-green-100 text-green-700"
												: "bg-[var(--chip-bg)] text-[var(--sea-ink-soft)]"
									}`}
								>
									{isDone ? (
										<CheckCircle2 size={12} />
									) : (
										<span className="w-4 h-4 flex items-center justify-center rounded-full bg-current text-[var(--panel-bg)] text-[0.55rem] font-bold">
											{s.num}
										</span>
									)}
									{s.label}
								</div>
							</div>
						);
					})}
				</div>

				<div className="max-w-2xl">
					{/* Step 1: Install App */}
					{step === "install" && (
						<div className="panel">
							<div className="p-8 text-center">
								<div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-[var(--chip-bg)] flex items-center justify-center">
									<Github size={32} className="text-[var(--sea-ink)]" />
								</div>
								<h2 className="text-lg font-semibold text-[var(--sea-ink)] mb-2">
									Install CyberZen GitHub App
								</h2>
								<p className="text-sm text-[var(--sea-ink-soft)] mb-6 max-w-md mx-auto">
									Grant CyberZen read access to your repositories so we can scan
									for vulnerabilities, misconfigurations, and supply chain risks.
								</p>
								<div className="space-y-3 text-left max-w-md mx-auto mb-6">
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Read access to code and metadata</span>
									</div>
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Webhook events for push, PR, and security advisories</span>
									</div>
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Write access for automated pull request fixes</span>
									</div>
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Commit status checks for CI/CD gate enforcement</span>
									</div>
								</div>
								<button
									type="button"
									className="signal-button"
									onClick={handleSimulateInstall}
								>
									Install GitHub App
									<ArrowRight size={14} />
								</button>
							</div>
						</div>
					)}

					{/* Step 2: Select Repos */}
					{step === "select-repos" && (
						<div className="panel">
							<div className="px-4 py-3 border-b border-[var(--line)]">
								<h2 className="text-sm font-semibold text-[var(--sea-ink)]">
									Select Repositories to Monitor
								</h2>
								<p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
									Choose which repositories CyberZen should scan and protect.
								</p>
							</div>

							{/* Search filter */}
							<div className="px-4 py-2 border-b border-[var(--line)]">
								<div className="relative">
									<Search
										size={14}
										className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--sea-ink-soft)]"
									/>
									<input
										type="text"
										className="input-field w-full pl-9"
										placeholder="Filter repositories..."
										value={repoFilter}
										onChange={(e) => setRepoFilter(e.target.value)}
									/>
								</div>
							</div>

							{/* Repo list */}
							<div className="max-h-[400px] overflow-y-auto">
								{filteredRepos.length === 0 && (
									<div className="p-8 text-center text-sm text-[var(--sea-ink-soft)]">
										{repoFilter
											? "No repositories match your filter."
											: "No repositories found. Connect repos to your workspace first."}
									</div>
								)}

								{filteredRepos.map((repo: any) => {
									const name = repo.fullName ?? repo.name ?? "unknown";
									const isSelected = selectedRepos.has(name);
									return (
										<button
											key={name}
											type="button"
											className={`w-full flex items-center gap-3 px-4 py-3 text-left border-b border-[var(--line)] transition-colors ${
												isSelected
													? "bg-[rgba(158,255,100,0.08)]"
													: "hover:bg-[var(--chip-bg)]"
											}`}
											onClick={() => toggleRepo(name)}
										>
											<div
												className={`w-4 h-4 rounded border-2 flex items-center justify-center shrink-0 ${
													isSelected
														? "border-[var(--signal)] bg-[var(--signal)]"
														: "border-[var(--chip-line)]"
												}`}
											>
												{isSelected && (
													<svg
														width="10"
														height="10"
														viewBox="0 0 10 10"
														fill="none"
													>
														<path
															d="M2 5L4 7L8 3"
															stroke="var(--panel-bg)"
															strokeWidth="1.5"
															strokeLinecap="round"
															strokeLinejoin="round"
														/>
													</svg>
												)}
											</div>
											<GitBranch size={14} className="text-[var(--sea-ink-soft)] shrink-0" />
											<div className="min-w-0 flex-1">
												<div className="text-sm font-medium text-[var(--sea-ink)] truncate">
													{name}
												</div>
												<div className="text-xs text-[var(--sea-ink-soft)]">
													{repo.primaryLanguage ?? "Unknown"} · {repo.visibility ?? "private"}
												</div>
											</div>
										</button>
									);
								})}
							</div>

							<div className="px-4 py-3 border-t border-[var(--line)] flex items-center justify-between">
								<span className="text-xs text-[var(--sea-ink-soft)]">
									{selectedRepos.size} repos selected
								</span>
								<div className="flex gap-2">
									<button
										type="button"
										className="secondary-button"
										onClick={() => setStep("install")}
									>
										Back
									</button>
									<button
										type="button"
										className="signal-button"
										onClick={handleConfirmRepos}
										disabled={selectedRepos.size === 0}
									>
										Continue
										<ArrowRight size={14} />
									</button>
								</div>
							</div>
						</div>
					)}

					{/* Step 3: Initial Scan */}
					{step === "initial-scan" && (
						<div className="panel">
							<div className="p-8 text-center">
								<div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-[rgba(158,255,100,0.1)] flex items-center justify-center">
									<GitBranch size={28} className="text-[var(--signal)]" />
								</div>
								<h2 className="text-lg font-semibold text-[var(--sea-ink)] mb-2">
									Ready for Initial Scan
								</h2>
								<p className="text-sm text-[var(--sea-ink-soft)] mb-4 max-w-md mx-auto">
									CyberZen will run an initial security scan on{" "}
									<strong className="text-[var(--sea-ink)]">
										{selectedRepos.size} repositor{selectedRepos.size === 1 ? "y" : "ies"}
									</strong>
									. This includes SAST, SCA, secret detection, and SBOM generation.
								</p>

								<div className="space-y-2 max-w-sm mx-auto mb-6 text-left">
									{Array.from(selectedRepos).map((name) => (
										<div
											key={name}
											className="flex items-center gap-2 text-sm text-[var(--sea-ink-soft)]"
										>
											<GitBranch size={12} className="shrink-0" />
											<span className="truncate">{name}</span>
										</div>
									))}
								</div>

								{!scanTriggered ? (
									<button
										type="button"
										className="signal-button"
										onClick={handleStartScan}
									>
										Start Initial Scan
										<ArrowRight size={14} />
									</button>
								) : (
									<div className="flex items-center justify-center gap-2 text-sm text-[var(--signal)]">
										<Loader2 size={16} className="animate-spin" />
										Running initial scan...
									</div>
								)}
							</div>
						</div>
					)}

					{/* Step 4: Complete */}
					{step === "complete" && (
						<div className="panel">
							<div className="p-8 text-center">
								<div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-green-100 flex items-center justify-center">
									<CheckCircle2 size={32} className="text-green-600" />
								</div>
								<h2 className="text-lg font-semibold text-[var(--sea-ink)] mb-2">
									GitHub Connection Complete
								</h2>
								<p className="text-sm text-[var(--sea-ink-soft)] mb-6 max-w-md mx-auto">
									Your repositories are connected and the initial scan is underway.
									You'll be notified when results are ready.
								</p>

								<div className="space-y-3 text-left max-w-sm mx-auto mb-6">
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>
											<strong className="text-[var(--sea-ink)]">{selectedRepos.size}</strong>{" "}
											repositor{selectedRepos.size === 1 ? "y" : "ies"} connected
										</span>
									</div>
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Webhook events configured</span>
									</div>
									<div className="flex items-start gap-2 text-sm text-[var(--sea-ink-soft)]">
										<CheckCircle2 size={14} className="mt-0.5 text-green-600 shrink-0" />
										<span>Initial scan dispatched</span>
									</div>
								</div>

								<div className="flex justify-center gap-3">
									<a href="/repositories" className="signal-button">
										View Repositories
									</a>
									<a href="/findings" className="secondary-button">
										View Findings
									</a>
								</div>
							</div>
						</div>
					)}
				</div>
			</div>
		</main>
	);
}
