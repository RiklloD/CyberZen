import { useQuery, useMutation, useAction } from "convex/react";
import {
	Github,
	Search,
	X,
	GitBranch,
	Loader2,
	CheckCircle2,
	ArrowRight,
	AlertCircle,
	Plus,
	RotateCw,
} from "lucide-react";
import { useState, useEffect, useCallback, useMemo } from "react";
import StatusPill from "./StatusPill";
import { api } from "../lib/convex";

type GithubRepo = {
	id: number;
	fullName: string;
	name: string;
	defaultBranch: string;
	primaryLanguage: string;
	visibility: "private" | "public";
	description?: string;
	htmlUrl: string;
	archived: boolean;
	fork: boolean;
	updatedAt?: string;
};

type AddResult = {
	fullName: string;
	repositoryId: string;
	status: "created" | "revived" | "already_active";
};

export default function AddRepositoryModal({
	tenantSlug,
	onClose,
}: {
	tenantSlug: string;
	onClose: () => void;
}) {
	const githubConnection = useQuery(
		api.githubIntegration.getGithubConnectionStatus,
		{ tenantSlug },
	);
	const tenantRepos = useQuery(api.dashboard.repoSummaries, { tenantSlug });
	const fetchGithubRepos = useAction(api.githubIntegration.listGithubRepos);
	const addRepository = useMutation(api.repositories.addRepository);
	const dispatchScan = useMutation(api.events.dispatchScannerForRepository);

	const [githubRepos, setGithubRepos] = useState<GithubRepo[] | null>(null);
	const [reposLoading, setReposLoading] = useState(false);
	const [reposError, setReposError] = useState<string | null>(null);
	const [filter, setFilter] = useState("");
	const [selected, setSelected] = useState<Set<string>>(new Set());
	const [phase, setPhase] = useState<"select" | "linking" | "done">("select");
	const [results, setResults] = useState<AddResult[] | null>(null);
	const [scanError, setScanError] = useState<string | null>(null);

	// Existing tracked repos (so we can mark them in the list)
	const trackedRepos = useMemo(() => {
		const set = new Set<string>();
		for (const r of tenantRepos ?? []) {
			if (r.fullName) set.add(r.fullName);
		}
		return set;
	}, [tenantRepos]);

	// Fetch GitHub repos when connection confirmed
	const loadRepos = useCallback(() => {
		if (reposLoading || githubRepos) return;
		setReposLoading(true);
		setReposError(null);
		fetchGithubRepos({ tenantSlug, perPage: 100 })
			.then((res) => setGithubRepos(res.repos))
			.catch((err) => {
				setReposError(
					err instanceof Error
						? err.message
						: "Failed to fetch GitHub repositories.",
				);
			})
			.finally(() => setReposLoading(false));
	}, [
		fetchGithubRepos,
		tenantSlug,
		reposLoading,
		githubRepos,
	]);

	useEffect(() => {
		if (githubConnection?.connected) {
			loadRepos();
		}
	}, [githubConnection?.connected, loadRepos]);

	// Filter
	const filteredRepos = useMemo(() => {
		if (!githubRepos) return [];
		if (!filter) return githubRepos;
		const q = filter.toLowerCase();
		return githubRepos.filter(
			(r) =>
				r.fullName.toLowerCase().includes(q) ||
				(r.description ?? "").toLowerCase().includes(q) ||
				(r.primaryLanguage ?? "").toLowerCase().includes(q),
		);
	}, [githubRepos, filter]);

	function toggleRepo(fullName: string) {
		setSelected((prev) => {
			const next = new Set(prev);
			if (next.has(fullName)) next.delete(fullName);
			else next.add(fullName);
			return next;
		});
	}

	// Select all untracked repos from the filtered list
	function selectAllUntracked() {
		setSelected((prev) => {
			const next = new Set(prev);
			for (const r of filteredRepos) {
				if (!trackedRepos.has(r.fullName) && !r.archived) {
					next.add(r.fullName);
				}
			}
			return next;
		});
	}

	function clearSelection() {
		setSelected(new Set());
	}

	async function handleAdd() {
		if (selected.size === 0) return;
		setPhase("linking");
		setScanError(null);

		try {
			// Build repo specs from selected GitHub repos
			const specs = Array.from(selected)
				.map((fullName) => githubRepos?.find((r) => r.fullName === fullName))
				.filter((r): r is GithubRepo => !!r)
				.map((r) => ({
					fullName: r.fullName,
					provider: "github" as const,
					defaultBranch: r.defaultBranch,
					primaryLanguage: r.primaryLanguage,
					visibility: r.visibility,
				}));

			const res = await addRepository({ tenantSlug, repos: specs });
			setResults(res.added);

			// Dispatch scans for created + revived repos
			const toScan = res.added.filter(
				(r) => r.status === "created" || r.status === "revived",
			);
			for (const r of toScan) {
				try {
					await dispatchScan({
						tenantSlug,
						repositoryFullName: r.fullName,
						scannerType: "full_scan",
					});
				} catch {
					// Scan failures are non-fatal — the repo is linked.
					// Surface a warning but keep going.
				}
			}

			setPhase("done");
		} catch (err) {
			setScanError(
				err instanceof Error
					? err.message
					: "Failed to add repositories. Please try again.",
			);
			setPhase("select");
		}
	}

	// GitHub not connected state
	const notConnected =
		githubConnection && !githubConnection.connected;

	return (
		<div
			className="fixed inset-0 z-50 flex items-center justify-center p-4"
			onClick={onClose}
		>
			{/* Backdrop */}
			<div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />

			{/* Modal */}
			<div
				className="relative w-full max-w-2xl max-h-[85vh] flex flex-col rounded-2xl border border-[var(--line)] bg-[var(--panel-bg,var(--surface))] shadow-2xl"
				onClick={(e) => e.stopPropagation()}
			>
				{/* Header */}
				<div className="flex items-center justify-between px-5 py-4 border-b border-[var(--line)]">
					<div className="flex items-center gap-2.5">
						<div className="w-8 h-8 rounded-lg bg-[var(--chip-bg)] flex items-center justify-center">
							<Plus size={16} className="text-[var(--signal)]" />
						</div>
						<div>
							<h2 className="text-base font-bold text-[var(--sea-ink)]">
								Add Repository
							</h2>
							<p className="text-xs text-[var(--sea-ink-soft)]">
								Link GitHub repositories to your workspace
							</p>
						</div>
					</div>
					<button
						type="button"
						className="p-1.5 rounded-lg hover:bg-[var(--chip-bg)] text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)] transition-colors"
						onClick={onClose}
						aria-label="Close"
					>
						<X size={18} />
					</button>
				</div>

				{/* Body */}
				<div className="flex-1 overflow-y-auto">
					{/* GitHub not connected */}
					{notConnected && (
						<div className="p-6">
							<div className="flex flex-col items-center text-center gap-3">
								<div className="w-14 h-14 rounded-2xl bg-[var(--chip-bg)] flex items-center justify-center">
									<Github size={28} className="text-[var(--sea-ink)]" />
								</div>
								<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
									Connect GitHub first
								</h3>
								<p className="text-xs text-[var(--sea-ink-soft)] max-w-sm">
									Link your GitHub account to browse and add your repositories.
								</p>
								<a
									href="/connect/github"
									className="signal-button mt-1"
								>
									Connect GitHub
									<ArrowRight size={14} />
								</a>
							</div>
						</div>
					)}

					{/* Select repos phase */}
					{!notConnected && phase === "select" && (
						<>
							{/* Search + filter bar */}
							<div className="px-5 py-3 border-b border-[var(--line)] space-y-2">
								<div className="flex items-center gap-2">
									<div className="relative flex-1">
										<Search
											size={14}
											className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--sea-ink-soft)]"
										/>
										<input
											type="text"
											className="input-field w-full pl-9"
											placeholder="Search repositories..."
											value={filter}
											onChange={(e) => setFilter(e.target.value)}
											autoFocus
										/>
									</div>
								</div>
								<div className="flex items-center justify-between">
									<span className="text-xs text-[var(--sea-ink-soft)]">
										{githubConnection?.login
											? `@${githubConnection.login}`
											: "GitHub"}
										{githubRepos
											? ` · ${githubRepos.length} repos`
											: ""}
										{selected.size > 0 && ` · ${selected.size} selected`}
									</span>
									<div className="flex gap-2">
										<button
											type="button"
											className="text-xs text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
											onClick={selectAllUntracked}
										>
											Select all untracked
										</button>
										{selected.size > 0 && (
											<button
												type="button"
												className="text-xs text-[var(--sea-ink-soft)] hover:text-[var(--warning)] transition-colors"
												onClick={clearSelection}
											>
												Clear
											</button>
										)}
									</div>
								</div>
							</div>

							{/* Repo list */}
							{reposLoading && (
								<div className="flex items-center justify-center gap-2 py-12 text-sm text-[var(--sea-ink-soft)]">
									<Loader2 size={16} className="animate-spin" />
									Loading repositories...
								</div>
							)}

							{reposError && (
								<div className="m-5 rounded-lg border border-[var(--danger,var(--error,red))] bg-red-50 dark:bg-red-950/20 px-4 py-3 text-sm text-red-700 dark:text-red-400">
									<div className="flex items-start gap-2">
										<AlertCircle size={14} className="mt-0.5 shrink-0" />
										<span>{reposError}</span>
									</div>
								</div>
							)}

							{!reposLoading && !reposError && githubRepos && (
								<div className="divide-y divide-[var(--line)]">
									{filteredRepos.length === 0 && (
										<div className="py-12 text-center text-sm text-[var(--sea-ink-soft)]">
											{filter
												? "No repositories match your search."
												: "No repositories found."}
										</div>
									)}
									{filteredRepos.map((repo) => {
										const isSelected = selected.has(repo.fullName);
										const isTracked = trackedRepos.has(repo.fullName);
										return (
											<button
												key={repo.id}
												type="button"
												className={`w-full flex items-center gap-3 px-5 py-3 text-left transition-colors ${
													isSelected
														? "bg-[rgba(158,255,100,0.08)]"
														: "hover:bg-[var(--chip-bg)]"
												}`}
												onClick={() => !repo.archived && toggleRepo(repo.fullName)}
												disabled={repo.archived}
											>
												{/* Checkbox */}
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

												<GitBranch
													size={14}
													className="text-[var(--sea-ink-soft)] shrink-0"
												/>

												<div className="min-w-0 flex-1">
													<div className="text-sm font-medium text-[var(--sea-ink)] truncate">
														{repo.fullName}
													</div>
													{repo.description && (
														<div className="text-xs text-[var(--sea-ink-soft)] truncate">
															{repo.description}
														</div>
													)}
													<div className="flex flex-wrap items-center gap-2 mt-0.5 text-xs text-[var(--sea-ink-soft)]">
														{repo.primaryLanguage && (
															<span>{repo.primaryLanguage}</span>
														)}
														{repo.primaryLanguage && <span>·</span>}
														<span>{repo.visibility}</span>
														{repo.fork && (
															<>
																<span>·</span>
																<span>fork</span>
															</>
														)}
														{repo.archived && (
															<>
																<span>·</span>
																<span className="text-[var(--warning)]">archived</span>
															</>
														)}
													</div>
												</div>

												{isTracked && !isSelected && (
													<StatusPill label="tracked" tone="success" />
												)}
											</button>
										);
									})}
								</div>
							)}
						</>
					)}

					{/* Linking phase */}
					{phase === "linking" && (
						<div className="flex flex-col items-center justify-center gap-3 py-16">
							<Loader2 size={28} className="animate-spin text-[var(--signal)]" />
							<p className="text-sm text-[var(--sea-ink-soft)]">
								Linking {selected.size} repositor{selected.size === 1 ? "y" : "ies"} and dispatching scans...
							</p>
						</div>
					)}

					{/* Done phase */}
					{phase === "done" && results && (
						<div className="p-6">
							<div className="flex flex-col items-center text-center gap-2 mb-5">
								<div className="w-14 h-14 rounded-2xl bg-green-100 dark:bg-green-950/30 flex items-center justify-center">
									<CheckCircle2
										size={28}
										className="text-green-600"
									/>
								</div>
								<h3 className="text-sm font-semibold text-[var(--sea-ink)]">
									Repositories Added
								</h3>
								<p className="text-xs text-[var(--sea-ink-soft)] max-w-sm">
									Scans have been dispatched for newly linked repositories.
								</p>
							</div>

							{/* Per-repo results */}
							<div className="space-y-1.5">
								{results.map((r) => (
									<div
										key={r.repositoryId}
										className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--chip-bg)]"
									>
										{r.status === "created" && (
											<Plus size={14} className="text-[var(--signal)] shrink-0" />
										)}
										{r.status === "revived" && (
											<RotateCw
												size={14}
												className="text-[var(--signal)] shrink-0"
											/>
										)}
										{r.status === "already_active" && (
											<CheckCircle2
												size={14}
												className="text-[var(--sea-ink-soft)] shrink-0"
											/>
										)}
										<span className="text-sm text-[var(--sea-ink)] truncate flex-1">
											{r.fullName}
										</span>
										<StatusPill
											label={
												r.status === "created"
													? "added"
													: r.status === "revived"
														? "revived"
														: "already tracked"
											}
											tone={
												r.status === "already_active" ? "neutral" : "success"
											}
										/>
									</div>
								))}
							</div>
						</div>
					)}
				</div>

				{/* Footer */}
				{phase === "select" && (
					<div className="flex items-center justify-between px-5 py-3 border-t border-[var(--line)]">
						{scanError ? (
							<span className="text-xs text-red-600 dark:text-red-400">
								{scanError}
							</span>
						) : (
							<span className="text-xs text-[var(--sea-ink-soft)]">
								{selected.size > 0
									? `${selected.size} repositor${selected.size === 1 ? "y" : "ies"} selected`
									: "Select repositories to add"}
							</span>
						)}
						<div className="flex gap-2">
							<button
								type="button"
								className="secondary-button"
								onClick={onClose}
							>
								Cancel
							</button>
							<button
								type="button"
								className="signal-button"
								onClick={handleAdd}
								disabled={selected.size === 0}
							>
								Add {selected.size > 0 && `(${selected.size})`}
								<ArrowRight size={14} />
							</button>
						</div>
					</div>
				)}

				{phase === "done" && (
					<div className="flex justify-end gap-2 px-5 py-3 border-t border-[var(--line)]">
						<button
							type="button"
							className="signal-button"
							onClick={onClose}
						>
							Done
						</button>
					</div>
				)}
			</div>
		</div>
	);
}
