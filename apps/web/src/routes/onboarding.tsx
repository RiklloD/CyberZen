import { useAuthToken } from "@convex-dev/auth/react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation } from "convex/react";
import { Building2, Plus, Rocket, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import StatusPill from "../components/StatusPill";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

type RepoDraft = {
	id: string;
	fullName: string;
	provider: "github" | "gitlab";
	defaultBranch: string;
	primaryLanguage: string;
	visibility: "private" | "public";
};

type DeploymentMode = "cloud_saas" | "vpc_injection" | "on_prem";

type ProvisionResult = {
	tenantId: string;
	tenantSlug: string;
	tenantName: string;
	createdTenant: boolean;
	repositories: Array<{
		_id: string;
		fullName: string;
		provider: string;
		created: boolean;
		scanQueued: boolean;
		workflowRunId?: string;
		snapshotId?: string;
		componentCount?: number;
	}>;
};

type InviteResult = {
	token: string;
	inviteUrl: string;
	tenantSlug: string;
	tenantName: string;
	email: string;
	role: "owner" | "admin" | "member";
	expiresAt?: number;
};

type ImportSnapshotDraft = {
	rootPath?: string;
	sourceFiles: string[];
	components: Array<{
		name: string;
		version: string;
		ecosystem: string;
		layer: string;
		isDirect: boolean;
		sourceFile: string;
		dependents: string[];
		license?: string;
	}>;
};

export const Route = createFileRoute("/onboarding")({
	errorComponent: RouteErrorBoundary,
	component: OnboardingPage,
});

function humanizeSlug(slug: string) {
	return slug
		.split("-")
		.filter(Boolean)
		.map((part) => part[0]?.toUpperCase() + part.slice(1))
		.join(" ");
}

function createRepoDraft(overrides: Partial<RepoDraft> = {}): RepoDraft {
	return {
		id: `repo-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
		fullName: "",
		provider: "github",
		defaultBranch: "main",
		primaryLanguage: "TypeScript",
		visibility: "private",
		...overrides,
	};
}

function OnboardingPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken();
	const provisionWorkspace = useMutation(api.onboarding.provisionWorkspace);
	const createWorkspaceInvite = useMutation(
		api.workspaceAuth.createWorkspaceInvite,
	);
	const [companyName, setCompanyName] = useState(humanizeSlug(TENANT));
	const [deploymentMode, setDeploymentMode] =
		useState<DeploymentMode>("cloud_saas");
	const [repositories, setRepositories] = useState<RepoDraft[]>([
		createRepoDraft(),
	]);
	const [importSnapshotJson, setImportSnapshotJson] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<ProvisionResult | null>(null);
	const [inviteEmail, setInviteEmail] = useState("");
	const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
	const [inviteError, setInviteError] = useState<string | null>(null);
	const [inviteResult, setInviteResult] = useState<InviteResult | null>(null);
	const [isCreatingInvite, setIsCreatingInvite] = useState(false);
	const hasImportBundle = importSnapshotJson.trim().length > 0;

	function updateRepository(id: string, patch: Partial<RepoDraft>) {
		setRepositories((current) =>
			current.map((repo) => (repo.id === id ? { ...repo, ...patch } : repo)),
		);
	}

	function addRepository() {
		setRepositories((current) => [...current, createRepoDraft()]);
	}

	function removeRepository(id: string) {
		setRepositories((current) =>
			current.length === 1 ? current : current.filter((repo) => repo.id !== id),
		);
	}

	async function handleSubmit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setError(null);
		setIsSubmitting(true);

		try {
			const cleanedRepositories = repositories
				.map((repo) => ({
					fullName: repo.fullName.trim(),
					provider: repo.provider,
					defaultBranch: repo.defaultBranch.trim() || "main",
					primaryLanguage: repo.primaryLanguage.trim() || "TypeScript",
					visibility: repo.visibility,
				}))
				.filter((repo) => repo.fullName.length > 0);

			if (cleanedRepositories.length === 0) {
				throw new Error("Add at least one repository before continuing.");
			}

			let importSnapshot: ImportSnapshotDraft | undefined;
			const trimmedSnapshotJson = importSnapshotJson.trim();

			if (trimmedSnapshotJson.length > 0) {
				if (cleanedRepositories.length !== 1) {
					throw new Error(
						"Live SBOM import currently supports one repository at a time.",
					);
				}

				const parsed = JSON.parse(
					trimmedSnapshotJson,
				) as Partial<ImportSnapshotDraft> & {
					sourceFiles?: unknown;
					components?: unknown;
				};

				if (
					!Array.isArray(parsed.sourceFiles) ||
					!Array.isArray(parsed.components)
				) {
					throw new Error(
						"Snapshot JSON must include sourceFiles and components arrays.",
					);
				}

				importSnapshot = {
					rootPath:
						typeof parsed.rootPath === "string" ? parsed.rootPath : undefined,
					sourceFiles: parsed.sourceFiles.map((sourceFile) =>
						String(sourceFile),
					),
					components: parsed.components.map((component) => {
						if (component === null || typeof component !== "object") {
							throw new Error("Snapshot components must be objects.");
						}

						const value = component as Record<string, unknown>;

						return {
							name: String(value.name ?? ""),
							version: String(value.version ?? ""),
							ecosystem: String(value.ecosystem ?? ""),
							layer: String(value.layer ?? ""),
							isDirect: Boolean(value.isDirect),
							sourceFile: String(value.sourceFile ?? ""),
							dependents: Array.isArray(value.dependents)
								? value.dependents.map((dependent) => String(dependent))
								: [],
							license:
								typeof value.license === "string" ? value.license : undefined,
						};
					}),
				};
			}

			const primaryRepository = cleanedRepositories[0];
			const repositoriesForProvision = [
				{
					...primaryRepository,
					...(importSnapshot ? { importSnapshot } : {}),
				},
				...cleanedRepositories.slice(1),
			];

			const response = (await provisionWorkspace({
				authToken: authToken ?? "",
				tenantSlug: TENANT,
				companyName: companyName.trim(),
				deploymentMode,
				repositories: repositoriesForProvision,
			})) as ProvisionResult;

			setResult(response);
		} catch (err) {
			setError(
				err instanceof Error
					? err.message
					: "Could not provision the workspace.",
			);
		} finally {
			setIsSubmitting(false);
		}
	}

	async function handleInviteSubmit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!result) {
			return;
		}

		setInviteError(null);
		setIsCreatingInvite(true);

		try {
			const normalizedEmail = inviteEmail.trim();
			if (!normalizedEmail) {
				throw new Error("Enter a teammate email before sending an invite.");
			}

			const created = (await createWorkspaceInvite({
				authToken: authToken ?? "",
				tenantSlug: result.tenantSlug,
				email: normalizedEmail,
				role: inviteRole,
			})) as InviteResult;

			setInviteResult(created);
			setInviteEmail("");
		} catch (thrown) {
			setInviteError(
				thrown instanceof Error ? thrown.message : "Could not create invite.",
			);
		} finally {
			setIsCreatingInvite(false);
		}
	}

	const inviteLink =
		inviteResult && typeof window !== "undefined"
			? new URL(inviteResult.inviteUrl, window.location.origin).toString()
			: (inviteResult?.inviteUrl ?? null);

	const repoCount = repositories.filter(
		(repo) => repo.fullName.trim().length > 0,
	).length;

	return (
		<main className="page-body-padded">
			<section className="panel rounded-[2rem] px-6 py-8 sm:px-10 sm:py-10">
				<div className="flex flex-wrap items-center gap-3">
					<StatusPill label="first-run setup" tone="info" />
					<StatusPill label={`slug ${TENANT}`} tone="neutral" />
					<StatusPill
						label={hasImportBundle ? "live import" : "quick start"}
						tone={hasImportBundle ? "info" : "success"}
					/>
				</div>
				<h1 className="display-title mt-4 max-w-3xl text-4xl leading-[1.02] text-[var(--sea-ink)] sm:text-6xl">
					Create the company workspace, import real manifests, and start
					scanning immediately.
				</h1>
				<p className="mt-5 max-w-3xl text-base text-[var(--sea-ink-soft)] sm:text-lg">
					This setup screen provisions the tenant record for the current
					deployment, registers one or more repositories, and can ingest a live
					SBOM bundle from the existing `sbom:import` parser so the dashboard is
					populated from real manifest data instead of a synthetic kickoff.
				</p>
			</section>

			{result && (
				<section className="mt-6 panel rounded-[1.75rem] p-6">
					<div className="flex flex-wrap items-center gap-3">
						<StatusPill
							label={
								result.createdTenant ? "workspace created" : "workspace updated"
							}
							tone={result.createdTenant ? "success" : "info"}
						/>
						<StatusPill
							label={`${result.repositories.length} repos connected`}
							tone="neutral"
						/>
					</div>
					<h2 className="mt-3 text-2xl font-semibold text-[var(--sea-ink)]">
						{result.tenantName} is ready.
					</h2>
					<p className="mt-2 text-sm text-[var(--sea-ink-soft)]">
						{result.repositories.some((repo) => repo.snapshotId)
							? "We imported a live SBOM bundle for the primary repo and queued the downstream scanners from real manifest data."
							: "We queued a baseline scan for every repo you added. Real webhook pushes will keep the workspace fresh after this initial kickoff."}
					</p>

					<div className="mt-5 space-y-2">
						{result.repositories.map((repo) => (
							<div
								key={repo._id}
								className="inset-panel flex flex-wrap items-center gap-2"
							>
								<StatusPill
									label={repo.created ? "created" : "updated"}
									tone={repo.created ? "success" : "info"}
								/>
								<StatusPill
									label={repo.scanQueued ? "scan queued" : "scan skipped"}
									tone={repo.scanQueued ? "success" : "warning"}
								/>
								<span className="font-medium text-[var(--sea-ink)]">
									{repo.fullName}
								</span>
								{repo.snapshotId && (
									<StatusPill label="live import" tone="info" />
								)}
								{repo.componentCount !== undefined && (
									<StatusPill
										label={`${repo.componentCount} imported components`}
										tone="success"
									/>
								)}
								{repo.workflowRunId && (
									<span className="text-xs text-[var(--sea-ink-soft)]">
										run <code>{repo.workflowRunId.slice(0, 8)}</code>
									</span>
								)}
								{repo.snapshotId && (
									<span className="text-xs text-[var(--sea-ink-soft)]">
										snapshot <code>{repo.snapshotId.slice(0, 8)}</code>
									</span>
								)}
							</div>
						))}
					</div>

					<div className="mt-6 flex flex-wrap gap-3">
						<Link to="/" className="signal-button">
							Open dashboard
						</Link>
						<Link to="/integrations" className="signal-button secondary-button">
							Connect integrations
						</Link>
					</div>

					<div className="mt-6 rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] p-4">
						<div className="flex flex-wrap items-start justify-between gap-3">
							<div>
								<p className="panel-label">Teammates</p>
								<h3 className="text-lg font-semibold text-[var(--sea-ink)]">
									Invite a teammate
								</h3>
								<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
									Send a join link so another user can sign in and switch into
									this workspace.
								</p>
							</div>
							{inviteResult && (
								<StatusPill label="invite ready" tone="success" />
							)}
						</div>

						<form
							className="mt-4 grid gap-3 lg:grid-cols-[1.4fr_0.8fr_auto]"
							onSubmit={handleInviteSubmit}
						>
							<label className="block">
								<span className="mb-2 block text-xs font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
									Teammate email
								</span>
								<input
									value={inviteEmail}
									onChange={(event) => setInviteEmail(event.target.value)}
									className="w-full rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] px-4 py-3 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
									placeholder="sam@acme.com"
									type="email"
								/>
							</label>

							<label className="block">
								<span className="mb-2 block text-xs font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
									Role
								</span>
								<select
									value={inviteRole}
									onChange={(event) =>
										setInviteRole(event.target.value as "admin" | "member")
									}
									className="w-full rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] px-4 py-3 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
								>
									<option value="member">Member</option>
									<option value="admin">Admin</option>
								</select>
							</label>

							<button
								type="submit"
								className="signal-button h-fit self-end"
								disabled={isCreatingInvite}
							>
								{isCreatingInvite ? "Creating..." : "Create invite"}
							</button>
						</form>

						{inviteError && (
							<p className="mt-3 text-sm text-red-400">{inviteError}</p>
						)}

						{inviteResult && (
							<div className="mt-4 rounded-2xl border border-[var(--line)] bg-[var(--surface)] p-4">
								<p className="panel-label">Invite link</p>
								<div className="mt-2 flex flex-wrap items-center gap-2">
									<code className="break-all">{inviteLink}</code>
									<button
										type="button"
										className="signal-button secondary-button"
										onClick={async () => {
											if (!inviteLink) {
												return;
											}

											await navigator.clipboard.writeText(inviteLink);
										}}
									>
										Copy link
									</button>
								</div>
								<p className="mt-2 text-xs text-[var(--sea-ink-soft)]">
									{inviteResult.email} is invited as {inviteResult.role}.
								</p>
							</div>
						)}
					</div>
				</section>
			)}

			<div className="mt-6 grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
				<section className="panel rounded-[1.75rem] p-6">
					<div className="flex items-center gap-3">
						<span className="metric-icon">
							<Building2 size={14} />
						</span>
						<div>
							<p className="panel-label">Workspace</p>
							<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
								Company and repository onboarding
							</h2>
						</div>
					</div>

					<form className="mt-6 space-y-6" onSubmit={handleSubmit}>
						<div className="grid gap-4 sm:grid-cols-2">
							<label className="block">
								<span className="mb-2 block text-xs font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
									Company name
								</span>
								<input
									value={companyName}
									onChange={(event) => setCompanyName(event.target.value)}
									className="w-full rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] px-4 py-3 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
									placeholder="Acme Security"
								/>
							</label>

							<label className="block">
								<span className="mb-2 block text-xs font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
									Deployment mode
								</span>
								<select
									value={deploymentMode}
									onChange={(event) =>
										setDeploymentMode(event.target.value as DeploymentMode)
									}
									className="w-full rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] px-4 py-3 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
								>
									<option value="cloud_saas">Cloud SaaS</option>
									<option value="vpc_injection">VPC Injection</option>
									<option value="on_prem">On-prem</option>
								</select>
							</label>
						</div>

						<div>
							<div className="mb-3 flex items-center justify-between gap-3">
								<div>
									<p className="panel-label">Repositories</p>
									<p className="text-sm text-[var(--sea-ink-soft)]">
										Add every repo you want monitored. If you paste a live SBOM
										bundle below, the first repo will be seeded from real
										manifest data; otherwise we queue a sensible baseline from
										repo metadata.
									</p>
								</div>
								<p className="text-xs text-[var(--sea-ink-soft)]">
									{repoCount} connected
								</p>
							</div>

							<div className="space-y-3">
								{repositories.map((repo) => (
									<div
										key={repo.id}
										className="grid gap-3 rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] p-4 lg:grid-cols-[1.6fr_0.9fr_0.9fr_1fr_0.8fr_auto]"
									>
										<label className="block">
											<span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
												Full name
											</span>
											<input
												value={repo.fullName}
												onChange={(event) =>
													updateRepository(repo.id, {
														fullName: event.target.value,
													})
												}
												className="w-full rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] px-3 py-2.5 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
												placeholder="acme/payments-api"
											/>
										</label>

										<label className="block">
											<span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
												Provider
											</span>
											<select
												value={repo.provider}
												onChange={(event) =>
													updateRepository(repo.id, {
														provider: event.target
															.value as RepoDraft["provider"],
													})
												}
												className="w-full rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] px-3 py-2.5 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
											>
												<option value="github">GitHub</option>
												<option value="gitlab">GitLab</option>
											</select>
										</label>

										<label className="block">
											<span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
												Default branch
											</span>
											<input
												value={repo.defaultBranch}
												onChange={(event) =>
													updateRepository(repo.id, {
														defaultBranch: event.target.value,
													})
												}
												className="w-full rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] px-3 py-2.5 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
												placeholder="main"
											/>
										</label>

										<label className="block">
											<span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
												Language
											</span>
											<input
												value={repo.primaryLanguage}
												onChange={(event) =>
													updateRepository(repo.id, {
														primaryLanguage: event.target.value,
													})
												}
												className="w-full rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] px-3 py-2.5 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
												placeholder="TypeScript"
											/>
										</label>

										<label className="block">
											<span className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--sea-ink-soft)]">
												Visibility
											</span>
											<select
												value={repo.visibility}
												onChange={(event) =>
													updateRepository(repo.id, {
														visibility: event.target
															.value as RepoDraft["visibility"],
													})
												}
												className="w-full rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] px-3 py-2.5 text-sm text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
											>
												<option value="private">Private</option>
												<option value="public">Public</option>
											</select>
										</label>

										<div className="flex items-end">
											<button
												type="button"
												onClick={() => removeRepository(repo.id)}
												disabled={repositories.length === 1}
												className="signal-button secondary-button w-full justify-center"
												style={{
													padding: "0.74rem 0.9rem",
													fontSize: "0.8rem",
												}}
											>
												<Trash2 size={14} className="mr-1.5" />
												Remove
											</button>
										</div>
									</div>
								))}
							</div>

							<button
								type="button"
								onClick={addRepository}
								className="signal-button secondary-button mt-3"
								style={{ padding: "0.74rem 0.95rem", fontSize: "0.82rem" }}
							>
								<Plus size={14} className="mr-1.5" />
								Add repository
							</button>
						</div>

						<div className="rounded-2xl border border-[var(--line)] bg-[var(--bg-panel)] p-4">
							<div className="flex flex-wrap items-center justify-between gap-3">
								<div>
									<p className="panel-label">Optional live import</p>
									<p className="mt-1 text-sm text-[var(--sea-ink-soft)]">
										Paste the JSON emitted by `bun run sbom:import --{" "}
										<code>&lt;repo-path&gt;</code> ...` or a CI artifact. If
										present, the first repository below will be imported from
										real manifest data instead of the demo push fallback.
									</p>
								</div>
								<StatusPill label="sbom bundle" tone="info" />
							</div>
							<textarea
								value={importSnapshotJson}
								onChange={(event) => setImportSnapshotJson(event.target.value)}
								className="mt-4 min-h-[160px] w-full rounded-2xl border border-[var(--line)] bg-[var(--surface-strong)] px-4 py-3 font-mono text-xs text-[var(--sea-ink)] outline-none transition focus:border-[var(--accent-line)] focus:ring-2 focus:ring-[rgba(47,207,132,0.14)]"
								placeholder={`{
  "rootPath": "C:/repos/payments-api",
  "sourceFiles": ["package.json", "pnpm-lock.yaml"],
  "components": [...]
}`}
							/>
							<p className="mt-3 text-xs text-[var(--sea-ink-soft)]">
								Import mode currently supports one repository at a time.
							</p>
						</div>

						{error && (
							<div className="rounded-2xl border border-[rgba(220,38,38,0.22)] bg-[rgba(220,38,38,0.08)] px-4 py-3 text-sm text-[var(--danger)]">
								{error}
							</div>
						)}

						<div className="flex flex-wrap items-center gap-3">
							<button
								type="submit"
								disabled={isSubmitting}
								className="signal-button"
								style={{ padding: "0.85rem 1.1rem", fontSize: "0.88rem" }}
							>
								<Rocket size={15} className="mr-2" />
								{isSubmitting
									? hasImportBundle
										? "Importing bundle..."
										: "Provisioning..."
									: hasImportBundle
										? "Import bundle & start scanning"
										: "Create company & start scanning"}
							</button>
							<p className="text-xs text-[var(--sea-ink-soft)]">
								{hasImportBundle
									? "This uses the live SBOM bundle you pasted and then fans out into the existing downstream scans."
									: "This queues a baseline push-style scan for each repo using the existing Convex pipeline."}
							</p>
						</div>
					</form>
				</section>

				<aside className="space-y-4">
					<section className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">What this does</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Provision the workspace in one pass.
						</h2>
						<ul className="mt-4 space-y-3 text-sm text-[var(--sea-ink-soft)]">
							<li>
								Creates or updates the tenant record for this deployment slug.
							</li>
							<li>Registers the repositories you entered under that tenant.</li>
							<li>
								Queues a first scan through the same push-ingest path the
								webhooks use.
							</li>
							<li>
								Leaves the workspace ready for real push events and CI triggers.
							</li>
						</ul>
					</section>

					<section className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Deployment slug</p>
						<p className="text-sm text-[var(--sea-ink-soft)]">
							This app is configured for the current customer workspace slug:
						</p>
						<div className="mt-3 inline-flex items-center rounded-full border border-[var(--line)] bg-[var(--surface-strong)] px-3 py-1.5 text-sm font-semibold text-[var(--sea-ink)]">
							<code>{TENANT}</code>
						</div>
						<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
							After onboarding, use the dashboard and integrations screen to
							wire in GitHub, GitLab, CircleCI, or whatever stack the customer
							actually uses.
						</p>
					</section>

					<section className="panel rounded-[1.75rem] p-6">
						<p className="island-kicker mb-2">Next step</p>
						<h2 className="text-2xl font-semibold text-[var(--sea-ink)]">
							Connect live webhooks.
						</h2>
						<p className="mt-3 text-sm text-[var(--sea-ink-soft)]">
							The onboarding flow now supports both a fast demo kickoff and a
							live SBOM bundle import. Once the customer connects repo webhooks,
							every new push will keep the scanners and findings current.
						</p>
						<div className="mt-5">
							<Link
								to="/integrations"
								className="signal-button secondary-button"
							>
								View integrations
							</Link>
						</div>
					</section>
				</aside>
			</div>
		</main>
	);
}
