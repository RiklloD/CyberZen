import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Key, Plus, RefreshCw, Trash2, X, Copy, AlertTriangle, BarChart3 } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/api-keys")({
	errorComponent: QueryErrorFallback,
	component: ApiKeysPage });

const AVAILABLE_SCOPES = [
	"findings:read",
	"findings:write",
	"repositories:read",
	"repositories:write",
	"audit:read",
	"compliance:read",
	"sbom:read",
	"webhooks:write",
];

function ApiKeysPage() {
	const TENANT = useTenantSlug();
	const [modalOpen, setModalOpen] = useState(false);
	const [revealData, setRevealData] = useState<{
		secret: string;
		name: string;
	} | null>(null);

	const keys = useQuery(
		api.apiKeys.listApiKeys,
		{ tenantSlug: TENANT },
	);

	const currentUser = useQuery(api.workspaceAuth.currentWorkspace);

	const currentUserCanAdmin =
		currentUser?.workspaces?.some(
			(w: { tenantSlug: string; role: string }) => w.tenantSlug === TENANT && (w.role === "owner" || w.role === "admin"),
		) ?? false;

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Key size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">API Keys</h1>
						<p className="page-subtitle">
							Manage API keys for programmatic access
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				<div className="section-header mb-3">
					<h2 className="section-title">Keys</h2>
					{keys && (
						<StatusPill
							label={`${keys.length} key${keys.length !== 1 ? "s" : ""}`}
							tone="neutral"
						/>
					)}
					{currentUserCanAdmin && (
						<button
							type="button"
							onClick={() => setModalOpen(true)}
							className="signal-button ml-auto"
							style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
						>
							<Plus size={14} className="mr-1" />
							Create Key
						</button>
					)}
				</div>

				{keys ? (
					<ApiKeyList
						keys={keys}
						tenantSlug={TENANT}
						currentUserCanAdmin={currentUserCanAdmin}
					/>
				) : (
					<div className="space-y-2">
						{["a", "b", "c"].map((k) => (
							<div key={k} className="loading-panel h-14 rounded-2xl" />
						))}
					</div>
				)}
			</div>

			{modalOpen && currentUserCanAdmin && (
				<CreateApiKeyModal
					tenantSlug={TENANT}
					onClose={() => setModalOpen(false)}
					onCreated={(secret, name) => setRevealData({ secret, name })}
				/>
			)}

			{revealData && (
				<SecretRevealModal
					secret={revealData.secret}
					name={revealData.name}
					onClose={() => setRevealData(null)}
				/>
			)}

			{/* §6.28 API Rate Limiting — Usage Panel */}
			{currentUserCanAdmin && (
				<ApiUsagePanel tenantSlug={TENANT} />
			)}
		</main>
	);
}

// ─── ApiKeyList ─────────────────────────────────────────────────────────────

type ApiKey = {
	_id: string;
	name: string;
	prefix: string;
	scopes: string[];
	lastUsedAt?: number;
	expiresAt?: number;
	revokedAt?: number;
	createdAt: number;
};

interface ApiKeyListProps {
	keys: ApiKey[];
	tenantSlug: string;
	currentUserCanAdmin: boolean;
}

function ApiKeyList({ keys, tenantSlug, currentUserCanAdmin }: ApiKeyListProps) {
	const [isPending, startTransition] = useTransition();
	const [rotatingId, setRotatingId] = useState<string | null>(null);
	const [rotatedSecret, setRotatedSecret] = useState<{
		secret: string;
		name: string;
	} | null>(null);

	const revokeKey = useMutation(api.apiKeys.revokeApiKey);
	const rotateKey = useMutation(api.apiKeys.rotateApiKey);

	function handleRevoke(keyId: string, name: string) {
		if (!confirm(`Revoke API key "${name}"? This action cannot be undone.`)) return;
		startTransition(async () => {
			await revokeKey({ tenantSlug, keyId: keyId as any });
		});
	}

	function handleRotate(keyId: string) {
		setRotatingId(keyId);
		startTransition(async () => {
			const result = await rotateKey({
				tenantSlug,
				keyId: keyId as any });
			setRotatingId(null);
			setRotatedSecret({ secret: result.secret, name: result.name });
		});
	}

	return (
		<>
			<div className="space-y-2">
				{keys.map((key) => {
					const isRevoked = !!key.revokedAt;
					const isExpired = key.expiresAt ? key.expiresAt < Date.now() : false;
					const isRotating = rotatingId === key._id;

					return (
						<div key={key._id} className="card card-sm">
							<div className="flex items-center justify-between gap-3">
								<div className="flex items-center gap-3 min-w-0">
									<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
										<Key size={14} className="text-[var(--signal)]" />
									</div>
									<div className="min-w-0">
										<div className="flex items-center gap-2">
											<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
												{key.name}
											</p>
											{isRevoked && (
												<StatusPill label="revoked" tone="danger" />
											)}
											{isExpired && !isRevoked && (
												<StatusPill label="expired" tone="warning" />
											)}
											{!isRevoked && !isExpired && (
												<StatusPill label="active" tone="success" />
											)}
										</div>
										<p className="text-xs text-[var(--sea-ink-soft)]">
											<code className="bg-[var(--surface)] px-1 rounded text-[0.7rem]">
												{key.prefix}••••••••
											</code>
											{key.lastUsedAt && (
												<span className="ml-2">
													Last used{" "}
													{new Date(key.lastUsedAt).toLocaleDateString()}
												</span>
											)}
										</p>
										<div className="flex gap-1 mt-1 flex-wrap">
											{key.scopes.map((s) => (
												<StatusPill key={s} label={s} tone="neutral" />
											))}
										</div>
									</div>
								</div>

								{currentUserCanAdmin && !isRevoked && (
									<div className="flex items-center gap-1.5 flex-shrink-0">
										<button
											type="button"
											disabled={isPending || isRotating}
											onClick={() => handleRotate(key._id)}
											className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--signal)] hover:bg-[var(--signal)]/10 transition-colors disabled:opacity-40"
											title="Rotate key"
										>
											<RefreshCw
												size={14}
												className={isRotating ? "animate-spin" : ""}
											/>
										</button>
										<button
											type="button"
											disabled={isPending}
											onClick={() => handleRevoke(key._id, key.name)}
											className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
											title="Revoke key"
										>
											<Trash2 size={14} />
										</button>
									</div>
								)}
							</div>
						</div>
					);
				})}

				{keys.length === 0 && (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Key size={24} className="mb-2 opacity-40" />
						<p>No API keys yet. Create one to get started.</p>
					</div>
				)}
			</div>

			{rotatedSecret && (
				<SecretRevealModal
					secret={rotatedSecret.secret}
					name={rotatedSecret.name}
					onClose={() => setRotatedSecret(null)}
				/>
			)}
		</>
	);
}

// ─── CreateApiKeyModal ──────────────────────────────────────────────────────

interface CreateApiKeyModalProps {
	tenantSlug: string;
	onClose: () => void;
	onCreated: (secret: string, name: string) => void;
}

function CreateApiKeyModal({
	tenantSlug,
	onClose,
	onCreated }: CreateApiKeyModalProps) {
	const [name, setName] = useState("");
	const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
	const [expiresInDays, setExpiresInDays] = useState<number>(90);
	const [isPending, startTransition] = useTransition();

	const createKey = useMutation(api.apiKeys.createApiKey);

	function toggleScope(scope: string) {
		setSelectedScopes((prev) =>
			prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
		);
	}

	function handleCreate() {
		if (!name.trim() || selectedScopes.length === 0) return;
		startTransition(async () => {
			const now = Date.now();
			const expiresAt = expiresInDays > 0 ? now + expiresInDays * 24 * 60 * 60 * 1000 : undefined;
			const result = await createKey({
				tenantSlug,
				name: name.trim(),
				scopes: selectedScopes,
				expiresAt });
			onCreated(result.secret, result.name);
		});
	}

	return (
		<div className="drawer-overlay" onClick={onClose}>
			<div
				className="drawer-panel"
				onClick={(e) => e.stopPropagation()}
				style={{ maxWidth: "480px" }}
			>
				<div className="drawer-header">
					<h2 className="drawer-title">Create API Key</h2>
					<button type="button" onClick={onClose} className="drawer-close">
						<X size={18} />
					</button>
				</div>

				<div className="drawer-body space-y-4">
					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							Key Name
						</label>
						<input
							type="text"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="e.g. CI/CD Pipeline"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							Expires In
						</label>
						<select
							value={expiresInDays}
							onChange={(e) => setExpiresInDays(Number(e.target.value))}
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						>
							<option value={30}>30 days</option>
							<option value={90}>90 days</option>
							<option value={180}>180 days</option>
							<option value={365}>1 year</option>
							<option value={0}>Never</option>
						</select>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Scopes
						</label>
						<div className="grid grid-cols-2 gap-2">
							{AVAILABLE_SCOPES.map((scope) => {
								const isSelected = selectedScopes.includes(scope);
								return (
									<button
										key={scope}
										type="button"
										onClick={() => toggleScope(scope)}
										className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs transition-colors text-left ${
											isSelected
												? "border-[var(--signal)] bg-[var(--signal)]/10 text-[var(--signal)]"
												: "border-[var(--line)] bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:border-[var(--signal)]/40"
										}`}
									>
										{isSelected ? (
											<div className="w-3 h-3 rounded border border-current flex items-center justify-center">
												<div className="w-1.5 h-1.5 rounded-sm bg-current" />
											</div>
										) : (
											<div className="w-3 h-3 rounded border border-[var(--line)]" />
										)}
										<span className="truncate">{scope}</span>
									</button>
								);
							})}
						</div>
					</div>
				</div>

				<div className="drawer-footer">
					<button
						type="button"
						onClick={onClose}
						className="secondary-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Cancel
					</button>
					<button
						type="button"
						onClick={handleCreate}
						disabled={isPending || !name.trim() || selectedScopes.length === 0}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						{isPending ? "Creating..." : "Create Key"}
					</button>
				</div>
			</div>
		</div>
	);
}

// ─── SecretRevealModal ──────────────────────────────────────────────────────

function SecretRevealModal({
	secret,
	name,
	onClose }: {
	secret: string;
	name: string;
	onClose: () => void;
}) {
	const [copied, setCopied] = useState(false);

	function handleCopy() {
		navigator.clipboard.writeText(secret).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		});
	}

	return (
		<div className="drawer-overlay" onClick={onClose}>
			<div
				className="drawer-panel"
				onClick={(e) => e.stopPropagation()}
				style={{ maxWidth: "520px" }}
			>
				<div className="drawer-header">
					<h2 className="drawer-title">API Key Created</h2>
					<button type="button" onClick={onClose} className="drawer-close">
						<X size={18} />
					</button>
				</div>

				<div className="drawer-body space-y-4">
					<div className="flex items-start gap-3 p-3 rounded-lg bg-[var(--warning)]/10 border border-[var(--warning)]/30">
						<AlertTriangle size={18} className="text-[var(--warning)] flex-shrink-0 mt-0.5" />
						<p className="text-sm text-[var(--warning)]">
							Copy this key now. You won't be able to see it again.
						</p>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
							{name}
						</label>
						<div className="flex items-center gap-2">
							<code className="flex-1 bg-[var(--surface)] border border-[var(--line)] rounded-lg px-3 py-2 text-xs text-[var(--sea-ink)] font-mono break-all">
								{secret}
							</code>
							<button
								type="button"
								onClick={handleCopy}
								className="p-2 rounded-lg border border-[var(--line)] hover:bg-[var(--signal)]/10 hover:border-[var(--signal)]/40 transition-colors"
								title="Copy to clipboard"
							>
								<Copy size={14} className={copied ? "text-[var(--success)]" : "text-[var(--sea-ink-soft)]"} />
							</button>
						</div>
					</div>
				</div>

				<div className="drawer-footer">
					<button
						type="button"
						onClick={onClose}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						Done
					</button>
				</div>
			</div>
		</div>
	);
}

// ─── §6.28 ApiUsagePanel ──────────────────────────────────────────────────

function ApiUsagePanel({ tenantSlug }: { tenantSlug: string }) {
	const usage = useQuery(
		api.apiKeys.getApiKeyUsage,
		{ tenantSlug },
	);

	return (
		<div className="mt-8">
			<div className="section-header mb-3">
				<BarChart3 size={16} className="text-[var(--signal)]" />
				<h2 className="section-title ml-2">API Usage &amp; Rate Limits</h2>
			</div>

			{!usage ? (
				<div className="space-y-2">
					{["a", "b"].map((k) => (
						<div key={k} className="loading-panel h-16 rounded-2xl" />
					))}
				</div>
			) : usage.length === 0 ? (
				<div className="card card-sm p-4 text-center">
					<BarChart3 size={20} className="mx-auto mb-1 opacity-40" />
					<p className="text-sm text-[var(--sea-ink-soft)]">No API usage data yet</p>
				</div>
			) : (
				<div className="space-y-2">
					{usage.map((item: any) => {
						const hourlyPct = Math.min(
							Math.round((item.hourlyRequests / item.rateLimitPerHour) * 100),
							100,
						);
						const barColor =
							hourlyPct > 90
								? "var(--danger)"
								: hourlyPct > 70
									? "var(--warning)"
									: "var(--success)";

						return (
							<div key={item.keyId} className="card card-sm">
								<div className="flex items-center justify-between gap-3 px-1">
									<div className="min-w-0 flex-1">
										<div className="flex items-center gap-2 mb-1">
											<span className="text-sm font-medium text-[var(--sea-ink)] truncate">
												{item.name}
											</span>
											<code className="text-[0.65rem] text-[var(--sea-ink-soft)] bg-[var(--surface)] px-1 rounded">
												{item.prefix}••••
											</code>
											{item.isRevoked && (
												<StatusPill label="revoked" tone="danger" />
											)}
										</div>
										<div className="flex items-center gap-4 text-xs text-[var(--sea-ink-soft)]">
											<span>{item.hourlyRequests.toLocaleString()} req/hr</span>
											<span>{item.dailyRequests.toLocaleString()} req/day</span>
											{item.hourlyBlocked > 0 && (
												<span className="text-[var(--danger)]">
													{item.hourlyBlocked} blocked
												</span>
											)}
										</div>
										<div className="mt-2 h-1.5 rounded-full bg-[var(--surface)] overflow-hidden">
											<div
												className="h-full rounded-full transition-all"
												style={{
													width: `${hourlyPct}%`,
													backgroundColor: barColor }}
											/>
										</div>
										<p className="text-[0.6rem] text-[var(--sea-ink-soft)] mt-0.5">
											{hourlyPct}% of hourly limit ({item.rateLimitPerHour.toLocaleString()} req/hr)
										</p>
									</div>
								</div>
							</div>
						);
					})}
				</div>
			)}
		</div>
	);
}
