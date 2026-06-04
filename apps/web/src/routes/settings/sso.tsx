import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "@convex-dev/auth/react";
import { useMutation, useQuery } from "convex/react";
import {
	Shield,
	Plus,
	Trash2,
	Upload,
	X,
	Copy,
} from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import RouteErrorBoundary from "../../components/RouteErrorBoundary";

export const Route = createFileRoute("/settings/sso")({
	errorComponent: RouteErrorBoundary,
	component: SsoPage,
});

function SsoPage() {
	const TENANT = useTenantSlug();
	const authToken = useAuthToken() ?? "";
	const [createOpen, setCreateOpen] = useState(false);

	const configs = useQuery(
		api.sso.listSsoConfigs,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	const acsInfo = useQuery(
		api.sso.getAcsUrl,
		authToken ? { authToken, tenantSlug: TENANT } : "skip",
	);

	return (
		<main>
			<div className="page-header">
				<div className="flex items-center gap-3">
					<Shield size={20} className="text-[var(--signal)]" />
					<div>
						<h1 className="page-title">SSO / SAML Configuration</h1>
						<p className="page-subtitle">
							Manage SAML and OIDC identity provider connections
						</p>
					</div>
				</div>
			</div>

			<div className="page-body">
				{/* ACS URL Display */}
				{acsInfo && (
					<div className="card card-sm mb-4 p-4">
						<h3 className="text-xs font-semibold text-[var(--sea-ink)] mb-2">
							Service Provider Details
						</h3>
						<div className="space-y-2">
							<AcsUrlRow label="ACS URL" value={acsInfo.acsUrl} />
							<AcsUrlRow label="Entity ID" value={acsInfo.entityId} />
							<AcsUrlRow label="Audience" value={acsInfo.audience} />
						</div>
					</div>
				)}

				<div className="section-header mb-3">
					<h2 className="section-title">Identity Providers</h2>
					{configs && (
						<StatusPill
							label={`${configs.length} config${configs.length !== 1 ? "s" : ""}`}
							tone="neutral"
						/>
					)}
					<button
						type="button"
						onClick={() => setCreateOpen(true)}
						className="signal-button ml-auto"
						style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
					>
						<Plus size={14} className="mr-1" />
						Add Provider
					</button>
				</div>

				{!configs ? (
					<div className="space-y-2">
						{["a", "b"].map((k) => (
							<div key={k} className="loading-panel h-20 rounded-2xl" />
						))}
					</div>
				) : configs.length === 0 ? (
					<div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
						<Shield size={24} className="mb-2 opacity-40" />
						<p>No SSO providers configured. Add one to get started.</p>
					</div>
				) : (
					<div className="space-y-2">
						{configs.map((config: any) => (
							<SsoConfigCard
								key={config._id}
								config={config}
								authToken={authToken}
								tenantSlug={TENANT}
							/>
						))}
					</div>
				)}
			</div>

			{createOpen && (
				<CreateSsoModal
					authToken={authToken}
					tenantSlug={TENANT}
					onClose={() => setCreateOpen(false)}
				/>
			)}
		</main>
	);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function AcsUrlRow({ label, value }: { label: string; value: string }) {
	const [copied, setCopied] = useState(false);

	return (
		<div className="flex items-center gap-2">
			<span className="text-xs text-[var(--sea-ink-soft)] w-20 flex-shrink-0">{label}</span>
			<code className="flex-1 bg-[var(--surface)] border border-[var(--line)] rounded px-2 py-1 text-xs text-[var(--sea-ink)] font-mono truncate">
				{value}
			</code>
			<button
				type="button"
				onClick={() => {
					navigator.clipboard.writeText(value);
					setCopied(true);
					setTimeout(() => setCopied(false), 2000);
				}}
				className="p-1 rounded hover:bg-[var(--surface)] transition-colors"
			>
				<Copy size={12} className={copied ? "text-[var(--success)]" : "text-[var(--sea-ink-soft)]"} />
			</button>
		</div>
	);
}

function SsoConfigCard({
	config,
	authToken,
	tenantSlug,
}: {
	config: any;
	authToken: string;
	tenantSlug: string;
}) {
	const [isPending, startTransition] = useTransition();
	const deleteConfig = useMutation(api.sso.deleteSsoConfig);

	function handleDelete() {
		if (!confirm(`Delete SSO provider "${config.displayName}"?`)) return;
		startTransition(async () => {
			await deleteConfig({ authToken, tenantSlug, configId: config._id });
		});
	}

	return (
		<div className="card card-sm">
			<div className="flex items-center justify-between gap-3">
				<div className="flex items-center gap-3 min-w-0">
					<div className="flex-shrink-0 w-8 h-8 rounded-full bg-[var(--surface)] border border-[var(--line)] flex items-center justify-center">
						<Shield size={14} className="text-[var(--signal)]" />
					</div>
					<div className="min-w-0">
						<div className="flex items-center gap-2">
							<p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
								{config.displayName}
							</p>
							<StatusPill label={config.protocol.toUpperCase()} tone="neutral" />
							{config.enabled ? (
								<StatusPill label="enabled" tone="success" />
							) : (
								<StatusPill label="disabled" tone="warning" />
							)}
							{config.enforced && <StatusPill label="enforced" tone="danger" />}
						</div>
						<p className="text-xs text-[var(--sea-ink-soft)]">
							Default role: {config.defaultRole} • Created{" "}
							{new Date(config.createdAt).toLocaleDateString()}
							{config.lastTestedAt && (
								<> • Last tested: {new Date(config.lastTestedAt).toLocaleDateString()}</>
							)}
						</p>
					</div>
				</div>
				<button
					type="button"
					onClick={handleDelete}
					disabled={isPending}
					className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
					title="Delete provider"
				>
					<Trash2 size={14} />
				</button>
			</div>
		</div>
	);
}

function validateMetadataXml(xml: string): string | null {
	if (!xml.trim()) return null;
	if (/<!DOCTYPE/i.test(xml)) return "Metadata XML must not contain DOCTYPE declarations.";
	if (/<!ENTITY/i.test(xml)) return "Metadata XML must not contain ENTITY declarations.";
	try {
		const doc = new DOMParser().parseFromString(xml, "application/xml");
		const parseError = doc.querySelector("parsererror");
		if (parseError) return "Metadata XML is not well-formed XML.";
	} catch {
		return "Unable to parse metadata XML.";
	}
	if (!xml.includes("entityID")) return 'Metadata XML must contain an "entityID" attribute.';
	return null;
}

function CreateSsoModal({
	authToken,
	tenantSlug,
	onClose,
}: {
	authToken: string;
	tenantSlug: string;
	onClose: () => void;
}) {
	const [protocol, setProtocol] = useState<"saml" | "oidc">("saml");
	const [displayName, setDisplayName] = useState("");
	const [entityId, setEntityId] = useState("");
	const [ssoUrl, setSsoUrl] = useState("");
	const [certificate, setCertificate] = useState("");
	const [metadataXml, setMetadataXml] = useState("");
	const [fieldError, setFieldError] = useState<string | null>(null);
	const [isPending, startTransition] = useTransition();
	const createConfig = useMutation(api.sso.createSsoConfig);

	function handleCreate() {
		if (!displayName.trim()) return;
		setFieldError(null);

		if (protocol === "saml") {
			const xmlError = validateMetadataXml(metadataXml);
			if (xmlError) { setFieldError(xmlError); return; }

			if (!metadataXml.trim()) {
				if (!entityId.trim()) { setFieldError("Entity ID is required."); return; }
				if (!ssoUrl.trim()) { setFieldError("SSO URL is required."); return; }
				try {
					const u = new URL(ssoUrl);
					if (u.protocol !== "https:") { setFieldError("SSO URL must use HTTPS."); return; }
				} catch {
					setFieldError("SSO URL is not a valid URL."); return;
				}
			}
		}

		startTransition(async () => {
			try {
				await createConfig({
					authToken,
					tenantSlug,
					protocol,
					displayName: displayName.trim(),
					enabled: false,
					enforced: false,
					defaultRole: "member",
					samlEntityId: protocol === "saml" ? entityId : undefined,
					samlSsoUrl: protocol === "saml" ? ssoUrl : undefined,
					samlCertificate: protocol === "saml" ? certificate : undefined,
					samlMetadataXml: protocol === "saml" ? metadataXml || undefined : undefined,
				});
				onClose();
			} catch (err) {
				setFieldError(err instanceof Error ? err.message : "Failed to create SSO provider.");
			}
		});
	}

	return (
		<div className="drawer-overlay" onClick={onClose}>
			<div className="drawer-panel" style={{ maxWidth: "540px" }} onClick={(e) => e.stopPropagation()}>
				<div className="drawer-header">
					<h2 className="drawer-title">Add SSO Provider</h2>
					<button type="button" onClick={onClose} className="drawer-close">
						<X size={18} />
					</button>
				</div>

				<div className="drawer-body space-y-4">
					{/* Protocol Selection */}
					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">Protocol</label>
						<div className="flex gap-2">
							{(["saml", "oidc"] as const).map((p) => (
								<button
									key={p}
									type="button"
									onClick={() => setProtocol(p)}
									className={`flex-1 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
										protocol === p
											? "border-[var(--signal)] bg-[var(--signal)]/10 text-[var(--signal)]"
											: "border-[var(--line)] bg-[var(--surface)] text-[var(--sea-ink-soft)] hover:border-[var(--signal)]/40"
									}`}
								>
									{p.toUpperCase()}
								</button>
							))}
						</div>
					</div>

					<div>
						<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">Display Name</label>
						<input
							type="text"
							value={displayName}
							onChange={(e) => setDisplayName(e.target.value)}
							placeholder="e.g. Okta, Azure AD"
							className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
						/>
					</div>

					{protocol === "saml" && (
						<>
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">Entity ID</label>
								<input
									type="text"
									value={entityId}
									onChange={(e) => setEntityId(e.target.value)}
									placeholder="https://your-idp.com/entity"
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
								/>
							</div>
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">SSO URL</label>
								<input
									type="text"
									value={ssoUrl}
									onChange={(e) => setSsoUrl(e.target.value)}
									placeholder="https://your-idp.com/sso/saml"
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
								/>
							</div>
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
									X.509 Certificate
								</label>
								<textarea
									value={certificate}
									onChange={(e) => setCertificate(e.target.value)}
									placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
									rows={4}
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] font-mono resize-none"
								/>
							</div>
							<div>
								<label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
									<Upload size={12} className="inline mr-1" />
									Or upload IdP Metadata XML
								</label>
								<textarea
									value={metadataXml}
									onChange={(e) => setMetadataXml(e.target.value)}
									placeholder="Paste your IdP metadata XML here..."
									rows={4}
									className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] font-mono resize-none"
								/>
							</div>
						</>
					)}
				</div>

				{fieldError && (
					<p className="text-xs text-[var(--danger)] px-6 pb-2">{fieldError}</p>
				)}

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
						disabled={isPending || !displayName.trim()}
						className="signal-button"
						style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
					>
						{isPending ? "Creating..." : "Add Provider"}
					</button>
				</div>
			</div>
		</div>
	);
}
