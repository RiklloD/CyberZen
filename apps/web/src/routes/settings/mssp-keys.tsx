import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "convex/react";
import { Plus, RefreshCw, Trash2, Copy, Shield } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/mssp-keys")({
  errorComponent: QueryErrorFallback,
  component: MsspKeysPage });

const AVAILABLE_SCOPES = [
  "findings:read",
  "repositories:read",
  "audit:read",
  "compliance:read",
  "tenants:read",
  "tenants:manage",
];

function MsspKeysPage() {
  const TENANT = useTenantSlug();
  const [modalOpen, setModalOpen] = useState(false);
  const [partnerName, setPartnerName] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [revealSecret, setRevealSecret] = useState<{ secret: string; partner: string } | null>(null);
  const [, startTransition] = useTransition();

  const keys = useQuery(
    api.msspApiKeys.listMsspApiKeys,
    { tenantSlug: TENANT },
  );

  const createKey = useMutation(api.msspApiKeys.createMsspApiKey);
  const rotateKey = useMutation(api.msspApiKeys.rotateMsspApiKey);
  const revokeKey = useMutation(api.msspApiKeys.revokeMsspApiKey);

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

  async function handleCreate() {
    if (!partnerName || selectedScopes.length === 0) return;
    startTransition(async () => {
      try {
        const result = await createKey({
          tenantSlug: TENANT,
          partnerName,
          scopes: selectedScopes });
        setRevealSecret({ secret: result.secret, partner: result.partnerName });
        setModalOpen(false);
        setPartnerName("");
        setSelectedScopes([]);
      } catch (e) {
        console.error(e);
      }
    });
  }

  async function handleRotate(keyId: string) {
    startTransition(async () => {
      try {
        const result = await rotateKey({
          tenantSlug: TENANT,
          keyId: keyId as any });
        setRevealSecret({ secret: result.secret, partner: result.partnerName });
      } catch (e) {
        console.error(e);
      }
    });
  }

  async function handleRevoke(keyId: string) {
    if (!confirm("Revoke this MSSP API key? This cannot be undone.")) return;
    startTransition(async () => {
      try {
        await revokeKey({ tenantSlug: TENANT, keyId: keyId as any });
      } catch (e) {
        console.error(e);
      }
    });
  }

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Shield size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">MSSP API Keys</h1>
            <p className="page-subtitle">
              Per-partner API keys with scoped access for managed security providers
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        <div className="section-header mb-3">
          <h2 className="section-title">Partner Keys</h2>
          {keys && (
            <StatusPill label={`${keys.length} key${keys.length !== 1 ? "s" : ""}`} tone="neutral" />
          )}
          <button
            type="button"
            onClick={() => setModalOpen(true)}
            className="signal-button ml-auto"
            style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
          >
            <Plus size={14} className="mr-1" />
            Add Key
          </button>
        </div>

        {keys && keys.length > 0 ? (
          <div className="rounded-xl border border-[var(--line)] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--line)] bg-[var(--surface-soft)]">
                  <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Partner</th>
                  <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Prefix</th>
                  <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Scopes</th>
                  <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Status</th>
                  <th className="px-4 py-2 text-left text-xs font-semibold text-[var(--sea-ink-soft)]">Last Used</th>
                  <th className="px-4 py-2 text-right text-xs font-semibold text-[var(--sea-ink-soft)]">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key: any) => (
                  <tr key={key._id} className="border-b border-[var(--line)] last:border-0">
                    <td className="px-4 py-3 font-medium text-[var(--sea-ink)]">{key.partnerName}</td>
                    <td className="px-4 py-3 font-mono text-xs text-[var(--sea-ink-soft)]">{key.keyPrefix}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {key.scopes.map((s: string) => (
                          <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-soft)] border border-[var(--line)] text-[var(--sea-ink-soft)]">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {key.revokedAt ? (
                        <StatusPill label="Revoked" tone="danger" />
                      ) : key.isActive ? (
                        <StatusPill label="Active" tone="success" />
                      ) : (
                        <StatusPill label="Inactive" tone="neutral" />
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--sea-ink-soft)]">
                      {key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleDateString() : "Never"}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {!key.revokedAt && (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            onClick={() => handleRotate(key._id)}
                            title="Rotate"
                            className="ghost-button p-1.5"
                          >
                            <RefreshCw size={14} />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRevoke(key._id)}
                            title="Revoke"
                            className="danger-button p-1.5"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-sm text-[var(--sea-ink-soft)]">
            No MSSP API keys yet. Add one to grant partner access.
          </div>
        )}
      </div>

      {/* Create Key Modal */}
      {modalOpen && (
        <div className="modal-overlay" onClick={() => setModalOpen(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-[var(--sea-ink)] mb-4">Add MSSP API Key</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--sea-ink-soft)] mb-1">Partner Name</label>
                <input
                  className="input w-full"
                  placeholder="e.g. Acme Security LLC"
                  value={partnerName}
                  onChange={(e) => setPartnerName(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[var(--sea-ink-soft)] mb-2">Scopes</label>
                <div className="flex flex-wrap gap-2">
                  {AVAILABLE_SCOPES.map((scope) => (
                    <button
                      key={scope}
                      type="button"
                      onClick={() => toggleScope(scope)}
                      className={`text-xs px-2 py-1 rounded border transition-colors ${
                        selectedScopes.includes(scope)
                          ? "border-[var(--signal)] bg-[var(--signal-soft)] text-[var(--signal)]"
                          : "border-[var(--line)] text-[var(--sea-ink-soft)]"
                      }`}
                    >
                      {scope}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button type="button" className="ghost-button" onClick={() => setModalOpen(false)}>Cancel</button>
              <button
                type="button"
                className="signal-button"
                onClick={handleCreate}
                disabled={!partnerName || selectedScopes.length === 0}
              >
                Create Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reveal Secret Modal */}
      {revealSecret && (
        <div className="modal-overlay" onClick={() => setRevealSecret(null)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-[var(--sea-ink)] mb-2">API Key Created</h3>
            <p className="text-xs text-[var(--sea-ink-soft)] mb-4">
              Copy this key now — it will not be shown again.
            </p>
            <div className="flex items-center gap-2 p-3 rounded-lg bg-[var(--surface-soft)] border border-[var(--line)] font-mono text-xs break-all">
              <span className="flex-1 text-[var(--sea-ink)]">{revealSecret.secret}</span>
              <button
                type="button"
                onClick={() => navigator.clipboard.writeText(revealSecret.secret)}
                className="ghost-button p-1"
              >
                <Copy size={14} />
              </button>
            </div>
            <div className="flex justify-end mt-4">
              <button type="button" className="signal-button" onClick={() => setRevealSecret(null)}>Done</button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
