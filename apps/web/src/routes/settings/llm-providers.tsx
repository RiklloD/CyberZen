import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useAction } from "convex/react";
import {
  Plug,
  Plus,
  Trash2,
  X,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Eye,
  EyeOff,
  Loader2,
  Zap,
  Cpu,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";
import { useState, useTransition, type ReactNode } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/llm-providers")({
  errorComponent: QueryErrorFallback,
  component: LlmProvidersPage,
});

// ─── Page ───────────────────────────────────────────────────────────────────

function LlmProvidersPage() {
  const TENANT = useTenantSlug();

  const configs = useQuery(api.llmProviders.listProviderConfigs, {
    tenantSlug: TENANT,
  });
  const catalog = useQuery(api.llmProviders.getProviderCatalog, {});

  const currentUser = useQuery(api.workspaceAuth.currentWorkspace);
  const currentUserCanAdmin =
    currentUser?.workspaces?.some(
      (w: { tenantSlug: string; role: string }) =>
        w.tenantSlug === TENANT &&
        (w.role === "owner" || w.role === "admin"),
    ) ?? false;

  const [modalOpen, setModalOpen] = useState(false);

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Cpu size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">LLM Providers</h1>
            <p className="page-subtitle">
              Connect AI providers to power the agent system — remediation,
              exploit validation, Red-Blue adversarial rounds, and compliance
              analysis
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Info banner */}
        <div
          className="rounded-2xl p-4 mb-5"
          style={{
            background: "var(--signal)",
            opacity: 0.08,
            border: "1px solid var(--signal)",
          }}
        >
          <div className="flex items-start gap-3">
            <Zap
              size={16}
              className="flex-shrink-0 mt-0.5"
              style={{ color: "var(--signal)" }}
            />
            <div className="text-sm">
              <p
                className="font-semibold mb-1"
                style={{ color: "var(--signal)" }}
              >
                How provider priority works
              </p>
              <p style={{ color: "var(--sea-ink-soft)" }}>
                The agent system automatically picks the best available
                provider for each task type. Enable multiple providers for
                redundancy — if one fails, the system falls back to the next.
                Keys are encrypted and never shown again after saving.
              </p>
            </div>
          </div>
        </div>

        <div className="section-header mb-3">
          <h2 className="section-title">Connected Providers</h2>
          {configs && (
            <StatusPill
              label={`${configs.length} configured`}
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
              Add Provider
            </button>
          )}
        </div>

        {configs && catalog ? (
          <ProviderList
            configs={configs}
            catalog={catalog}
            tenantSlug={TENANT}
            currentUserCanAdmin={currentUserCanAdmin}
          />
        ) : (
          <div className="space-y-2">
            {["a", "b", "c"].map((k) => (
              <div
                key={k}
                className="loading-panel h-20 rounded-2xl"
              />
            ))}
          </div>
        )}

        {/* Available providers (not yet configured) */}
        {configs && catalog && (
          <AvailableProviders
            configuredKeys={configs.map((c) => c.providerKey)}
            catalog={catalog}
            onAdd={() => setModalOpen(true)}
            canAdmin={currentUserCanAdmin}
          />
        )}
      </div>

      {modalOpen && currentUserCanAdmin && (
        <AddProviderModal
          tenantSlug={TENANT}
          catalog={catalog ?? {}}
          existingKeys={configs?.map((c) => c.providerKey) ?? []}
          onClose={() => setModalOpen(false)}
        />
      )}
    </main>
  );
}

// ─── Provider List ──────────────────────────────────────────────────────────

type ProviderConfig = {
  _id: string;
  providerKey: string;
  label: string;
  apiKeyMasked: string;
  baseUrl?: string;
  defaultModel?: string;
  enabled: boolean;
  lastTestedAt?: number;
  lastTestResult?: "success" | "failed";
  lastTestError?: string;
  createdAt: number;
};

type CatalogEntry = {
  label: string;
  icon: string;
  description: string;
  defaultBaseUrl: string;
  defaultModel: string;
  keyPrefix: string;
  keyPlaceholder: string;
  docsUrl: string;
  apiFormat: string;
};

interface ProviderListProps {
  configs: ProviderConfig[];
  catalog: Record<string, CatalogEntry>;
  tenantSlug: string;
  currentUserCanAdmin: boolean;
}

function ProviderList({
  configs,
  catalog,
  tenantSlug,
  currentUserCanAdmin,
}: ProviderListProps) {
  if (configs.length === 0) {
    return (
      <div className="empty-state border border-dashed border-[var(--line)] rounded-2xl mb-6">
        <Plug size={24} className="mb-2 opacity-40" />
        <p>No LLM providers connected yet.</p>
        <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
          Add a provider below to enable the AI agent system.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 mb-6">
      {configs.map((config) => {
        const meta = catalog[config.providerKey];
        return (
          <ProviderCard
            key={config._id}
            config={config}
            meta={meta}
            tenantSlug={tenantSlug}
            currentUserCanAdmin={currentUserCanAdmin}
          />
        );
      })}
    </div>
  );
}

function ProviderCard({
  config,
  meta,
  tenantSlug,
  currentUserCanAdmin,
}: {
  config: ProviderConfig;
  meta?: CatalogEntry;
  tenantSlug: string;
  currentUserCanAdmin: boolean;
}) {
  const [isPending, startTransition] = useTransition();
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    error?: string;
    responsePreview?: string;
  } | null>(null);

  const toggleProvider = useMutation(api.llmProviders.toggleProviderConfig);
  const deleteProvider = useMutation(api.llmProviders.deleteProviderConfig);
  const testConnection = useAction(api.llmProviders.testProviderConnection);

  function handleToggle() {
    startTransition(async () => {
      await toggleProvider({
        tenantSlug,
        configId: config._id as any,
        enabled: !config.enabled,
      });
    });
  }

  function handleDelete() {
    if (
      !confirm(
        `Delete "${config.label}"? This will remove the provider configuration permanently.`,
      )
    )
      return;
    startTransition(async () => {
      await deleteProvider({
        tenantSlug,
        configId: config._id as any,
      });
    });
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testConnection({
        tenantSlug,
        configId: config._id as any,
      });
      setTestResult(result as any);
    } catch (err) {
      setTestResult({
        success: false,
        error: (err as Error).message,
      });
    }
    setTesting(false);
  }

  const label = meta?.label ?? config.providerKey;
  const description = meta?.description ?? "";
  const model = config.defaultModel ?? meta?.defaultModel ?? "—";
  const baseUrl = config.baseUrl ?? meta?.defaultBaseUrl ?? "";

  return (
    <div className="card card-sm" style={{ padding: "1rem 1.25rem" }}>
      <div className="flex items-start justify-between gap-4">
        {/* Left: Provider info */}
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <ProviderIcon
            providerKey={config.providerKey}
            size={36}
          />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm font-semibold text-[var(--sea-ink)]">
                {config.label}
              </p>
              {config.enabled ? (
                <StatusPill label="active" tone="success" />
              ) : (
                <StatusPill label="disabled" tone="neutral" />
              )}
              {config.lastTestResult === "success" && (
                <StatusPill label="verified" tone="success" />
              )}
              {config.lastTestResult === "failed" && (
                <StatusPill label="test failed" tone="danger" />
              )}
            </div>
            <p className="text-xs text-[var(--sea-ink-soft)] mt-0.5">
              {description}
            </p>
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              <span className="text-xs text-[var(--sea-ink-soft)]">
                Model:{" "}
                <code className="bg-[var(--surface)] px-1 rounded text-[0.7rem]">
                  {model}
                </code>
              </span>
              <span className="text-xs text-[var(--sea-ink-soft)]">
                Key:{" "}
                <code className="bg-[var(--surface)] px-1 rounded text-[0.7rem]">
                  {config.apiKeyMasked}
                </code>
              </span>
              {config.lastTestedAt && (
                <span className="text-xs text-[var(--sea-ink-soft)]">
                  Last tested{" "}
                  {new Date(config.lastTestedAt).toLocaleDateString()}
                </span>
              )}
            </div>
            {/* Show test error inline */}
            {config.lastTestError && !testResult && (
              <p className="text-xs text-[var(--danger)] mt-1.5 font-mono break-all">
                {config.lastTestError.slice(0, 200)}
              </p>
            )}
            {/* Show inline test result */}
            {testResult && (
              <div className="mt-2">
                {testResult.success ? (
                  <div className="flex items-center gap-1.5 text-xs text-[var(--success)]">
                    <CheckCircle2 size={12} />
                    <span>
                      Connection successful
                      {testResult.responsePreview &&
                        ` — "${testResult.responsePreview}"`}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-start gap-1.5 text-xs text-[var(--danger)]">
                    <XCircle size={12} className="mt-0.5 flex-shrink-0" />
                    <span className="font-mono break-all">
                      {testResult.error}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right: Actions */}
        {currentUserCanAdmin && (
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <button
              type="button"
              disabled={testing || isPending}
              onClick={handleTest}
              className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--signal)] hover:bg-[var(--signal)]/10 transition-colors disabled:opacity-40"
              title="Test connection"
            >
              {testing ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Zap size={14} />
              )}
            </button>
            <button
              type="button"
              disabled={isPending}
              onClick={handleToggle}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-40 ${
                config.enabled
                  ? "text-[var(--warning)] hover:bg-[var(--warning)]/10"
                  : "text-[var(--success)] hover:bg-[var(--success)]/10"
              }`}
              title={config.enabled ? "Disable provider" : "Enable provider"}
            >
              {config.enabled ? "Disable" : "Enable"}
            </button>
            <button
              type="button"
              disabled={isPending}
              onClick={handleDelete}
              className="p-1.5 rounded-lg text-[var(--sea-ink-soft)] hover:text-[var(--danger)] hover:bg-[var(--danger)]/10 transition-colors disabled:opacity-40"
              title="Delete provider"
            >
              <Trash2 size={14} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Available Providers (not yet connected) ───────────────────────────────

function AvailableProviders({
  configuredKeys,
  catalog,
  onAdd,
  canAdmin,
}: {
  configuredKeys: string[];
  catalog: Record<string, CatalogEntry>;
  onAdd: () => void;
  canAdmin: boolean;
}) {
  const available = Object.entries(catalog).filter(
    ([key]) => !configuredKeys.includes(key),
  );

  if (available.length === 0) return null;

  return (
    <>
      <div className="section-header mb-3 mt-6">
        <h2 className="section-title">Available Providers</h2>
        <StatusPill label={`${available.length} available`} tone="neutral" />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {available.map(([key, meta]) => (
          <div
            key={key}
            className="card card-sm flex items-center gap-3"
            style={{ padding: "0.875rem 1rem" }}
          >
            <ProviderIcon providerKey={key} size={32} />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-[var(--sea-ink)] truncate">
                {meta.label}
              </p>
              <p className="text-xs text-[var(--sea-ink-soft)] truncate">
                {meta.description}
              </p>
            </div>
            {canAdmin && (
              <button
                type="button"
                onClick={onAdd}
                className="p-1.5 rounded-lg text-[var(--signal)] hover:bg-[var(--signal)]/10 transition-colors flex-shrink-0"
                title={`Add ${meta.label}`}
              >
                <Plus size={16} />
              </button>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

// ─── Add Provider Modal ───────────────────────────────────────────────────

function AddProviderModal({
  tenantSlug,
  catalog,
  existingKeys,
  onClose,
}: {
  tenantSlug: string;
  catalog: Record<string, CatalogEntry>;
  existingKeys: string[];
  onClose: () => void;
}) {
  const availableKeys = Object.keys(catalog).filter(
    (k) => !existingKeys.includes(k),
  );
  const allKeys = Object.keys(catalog);

  const [selectedProvider, setSelectedProvider] = useState<string>(
    availableKeys[0] ?? allKeys[0] ?? "openai",
  );
  const [label, setLabel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [isPending, startTransition] = useTransition();

  const meta = catalog[selectedProvider];

  // Auto-fill label and defaults when provider changes
  function selectProvider(key: string) {
    setSelectedProvider(key);
    const m = catalog[key];
    if (m) {
      setLabel(m.label);
      setDefaultModel(m.defaultModel);
      setBaseUrl(""); // let backend use the default
    }
  }

  // Initialize label on mount
  if (!label && meta) {
    setLabel(meta.label);
  }
  if (!defaultModel && meta) {
    setDefaultModel(meta.defaultModel);
  }

  const upsertConfig = useMutation(api.llmProviders.upsertProviderConfig);

  function handleSave() {
    if (!apiKey.trim()) return;
    startTransition(async () => {
      await upsertConfig({
        tenantSlug,
        providerKey: selectedProvider,
        label: label.trim() || meta?.label || selectedProvider,
        apiKey: apiKey.trim(),
        baseUrl: baseUrl.trim() || undefined,
        defaultModel: defaultModel.trim() || undefined,
        enabled: true,
      });
      onClose();
    });
  }

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div
        className="drawer-panel"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: "560px" }}
      >
        <div className="drawer-header">
          <h2 className="drawer-title">Add LLM Provider</h2>
          <button type="button" onClick={onClose} className="drawer-close">
            <X size={18} />
          </button>
        </div>

        <div className="drawer-body space-y-4">
          {/* Provider selector */}
          <div>
            <label className="block text-xs font-semibold text-[var(--sea-ink)] mb-2">
              Provider
            </label>
            <div className="grid grid-cols-1 gap-2">
              {allKeys.map((key) => {
                const m = catalog[key];
                const isExisting = existingKeys.includes(key);
                const isSelected = selectedProvider === key;
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => !isExisting && selectProvider(key)}
                    disabled={isExisting}
                    className={`flex items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors ${
                      isSelected
                        ? "border-[var(--signal)] bg-[var(--signal)]/10"
                        : "border-[var(--line)] bg-[var(--surface)] hover:border-[var(--signal)]/40"
                    } ${isExisting ? "opacity-40 cursor-not-allowed" : ""}`}
                  >
                    <ProviderIcon providerKey={key} size={28} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-[var(--sea-ink)]">
                        {m.label}
                      </p>
                      <p className="text-xs text-[var(--sea-ink-soft)] truncate">
                        {m.description}
                      </p>
                    </div>
                    {isExisting && (
                      <StatusPill label="configured" tone="neutral" />
                    )}
                    {isSelected && !isExisting && (
                      <CheckCircle2
                        size={16}
                        className="text-[var(--signal)] flex-shrink-0"
                      />
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Label */}
          <div>
            <label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
              Display Name
            </label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder={meta?.label ?? "Provider name"}
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
            />
          </div>

          {/* API Key */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-semibold text-[var(--sea-ink)]">
                API Key
              </label>
              {meta?.docsUrl && (
                <a
                  href={meta.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[var(--signal)] hover:underline flex items-center gap-1"
                >
                  Get key
                  <ExternalLink size={10} />
                </a>
              )}
            </div>
            <div className="relative">
              <input
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={meta?.keyPlaceholder ?? "Enter API key"}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 pr-10 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] font-mono"
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-[var(--sea-ink-soft)] hover:text-[var(--signal)] transition-colors"
                title={showKey ? "Hide key" : "Show key"}
              >
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {/* Default Model */}
          <div>
            <label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
              Default Model{" "}
              <span className="text-[var(--sea-ink-soft)] font-normal">
                (optional)
              </span>
            </label>
            <input
              type="text"
              value={defaultModel}
              onChange={(e) => setDefaultModel(e.target.value)}
              placeholder={meta?.defaultModel ?? "model-name"}
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] font-mono"
            />
          </div>

          {/* Base URL override */}
          <div>
            <label className="block text-xs font-semibold text-[var(--sea-ink)] mb-1.5">
              Base URL{" "}
              <span className="text-[var(--sea-ink-soft)] font-normal">
                (optional — leave blank for default)
              </span>
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={meta?.defaultBaseUrl ?? "https://api.example.com/v1"}
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] font-mono"
            />
          </div>

          {/* Security notice */}
          <div
            className="flex items-start gap-2 p-3 rounded-lg"
            style={{
              background: "var(--warning)",
              opacity: 0.08,
            }}
          >
            <AlertTriangle
              size={14}
              className="flex-shrink-0 mt-0.5"
              style={{ color: "var(--warning)" }}
            />
            <p className="text-xs text-[var(--sea-ink-soft)]">
              Your API key is encrypted at rest and never displayed again after
              saving. Only a masked prefix is shown in the UI.
            </p>
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
            onClick={handleSave}
            disabled={isPending || !apiKey.trim()}
            className="signal-button"
            style={{ padding: "0.5rem 1rem", fontSize: "0.8rem" }}
          >
            {isPending ? "Saving..." : "Save Provider"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Provider Icons ────────────────────────────────────────────────────────

function ProviderIcon({
  providerKey,
  size = 32,
}: {
  providerKey: string;
  size?: number;
}) {
  const bg = "var(--surface)";
  const color = "var(--signal)";

  // All icons are text-based for reliability (no external SVG dependencies)
  const initials: Record<string, { text: string; bg: string; color: string }> =
    {
      openai: {
        text: "AI",
        bg: "#10a37f20",
        color: "#10a37f",
      },
      zai_coding: {
        text: "Z",
        bg: "#3b82f620",
        color: "#3b82f6",
      },
      zai_token: {
        text: "Z",
        bg: "#3b82f620",
        color: "#3b82f6",
      },
      minimax_token: {
        text: "M",
        bg: "#8b5cf620",
        color: "#8b5cf6",
      },
      openrouter: {
        text: "OR",
        bg: "#f9731620",
        color: "#f97316",
      },
    };

  const config = initials[providerKey] ?? {
    text: providerKey.slice(0, 2).toUpperCase(),
    bg,
    color,
  };

  return (
    <div
      className="flex-shrink-0 rounded-xl flex items-center justify-center font-bold"
      style={{
        width: size,
        height: size,
        background: config.bg,
        color: config.color,
        fontSize: size * 0.36,
        border: `1px solid ${config.color}30`,
      }}
    >
      {config.text}
    </div>
  );
}
