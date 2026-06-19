import { createFileRoute } from "@tanstack/react-router";
import { useAuthToken } from "../../lib/clerk-compat";
import { useMutation, useQuery } from "convex/react";
import { Globe, Plus, Trash2, CheckCircle, XCircle } from "lucide-react";
import { useState, useTransition } from "react";
import StatusPill from "../../components/StatusPill";
import { api } from "../../lib/convex";
import { useTenantSlug } from "../../lib/workspace";
import QueryErrorFallback from "../../components/QueryErrorFallback";

export const Route = createFileRoute("/settings/ip-allowlist")({
  errorComponent: QueryErrorFallback,
  component: IpAllowlistPage,
});

function IpAllowlistPage() {
  const TENANT = useTenantSlug();
  const authToken = useAuthToken() ?? "";
  const [newCidr, setNewCidr] = useState("");
  const [testIp, setTestIp] = useState("");
  const [, startTransition] = useTransition();

  const allowlist = useQuery(
    api.ipAllowlist.getIpAllowlist,
    authToken ? { authToken, tenantSlug: TENANT } : "skip",
  );
  const testResult2 = useQuery(
    api.ipAllowlist.testIpAccess,
    authToken && testIp.length > 6 ? { authToken, tenantSlug: TENANT, testIp } : "skip",
  );

  const updateAllowlist = useMutation(api.ipAllowlist.updateIpAllowlist);

  async function handleAddCidr() {
    if (!newCidr || !allowlist) return;
    const updated = [...allowlist, newCidr];
    startTransition(async () => {
      try {
        await updateAllowlist({ authToken, tenantSlug: TENANT, cidrs: updated });
        setNewCidr("");
      } catch (e: any) {
        alert(e.message ?? "Invalid CIDR");
      }
    });
  }

  async function handleRemoveCidr(cidr: string) {
    if (!allowlist) return;
    const updated = (allowlist as string[]).filter((c) => c !== cidr);
    startTransition(async () => {
      try {
        await updateAllowlist({ authToken, tenantSlug: TENANT, cidrs: updated });
      } catch (e) {
        console.error(e);
      }
    });
  }

  async function handleClearAll() {
    if (!confirm("Remove all IP restrictions? All IPs will be allowed.")) return;
    startTransition(async () => {
      try {
        await updateAllowlist({ authToken, tenantSlug: TENANT, cidrs: [] });
      } catch (e) {
        console.error(e);
      }
    });
  }

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Globe size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">IP Allowlist</h1>
            <p className="page-subtitle">
              Restrict API access to specific IP ranges (CIDR notation)
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Current allowlist */}
        <div className="section-header mb-3">
          <h2 className="section-title">Allowed Ranges</h2>
          {allowlist !== undefined && (
            <StatusPill
              label={allowlist.length === 0 ? "All IPs allowed" : `${allowlist.length} range${allowlist.length !== 1 ? "s" : ""}`}
              tone={allowlist.length === 0 ? "success" : "warning"}
            />
          )}
          {allowlist && allowlist.length > 0 && (
            <button
              type="button"
              onClick={handleClearAll}
              className="danger-button ml-auto"
              style={{ padding: "0.45rem 0.85rem", fontSize: "0.78rem" }}
            >
              Clear All
            </button>
          )}
        </div>

        <div className="mb-4">
          <div className="flex gap-2">
            <input
              className="input flex-1"
              placeholder="e.g. 10.0.0.0/8 or 203.0.113.5/32"
              value={newCidr}
              onChange={(e) => setNewCidr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAddCidr()}
            />
            <button
              type="button"
              className="signal-button"
              onClick={handleAddCidr}
              disabled={!newCidr}
            >
              <Plus size={14} className="mr-1" />
              Add
            </button>
          </div>
        </div>

        {allowlist && allowlist.length > 0 ? (
          <div className="rounded-xl border border-[var(--line)] overflow-hidden mb-6">
            {(allowlist as string[]).map((cidr) => (
              <div
                key={cidr}
                className="flex items-center justify-between px-4 py-3 border-b border-[var(--line)] last:border-0"
              >
                <span className="font-mono text-sm text-[var(--sea-ink)]">{cidr}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveCidr(cidr)}
                  className="danger-button p-1.5"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        ) : allowlist !== undefined ? (
          <div className="text-center py-6 mb-6 text-sm text-[var(--sea-ink-soft)] rounded-xl border border-[var(--line)]">
            No IP restrictions configured — all IPs are allowed.
          </div>
        ) : null}

        {/* Test IP */}
        <div className="mt-6">
          <div className="section-header mb-3">
            <h2 className="section-title">Test IP Access</h2>
          </div>
          <div className="flex gap-2 mb-3">
            <input
              className="input flex-1"
              placeholder="Enter an IP address to test (e.g. 10.0.0.5)"
              value={testIp}
              onChange={(e) => setTestIp(e.target.value)}
            />
          </div>
          {testResult2 && testIp.length > 6 && (
            <div className={`flex items-center gap-2 p-3 rounded-xl border ${testResult2.allowed ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}`}>
              {testResult2.allowed ? (
                <CheckCircle size={16} className="text-green-600" />
              ) : (
                <XCircle size={16} className="text-red-600" />
              )}
              <span className="text-sm">
                {testResult2.allowed
                  ? `${testIp} is allowed${testResult2.matchedCidr ? ` (matched ${testResult2.matchedCidr})` : ""}`
                  : `${testIp} would be blocked`}
              </span>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
