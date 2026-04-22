import type { SentinelClient } from "./sentinelClient.js";
import type { FindingStore } from "./findingStore.js";
import type { StoreSnapshot } from "./types.js";
import { openFindingsPanel } from "./findingsPanel.js";
import { isConfigured } from "./config.js";
import type { getConfig } from "./config.js";

/** Registers all Sentinel commands with the VS Code extension context. */
export function registerCommands(
  vscode: typeof import("vscode"),
  context: import("vscode").ExtensionContext,
  store: FindingStore,
  client: SentinelClient,
  config: ReturnType<typeof getConfig>,
): void {
  // ── sentinel.refresh ──────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("sentinel.refresh", async () => {
      await store.refresh();
      void vscode.window.showInformationMessage("Sentinel: Findings refreshed.");
    }),
  );

  // ── sentinel.triggerScan ──────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("sentinel.triggerScan", async () => {
      if (!isConfigured(config)) {
        void vscode.window.showWarningMessage(
          "Sentinel: Configure sentinel.apiKey, sentinel.tenantSlug, and sentinel.repositoryFullName first.",
        );
        return;
      }
      void vscode.window.showInformationMessage("Sentinel: Scan triggered. Results will appear within minutes.");
      await client.triggerScan();
      // Refresh findings after a short delay to pick up new results
      setTimeout(() => void store.refresh(), 15_000);
    }),
  );

  // ── sentinel.viewFindings ─────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("sentinel.viewFindings", (filterPackage?: string) => {
      const snap: StoreSnapshot = store.snapshot();
      openFindingsPanel(vscode, context, snap, filterPackage);
    }),
  );

  // ── sentinel.openDashboard ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("sentinel.openDashboard", () => {
      const url = config.dashboardUrl || config.apiUrl;
      if (!url) {
        void vscode.window.showWarningMessage("Sentinel: Set sentinel.dashboardUrl to open the dashboard.");
        return;
      }
      void vscode.env.openExternal(vscode.Uri.parse(url));
    }),
  );

  // ── sentinel.openFinding ─────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("sentinel.openFinding", (findingId: string) => {
      const url = `${config.apiUrl}/findings/${findingId}`;
      void vscode.env.openExternal(vscode.Uri.parse(url));
    }),
  );
}
