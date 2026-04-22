/**
 * Sentinel VS Code Extension — main activation entrypoint.
 *
 * Activation flow:
 *  1. Read configuration from workspace settings.
 *  2. Build SentinelClient + FindingStore.
 *  3. Register StatusBarItem, DiagnosticsProvider, CodeLensProvider, and Commands.
 *  4. Subscribe all providers to the store so they react to data changes automatically.
 *  5. Start the auto-refresh timer.
 *
 * On deactivation: dispose all VS Code resources and stop the refresh timer.
 */

// The `vscode` module is injected at runtime by the VS Code host. We import the
// type only so the rest of the extension remains testable outside the host.
import * as vscode from "vscode";

import { getConfig, isConfigured } from "./config.js";
import { SentinelClient } from "./sentinelClient.js";
import { FindingStore } from "./findingStore.js";
import { createStatusBarItem } from "./statusBarItem.js";
import { createDiagnosticsProvider } from "./diagnosticsProvider.js";
import { createCodeLensProvider } from "./codeLensProvider.js";
import { registerCommands } from "./commands.js";
import { ALL_MANIFEST_BASENAMES } from "./types.js";

// Track disposables so deactivate() can clean everything up.
const disposables: vscode.Disposable[] = [];
let store: FindingStore | null = null;

export function activate(context: vscode.ExtensionContext): void {
  const config = getConfig(vscode);

  if (!isConfigured(config)) {
    // Show a gentle nudge in the status bar — the extension can still activate
    // and show commands; it just won't fetch data until credentials are set.
    void vscode.window.showInformationMessage(
      "Sentinel: Set sentinel.apiKey, sentinel.tenantSlug, and sentinel.repositoryFullName to enable live findings.",
      "Open Settings",
    ).then((choice) => {
      if (choice === "Open Settings") {
        void vscode.commands.executeCommand("workbench.action.openSettings", "sentinel");
      }
    });
  }

  // ── Core services ───────────────────────────────────────────────────────────
  const client = new SentinelClient(config);
  store = new FindingStore(client, config.refreshIntervalSeconds * 1000);

  // ── Status bar ──────────────────────────────────────────────────────────────
  const { item: statusBarItem, update: updateStatusBar } = createStatusBarItem(vscode);
  disposables.push(statusBarItem);

  // ── Diagnostics ─────────────────────────────────────────────────────────────
  const { collection, update: updateDiagnostics } = createDiagnosticsProvider(vscode, config.minSeverity);
  disposables.push(collection);

  // ── CodeLens ────────────────────────────────────────────────────────────────
  let currentFindings = store.snapshot().findings;
  const codeLensProvider = createCodeLensProvider(vscode, () => currentFindings) as vscode.CodeLensProvider & {
    _notifyChange(): void;
  };

  if (config.enableCodeLens) {
    const selector: vscode.DocumentSelector = ALL_MANIFEST_BASENAMES.map((name) => ({
      scheme: "file",
      pattern: `**/${name}`,
    }));
    disposables.push(vscode.languages.registerCodeLensProvider(selector, codeLensProvider));
  }

  // ── Bind store → providers ───────────────────────────────────────────────────
  const unsubscribe = store.subscribe((snap) => {
    currentFindings = snap.findings;
    updateStatusBar(snap);
    const openDocs = vscode.workspace.textDocuments;
    void updateDiagnostics(snap, openDocs);
    codeLensProvider._notifyChange();
  });
  disposables.push({ dispose: unsubscribe });

  // Re-run diagnostics when a document is opened/changed
  disposables.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      void collection.delete(doc.uri); // clear stale entries
      if (store) {
        const snap = store.snapshot();
        if (!snap.isLoading && snap.findings.length > 0) {
          const { refreshDocument } = createDiagnosticsProvider(vscode, config.minSeverity);
          void refreshDocument(doc, snap.findings).then(() => {});
        }
      }
    }),
  );

  // ── Commands ────────────────────────────────────────────────────────────────
  registerCommands(vscode, context, store, client, config);

  // ── Configuration change listener ────────────────────────────────────────────
  disposables.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("sentinel")) {
        void vscode.window.showInformationMessage("Sentinel: Configuration changed. Reload window to apply.");
      }
    }),
  );

  // ── Start auto-refresh ───────────────────────────────────────────────────────
  if (isConfigured(config)) {
    store.startAutoRefresh();
  }

  // Register all disposables with the context so VS Code cleans them up
  context.subscriptions.push(...disposables);
}

export function deactivate(): void {
  store?.dispose();
  store = null;
  for (const d of disposables) d.dispose();
  disposables.length = 0;
}
