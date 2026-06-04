import type { Severity } from "./types.js";

const SECTION = "sentinel";

/** Strongly-typed accessor for all extension settings */
export interface SentinelConfig {
  apiUrl: string;
  apiKey: string;
  tenantSlug: string;
  repositoryFullName: string;
  minSeverity: Severity;
  refreshIntervalSeconds: number;
  dashboardUrl: string;
  enableCodeLens: boolean;
}

/** Reads the current workspace configuration for the sentinel section.
 *  Safe to call on every use — vscode caches and invalidates automatically. */
export function getConfig(vscode: typeof import("vscode")): SentinelConfig {
  const cfg = vscode.workspace.getConfiguration(SECTION);
  return {
    apiUrl: cfg.get<string>("apiUrl", "https://api.sentinelsec.io").replace(/\/$/, ""),
    apiKey: cfg.get<string>("apiKey", ""),
    tenantSlug: cfg.get<string>("tenantSlug", ""),
    repositoryFullName: cfg.get<string>("repositoryFullName", ""),
    minSeverity: cfg.get<Severity>("minSeverity", "medium"),
    refreshIntervalSeconds: Math.max(60, cfg.get<number>("refreshIntervalSeconds", 300)),
    dashboardUrl: cfg.get<string>("dashboardUrl", ""),
    enableCodeLens: cfg.get<boolean>("enableCodeLens", true),
  };
}

/** Returns true if the extension has the minimum config needed to make API calls. */
export function isConfigured(config: SentinelConfig): boolean {
  return (
    config.apiUrl.length > 0 &&
    config.apiKey.length > 0 &&
    config.tenantSlug.length > 0 &&
    config.repositoryFullName.length > 0
  );
}
