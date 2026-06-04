import type { StoreSnapshot } from "./types.js";

/**
 * Security posture pill in the VS Code status bar.
 *
 * Shows:  🛡 Sentinel: 82 (healthy)
 *   or:   🛡 Sentinel: loading…
 *   or:   ⚠ Sentinel: not configured
 */
export function createStatusBarItem(vscode: typeof import("vscode")) {
  const item = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    // Priority 100 keeps it to the left of language indicator but right of git
    100,
  );
  item.command = "sentinel.viewFindings";
  item.show();

  function update(snap: StoreSnapshot): void {
    if (snap.isLoading && snap.lastRefreshedAt === null) {
      item.text = "$(shield) Sentinel: loading…";
      item.tooltip = "Fetching security posture from Sentinel…";
      item.backgroundColor = undefined;
      return;
    }

    if (snap.error && snap.lastRefreshedAt === null) {
      item.text = "$(alert) Sentinel: error";
      item.tooltip = `Sentinel API error: ${snap.error}`;
      item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      return;
    }

    if (!snap.posture) {
      item.text = "$(shield) Sentinel";
      item.tooltip = "Click to view findings. Configure sentinel.apiKey to enable posture score.";
      item.backgroundColor = undefined;
      return;
    }

    const { postureScore, postureLevel } = snap.posture;
    const icon = postureLevel === "critical" || postureLevel === "degraded" ? "$(alert)" : "$(shield)";
    item.text = `${icon} Sentinel: ${postureScore} (${postureLevel})`;
    item.tooltip = [
      `Security Posture: ${postureScore}/100 — ${postureLevel}`,
      snap.posture.topActions.length > 0
        ? `Top actions:\n${snap.posture.topActions.map((a) => `  • ${a}`).join("\n")}`
        : "",
      snap.lastRefreshedAt ? `Last refreshed: ${snap.lastRefreshedAt.toLocaleTimeString()}` : "",
    ]
      .filter(Boolean)
      .join("\n");

    item.backgroundColor =
      postureLevel === "critical"
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : postureLevel === "degraded" || postureLevel === "at_risk"
          ? new vscode.ThemeColor("statusBarItem.warningBackground")
          : undefined;
  }

  return { item, update };
}
