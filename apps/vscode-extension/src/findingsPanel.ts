import type { SentinelFinding, StoreSnapshot } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

/**
 * WebviewPanel that displays all active findings in a filterable list.
 * Opened by the "Sentinel: View All Findings" command.
 */
export function openFindingsPanel(
  vscode: typeof import("vscode"),
  context: import("vscode").ExtensionContext,
  snap: StoreSnapshot,
  filterPackage?: string,
): void {
  const panel = vscode.window.createWebviewPanel(
    "sentinel.findings",
    "Sentinel Findings",
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true },
  );

  panel.webview.html = buildHtml(snap, filterPackage);

  // Handle messages from the webview (e.g. "open PR URL")
  panel.webview.onDidReceiveMessage(
    (msg: { command: string; url?: string }) => {
      if (msg.command === "openUrl" && msg.url) {
        void vscode.env.openExternal(vscode.Uri.parse(msg.url));
      }
    },
    undefined,
    context.subscriptions,
  );
}

// ─── HTML generation ──────────────────────────────────────────────────────────

function severityColor(s: string): string {
  return (
    { critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#a3e635", informational: "#94a3b8" }[s] ??
    "#94a3b8"
  );
}

function buildFindingRow(f: SentinelFinding): string {
  const sev = f.escalatedSeverity ?? f.severity;
  const cves = f.cveIds?.join(", ") ?? "";
  const validated = f.validationStatus === "validated" ? "⚡ " : "";
  const prBtn = f.prUrl
    ? `<button onclick="openUrl('${f.prUrl}')" style="background:#1d4ed8;color:#fff;border:none;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px">View PR</button>`
    : "";
  return `
    <tr style="border-bottom:1px solid #1e293b">
      <td style="padding:8px 4px;white-space:nowrap">
        <span style="background:${severityColor(sev)};color:#0f172a;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600">${sev.toUpperCase()}</span>
      </td>
      <td style="padding:8px 4px">${validated}${escHtml(f.title)}</td>
      <td style="padding:8px 4px;font-size:11px;color:#94a3b8">${escHtml(cves)}</td>
      <td style="padding:8px 4px;font-size:11px;color:#94a3b8">${escHtml(f.affectedPackages?.join(", ") ?? "")}</td>
      <td style="padding:8px 4px">${prBtn}</td>
    </tr>`;
}

function buildHtml(snap: StoreSnapshot, filterPackage?: string): string {
  const findings = [...snap.findings]
    .filter((f) => {
      if (f.status === "resolved" || f.status === "false_positive" || f.status === "ignored") return false;
      if (filterPackage) {
        return (f.affectedPackages ?? []).some((p) => p.toLowerCase().includes(filterPackage.toLowerCase()));
      }
      return true;
    })
    .sort((a, b) => SEVERITY_RANK[b.escalatedSeverity ?? b.severity] - SEVERITY_RANK[a.escalatedSeverity ?? a.severity]);

  const posture = snap.posture;
  const scoreHtml = posture
    ? `<div style="margin-bottom:16px;padding:12px;background:#1e293b;border-radius:8px">
         <span style="font-size:24px;font-weight:700;color:#f8fafc">${posture.postureScore}</span>
         <span style="margin-left:8px;color:#94a3b8">/100 — ${posture.postureLevel}</span>
         ${
           posture.topActions.length
             ? `<ul style="margin:8px 0 0 16px;color:#cbd5e1;font-size:12px">${posture.topActions.map((a) => `<li>${escHtml(a)}</li>`).join("")}</ul>`
             : ""
         }
       </div>`
    : "";

  const filterNote = filterPackage ? `<p style="color:#94a3b8;font-size:12px">Filtered by: ${escHtml(filterPackage)}</p>` : "";

  const rows = findings.length
    ? findings.map(buildFindingRow).join("")
    : `<tr><td colspan="5" style="padding:16px;text-align:center;color:#64748b">No active findings${filterPackage ? " for this package" : ""}</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Sentinel Findings</title>
  <style>
    body { font-family: var(--vscode-font-family, sans-serif); background: #0f172a; color: #e2e8f0; margin: 0; padding: 16px; }
    h2 { margin: 0 0 12px; font-size: 16px; color: #f8fafc; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 6px 4px; color: #64748b; font-weight: 600; border-bottom: 2px solid #1e293b; }
    tr:hover td { background: #1e293b44; }
    button:hover { opacity: 0.85; }
  </style>
  <script>
    const vscode = acquireVsCodeApi();
    function openUrl(url) { vscode.postMessage({ command: 'openUrl', url }); }
  </script>
</head>
<body>
  <h2>🛡 Sentinel Security Findings</h2>
  ${scoreHtml}
  ${filterNote}
  <table>
    <thead><tr>
      <th>Severity</th><th>Title</th><th>CVEs</th><th>Packages</th><th></th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
  ${snap.lastRefreshedAt ? `<p style="margin-top:12px;color:#475569;font-size:11px">Last refreshed: ${snap.lastRefreshedAt.toLocaleString()}</p>` : ""}
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
