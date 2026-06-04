import type { SentinelFinding, Severity, StoreSnapshot } from "./types.js";
import { stripPackageName } from "./codeLensProvider.js";
import { SEVERITY_RANK, SEVERITY_TO_DIAGNOSTIC } from "./types.js";

/**
 * Publishes Sentinel findings as VS Code Diagnostics on the relevant files.
 *
 * Strategy: findings carry `affectedPackages[]`. We scan every open text document
 * for lines that mention one of those package names, then attach a diagnostic at
 * that line. This gives "inline" highlights without needing a language server.
 *
 * The diagnostic collection is named "sentinel" so the Problems panel shows a
 * clear source column.
 */
export function createDiagnosticsProvider(
  vscode: typeof import("vscode"),
  minSeverity: Severity,
) {
  const collection = vscode.languages.createDiagnosticCollection("sentinel");

  function severityPasses(s: Severity): boolean {
    return SEVERITY_RANK[s] >= SEVERITY_RANK[minSeverity];
  }

  function buildDiagnostic(finding: SentinelFinding, line: number): import("vscode").Diagnostic {
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const severity = finding.escalatedSeverity ?? finding.severity;
    const diag = new vscode.Diagnostic(
      range,
      [
        `[Sentinel] ${finding.title}`,
        finding.cveIds?.length ? `CVEs: ${finding.cveIds.join(", ")}` : "",
        finding.validationStatus === "validated" ? "⚡ Exploit confirmed" : "",
        finding.prUrl ? `Fix PR: ${finding.prUrl}` : "No fix PR yet",
      ]
        .filter(Boolean)
        .join(" · "),
      SEVERITY_TO_DIAGNOSTIC[severity] as import("vscode").DiagnosticSeverity,
    );
    diag.source = "Sentinel";
    diag.code = finding._id;
    if (finding.cveIds?.length) {
      diag.tags = [];
    }
    return diag;
  }

  async function refreshDocument(
    doc: import("vscode").TextDocument,
    findings: SentinelFinding[],
  ): Promise<void> {
    const active = findings.filter(
      (f) =>
        f.status !== "resolved" &&
        f.status !== "false_positive" &&
        f.status !== "ignored" &&
        f.status !== "accepted_risk" &&
        severityPasses(f.escalatedSeverity ?? f.severity),
    );

    const diagnostics: import("vscode").Diagnostic[] = [];
    const text = doc.getText();
    const lines = text.split("\n");

    for (const finding of active) {
      if (!finding.affectedPackages?.length) continue;
      for (const pkg of finding.affectedPackages) {
        const pkgName = stripPackageName(pkg);
        for (let i = 0; i < lines.length; i++) {
          // Match the package name as a quoted string or bare word to avoid false matches
          if (new RegExp(`["' ]${escapeRegex(pkgName)}["'@: ]|"${escapeRegex(pkgName)}"`).test(lines[i])) {
            diagnostics.push(buildDiagnostic(finding, i));
            break; // one diagnostic per finding per file
          }
        }
      }
    }

    collection.set(doc.uri, diagnostics);
  }

  async function update(snap: StoreSnapshot, openDocs: readonly import("vscode").TextDocument[]): Promise<void> {
    collection.clear();
    if (snap.isLoading || snap.error || snap.findings.length === 0) return;
    await Promise.all(openDocs.map((doc) => refreshDocument(doc, snap.findings)));
  }

  return { collection, update, refreshDocument };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
