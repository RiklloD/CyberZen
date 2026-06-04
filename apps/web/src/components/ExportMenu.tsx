import { useState, useRef, useEffect, useCallback } from "react";
import { useAuthToken } from "@convex-dev/auth/react";
import { useAction } from "convex/react";
import { Download, ChevronDown, FileText, FileSpreadsheet, Loader2 } from "lucide-react";
import { api } from "../lib/convex";
import { track } from "../lib/analytics";

interface ExportMenuProps {
  tenantSlug: string;
  variant: "findings" | "executive-report" | "compliance";
  severity?: string;
}

/**
 * §6.22 — Reusable export dropdown.
 * Supports CSV findings export and HTML/PDF report generation.
 * Used in findings.tsx, executive-report.tsx, and compliance.tsx.
 */
export default function ExportMenu({ tenantSlug, variant, severity }: ExportMenuProps) {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const authToken = useAuthToken() ?? ""; // FIX: C3 — auth token for export authorization

  const exportFindingsCsv = useAction(api.exports.exportFindingsCsv);
  const exportExecReportPdf = useAction(api.exports.exportExecReportPdf);
  const exportComplianceEvidencePdf = useAction(api.exports.exportComplianceEvidencePdf);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener("mousedown", handleClick);
      return () => document.removeEventListener("mousedown", handleClick);
    }
  }, [open]);

  const triggerDownload = useCallback((content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const handleExportCsv = useCallback(async () => {
    setExporting("csv");
    setError(null);
    try {
      const result = await exportFindingsCsv({
        tenantSlug,
        authToken, // FIX: C3 — pass auth token
        severity: severity as any,
      });
      triggerDownload(result.csv, result.filename, "text/csv");
      track("export.run", {
        format: "csv",
        scope: `findings:${variant}`,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(null);
      setOpen(false);
    }
  }, [exportFindingsCsv, tenantSlug, severity, triggerDownload]);

  const handleExportExecReport = useCallback(async () => {
    setExporting("exec-report");
    setError(null);
    try {
      const result = await exportExecReportPdf({ tenantSlug });
      triggerDownload(result.html, result.filename, "text/html");
      track("export.run", {
        format: "pdf",
        scope: "executive-report",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(null);
      setOpen(false);
    }
  }, [exportExecReportPdf, tenantSlug, triggerDownload]);

  const handleExportComplianceEvidence = useCallback(async () => {
    setExporting("compliance");
    setError(null);
    try {
      const result = await exportComplianceEvidencePdf({ tenantSlug });
      triggerDownload(result.html, result.filename, "text/html");
      track("export.run", {
        format: "pdf",
        scope: "compliance-evidence",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(null);
      setOpen(false);
    }
  }, [exportComplianceEvidencePdf, tenantSlug, triggerDownload]);

  const isExporting = exporting !== null;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        disabled={isExporting}
        className="signal-button secondary-button"
        style={{ padding: "0.4rem 0.8rem", fontSize: "0.75rem" }}
      >
        {isExporting ? (
          <Loader2 size={12} className="mr-1 animate-spin" />
        ) : (
          <Download size={12} className="mr-1" />
        )}
        Export
        <ChevronDown size={10} className="ml-1" />
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            right: 0,
            marginTop: 4,
            zIndex: 40,
            minWidth: 220,
          }}
          className="card"
        >
          <div className="py-1">
            {error && (
              <div className="px-3 py-2 text-xs text-[var(--danger)] border-b border-[var(--line)]">
                {error}
              </div>
            )}

            {(variant === "findings" || variant === "executive-report" || variant === "compliance") && (
              <button
                type="button"
                onClick={handleExportCsv}
                disabled={isExporting}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--sea-ink)] hover:bg-[var(--surface-soft)] transition-colors text-left"
              >
                <FileSpreadsheet size={14} className="text-emerald-500 flex-shrink-0" />
                <div>
                  <p className="font-medium">Findings CSV</p>
                  <p className="text-[10px] text-[var(--sea-ink-soft)]">
                    Download all findings as spreadsheet
                  </p>
                </div>
              </button>
            )}

            {(variant === "executive-report" || variant === "findings") && (
              <button
                type="button"
                onClick={handleExportExecReport}
                disabled={isExporting}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--sea-ink)] hover:bg-[var(--surface-soft)] transition-colors text-left"
              >
                <FileText size={14} className="text-blue-500 flex-shrink-0" />
                <div>
                  <p className="font-medium">Executive Report</p>
                  <p className="text-[10px] text-[var(--sea-ink-soft)]">
                    KPIs, trends, and repo leaderboard
                  </p>
                </div>
              </button>
            )}

            {(variant === "compliance" || variant === "findings") && (
              <button
                type="button"
                onClick={handleExportComplianceEvidence}
                disabled={isExporting}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-[var(--sea-ink)] hover:bg-[var(--surface-soft)] transition-colors text-left"
              >
                <FileText size={14} className="text-amber-500 flex-shrink-0" />
                <div>
                  <p className="font-medium">Compliance Evidence</p>
                  <p className="text-[10px] text-[var(--sea-ink-soft)]">
                    Framework evidence report (SOC2/GDPR/HIPAA/PCI/NIS2)
                  </p>
                </div>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
