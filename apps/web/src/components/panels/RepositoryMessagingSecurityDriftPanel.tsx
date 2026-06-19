import type { FunctionReturnType } from "convex/server";
import { ChevronDown, ChevronRight, ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";

type ScanDoc = NonNullable<
  FunctionReturnType<typeof api.messagingSecurityDriftIntel.getLatestMessagingSecurityDrift>
>;

function driftTone(level: string): "success" | "warning" | "danger" | "info" | "neutral" {
  if (level === "none" || level === "low") return "success";
  if (level === "medium") return "warning";
  if (level === "high" || level === "critical") return "danger";
  return "neutral";
}

function gradeTone(grade: string): "success" | "warning" | "danger" | "neutral" {
  if (["A", "A+"].includes(grade)) return "success";
  if (["B", "C"].includes(grade)) return "warning";
  return "danger";
}

export default function RepositoryMessagingSecurityDriftPanel({
  data }: {
  data: ScanDoc;
}) {
  const [expandedRules, setExpandedRules] = useState<Set<number>>(new Set());

  if (!data) return null;

  const rules = data.rules ?? data.findings ?? data.checkedControls ?? [];
  const totalRules = rules.length;
  const failedRules = rules.filter((r: any) => r.status === "fail" || r.status === "drifted" || r.status === "misconfigured").length;
  const passRate = totalRules > 0 ? Math.round(((totalRules - failedRules) / totalRules) * 100) : 100;
  const grade = passRate >= 90 ? "A" : passRate >= 80 ? "B" : passRate >= 70 ? "C" : passRate >= 60 ? "D" : "F";

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <ShieldCheck size={16} className="text-[var(--signal)]" />
          <h3 className="section-title">Messaging Security Drift</h3>
          <StatusPill label={grade} tone={gradeTone(grade)} />
        </div>
        <div className="flex items-center gap-2">
          <StatusPill label={`${failedRules}`} tone={failedRules > 0 ? "danger" : "success"} />
          <span className="text-xs text-[var(--sea-ink-soft)]">
            {totalRules} rules · {passRate}% pass
          </span>
        </div>
      </div>

      {passRate < 100 && (
        <div className="mb-3 flex items-center gap-2 text-xs text-[var(--warning)]">
          <AlertTriangle size={12} />
          <span>{failedRules} rule{failedRules !== 1 ? "s" : ""} drifted</span>
        </div>
      )}

      <div className="w-full bg-[var(--sea-foam-soft)] rounded-full h-1.5 mb-4">
        <div
          className="h-1.5 rounded-full transition-all"
          style={{
            width: `${passRate}%`,
            backgroundColor:
              passRate >= 80
                ? "var(--success)"
                : passRate >= 60
                  ? "var(--warning)"
                  : "var(--danger)" }}
        />
      </div>

      {rules.length > 0 && (
        <div className="space-y-1">
          {rules.map((rule: any, idx: number) => {
            const isFail = rule.status === "fail" || rule.status === "drifted" || rule.status === "misconfigured";
            const expanded = expandedRules.has(idx);
            return (
              <div key={idx}>
                <button
                  type="button"
                  className="w-full flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-[var(--sea-foam-soft)] transition-colors text-left"
                  onClick={() => {
                    const next = new Set(expandedRules);
                    if (next.has(idx)) next.delete(idx);
                    else next.add(idx);
                    setExpandedRules(next);
                  }}
                >
                  {isFail ? (
                    <ShieldAlert size={12} className="text-[var(--danger)] flex-shrink-0" />
                  ) : (
                    <ShieldCheck size={12} className="text-[var(--success)] flex-shrink-0" />
                  )}
                  <span className="text-xs font-medium text-[var(--sea-ink)] truncate flex-1">
                    {rule.ruleId ?? rule.controlId ?? rule.name ?? `Rule ${idx + 1}`}
                  </span>
                  <StatusPill
                    label={rule.status ?? "pass"}
                    tone={driftTone(rule.status ?? "pass")}
                  />
                  {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                </button>
                {expanded && (
                  <div className="ml-6 mr-2 mb-2 px-3 py-2 rounded-lg bg-[var(--sea-foam-soft)] text-xs text-[var(--sea-ink-soft)] space-y-1">
                    {rule.description && <p>{rule.description}</p>}
                    {rule.evidence && <p className="font-mono text-[var(--sea-ink)]">{rule.evidence}</p>}
                    {rule.expected && (
                      <p>Expected: <span className="font-mono">{rule.expected}</span></p>
                    )}
                    {rule.actual && (
                      <p>Actual: <span className="font-mono">{rule.actual}</span></p>
                    )}
                    {rule.remediation && (
                      <p className="text-[var(--signal)]">Fix: {rule.remediation}</p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {data.summary && (
        <p className="text-xs text-[var(--sea-ink-soft)] mt-3 pt-3 border-t border-[var(--sea-foam-soft)]">
          {data.summary}
        </p>
      )}
    </div>
  );
}
