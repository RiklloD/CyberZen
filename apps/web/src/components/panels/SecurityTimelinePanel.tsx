/**
 * SecurityTimelinePanel — §1.20
 *
 * Chronological event stream for a repository's security lifecycle.
 * Filter chips let the user narrow by category (finding, gate, fix, escalation).
 * Each event node is collapsible to reveal detail/metadata.
 */

import type { FunctionReturnType } from "convex/server";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  GitMerge,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Skull,
  Wrench,
  Eye,
  Zap,
  FileCheck2,
  Unlock,
  LockOpen,
  Bug,
  type LucideIcon } from "lucide-react";
import { useState } from "react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────

type TimelineEntry = NonNullable<
  FunctionReturnType<
    typeof api.securityTimelineIntel.getSecurityTimelineForRepository
  >
>[number];

type EventCounts = NonNullable<
  FunctionReturnType<
    typeof api.securityTimelineIntel.getTimelineEventCountsByType
  >
>;

// ── Filter categories ──────────────────────────────────────────────────────

type FilterCategory = "all" | "finding" | "gate" | "fix" | "escalation";

const FILTER_OPTIONS: {
  key: FilterCategory;
  label: string;
  eventTypes: string[];
}[] = [
  {
    key: "all",
    label: "All Events",
    eventTypes: [] },
  {
    key: "finding",
    label: "Findings",
    eventTypes: ["finding_created", "finding_triaged", "secret_detected"] },
  {
    key: "gate",
    label: "Gates",
    eventTypes: [
      "gate_blocked",
      "gate_approved",
      "gate_overridden",
      "sla_breached",
    ] },
  {
    key: "fix",
    label: "Fixes",
    eventTypes: [
      "pr_opened",
      "pr_merged",
      "auto_remediation_dispatched",
    ] },
  {
    key: "escalation",
    label: "Escalations",
    eventTypes: [
      "finding_escalated",
      "risk_accepted",
      "risk_revoked",
      "red_agent_win",
    ] },
];

// ── Icon + tone per event type ─────────────────────────────────────────────

function eventIcon(eventType: string): LucideIcon {
  switch (eventType) {
    case "finding_created":
      return AlertTriangle;
    case "finding_escalated":
      return Zap;
    case "finding_triaged":
      return FileCheck2;
    case "gate_blocked":
      return ShieldAlert;
    case "gate_approved":
      return ShieldCheck;
    case "gate_overridden":
      return ShieldOff;
    case "pr_opened":
      return GitMerge;
    case "pr_merged":
      return GitMerge;
    case "sla_breached":
      return Shield;
    case "risk_accepted":
      return LockOpen;
    case "risk_revoked":
      return Unlock;
    case "red_agent_win":
      return Skull;
    case "auto_remediation_dispatched":
      return Wrench;
    case "secret_detected":
      return Eye;
    default:
      return Bug;
  }
}

function eventTone(eventType: string): "success" | "danger" | "warning" | "neutral" | "info" {
  switch (eventType) {
    case "finding_created":
    case "sla_breached":
    case "red_agent_win":
    case "secret_detected":
    case "gate_blocked":
      return "danger";
    case "finding_escalated":
      return "warning";
    case "gate_approved":
    case "pr_merged":
    case "risk_revoked":
      return "success";
    case "gate_overridden":
      return "warning";
    case "pr_opened":
    case "auto_remediation_dispatched":
    case "finding_triaged":
    case "risk_accepted":
      return "info";
    default:
      return "neutral";
  }
}

function eventTypeLabel(eventType: string): string {
  return eventType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Props ──────────────────────────────────────────────────────────────────

export interface SecurityTimelinePanelProps {
  events: TimelineEntry[] | undefined;
  counts: EventCounts | undefined;
  /** Event ID to scroll to (for deep linking). */
  highlightId?: string | null;
}

// ── Component ──────────────────────────────────────────────────────────────

export default function SecurityTimelinePanel({
  events,
  counts,
  highlightId }: SecurityTimelinePanelProps) {
  const [activeFilter, setActiveFilter] = useState<FilterCategory>("all");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  // Loading state
  if (!events) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-[var(--signal)]" />
          <h3 className="section-title">Security Timeline</h3>
        </div>
        <div className="flex flex-wrap gap-2">
          {["a", "b", "c", "d", "e"].map((k) => (
            <div key={k} className="loading-panel h-7 w-20 rounded-full" />
          ))}
        </div>
        <div className="grid gap-3">
          {["a", "b", "c", "d"].map((k) => (
            <div key={k} className="loading-panel h-20 rounded-2xl" />
          ))}
        </div>
      </div>
    );
  }

  // Filter events
  const filterDef = FILTER_OPTIONS.find((f) => f.key === activeFilter)!;
  const filtered =
    activeFilter === "all"
      ? events
      : events.filter((e) => filterDef.eventTypes.includes(e.eventType));

  // Toggle expanded state
  function toggleExpand(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  // Count per filter category
  function filterCount(key: FilterCategory): number {
    if (!counts) return 0;
    if (key === "all") return counts.total;
    const def = FILTER_OPTIONS.find((f) => f.key === key)!;
    return def.eventTypes.reduce(
      (sum, et) => sum + ((counts as Record<string, number>)[et] ?? 0),
      0,
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Shield size={16} className="text-[var(--signal)]" />
        <h3 className="section-title">Security Timeline</h3>
        <StatusPill label={`${events.length} events`} tone="neutral" />
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        {FILTER_OPTIONS.map((opt) => (
          <button
            key={opt.key}
            type="button"
            onClick={() => setActiveFilter(opt.key)}
            className={`tab-btn ${activeFilter === opt.key ? "is-active" : ""}`}
          >
            {opt.label}
            {filterCount(opt.key) > 0 && (
              <span className="ml-1.5 text-[var(--sea-ink-soft)]">
                ({filterCount(opt.key)})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Timeline stream */}
      <div className="space-y-2">
        {filtered.map((event) => {
          const Icon = eventIcon(event.eventType);
          const isExpanded = expandedIds.has(event.id);
          const isHighlighted = highlightId === event.id;
          const tone = eventTone(event.eventType);

          return (
            <div
              key={event.id}
              id={`timeline-${event.id}`}
              className={`card card-sm transition-colors ${
                isHighlighted
                  ? "border-[var(--signal)] ring-1 ring-[var(--signal)]"
                  : ""
              }`}
            >
              <button
                type="button"
                onClick={() => toggleExpand(event.id)}
                className="w-full text-left flex items-start gap-3"
              >
                {/* Timeline connector dot */}
                <div
                  className={`mt-0.5 flex-shrink-0 rounded-full p-1.5 ${
                    tone === "danger"
                      ? "bg-[rgba(220,38,38,0.12)] text-[var(--danger)]"
                      : tone === "warning"
                        ? "bg-[rgba(217,119,6,0.12)] text-[var(--warning)]"
                        : tone === "success"
                          ? "bg-[rgba(5,150,105,0.12)] text-[var(--success)]"
                          : "bg-[rgba(130,122,110,0.1)] text-[var(--sea-ink-soft)]"
                  }`}
                >
                  <Icon size={14} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusPill
                      label={eventTypeLabel(event.eventType)}
                      tone={tone}
                    />
                    {event.severity && (
                      <StatusPill label={event.severity} tone={tone} />
                    )}
                    <span className="text-xs text-[var(--sea-ink-soft)] ml-auto">
                      {formatTimestamp(event.timestamp)}
                    </span>
                  </div>
                  <p className="mt-1 text-sm font-medium text-[var(--sea-ink)] truncate">
                    {event.title}
                  </p>
                  {!isExpanded && (
                    <p className="mt-0.5 text-xs text-[var(--sea-ink-soft)] truncate">
                      {event.detail}
                    </p>
                  )}
                </div>

                {/* Expand chevron */}
                <span className="flex-shrink-0 mt-1 text-[var(--sea-ink-soft)]">
                  {isExpanded ? (
                    <ChevronDown size={14} />
                  ) : (
                    <ChevronRight size={14} />
                  )}
                </span>
              </button>

              {/* Collapsible detail */}
              {isExpanded && (
                <div className="mt-2 ml-8 pt-2 border-t border-[var(--line)]">
                  <p className="text-xs text-[var(--sea-ink-soft)]">
                    {event.detail}
                  </p>
                  {Object.keys(event.metadata).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {Object.entries(event.metadata).map(([k, v]) => (
                        <StatusPill
                          key={k}
                          label={`${k}: ${v}`}
                          tone="neutral"
                        />
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {filtered.length === 0 && (
          <div className="empty-state border border-dashed border-[var(--line)] rounded-2xl">
            <Shield size={24} className="mb-2 opacity-40" />
            <p>No events match the current filter.</p>
          </div>
        )}
      </div>
    </div>
  );
}
