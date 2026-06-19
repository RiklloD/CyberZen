import type { FunctionReturnType } from "convex/server";
import { useState, useMemo } from "react";
import { useQuery, useMutation } from "convex/react";
import { Filter, TrendingUp, AlertTriangle, Code, Clock, Shield, CheckCircle, Search, Plus, Download, X } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp, severityTone } from "../../lib/utils";
import { PanelSkeleton } from "./SharedPanelComponents";
import MemoryCreatePatternModal from "./MemoryCreatePatternModal";

type Pattern = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPatterns>
>[number];

export default function MemoryPatternList({
  repositoryId,
  onPatternSelect,
  onPatternRefresh }: {
  repositoryId: string;
  onPatternSelect: (pattern: Pattern) => void;
  onPatternRefresh?: () => void;
}) {
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [activeFilter, setActiveFilter] = useState<boolean | undefined>(undefined);
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  const patterns = useQuery(api.neuralMemory.getPatterns, {
    repositoryId,
    type: typeFilter === "all" ? undefined : typeFilter as any,
    active: activeFilter });

  const dismissPattern = useMutation(api.neuralMemory.dismissPattern);
  const exportPatternsCsv = useMutation(api.neuralMemory.exportPatternsCsv);

  // Filter patterns by search term
  const filteredPatterns = useMemo(() => {
    if (!patterns || !searchTerm.trim()) return patterns || [];

    const term = searchTerm.toLowerCase();
    return patterns.filter((pattern: Pattern) =>
      pattern.name.toLowerCase().includes(term) ||
      pattern.description.toLowerCase().includes(term)
    );
  }, [patterns, searchTerm]);

  if (patterns === undefined) {
    return <PanelSkeleton count={3} />;
  }

  const patternTypes = [
    { value: "all", label: "All Patterns" },
    { value: "recurring_vulnerability", label: "Vulnerabilities" },
    { value: "recurring_fix", label: "Fixes" },
    { value: "code_path_risk", label: "Risk Areas" },
    { value: "dependency_risk", label: "Dependencies" },
    { value: "false_positive_signal", label: "False Positives" },
    { value: "temporal_pattern", label: "Temporal" },
    { value: "developer_pattern", label: "Developer" },
  ];

  const getPatternIcon = (type: string) => {
    switch (type) {
      case "recurring_vulnerability": return AlertTriangle;
      case "recurring_fix": return CheckCircle;
      case "code_path_risk": return Code;
      case "dependency_risk": return Shield;
      case "temporal_pattern": return Clock;
      default: return TrendingUp;
    }
  };

  const handleDismissPattern = async (patternId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await dismissPattern({ patternId, dismissReason: "User dismissed" });
      onPatternRefresh?.();
    } catch (error) {
      console.error("Failed to dismiss pattern:", error);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    setShowExportMenu(false);
    try {
      if (format === 'csv') {
        const csvContent = await exportPatternsCsv({
          repositoryId,
          patternType: typeFilter === "all" ? undefined : typeFilter as any,
          active: activeFilter });

        // Download CSV
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `memory-patterns-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        // Export as JSON
        const jsonData = JSON.stringify(filteredPatterns, null, 2);
        const blob = new Blob([jsonData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `memory-patterns-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error("Failed to export patterns:", error);
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[var(--sea-ink-soft)]" />
        <input
          type="text"
          placeholder="Search patterns..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-10 pr-4 py-2 text-sm border border-[var(--sea-gray-light)] rounded-lg bg-[var(--surface)] focus:outline-none focus:ring-2 focus:ring-[var(--sea-blue)]"
        />
      </div>

      {/* Action Buttons */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-[var(--sea-purple)] text-white text-sm rounded hover:bg-[var(--sea-purple-dark)]"
          >
            <Plus className="w-3 h-3" />
            Create Pattern
          </button>

          <div className="relative">
            <button
              type="button"
              onClick={() => setShowExportMenu(!showExportMenu)}
              className="flex items-center gap-2 px-3 py-1.5 bg-[var(--sea-blue)] text-white text-sm rounded hover:bg-[var(--sea-blue-dark)]"
            >
              <Download className="w-3 h-3" />
              Export
            </button>
            {showExportMenu && (
              <div className="absolute top-full left-0 mt-1 bg-white border border-[var(--line)] rounded shadow-lg z-10">
                <button
                  type="button"
                  onClick={() => handleExport('csv')}
                  className="block w-full text-left px-4 py-2 text-sm hover:bg-[rgba(130,122,110,0.1)]"
                >
                  Export as CSV
                </button>
                <button
                  type="button"
                  onClick={() => handleExport('json')}
                  className="block w-full text-left px-4 py-2 text-sm hover:bg-[rgba(130,122,110,0.1)]"
                >
                  Export as JSON
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[var(--sea-ink-soft)]" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent"
          >
            {patternTypes.map(type => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => setActiveFilter(undefined)}
            className={`px-2 py-1 text-xs rounded ${
              activeFilter === undefined
                ? "bg-[var(--sea-green)] text-white"
                : "bg-[rgba(130,122,110,0.1)] text-[var(--sea-ink-soft)]"
            }`}
          >
            All
          </button>
          <button
            type="button"
            onClick={() => setActiveFilter(true)}
            className={`px-2 py-1 text-xs rounded ${
              activeFilter === true
                ? "bg-[var(--sea-green)] text-white"
                : "bg-[rgba(130,122,110,0.1)] text-[var(--sea-ink-soft)]"
            }`}
          >
            Active
          </button>
          <button
            type="button"
            onClick={() => setActiveFilter(false)}
            className={`px-2 py-1 text-xs rounded ${
              activeFilter === false
                ? "bg-[var(--sea-green)] text-white"
                : "bg-[rgba(130,122,110,0.1)] text-[var(--sea-ink-soft)]"
            }`}
          >
            Inactive
          </button>
        </div>
      </div>

      {/* Pattern List */}
      <div className="space-y-3">
        {filteredPatterns.length === 0 ? (
          <div className="card card-sm text-center py-8">
            <TrendingUp className="w-8 h-8 mx-auto mb-2 text-[var(--sea-ink-soft)]" />
            <p className="text-sm text-[var(--sea-ink-soft)]">
              {searchTerm ? "No patterns match your search" : "No patterns found matching your filters"}
            </p>
          </div>
        ) : (
          filteredPatterns.map((pattern: Pattern) => {
            const IconComponent = getPatternIcon(pattern.patternType);

            return (
              <button
                key={pattern._id}
                type="button"
                onClick={() => onPatternSelect(pattern)}
                className="group card card-sm w-full text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded ${
                    pattern.isActive
                      ? "bg-[rgba(158,255,100,0.1)]"
                      : "bg-[rgba(130,122,110,0.1)]"
                  }`}>
                    <IconComponent className={`w-4 h-4 ${
                      pattern.isActive
                        ? "text-[var(--sea-green)]"
                        : "text-[var(--sea-ink-soft)]"
                    }`} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-medium truncate">
                          {pattern.name}
                        </h3>
                        {!pattern.isActive && (
                          <StatusPill label="inactive" tone="neutral" />
                        )}
                      </div>
                      {pattern.isActive && (
                        <button
                          type="button"
                          onClick={(e) => handleDismissPattern(pattern._id, e)}
                          className="p-1 hover:bg-[rgba(130,122,110,0.2)] rounded opacity-0 group-hover:opacity-100 transition-opacity"
                          title="Dismiss pattern"
                        >
                          <X className="w-3 h-3 text-[var(--sea-ink-soft)]" />
                        </button>
                      )}
                    </div>

                    <p className="text-xs text-[var(--sea-ink-soft)] mb-2 line-clamp-2">
                      {pattern.description}
                    </p>

                    <div className="flex flex-wrap gap-2">
                      {/* Confidence */}
                      <div className="flex items-center gap-1">
                        <div className="w-12 bg-[rgba(130,122,110,0.1)] rounded-full h-1.5">
                          <div
                            className="h-full bg-[var(--sea-green)] rounded-full transition-all"
                            style={{ width: `${pattern.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-[var(--sea-ink-soft)]">
                          {Math.round(pattern.confidence * 100)}%
                        </span>
                      </div>

                      <StatusPill
                        label={`${pattern.frequency} episodes`}
                        tone="neutral"
                      />

                      <StatusPill
                        label={pattern.severity}
                        tone={severityTone(pattern.severity)}
                      />
                    </div>

                    <div className="flex items-center gap-4 mt-2 text-xs text-[var(--sea-ink-soft)]">
                      <span>First seen {formatTimestamp(pattern.firstSeenAt)}</span>
                      <span>Last seen {formatTimestamp(pattern.lastSeenAt)}</span>
                    </div>
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>

      {/* Create Pattern Modal */}
      <MemoryCreatePatternModal
        open={showCreateModal}
        repositoryId={repositoryId}
        onClose={() => setShowCreateModal(false)}
        onSuccess={() => onPatternRefresh?.()}
      />
    </div>
  );
}