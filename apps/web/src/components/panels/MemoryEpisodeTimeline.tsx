import type { FunctionReturnType } from "convex/server";
import { useState, useMemo } from "react";
import { useQuery, useMutation } from "convex/react";
import { Filter, Activity, AlertTriangle, CheckCircle, Shield, X, Search, Calendar, Download } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import { PanelSkeleton } from "./SharedPanelComponents";
import MemoryNotesSection from "./MemoryNotesSection";

type Episode = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getEpisodes>
>[number];

export default function MemoryEpisodeTimeline({
  repositoryId,
}: {
  repositoryId: string;
}) {
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [limit, setLimit] = useState(50);
  const [selectedEpisode, setSelectedEpisode] = useState<Episode | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [showExportMenu, setShowExportMenu] = useState(false);

  const episodes = useQuery(api.neuralMemory.getEpisodes, {
    repositoryId,
    type: typeFilter === "all" ? undefined : typeFilter as any,
    limit,
  });

  const exportEpisodesCsv = useMutation(api.neuralMemory.exportEpisodesCsv);

  const filteredEpisodes = useMemo(() => {
    if (!episodes || !searchTerm.trim()) return episodes || [];
    const term = searchTerm.toLowerCase();
    return episodes.filter((episode: Episode) => {
      const payloadText = JSON.stringify(episode.payload || {}).toLowerCase();
      return payloadText.includes(term) || episode.sourceRef.toLowerCase().includes(term);
    });
  }, [episodes, searchTerm]);

  if (episodes === undefined) {
    return <PanelSkeleton count={4} />;
  }

  const episodeTypes = [
    { value: "all", label: "All Episodes" },
    { value: "finding", label: "Findings" },
    { value: "fix", label: "Fixes" },
    { value: "gate_block", label: "Gate Blocks" },
    { value: "false_positive", label: "False Positives" },
    { value: "scan_result", label: "Scan Results" },
    { value: "deployment", label: "Deployments" },
    { value: "breach", label: "Breaches" },
  ];

  const getEpisodeIcon = (type: string) => {
    switch (type) {
      case "finding": return AlertTriangle;
      case "fix": return CheckCircle;
      case "gate_block": return Shield;
      case "false_positive": return X;
      case "scan_result": return Search;
      case "deployment": return Calendar;
      default: return Activity;
    }
  };

  const getEpisodeColor = (type: string) => {
    switch (type) {
      case "finding": return "var(--sea-red)";
      case "fix": return "var(--sea-green)";
      case "gate_block": return "var(--sea-blue)";
      case "false_positive": return "var(--sea-gray)";
      case "scan_result": return "var(--sea-purple)";
      case "deployment": return "var(--sea-yellow)";
      default: return "var(--sea-ink-soft)";
    }
  };

  const formatPayload = (payload: any) => {
    if (!payload) return "No details available";

    const details = [];
    if (payload.severity) details.push(`Severity: ${payload.severity}`);
    if (payload.cwe) details.push(`CWE: ${payload.cwe}`);
    if (payload.filePath) details.push(`File: ${payload.filePath}`);
    if (payload.ruleId) details.push(`Rule: ${payload.ruleId}`);
    if (payload.action) details.push(`Action: ${payload.action}`);
    if (payload.fixType) details.push(`Fix Type: ${payload.fixType}`);
    if (payload.decision) details.push(`Decision: ${payload.decision}`);
    if (payload.outcome) details.push(`Outcome: ${payload.outcome}`);

    return details.length > 0 ? details.join(" • ") : "Processing...";
  };

  const handleExport = async (format: 'csv' | 'json') => {
    setShowExportMenu(false);
    try {
      if (format === 'csv') {
        const csvContent = await exportEpisodesCsv({
          repositoryId: repositoryId as any,
          episodeType: typeFilter === "all" ? undefined : typeFilter as any,
          limit,
        });
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `memory-episodes-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const jsonData = JSON.stringify(filteredEpisodes, null, 2);
        const blob = new Blob([jsonData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `memory-episodes-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error("Failed to export episodes:", error);
    }
  };

  if (selectedEpisode) {
    return (
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Episode Details</h3>
          <button
            type="button"
            onClick={() => setSelectedEpisode(null)}
            className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Episode Detail */}
        <div className="card card-sm">
          <div className="flex items-start gap-3 mb-4">
            {(() => {
              const IconComponent = getEpisodeIcon(selectedEpisode.episodeType);
              return (
                <div
                  className="p-2 rounded"
                  style={{ backgroundColor: `${getEpisodeColor(selectedEpisode.episodeType)}20` }}
                >
                  <IconComponent
                    className="w-5 h-5"
                    style={{ color: getEpisodeColor(selectedEpisode.episodeType) }}
                  />
                </div>
              );
            })()}
            <div>
              <StatusPill
                label={selectedEpisode.episodeType.replace('_', ' ')}
                tone="neutral"
              />
              <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
                {formatTimestamp(selectedEpisode.timestamp)}
              </p>
            </div>
          </div>

          <div className="space-y-4">
            {/* Source Reference */}
            <div>
              <p className="text-sm font-medium mb-1">Source Reference</p>
              <p className="text-sm font-mono bg-[rgba(130,122,110,0.05)] p-2 rounded">
                {selectedEpisode.sourceRef}
              </p>
            </div>

            {/* Processing Status */}
            <div>
              <p className="text-sm font-medium mb-1">Processing Status</p>
              <StatusPill
                label={selectedEpisode.processed ? "Processed" : "Pending"}
                tone={selectedEpisode.processed ? "success" : "warning"}
              />
            </div>

            {/* Features */}
            {selectedEpisode.embedding.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2">Extracted Features</p>
                <div className="flex flex-wrap gap-1">
                  {selectedEpisode.embedding.map((feature: string, index: number) => (
                    <span
                      key={index}
                      className="px-2 py-1 bg-[rgba(130,122,110,0.1)] rounded text-xs font-mono"
                    >
                      {feature}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Payload */}
            <div>
              <p className="text-sm font-medium mb-2">Event Data</p>
              <div className="bg-[rgba(130,122,110,0.05)] rounded p-3">
                <pre className="text-xs overflow-auto">
                  {JSON.stringify(selectedEpisode.payload, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>

        {/* Notes */}
        <MemoryNotesSection
          targetId={selectedEpisode._id}
          targetType="episode"
          repositoryId={repositoryId}
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search + Export */}
      <div className="flex gap-2 items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[var(--sea-ink-soft)]" />
          <input
            type="text"
            placeholder="Search episodes by payload or source ref..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-sm border border-[var(--sea-gray-light)] rounded-lg bg-[var(--surface)] focus:outline-none focus:ring-2 focus:ring-[var(--sea-blue)]"
          />
        </div>
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
            <div className="absolute top-full right-0 mt-1 bg-white border border-[var(--line)] rounded shadow-lg z-10">
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

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[var(--sea-ink-soft)]" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent"
          >
            {episodeTypes.map(type => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-sm text-[var(--sea-ink-soft)]">Show:</label>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent"
          >
            <option value={25}>25 episodes</option>
            <option value={50}>50 episodes</option>
            <option value={100}>100 episodes</option>
            <option value={200}>200 episodes</option>
          </select>
        </div>
      </div>

      {/* Timeline */}
      <div className="space-y-3">
        {filteredEpisodes.length === 0 ? (
          <div className="card card-sm text-center py-8">
            <Activity className="w-8 h-8 mx-auto mb-2 text-[var(--sea-ink-soft)]" />
            <p className="text-sm text-[var(--sea-ink-soft)]">
              {searchTerm ? "No episodes match your search" : "No episodes found matching your filters"}
            </p>
          </div>
        ) : (
          filteredEpisodes.map((episode: Episode, index: number) => {
            const IconComponent = getEpisodeIcon(episode.episodeType);
            const isLast = index === filteredEpisodes.length - 1;

            return (
              <div key={episode._id} className="relative">
                {/* Timeline line */}
                {!isLast && (
                  <div
                    className="absolute left-6 top-12 bottom-0 w-0.5 bg-[rgba(130,122,110,0.2)]"
                    style={{ marginLeft: "-1px" }}
                  />
                )}

                <button
                  type="button"
                  onClick={() => setSelectedEpisode(episode)}
                  className="card card-sm w-full text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div
                      className="p-2 rounded flex-shrink-0"
                      style={{
                        backgroundColor: `${getEpisodeColor(episode.episodeType)}20`
                      }}
                    >
                      <IconComponent
                        className="w-4 h-4"
                        style={{ color: getEpisodeColor(episode.episodeType) }}
                      />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <StatusPill
                          label={episode.episodeType.replace('_', ' ')}
                          tone="neutral"
                        />
                        {!episode.processed && (
                          <StatusPill label="pending" tone="warning" />
                        )}
                      </div>

                      <p className="text-xs text-[var(--sea-ink-soft)] mb-2">
                        {formatPayload(episode.payload)}
                      </p>

                      <div className="flex justify-between items-center">
                        <p className="text-xs text-[var(--sea-ink-soft)]">
                          {formatTimestamp(episode.timestamp)}
                        </p>
                        <p className="text-xs font-mono text-[var(--sea-ink-soft)]">
                          {episode.embedding.length} features
                        </p>
                      </div>
                    </div>
                  </div>
                </button>
              </div>
            );
          })
        )}
      </div>

      {/* Load More */}
      {episodes.length >= limit && (
        <div className="text-center">
          <button
            type="button"
            onClick={() => setLimit(limit + 50)}
            className="px-4 py-2 text-sm border border-[var(--sea-gray-light)] rounded hover:bg-[rgba(130,122,110,0.05)] transition-colors"
          >
            Load More Episodes
          </button>
        </div>
      )}
    </div>
  );
}
