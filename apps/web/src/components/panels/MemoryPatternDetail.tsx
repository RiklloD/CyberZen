import type { FunctionReturnType } from "convex/server";
import { X, TrendingUp, Calendar, Hash, Activity } from "lucide-react";
import StatusPill from "../StatusPill";
import type { api } from "../../lib/convex";
import { formatTimestamp, severityTone } from "../../lib/utils";
import MemoryNotesSection from "./MemoryNotesSection";

type Pattern = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPatterns>
>[number];

export default function MemoryPatternDetail({
  pattern,
  repositoryId,
  onClose,
  onNavigateToPattern }: {
  pattern: Pattern;
  repositoryId: string;
  onClose: () => void;
  onNavigateToPattern?: (patternId: string) => void;
}) {
  // Parse attributes to show structured data
  const attributes = pattern.attributes as any;
  const commonFeatures = attributes?.commonFeatures || [];
  const episodeIds = attributes?.episodeIds || [];
  const timeSpan = attributes?.timeSpan;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold mb-1">
            {pattern.name}
          </h2>
          <div className="flex flex-wrap gap-2">
            <StatusPill
              label={pattern.patternType.replace('_', ' ')}
              tone="neutral"
            />
            <StatusPill
              label={pattern.severity}
              tone={severityTone(pattern.severity)}
            />
            {pattern.isActive ? (
              <StatusPill label="active" tone="success" />
            ) : (
              <StatusPill label="inactive" tone="neutral" />
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Description */}
      <div className="card card-sm">
        <p className="panel-label mb-2">Description</p>
        <p className="text-sm text-[var(--sea-ink-soft)]">
          {pattern.description}
        </p>
      </div>

      {/* Confidence & Frequency */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-4 h-4 text-[var(--sea-green)]" />
            <p className="panel-label">Confidence</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-[rgba(130,122,110,0.1)] rounded-full h-2">
              <div
                className="h-full bg-[var(--sea-green)] rounded-full transition-all"
                style={{ width: `${pattern.confidence * 100}%` }}
              />
            </div>
            <span className="text-lg font-mono font-semibold">
              {Math.round(pattern.confidence * 100)}%
            </span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Based on {pattern.frequency} similar episodes
          </p>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-2">
            <Hash className="w-4 h-4 text-[var(--sea-blue)]" />
            <p className="panel-label">Frequency</p>
          </div>
          <p className="text-2xl font-mono font-semibold">
            {pattern.frequency}
          </p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Episodes contributed to this pattern
          </p>
        </div>
      </div>

      {/* Timeline */}
      <div className="card card-sm">
        <div className="flex items-center gap-2 mb-3">
          <Calendar className="w-4 h-4 text-[var(--sea-purple)]" />
          <p className="panel-label">Timeline</p>
        </div>
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-[var(--sea-ink-soft)]">First detected:</span>
            <span className="font-mono">{formatTimestamp(pattern.firstSeenAt)}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-[var(--sea-ink-soft)]">Last seen:</span>
            <span className="font-mono">{formatTimestamp(pattern.lastSeenAt)}</span>
          </div>
          {timeSpan && (
            <div className="flex justify-between text-sm">
              <span className="text-[var(--sea-ink-soft)]">Time span:</span>
              <span className="font-mono">
                {Math.round(timeSpan / (24 * 60 * 60 * 1000))} days
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Common Features */}
      {commonFeatures.length > 0 && (
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-4 h-4 text-[var(--sea-yellow)]" />
            <p className="panel-label">Common Characteristics</p>
          </div>
          <div className="flex flex-wrap gap-1">
            {commonFeatures.map((feature: string, index: number) => (
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

      {/* Contributing Episodes */}
      <div className="card card-sm">
        <p className="panel-label mb-3">Contributing Episodes</p>
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-[var(--sea-ink-soft)]">Episodes analyzed:</span>
            <span className="font-mono">{episodeIds.length}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-[var(--sea-ink-soft)]">Pattern strength:</span>
            <span className="font-mono">
              {episodeIds.length >= 5 ? "Strong" :
               episodeIds.length >= 3 ? "Moderate" : "Weak"}
            </span>
          </div>
        </div>
      </div>

      {/* Related Patterns */}
      {pattern.relatedPatternIds.length > 0 && (
        <div className="card card-sm">
          <p className="panel-label mb-3">Related Patterns</p>
          <div className="space-y-2">
            {pattern.relatedPatternIds.map((relatedId: string) => (
              <button
                key={relatedId}
                type="button"
                onClick={() => onNavigateToPattern?.(relatedId)}
                className="w-full text-left p-2 hover:bg-[rgba(130,122,110,0.1)] rounded border border-[rgba(130,122,110,0.2)] text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[var(--sea-blue)] font-mono">#{relatedId.slice(-8)}</span>
                  <span className="text-[var(--sea-ink-soft)]">→</span>
                  <span className="text-[var(--sea-ink)]">Click to view pattern</span>
                </div>
              </button>
            ))}
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-2 italic">
            {pattern.relatedPatternIds.length} related patterns detected
          </p>
        </div>
      )}

      {/* Notes Section */}
      <MemoryNotesSection
        targetId={pattern._id}
        targetType="pattern"
        repositoryId={repositoryId}
      />
    </div>
  );
}