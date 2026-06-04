import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { useQuery } from "convex/react";
import { Filter, Target, AlertTriangle, Lightbulb, MapPin, X, Calendar } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import { PanelSkeleton } from "./SharedPanelComponents";
import MemoryPredictionCard from "./MemoryPredictionCard";

type Prediction = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPredictions>
>[number];

export default function MemoryPredictionFeed({
  repositoryId,
}: {
  repositoryId: string;
}) {
  const [statusFilter, setStatusFilter] = useState<string>("active");
  const [selectedPrediction, setSelectedPrediction] = useState<Prediction | null>(null);

  const predictions = useQuery(api.neuralMemory.getPredictions, {
    repositoryId,
    status: statusFilter === "all" ? undefined : statusFilter as any,
  });

  if (predictions === undefined) {
    return <PanelSkeleton count={3} />;
  }

  const statusOptions = [
    { value: "active", label: "Active" },
    { value: "confirmed", label: "Confirmed" },
    { value: "disproved", label: "Disproved" },
    { value: "expired", label: "Expired" },
    { value: "all", label: "All" },
  ];

  const getPredictionIcon = (type: string) => {
    switch (type) {
      case "vulnerability_likelihood": return AlertTriangle;
      case "remediation_suggestion": return Lightbulb;
      case "risk_area": return MapPin;
      case "false_positive_candidate": return X;
      case "deployment_risk": return Calendar;
      default: return Target;
    }
  };

  const getPredictionTypeLabel = (type: string) => {
    switch (type) {
      case "vulnerability_likelihood": return "Vulnerability Risk";
      case "remediation_suggestion": return "Fix Suggestion";
      case "risk_area": return "Risk Area";
      case "false_positive_candidate": return "False Positive";
      case "deployment_risk": return "Deployment Risk";
      default: return type;
    }
  };

  const getStatusTone = (status: string) => {
    switch (status) {
      case "active": return "neutral";
      case "confirmed": return "success";
      case "disproved": return "danger";
      case "expired": return "warning";
      default: return "neutral";
    }
  };

  const getDaysUntilExpiry = (expiresAt: number | undefined) => {
    if (!expiresAt) return null;
    const days = Math.ceil((expiresAt - Date.now()) / (24 * 60 * 60 * 1000));
    return days;
  };

  if (selectedPrediction) {
    return (
      <MemoryPredictionCard
        prediction={selectedPrediction}
        repositoryId={repositoryId}
        onClose={() => setSelectedPrediction(null)}
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-[var(--sea-ink-soft)]" />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent"
        >
          {statusOptions.map(option => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      {/* Predictions List */}
      <div className="space-y-3">
        {predictions.length === 0 ? (
          <div className="card card-sm text-center py-8">
            <Target className="w-8 h-8 mx-auto mb-2 text-[var(--sea-ink-soft)]" />
            <p className="text-sm text-[var(--sea-ink-soft)]">
              {statusFilter === "active"
                ? "No active predictions"
                : "No predictions found matching your filter"
              }
            </p>
          </div>
        ) : (
          predictions.map((prediction: Prediction) => {
            const IconComponent = getPredictionIcon(prediction.predictionType);
            const daysUntilExpiry = getDaysUntilExpiry(prediction.expiresAt);

            return (
              <button
                key={prediction._id}
                type="button"
                onClick={() => setSelectedPrediction(prediction)}
                className="card card-sm w-full text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded ${
                    prediction.status === "active"
                      ? "bg-[rgba(158,255,100,0.1)]"
                      : prediction.status === "confirmed"
                      ? "bg-[rgba(34,197,94,0.1)]"
                      : "bg-[rgba(130,122,110,0.1)]"
                  }`}>
                    <IconComponent className={`w-4 h-4 ${
                      prediction.status === "active"
                        ? "text-[var(--sea-green)]"
                        : prediction.status === "confirmed"
                        ? "text-green-600"
                        : "text-[var(--sea-ink-soft)]"
                    }`} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-sm font-medium truncate">
                        {prediction.title}
                      </h3>
                      <StatusPill
                        label={prediction.status}
                        tone={getStatusTone(prediction.status)}
                      />
                    </div>

                    <p className="text-xs text-[var(--sea-ink-soft)] mb-2 line-clamp-2">
                      {prediction.description}
                    </p>

                    <div className="flex flex-wrap gap-2 mb-2">
                      <StatusPill
                        label={getPredictionTypeLabel(prediction.predictionType)}
                        tone="neutral"
                      />

                      {/* Confidence */}
                      <div className="flex items-center gap-1">
                        <div className="w-12 bg-[rgba(130,122,110,0.1)] rounded-full h-1.5">
                          <div
                            className="h-full bg-[var(--sea-blue)] rounded-full transition-all"
                            style={{ width: `${prediction.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-[var(--sea-ink-soft)]">
                          {Math.round(prediction.confidence * 100)}%
                        </span>
                      </div>

                      {prediction.basedOnPatternIds.length > 0 && (
                        <StatusPill
                          label={`${prediction.basedOnPatternIds.length} patterns`}
                          tone="neutral"
                        />
                      )}
                    </div>

                    <div className="flex items-center justify-between text-xs text-[var(--sea-ink-soft)]">
                      <span>Created {formatTimestamp(prediction.createdAt)}</span>
                      {daysUntilExpiry !== null && prediction.status === "active" && (
                        <span className={
                          daysUntilExpiry <= 3
                            ? "text-[var(--sea-red)]"
                            : daysUntilExpiry <= 7
                            ? "text-[var(--sea-yellow)]"
                            : ""
                        }>
                          {daysUntilExpiry > 0
                            ? `${daysUntilExpiry} days left`
                            : "Expired"
                          }
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}