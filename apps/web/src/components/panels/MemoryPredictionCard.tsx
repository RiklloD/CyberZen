import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { useMutation } from "convex/react";
import { X, Target, ThumbsUp, ThumbsDown, MessageSquare, Calendar, TrendingUp, Trash2 } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import MemoryNotesSection from "./MemoryNotesSection";

type Prediction = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPredictions>
>[number];

export default function MemoryPredictionCard({
  prediction,
  repositoryId,
  onClose,
  onPredictionRefresh }: {
  prediction: Prediction;
  repositoryId: string;
  onClose: () => void;
  onPredictionRefresh?: () => void;
}) {
  const [feedbackMode, setFeedbackMode] = useState<'confirmed' | 'disproved' | 'partial' | null>(null);
  const [feedbackText, setFeedbackText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const submitFeedback = useMutation(api.neuralMemory.submitFeedback);
  const resolvePrediction = useMutation(api.neuralMemory.resolvePrediction);

  const handleSubmitFeedback = async () => {
    if (!feedbackMode || !feedbackText.trim()) return;

    setIsSubmitting(true);
    try {
      await submitFeedback({
        predictionId: prediction._id,
        outcome: feedbackMode,
        actualEvent: feedbackText.trim() });
      onClose();
    } catch (error) {
      console.error("Failed to submit feedback:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDismissPrediction = async () => {
    setIsSubmitting(true);
    try {
      await resolvePrediction({
        predictionId: prediction._id,
        outcome: "disproved",
        actualEvent: "User dismissed prediction" });
      onPredictionRefresh?.();
      onClose();
    } catch (error) {
      console.error("Failed to dismiss prediction:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getDaysUntilExpiry = () => {
    if (!prediction.expiresAt) return null;
    const days = Math.ceil((prediction.expiresAt - Date.now()) / (24 * 60 * 60 * 1000));
    return days;
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

  const daysUntilExpiry = getDaysUntilExpiry();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold mb-1">
            {prediction.title}
          </h2>
          <div className="flex flex-wrap gap-2">
            <StatusPill
              label={prediction.predictionType.replace('_', ' ')}
              tone="neutral"
            />
            <StatusPill
              label={prediction.status}
              tone={getStatusTone(prediction.status)}
            />
          </div>
        </div>
        <div className="flex gap-1">
          {prediction.status === "active" && (
            <button
              type="button"
              onClick={handleDismissPrediction}
              disabled={isSubmitting}
              className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
              title="Dismiss prediction"
            >
              <Trash2 className="w-4 h-4 text-[var(--sea-red)]" />
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Description */}
      <div className="card card-sm">
        <p className="panel-label mb-2">Prediction Details</p>
        <p className="text-sm text-[var(--sea-ink-soft)]">
          {prediction.description}
        </p>
      </div>

      {/* Confidence & Timeline */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-4 h-4 text-[var(--sea-blue)]" />
            <p className="panel-label">Confidence</p>
          </div>
          <div className="flex items-center gap-2 mb-2">
            <div className="flex-1 bg-[rgba(130,122,110,0.1)] rounded-full h-2">
              <div
                className="h-full bg-[var(--sea-blue)] rounded-full transition-all"
                style={{ width: `${prediction.confidence * 100}%` }}
              />
            </div>
            <span className="text-lg font-mono font-semibold">
              {Math.round(prediction.confidence * 100)}%
            </span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Based on {prediction.basedOnPatternIds.length} learned patterns
          </p>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-2">
            <Calendar className="w-4 h-4 text-[var(--sea-purple)]" />
            <p className="panel-label">Timeline</p>
          </div>
          <div className="space-y-1">
            <div className="text-sm">
              <span className="text-[var(--sea-ink-soft)]">Created:</span>
              <span className="ml-1 font-mono">{formatTimestamp(prediction.createdAt)}</span>
            </div>
            {prediction.expiresAt && (
              <div className="text-sm">
                <span className="text-[var(--sea-ink-soft)]">Expires:</span>
                <span className={`ml-1 font-mono ${
                  daysUntilExpiry !== null && daysUntilExpiry <= 3
                    ? "text-[var(--sea-red)]"
                    : ""
                }`}>
                  {daysUntilExpiry !== null
                    ? daysUntilExpiry > 0
                      ? `${daysUntilExpiry} days`
                      : "Expired"
                    : formatTimestamp(prediction.expiresAt)
                  }
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Outcome */}
      {prediction.outcome && (
        <div className="card card-sm">
          <p className="panel-label mb-2">Actual Outcome</p>
          <p className="text-sm text-[var(--sea-ink-soft)]">
            {prediction.outcome}
          </p>
        </div>
      )}

      {/* Feedback Section (only for active predictions) */}
      {prediction.status === "active" && (
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-3">
            <MessageSquare className="w-4 h-4 text-[var(--sea-yellow)]" />
            <p className="panel-label">Provide Feedback</p>
          </div>

          {!feedbackMode ? (
            <div className="space-y-3">
              <p className="text-sm text-[var(--sea-ink-soft)]">
                Help improve Neural Memory by providing feedback on this prediction:
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setFeedbackMode('confirmed')}
                  className="flex items-center gap-1 px-3 py-1 bg-[var(--sea-green)] text-white rounded text-sm"
                >
                  <ThumbsUp className="w-3 h-3" />
                  Confirmed
                </button>
                <button
                  type="button"
                  onClick={() => setFeedbackMode('partial')}
                  className="flex items-center gap-1 px-3 py-1 bg-[var(--sea-yellow)] text-white rounded text-sm"
                >
                  <Target className="w-3 h-3" />
                  Partially Correct
                </button>
                <button
                  type="button"
                  onClick={() => setFeedbackMode('disproved')}
                  className="flex items-center gap-1 px-3 py-1 bg-[var(--sea-red)] text-white rounded text-sm"
                >
                  <ThumbsDown className="w-3 h-3" />
                  Incorrect
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">
                  Feedback: {feedbackMode.charAt(0).toUpperCase() + feedbackMode.slice(1)}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setFeedbackMode(null);
                    setFeedbackText("");
                  }}
                  className="text-xs text-[var(--sea-ink-soft)] hover:text-[var(--sea-ink)]"
                >
                  Change
                </button>
              </div>

              <textarea
                value={feedbackText}
                onChange={(e) => setFeedbackText(e.target.value)}
                placeholder="Please describe what actually happened..."
                className="w-full h-20 p-2 text-sm border border-[var(--sea-gray-light)] rounded resize-none"
                disabled={isSubmitting}
              />

              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleSubmitFeedback}
                  disabled={!feedbackText.trim() || isSubmitting}
                  className="px-3 py-1 bg-[var(--sea-green)] text-white rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? "Submitting..." : "Submit Feedback"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFeedbackMode(null);
                    setFeedbackText("");
                  }}
                  className="px-3 py-1 border border-[var(--sea-gray-light)] rounded text-sm"
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Notes Section */}
      <MemoryNotesSection
        targetId={prediction._id}
        targetType="prediction"
        repositoryId={repositoryId}
      />
    </div>
  );
}