import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { useQuery } from "convex/react";
import { Brain, TrendingUp, Target, Activity, Plus } from "lucide-react";
import StatusPill from "../StatusPill";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";
import { PanelSkeleton } from "./SharedPanelComponents";
import MemoryHealthGauge from "./MemoryHealthGauge";
import PredictionAccuracyChart from "./PredictionAccuracyChart";
import MemoryLogEpisodeModal from "./MemoryLogEpisodeModal";
import MemoryCreatePatternModal from "./MemoryCreatePatternModal";

type ProjectMemory = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getProjectMemory>
>;

type PredictionAccuracy = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPredictionAccuracy>
>;

export default function NeuralMemoryDashboard({
  repositoryId,
  onTabChange }: {
  repositoryId: string;
  onTabChange: (tab: string) => void;
}) {
  const [showLogModal, setShowLogModal] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const memory = useQuery(api.neuralMemory.getProjectMemory, { repositoryId });
  const accuracy = useQuery(api.neuralMemory.getPredictionAccuracy, { repositoryId });

  if (memory === undefined || accuracy === undefined) {
    return <PanelSkeleton count={2} className="grid-cols-1" />;
  }

  // Calculate memory health score (0-100)
  const healthScore = calculateMemoryHealth(memory, accuracy);

  return (
    <div className="space-y-6">
      {/* Memory Health Overview */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5 text-[var(--sea-green)]" />
            <p className="panel-label">Neural Memory Health</p>
          </div>
          <MemoryHealthGauge score={healthScore} size={120} />
          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-[var(--sea-ink-soft)]">Coverage</span>
              <span className="font-mono">{Math.round(memory.memoryStats.coverageScore * 100)}%</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--sea-ink-soft)]">Patterns</span>
              <span className="font-mono">{memory.memoryStats.totalPatterns}</span>
            </div>
          </div>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2 mb-3">
            <Target className="w-5 h-5 text-[var(--sea-blue)]" />
            <p className="panel-label">Prediction Accuracy</p>
          </div>
          <PredictionAccuracyChart accuracy={accuracy} />
          <div className="mt-3 flex flex-wrap gap-1.5">
            <StatusPill
              label={`${Math.round(accuracy.accuracy * 100)}% accurate`}
              tone={accuracy.accuracy > 0.8 ? "success" : accuracy.accuracy > 0.6 ? "neutral" : "danger"}
            />
            <StatusPill
              label={`${accuracy.totalPredictions} predictions`}
              tone="neutral"
            />
          </div>
        </div>
      </div>

      {/* Memory Statistics */}
      <div className="grid gap-4 sm:grid-cols-4">
        <div className="card card-sm">
          <p className="panel-label">Episodes Learned</p>
          <p className="text-2xl font-mono font-semibold mt-1">
            {memory.memoryStats.totalEpisodes.toLocaleString()}
          </p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Security events processed
          </p>
        </div>

        <div className="card card-sm">
          <p className="panel-label">Active Patterns</p>
          <p className="text-2xl font-mono font-semibold mt-1">
            {memory.memoryStats.totalPatterns}
          </p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Behavioral insights discovered
          </p>
        </div>

        <div className="card card-sm">
          <p className="panel-label">Confirmed Predictions</p>
          <p className="text-2xl font-mono font-semibold mt-1 text-[var(--sea-green)]">
            {accuracy.confirmed}
          </p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Out of {accuracy.totalPredictions} total
          </p>
        </div>

        <div className="card card-sm">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4" />
            <p className="panel-label">Last Learning</p>
          </div>
          <p className="text-sm mt-1">
            {memory.lastLearningAt
              ? formatTimestamp(memory.lastLearningAt)
              : "Never"
            }
          </p>
          <p className="text-xs text-[var(--sea-ink-soft)] mt-1">
            Memory version {memory.version}
          </p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid gap-3 sm:grid-cols-3">
        <button
          type="button"
          onClick={() => onTabChange('patterns')}
          className="card card-sm text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
        >
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-4 h-4 text-[var(--sea-green)]" />
            <span className="text-sm font-medium">View Patterns</span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Explore learned behavioral patterns and their confidence levels
          </p>
        </button>

        <button
          type="button"
          onClick={() => onTabChange('predictions')}
          className="card card-sm text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
        >
          <div className="flex items-center gap-2 mb-2">
            <Target className="w-4 h-4 text-[var(--sea-blue)]" />
            <span className="text-sm font-medium">Active Predictions</span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Review forward-looking insights and provide feedback
          </p>
        </button>

        <button
          type="button"
          onClick={() => onTabChange('episodes')}
          className="card card-sm text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
        >
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-4 h-4 text-[var(--sea-purple)]" />
            <span className="text-sm font-medium">Episode Timeline</span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Browse raw security events feeding into memory
          </p>
        </button>

        <button
          type="button"
          onClick={() => setShowLogModal(true)}
          className="card card-sm text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
        >
          <div className="flex items-center gap-2 mb-2">
            <Plus className="w-4 h-4 text-[var(--sea-yellow)]" />
            <span className="text-sm font-medium">Log Episode</span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Manually record a security event
          </p>
        </button>

        <button
          type="button"
          onClick={() => setShowCreateModal(true)}
          className="card card-sm text-left hover:border-[rgba(158,255,100,0.35)] transition-colors"
        >
          <div className="flex items-center gap-2 mb-2">
            <Plus className="w-4 h-4 text-[var(--sea-purple)]" />
            <span className="text-sm font-medium">Create Pattern</span>
          </div>
          <p className="text-xs text-[var(--sea-ink-soft)]">
            Manually define a behavioral security pattern
          </p>
        </button>
      </div>

      {/* Modals */}
      <MemoryLogEpisodeModal
        open={showLogModal}
        repositoryId={repositoryId}
        onClose={() => setShowLogModal(false)}
      />
      <MemoryCreatePatternModal
        open={showCreateModal}
        repositoryId={repositoryId}
        onClose={() => setShowCreateModal(false)}
      />
    </div>
  );
}

// Calculate memory health score based on coverage, patterns, and accuracy
function calculateMemoryHealth(memory: ProjectMemory, accuracy: PredictionAccuracy): number {
  const coverageWeight = 0.3;
  const patternsWeight = 0.3;
  const accuracyWeight = 0.4;

  // Normalize patterns count (assume 10+ patterns = 100%)
  const patternsScore = Math.min(1.0, memory.memoryStats.totalPatterns / 10);

  const healthScore =
    (memory.memoryStats.coverageScore * coverageWeight) +
    (patternsScore * patternsWeight) +
    (accuracy.accuracy * accuracyWeight);

  return Math.round(healthScore * 100);
}
