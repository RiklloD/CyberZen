import type { FunctionReturnType } from "convex/server";
import type { api } from "../../lib/convex";

type PredictionAccuracy = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getPredictionAccuracy>
>;

export default function PredictionAccuracyChart({
  accuracy }: {
  accuracy: PredictionAccuracy;
}) {
  const { confirmed, disproved, partial, totalPredictions } = accuracy;

  // Calculate percentages
  const confirmedPct = totalPredictions > 0 ? (confirmed / totalPredictions) * 100 : 0;
  const partialPct = totalPredictions > 0 ? (partial / totalPredictions) * 100 : 0;
  const disprovedPct = totalPredictions > 0 ? (disproved / totalPredictions) * 100 : 0;

  if (totalPredictions === 0) {
    return (
      <div className="flex items-center justify-center h-16">
        <p className="text-sm text-[var(--sea-ink-soft)]">
          No predictions yet
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Bar chart */}
      <div className="h-6 bg-[rgba(130,122,110,0.1)] rounded-full overflow-hidden flex">
        {confirmed > 0 && (
          <div
            className="bg-[var(--sea-green)] transition-all duration-500"
            style={{ width: `${confirmedPct}%` }}
            title={`${confirmed} confirmed`}
          />
        )}
        {partial > 0 && (
          <div
            className="bg-[var(--sea-yellow)] transition-all duration-500"
            style={{ width: `${partialPct}%` }}
            title={`${partial} partially correct`}
          />
        )}
        {disproved > 0 && (
          <div
            className="bg-[var(--sea-red)] transition-all duration-500"
            style={{ width: `${disprovedPct}%` }}
            title={`${disproved} disproved`}
          />
        )}
      </div>

      {/* Legend */}
      <div className="flex gap-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 bg-[var(--sea-green)] rounded" />
          <span className="text-[var(--sea-ink-soft)]">
            Confirmed ({confirmed})
          </span>
        </div>
        {partial > 0 && (
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 bg-[var(--sea-yellow)] rounded" />
            <span className="text-[var(--sea-ink-soft)]">
              Partial ({partial})
            </span>
          </div>
        )}
        {disproved > 0 && (
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 bg-[var(--sea-red)] rounded" />
            <span className="text-[var(--sea-ink-soft)]">
              Disproved ({disproved})
            </span>
          </div>
        )}
      </div>
    </div>
  );
}