import { useState, useTransition } from "react";
import { useMutation } from "convex/react";
import { PlusCircle, X } from "lucide-react";
import { api } from "../../lib/convex";

interface MemoryLogEpisodeModalProps {
  open: boolean;
  repositoryId: string;
  onClose: () => void;
  onSuccess?: () => void;
}

const EPISODE_TYPES = [
  { value: "finding", label: "Security Finding" },
  { value: "breach", label: "Security Breach" },
  { value: "fix", label: "Security Fix" },
  { value: "gate_block", label: "Gate Block" },
  { value: "false_positive", label: "False Positive" },
  { value: "scan_result", label: "Scan Result" },
  { value: "deployment", label: "Deployment" },
] as const;

export default function MemoryLogEpisodeModal({
  open,
  repositoryId,
  onClose,
  onSuccess,
}: MemoryLogEpisodeModalProps) {
  const [episodeType, setEpisodeType] = useState<
    "finding" | "breach" | "fix" | "gate_block" | "false_positive" | "scan_result" | "deployment"
  >("finding");
  const [description, setDescription] = useState("");
  const [sourceRef, setSourceRef] = useState("");
  const [isPending, startTransition] = useTransition();
  const [result, setResult] = useState<string | null>(null);

  const recordEpisode = useMutation(api.neuralMemory.recordEpisode);

  if (!open) return null;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!description.trim()) return;

    setResult(null);
    startTransition(async () => {
      try {
        await recordEpisode({
          repositoryId,
          episodeType,
          payload: {
            description: description.trim(),
            userGenerated: true,
            timestamp: Date.now(),
          },
          sourceRef: sourceRef.trim() || `manual-${Date.now()}`,
        });
        setResult("Episode logged successfully!");
        setDescription("");
        setSourceRef("");
        setEpisodeType("finding");
        onSuccess?.();
      } catch (error) {
        console.error("Failed to log episode:", error);
        setResult("Failed to log episode. Please try again.");
      }
    });
  }

  function handleBackdropClick(e: React.MouseEvent) {
    if (e.target === e.currentTarget) onClose();
  }

  function handleDone() {
    setResult(null);
    setDescription("");
    setSourceRef("");
    setEpisodeType("finding");
    onClose();
  }

  return (
    <div
      onClick={handleBackdropClick}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0, 0, 0, 0.44)",
        backdropFilter: "blur(2px)",
      }}
    >
      <div
        className="card"
        style={{
          width: "min(520px, 92vw)",
          maxHeight: "90vh",
          overflowY: "auto",
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <PlusCircle size={18} className="text-[var(--sea-blue)]" />
            <h2 className="text-sm font-bold text-[var(--sea-ink)]">
              Log Memory Episode
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {result ? (
          <div className="space-y-3">
            <p className={`text-xs ${result.includes("successfully")
              ? "text-[var(--sea-green)]"
              : "text-[var(--sea-red)]"}`}>
              {result}
            </p>
            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={handleDone}
                className="signal-button"
                style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
              >
                Done
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="episode-type"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Episode Type *
              </label>
              <select
                id="episode-type"
                value={episodeType}
                onChange={(e) => setEpisodeType(e.target.value as typeof episodeType)}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
              >
                {EPISODE_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                The type of security event or episode you're recording.
              </p>
            </div>

            <div>
              <label
                htmlFor="episode-description"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Description *
              </label>
              <textarea
                id="episode-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
                placeholder="Describe what happened, the context, and any relevant details..."
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none"
                rows={4}
              />
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                Provide context and details that will help the neural memory system learn patterns.
              </p>
            </div>

            <div>
              <label
                htmlFor="source-ref"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Source Reference (optional)
              </label>
              <input
                id="source-ref"
                type="text"
                value={sourceRef}
                onChange={(e) => setSourceRef(e.target.value)}
                placeholder="e.g., ticket ID, PR URL, commit hash..."
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
              />
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                A reference to track this episode back to its source (ticket, PR, etc.).
              </p>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                disabled={isPending}
                className="signal-button secondary-button"
                style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isPending || !description.trim()}
                className="signal-button"
                style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
              >
                {isPending ? "Logging…" : "Log Episode"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}