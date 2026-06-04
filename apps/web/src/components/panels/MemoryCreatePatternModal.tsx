import { useState, useTransition } from "react";
import { useMutation } from "convex/react";
import { Plus, X } from "lucide-react";
import { api } from "../../lib/convex";

interface MemoryCreatePatternModalProps {
  open: boolean;
  repositoryId: string;
  onClose: () => void;
  onSuccess?: () => void;
}

const PATTERN_TYPES = [
  { value: "recurring_vulnerability", label: "Recurring Vulnerability", description: "Vulnerabilities that appear repeatedly with similar characteristics" },
  { value: "recurring_fix", label: "Recurring Fix", description: "Fix patterns that have been successful multiple times" },
  { value: "developer_pattern", label: "Developer Pattern", description: "Team or developer-specific security patterns" },
  { value: "temporal_pattern", label: "Temporal Pattern", description: "Time-based patterns in security events" },
  { value: "dependency_risk", label: "Dependency Risk", description: "Patterns related to specific dependencies" },
  { value: "code_path_risk", label: "Code Path Risk", description: "High-risk areas in the codebase" },
  { value: "false_positive_signal", label: "False Positive Signal", description: "Patterns indicating likely false positives" },
] as const;

const SEVERITY_LEVELS = [
  { value: "critical", label: "Critical", description: "Immediate attention required" },
  { value: "high", label: "High", description: "High priority, address soon" },
  { value: "medium", label: "Medium", description: "Medium priority" },
  { value: "low", label: "Low", description: "Low priority" },
  { value: "informational", label: "Informational", description: "For reference only" },
] as const;

export default function MemoryCreatePatternModal({
  open,
  repositoryId,
  onClose,
  onSuccess,
}: MemoryCreatePatternModalProps) {
  const [patternType, setPatternType] = useState<
    "recurring_vulnerability" | "recurring_fix" | "developer_pattern" | "temporal_pattern" | "dependency_risk" | "code_path_risk" | "false_positive_signal"
  >("recurring_vulnerability");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<"critical" | "high" | "medium" | "low" | "informational">("medium");
  const [attributes, setAttributes] = useState("");
  const [isPending, startTransition] = useTransition();
  const [result, setResult] = useState<string | null>(null);

  const createUserPattern = useMutation(api.neuralMemory.createUserPattern);

  if (!open) return null;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !description.trim()) return;

    setResult(null);
    startTransition(async () => {
      try {
        // Parse attributes as JSON if provided, otherwise use empty object
        let parsedAttributes = {};
        if (attributes.trim()) {
          try {
            parsedAttributes = JSON.parse(attributes);
          } catch {
            // If JSON parsing fails, treat it as key-value pairs
            const lines = attributes.split('\n');
            parsedAttributes = lines.reduce((acc, line) => {
              const [key, ...valueParts] = line.split(':');
              if (key && valueParts.length > 0) {
                acc[key.trim()] = valueParts.join(':').trim();
              }
              return acc;
            }, {} as Record<string, string>);
          }
        }

        await createUserPattern({
          repositoryId,
          patternData: {
            patternType,
            name: name.trim(),
            description: description.trim(),
            severity,
            attributes: parsedAttributes,
          },
        });

        setResult("Pattern created successfully!");
        setName("");
        setDescription("");
        setAttributes("");
        setSeverity("medium");
        setPatternType("recurring_vulnerability");
        onSuccess?.();
      } catch (error) {
        console.error("Failed to create pattern:", error);
        setResult("Failed to create pattern. Please try again.");
      }
    });
  }

  function handleBackdropClick(e: React.MouseEvent) {
    if (e.target === e.currentTarget) onClose();
  }

  function handleDone() {
    setResult(null);
    setName("");
    setDescription("");
    setAttributes("");
    setSeverity("medium");
    setPatternType("recurring_vulnerability");
    onClose();
  }

  const selectedPatternType = PATTERN_TYPES.find(t => t.value === patternType);
  const selectedSeverity = SEVERITY_LEVELS.find(s => s.value === severity);

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
          width: "min(560px, 92vw)",
          maxHeight: "90vh",
          overflowY: "auto",
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Plus size={18} className="text-[var(--sea-purple)]" />
            <h2 className="text-sm font-bold text-[var(--sea-ink)]">
              Create Custom Pattern
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
                htmlFor="pattern-type"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Pattern Type *
              </label>
              <select
                id="pattern-type"
                value={patternType}
                onChange={(e) => setPatternType(e.target.value as typeof patternType)}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
              >
                {PATTERN_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              {selectedPatternType && (
                <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                  {selectedPatternType.description}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="pattern-name"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Pattern Name *
              </label>
              <input
                id="pattern-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                placeholder="e.g., SQL injection in user input handlers"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
              />
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                A descriptive name for this pattern that helps identify it.
              </p>
            </div>

            <div>
              <label
                htmlFor="pattern-description"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Description *
              </label>
              <textarea
                id="pattern-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
                placeholder="Describe the pattern, when it occurs, and what makes it significant..."
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none"
                rows={3}
              />
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                Provide details that will help the neural memory system recognize similar instances.
              </p>
            </div>

            <div>
              <label
                htmlFor="pattern-severity"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Severity Level *
              </label>
              <select
                id="pattern-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as typeof severity)}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)]"
              >
                {SEVERITY_LEVELS.map((level) => (
                  <option key={level.value} value={level.value}>
                    {level.label}
                  </option>
                ))}
              </select>
              {selectedSeverity && (
                <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                  {selectedSeverity.description}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="pattern-attributes"
                className="block text-xs font-semibold text-[var(--sea-ink)] mb-1"
              >
                Attributes (optional)
              </label>
              <textarea
                id="pattern-attributes"
                value={attributes}
                onChange={(e) => setAttributes(e.target.value)}
                placeholder={`Either JSON format:
{"cwe": "CWE-89", "framework": "express"}

Or key-value pairs:
cwe: CWE-89
framework: express
file_pattern: *.js`}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--sea-ink)] placeholder:text-[var(--sea-ink-soft)] focus:outline-none focus:ring-2 focus:ring-[var(--signal)] resize-none font-mono"
                rows={4}
              />
              <p className="mt-1 text-[10px] text-[var(--sea-ink-soft)]">
                Additional metadata in JSON format or key-value pairs (one per line).
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
                disabled={isPending || !name.trim() || !description.trim()}
                className="signal-button"
                style={{ padding: "0.5rem 0.9rem", fontSize: "0.78rem" }}
              >
                {isPending ? "Creating…" : "Create Pattern"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}