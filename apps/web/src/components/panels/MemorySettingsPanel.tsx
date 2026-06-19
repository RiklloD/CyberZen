import { useState, useEffect } from "react";
import { useQuery, useMutation } from "convex/react";
import { Settings, Save } from "lucide-react";
import { api } from "../../lib/convex";
import { PanelSkeleton } from "./SharedPanelComponents";

type MemorySettings = {
  episodesBeforePattern?: number;
  predictionHorizonDays?: number;
  patternExpiryDays?: number;
  enabledAlgorithms?: {
    patternDetection?: boolean;
    predictionGeneration?: boolean;
    falsePositiveLearning?: boolean;
    temporalAnalysis?: boolean;
  };
};

const ALGORITHMS = [
  { key: "patternDetection" as const, label: "Pattern Detection", desc: "Identify recurring vulnerability and fix patterns" },
  { key: "predictionGeneration" as const, label: "Prediction Generation", desc: "Generate forward-looking risk predictions" },
  { key: "falsePositiveLearning" as const, label: "False Positive Learning", desc: "Learn from dismissed findings to reduce noise" },
  { key: "temporalAnalysis" as const, label: "Temporal Analysis", desc: "Detect time-based patterns in security events" },
];

export default function MemorySettingsPanel({ repositoryId }: { repositoryId: string }) {
  const memory = useQuery(api.neuralMemory.getProjectMemory, { repositoryId });
  const updateSettings = useMutation(api.neuralMemory.updateMemorySettings);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const storedSettings: MemorySettings =
    memory && "settings" in memory && memory.settings ? (memory.settings as MemorySettings) : {};

  const [episodes, setEpisodes] = useState(storedSettings.episodesBeforePattern ?? 3);
  const [horizon, setHorizon] = useState(storedSettings.predictionHorizonDays ?? 30);
  const [expiry, setExpiry] = useState(storedSettings.patternExpiryDays ?? 90);
  const [algorithms, setAlgorithms] = useState({
    patternDetection: storedSettings.enabledAlgorithms?.patternDetection ?? true,
    predictionGeneration: storedSettings.enabledAlgorithms?.predictionGeneration ?? true,
    falsePositiveLearning: storedSettings.enabledAlgorithms?.falsePositiveLearning ?? true,
    temporalAnalysis: storedSettings.enabledAlgorithms?.temporalAnalysis ?? false });

  useEffect(() => {
    if (!memory || !("settings" in memory) || !memory.settings) return;
    const s = memory.settings as MemorySettings;
    if (s.episodesBeforePattern !== undefined) setEpisodes(s.episodesBeforePattern);
    if (s.predictionHorizonDays !== undefined) setHorizon(s.predictionHorizonDays);
    if (s.patternExpiryDays !== undefined) setExpiry(s.patternExpiryDays);
    if (s.enabledAlgorithms) {
      setAlgorithms({
        patternDetection: s.enabledAlgorithms.patternDetection ?? true,
        predictionGeneration: s.enabledAlgorithms.predictionGeneration ?? true,
        falsePositiveLearning: s.enabledAlgorithms.falsePositiveLearning ?? true,
        temporalAnalysis: s.enabledAlgorithms.temporalAnalysis ?? false });
    }
  }, [memory]);

  if (memory === undefined) return <PanelSkeleton count={2} />;

  async function handleSave() {
    setSaving(true);
    try {
      await updateSettings({
        repositoryId,
        settings: { episodesBeforePattern: episodes, predictionHorizonDays: horizon, patternExpiryDays: expiry, enabledAlgorithms: algorithms } });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="card card-sm">
        <div className="flex items-center gap-2 mb-4">
          <Settings className="w-4 h-4" />
          <p className="panel-label">Learning Configuration</p>
        </div>

        <div className="space-y-5">
          <div>
            <label className="text-sm font-medium block mb-1">
              Episodes Before Pattern Creation
            </label>
            <p className="text-xs text-[var(--sea-ink-soft)] mb-2">
              Minimum similar episodes required to form a new pattern
            </p>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={2}
                max={10}
                value={episodes}
                onChange={(e) => setEpisodes(Number(e.target.value))}
                className="flex-1"
              />
              <span className="font-mono text-sm w-6 text-center">{episodes}</span>
            </div>
          </div>

          <div>
            <label className="text-sm font-medium block mb-1">
              Prediction Horizon (days)
            </label>
            <p className="text-xs text-[var(--sea-ink-soft)] mb-2">
              How far ahead predictions should look
            </p>
            <input
              type="number"
              min={7}
              max={365}
              value={horizon}
              onChange={(e) => setHorizon(Number(e.target.value))}
              className="w-24 text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent font-mono"
            />
          </div>

          <div>
            <label className="text-sm font-medium block mb-1">
              Pattern Expiry (days)
            </label>
            <p className="text-xs text-[var(--sea-ink-soft)] mb-2">
              Inactive patterns older than this are automatically archived
            </p>
            <input
              type="number"
              min={30}
              max={730}
              value={expiry}
              onChange={(e) => setExpiry(Number(e.target.value))}
              className="w-24 text-sm border border-[var(--sea-gray-light)] rounded px-2 py-1 bg-transparent font-mono"
            />
          </div>
        </div>
      </div>

      <div className="card card-sm">
        <p className="panel-label mb-4">Learning Algorithms</p>
        <div className="space-y-3">
          {ALGORITHMS.map(({ key, label, desc }) => (
            <div key={key} className="flex items-start gap-3">
              <button
                type="button"
                role="switch"
                aria-checked={algorithms[key]}
                onClick={() => setAlgorithms((prev) => ({ ...prev, [key]: !prev[key] }))}
                className={`mt-0.5 relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors ${
                  algorithms[key] ? "bg-[var(--sea-green)]" : "bg-[var(--sea-gray-light)]"
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
                    algorithms[key] ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </button>
              <div>
                <p className="text-sm font-medium">{label}</p>
                <p className="text-xs text-[var(--sea-ink-soft)]">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="signal-button flex items-center gap-2"
        >
          <Save className="w-4 h-4" />
          {saving ? "Saving…" : "Save Settings"}
        </button>
        {saved && <span className="text-xs text-[var(--sea-green)]">Settings saved</span>}
      </div>
    </div>
  );
}
