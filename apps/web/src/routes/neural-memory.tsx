import { createFileRoute } from "@tanstack/react-router";
import type { FunctionReturnType } from "convex/server";
import { useQuery } from "convex/react";
import { Brain } from "lucide-react";
import { useState } from "react";
import QueryErrorFallback from "../components/QueryErrorFallback";
import NeuralMemoryDashboard from "../components/panels/NeuralMemoryDashboard";
import MemoryPatternList from "../components/panels/MemoryPatternList";
import MemoryPatternDetail from "../components/panels/MemoryPatternDetail";
import MemoryPredictionFeed from "../components/panels/MemoryPredictionFeed";
import MemoryEpisodeTimeline from "../components/panels/MemoryEpisodeTimeline";
import MemoryInsightsPanel from "../components/panels/MemoryInsightsPanel";
import MemorySettingsPanel from "../components/panels/MemorySettingsPanel";
import { api } from "../lib/convex";
import { useTenantSlug } from "../lib/workspace";

export const Route = createFileRoute("/neural-memory")({
  errorComponent: QueryErrorFallback,
  component: NeuralMemoryPage,
});

type Tab = "dashboard" | "patterns" | "predictions" | "episodes" | "insights" | "settings";
type OverviewData = NonNullable<FunctionReturnType<typeof api.dashboard.overview>>;
type OverviewRepository = OverviewData["repositories"][number];
type Pattern = FunctionReturnType<typeof api.neuralMemory.getPatterns>[number];

const TABS: { id: Tab; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "patterns", label: "Patterns" },
  { id: "predictions", label: "Predictions" },
  { id: "episodes", label: "Episodes" },
  { id: "insights", label: "Insights" },
  { id: "settings", label: "Settings" },
];

function NeuralMemoryPage() {
  const TENANT = useTenantSlug();
  const overview = useQuery(api.dashboard.overview, { tenantSlug: TENANT });
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [selectedPattern, setSelectedPattern] = useState<Pattern | null>(null);

  if (!overview) {
    return (
      <main className="page-body-padded">
        <div className="grid gap-3 sm:grid-cols-2">
          {["a", "b"].map((k) => (
            <div key={k} className="loading-panel h-40 rounded-2xl" />
          ))}
        </div>
      </main>
    );
  }

  const { repositories } = overview;
  const activeRepo: OverviewRepository | undefined = selectedRepo
    ? repositories.find((r: OverviewRepository) => r._id === selectedRepo)
    : repositories[0];

  return (
    <main>
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Brain size={20} className="text-[var(--signal)]" />
          <div>
            <h1 className="page-title">Neural Memory</h1>
            <p className="page-subtitle">
              Adaptive learning · Pattern detection · Predictive intelligence
            </p>
          </div>
        </div>
      </div>

      <div className="page-body">
        <div className="tab-bar mb-4">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`tab-btn ${activeTab === tab.id ? "is-active" : ""}`}
              onClick={() => { setActiveTab(tab.id); setSelectedPattern(null); }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab !== "insights" && repositories.length > 1 && (
          <div className="tab-bar mb-4">
            {repositories.map((r: OverviewRepository) => (
              <button
                key={r._id}
                type="button"
                className={`tab-btn ${activeRepo?._id === r._id ? "is-active" : ""}`}
                onClick={() => setSelectedRepo(r._id)}
              >
                {r.fullName.split("/").pop()}
              </button>
            ))}
          </div>
        )}

        {activeRepo && activeTab === "dashboard" && (
          <NeuralMemoryDashboard
            repositoryId={activeRepo._id}
            onTabChange={(tab) => { setActiveTab(tab as Tab); setSelectedPattern(null); }}
          />
        )}

        {activeRepo && activeTab === "patterns" && (
          selectedPattern ? (
            <MemoryPatternDetail pattern={selectedPattern} repositoryId={activeRepo._id} onClose={() => setSelectedPattern(null)} />
          ) : (
            <MemoryPatternList repositoryId={activeRepo._id} onPatternSelect={setSelectedPattern} />
          )
        )}

        {activeRepo && activeTab === "predictions" && (
          <MemoryPredictionFeed repositoryId={activeRepo._id} />
        )}

        {activeRepo && activeTab === "episodes" && (
          <MemoryEpisodeTimeline repositoryId={activeRepo._id} />
        )}

        {activeTab === "insights" && (
          <MemoryInsightsPanel tenantSlug={TENANT} />
        )}

        {activeRepo && activeTab === "settings" && (
          <MemorySettingsPanel repositoryId={activeRepo._id} />
        )}
      </div>
    </main>
  );
}
