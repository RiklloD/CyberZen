import type { SentinelFinding, SentinelPostureReport, StoreSnapshot } from "./types.js";
import type { SentinelClient } from "./sentinelClient.js";

type Listener = (snapshot: StoreSnapshot) => void;

/**
 * Centralised observable store for Sentinel data.
 *
 * All VS Code providers (DiagnosticsProvider, CodeLensProvider, StatusBarItem)
 * subscribe to this store rather than making independent API calls. This ensures
 * a single refresh cycle and consistent state across all UI surfaces.
 */
export class FindingStore {
  private findings: SentinelFinding[] = [];
  private posture: SentinelPostureReport | null = null;
  private lastRefreshedAt: Date | null = null;
  private isLoading = false;
  private error: string | null = null;
  private listeners: Set<Listener> = new Set();
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly client: SentinelClient,
    private readonly refreshIntervalMs: number,
  ) {}

  // ─── Subscription ───────────────────────────────────────────────────────────

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    // Immediately deliver the current snapshot to the new subscriber
    listener(this.snapshot());
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    const snap = this.snapshot();
    for (const l of this.listeners) l(snap);
  }

  snapshot(): StoreSnapshot {
    return {
      findings: [...this.findings],
      posture: this.posture,
      lastRefreshedAt: this.lastRefreshedAt,
      isLoading: this.isLoading,
      error: this.error,
    };
  }

  // ─── Data loading ───────────────────────────────────────────────────────────

  async refresh(): Promise<void> {
    this.isLoading = true;
    this.error = null;
    this.notify();

    try {
      const [findings, posture] = await Promise.all([
        this.client.getFindings(),
        this.client.getPostureReport(),
      ]);
      this.findings = findings;
      this.posture = posture;
      this.lastRefreshedAt = new Date();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.isLoading = false;
      this.notify();
    }
  }

  // ─── Lifecycle ───────────────────────────────────────────────────────────────

  startAutoRefresh(): void {
    this.stopAutoRefresh();
    // Fire immediately, then on the configured interval
    void this.refresh();
    this.refreshTimer = setInterval(() => void this.refresh(), this.refreshIntervalMs);
  }

  stopAutoRefresh(): void {
    if (this.refreshTimer !== null) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  dispose(): void {
    this.stopAutoRefresh();
    this.listeners.clear();
  }
}
