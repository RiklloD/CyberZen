import type { SentinelFinding, SentinelFindingsResponse, SentinelPostureReport } from "./types.js";
import type { SentinelConfig } from "./config.js";

/** Thin HTTP client for the Sentinel REST API (no vscode dependency — testable in isolation). */
export class SentinelClient {
  constructor(private readonly config: SentinelConfig) {}

  // ─── Private helpers ────────────────────────────────────────────────────────

  private headers(): Record<string, string> {
    return {
      "X-Sentinel-Api-Key": this.config.apiKey,
      Accept: "application/json",
    };
  }

  private url(path: string, params: Record<string, string> = {}): string {
    const u = new URL(`${this.config.apiUrl.replace(/\/$/, "")}${path}`);
    for (const [k, v] of Object.entries(params)) {
      if (v) u.searchParams.set(k, v);
    }
    return u.toString();
  }

  private async get<T>(path: string, params: Record<string, string> = {}): Promise<T> {
    const res = await fetch(this.url(path, params), {
      method: "GET",
      headers: this.headers(),
    });
    if (!res.ok) {
      throw new Error(`Sentinel API ${path} returned ${res.status}: ${await res.text()}`);
    }
    return res.json() as Promise<T>;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Fetch all active findings for the configured repository (up to 200). */
  async getFindings(): Promise<SentinelFinding[]> {
    const data = await this.get<SentinelFindingsResponse>("/api/findings", {
      tenantSlug: this.config.tenantSlug,
      repositoryFullName: this.config.repositoryFullName,
      limit: "200",
    });
    return data.findings ?? [];
  }

  /** Fetch the current security posture report for the repository. */
  async getPostureReport(): Promise<SentinelPostureReport | null> {
    try {
      return await this.get<SentinelPostureReport>("/api/reports/security-posture", {
        tenantSlug: this.config.tenantSlug,
        repositoryFullName: this.config.repositoryFullName,
      });
    } catch {
      // Posture report is optional — degrade gracefully when unavailable
      return null;
    }
  }

  /** Trigger an immediate scan via the advisory sync endpoint (best-effort). */
  async triggerScan(): Promise<void> {
    await fetch(this.url("/api/threat-intel/cisa-kev/sync"), {
      method: "POST",
      headers: this.headers(),
    }).catch(() => {
      // Fire-and-forget — ignore network errors
    });
  }
}
