/**
 * Sentinel HTTP API client for the GitHub Action.
 *
 * Calls the Sentinel control-plane REST API to:
 *  - Retrieve open validated findings for a repository
 *  - Get the security posture summary
 *  - Get the sandbox validation summary
 */

export type SentinelFinding = {
  _id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  validationStatus: "validated" | "likely_exploitable" | "pending" | "unexploitable" | "dismissed";
  status: "open" | "pr_opened" | "merged" | "resolved" | "accepted_risk";
  vulnClass: string;
  summary: string;
  blastRadiusSummary: string;
  prUrl?: string;
  pocArtifactUrl?: string;
  affectedFiles: string[];
  affectedPackages: string[];
  createdAt: number;
};

export type SentinelFindingsResponse = {
  findings: SentinelFinding[];
  totalCount: number;
};

export type SentinelPostureResponse = {
  postureScore: number;
  postureLevel: "excellent" | "good" | "fair" | "poor" | "critical";
  topActions: Array<{ title: string; priority: "high" | "medium" | "low" }>;
};

export type SentinelSandboxSummary = {
  totalRuns: number;
  exploited: number;
  likelyExploitable: number;
  withPoc: number;
};

export class SentinelApiClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly tenantSlug: string;
  private readonly repositoryFullName: string;

  constructor(opts: {
    baseUrl: string;
    apiKey: string;
    tenantSlug: string;
    repositoryFullName: string;
  }) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.tenantSlug = opts.tenantSlug;
    this.repositoryFullName = opts.repositoryFullName;
  }

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "X-Sentinel-Api-Key": this.apiKey,
    };
  }

  async getFindings(opts: {
    status?: string;
    severity?: string;
    limit?: number;
  } = {}): Promise<SentinelFindingsResponse> {
    const params = new URLSearchParams({
      tenantSlug: this.tenantSlug,
      repositoryFullName: this.repositoryFullName,
    });
    if (opts.status) params.set("status", opts.status);
    if (opts.severity) params.set("severity", opts.severity);
    if (opts.limit) params.set("limit", String(opts.limit));

    const resp = await fetch(`${this.baseUrl}/api/findings?${params}`, {
      headers: this.headers(),
    });

    if (!resp.ok) {
      throw new Error(`Sentinel API error ${resp.status}: ${await resp.text()}`);
    }

    const data = (await resp.json()) as unknown;
    if (Array.isArray(data)) {
      return { findings: data as SentinelFinding[], totalCount: (data as SentinelFinding[]).length };
    }
    return data as SentinelFindingsResponse;
  }

  async getSecurityPosture(): Promise<SentinelPostureResponse | null> {
    const params = new URLSearchParams({
      tenantSlug: this.tenantSlug,
      repositoryFullName: this.repositoryFullName,
    });

    const resp = await fetch(`${this.baseUrl}/api/reports/security-posture?${params}`, {
      headers: this.headers(),
    });

    if (!resp.ok) return null;
    return resp.json() as Promise<SentinelPostureResponse>;
  }

  async getSandboxSummary(): Promise<SentinelSandboxSummary | null> {
    const params = new URLSearchParams({
      tenantSlug: this.tenantSlug,
      repositoryFullName: this.repositoryFullName,
    });

    const resp = await fetch(`${this.baseUrl}/api/sandbox/summary?${params}`, {
      headers: this.headers(),
    });

    if (!resp.ok) return null;
    return resp.json() as Promise<SentinelSandboxSummary>;
  }
}
