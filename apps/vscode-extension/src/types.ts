// ─── Sentinel API response shapes ────────────────────────────────────────────

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export type FindingStatus =
  | "candidate"
  | "validated"
  | "pr_opened"
  | "resolved"
  | "false_positive"
  | "ignored"
  | "accepted_risk";

export interface SentinelFinding {
  _id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: FindingStatus;
  vulnClass?: string;
  affectedPackages?: string[];
  cveIds?: string[];
  repositoryId: string;
  createdAt: number;
  prUrl?: string;
  validationStatus?: "validated" | "likely_exploitable" | "unexploitable" | "unknown";
  blastRadiusTier?: "critical" | "severe" | "moderate" | "minimal";
  escalatedSeverity?: Severity;
}

export interface SentinelFindingsResponse {
  findings: SentinelFinding[];
  total: number;
  page: number;
  pageSize: number;
}

export interface SentinelPostureReport {
  repositoryId: string;
  tenantSlug: string;
  repositoryFullName: string;
  postureScore: number; // 0–100
  postureLevel: "secure" | "healthy" | "at_risk" | "degraded" | "critical";
  topActions: string[];
  computedAt: number;
}

// ─── Extension internal types ─────────────────────────────────────────────────

/** Severity ranks for comparison — higher = more severe */
export const SEVERITY_RANK: Record<Severity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Maps Sentinel severity → VS Code DiagnosticSeverity integer (0=Error, 1=Warning, 2=Info, 3=Hint) */
export const SEVERITY_TO_DIAGNOSTIC: Record<Severity, number> = {
  critical: 0,
  high: 0,
  medium: 1,
  low: 2,
  informational: 3,
};

/** A resolved association between a finding and a manifest file line number */
export interface ManifestMatch {
  finding: SentinelFinding;
  /** 0-based line number inside the manifest file */
  line: number;
  /** The matched package name */
  packageName: string;
}

/** Aggregated state exposed to all providers via the FindingStore */
export interface StoreSnapshot {
  findings: SentinelFinding[];
  posture: SentinelPostureReport | null;
  lastRefreshedAt: Date | null;
  isLoading: boolean;
  error: string | null;
}

/** Ecosystem → canonical manifest file names */
export const MANIFEST_FILES: Record<string, string[]> = {
  npm: ["package.json"],
  pip: ["requirements.txt", "Pipfile", "pyproject.toml"],
  cargo: ["Cargo.toml"],
  go: ["go.mod"],
  maven: ["pom.xml"],
  gem: ["Gemfile"],
  nuget: [".csproj"],
  composer: ["composer.json"],
};

/** All manifest basenames (flat list used for file watching) */
export const ALL_MANIFEST_BASENAMES = Object.values(MANIFEST_FILES).flat();
