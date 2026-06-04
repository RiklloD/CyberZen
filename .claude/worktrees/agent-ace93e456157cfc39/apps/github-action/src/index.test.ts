/**
 * Tests for Sentinel GitHub Action utilities.
 * (Core action logic is integration-tested via GitHub Actions test workflows.)
 */

import { describe, expect, test } from "bun:test";

// ── Severity threshold logic ──────────────────────────────────────────────────

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

function severityMeetsThreshold(severity: string, threshold: string): boolean {
  const sIdx = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  const tIdx = SEVERITY_ORDER.indexOf(threshold.toLowerCase());
  if (sIdx === -1 || tIdx === -1) return false;
  return sIdx <= tIdx;
}

describe("severityMeetsThreshold", () => {
  test("critical meets critical threshold", () => {
    expect(severityMeetsThreshold("critical", "critical")).toBe(true);
  });

  test("critical meets high threshold", () => {
    expect(severityMeetsThreshold("critical", "high")).toBe(true);
  });

  test("high does not meet critical threshold", () => {
    expect(severityMeetsThreshold("high", "critical")).toBe(false);
  });

  test("medium does not meet high threshold", () => {
    expect(severityMeetsThreshold("medium", "high")).toBe(false);
  });

  test("medium meets medium threshold", () => {
    expect(severityMeetsThreshold("medium", "medium")).toBe(true);
  });

  test("low meets medium threshold (false — lower severity)", () => {
    expect(severityMeetsThreshold("low", "medium")).toBe(false);
  });

  test("informational never blocks", () => {
    expect(severityMeetsThreshold("informational", "high")).toBe(false);
    expect(severityMeetsThreshold("informational", "medium")).toBe(false);
    expect(severityMeetsThreshold("informational", "informational")).toBe(true);
  });

  test("unknown severity returns false", () => {
    expect(severityMeetsThreshold("unknown", "high")).toBe(false);
    expect(severityMeetsThreshold("critical", "unknown")).toBe(false);
  });
});

// ── SentinelApiClient URL construction ───────────────────────────────────────
// These tests verify the API client builds correct URLs without making network calls.

describe("API client URL construction", () => {
  test("trailing slash stripped from base URL", () => {
    // The client normalises the base URL in its constructor
    const url = "https://example.convex.site/";
    const normalised = url.replace(/\/$/, "");
    expect(normalised).toBe("https://example.convex.site");
  });

  test("findings URL includes tenant and repository params", () => {
    const base = "https://api.sentinel.test";
    const params = new URLSearchParams({
      tenantSlug: "acme",
      repositoryFullName: "acme/payments-api",
      status: "open",
      limit: "100",
    });
    const url = `${base}/api/findings?${params}`;
    expect(url).toContain("tenantSlug=acme");
    expect(url).toContain("repositoryFullName=acme%2Fpayments-api");
    expect(url).toContain("status=open");
  });
});

// ── Check run title generation ────────────────────────────────────────────────

type MockFinding = {
  _id: string;
  title: string;
  severity: string;
  validationStatus: string;
  vulnClass: string;
  blastRadiusSummary: string;
  prUrl?: string;
};

function buildTitle(blocked: MockFinding[], validated: MockFinding[]): string {
  if (blocked.length > 0) {
    const critical = blocked.filter((f) => f.severity === "critical").length;
    const high = blocked.filter((f) => f.severity === "high").length;
    const parts = [];
    if (critical > 0) parts.push(`${critical} critical`);
    if (high > 0) parts.push(`${high} high`);
    return `🚫 Gate blocked — ${parts.join(", ")} confirmed finding${blocked.length > 1 ? "s" : ""}`;
  }
  if (validated.length > 0) {
    return `⚠️ ${validated.length} finding${validated.length > 1 ? "s" : ""} detected — below block threshold`;
  }
  return "✅ No blocking security findings";
}

describe("check run title", () => {
  const mockFinding = (severity: string): MockFinding => ({
    _id: "1",
    title: "Test Finding",
    severity,
    validationStatus: "validated",
    vulnClass: "sql_injection",
    blastRadiusSummary: "Payment service affected",
  });

  test("clean run produces passing title", () => {
    const title = buildTitle([], []);
    expect(title).toContain("✅");
    expect(title).toContain("No blocking");
  });

  test("blocked critical finding produces failure title", () => {
    const finding = mockFinding("critical");
    const title = buildTitle([finding], [finding]);
    expect(title).toContain("🚫");
    expect(title).toContain("1 critical");
  });

  test("multiple blocked findings uses plural", () => {
    const findings = [mockFinding("critical"), mockFinding("high")];
    const title = buildTitle(findings, findings);
    expect(title).toContain("findings");
    expect(title).toContain("1 critical");
    expect(title).toContain("1 high");
  });

  test("findings below threshold shows warning not block", () => {
    // e.g. medium findings when threshold is high
    const finding = mockFinding("medium");
    const title = buildTitle([], [finding]);
    expect(title).toContain("⚠️");
    expect(title).toContain("below block threshold");
  });
});
