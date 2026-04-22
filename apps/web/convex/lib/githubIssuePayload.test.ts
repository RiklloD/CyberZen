import { describe, expect, test } from "vitest";
import {
  buildGithubIssueTitle,
  buildGithubIssueLabels,
  buildGithubIssueBody,
  buildGithubIssueCreateBody,
  buildGithubIssueCloseBody,
  type FindingIssueInput,
} from "./githubIssuePayload";

// ── Shared fixture ─────────────────────────────────────────────────────────────

const BASE_INPUT: FindingIssueInput = {
  title: "SQL Injection in query builder",
  summary: "An attacker can inject arbitrary SQL via the search parameter.",
  severity: "critical",
  vulnClass: "sql_injection",
  blastRadiusSummary: "All unauthenticated endpoints that accept user search input.",
  affectedFiles: ["src/db/query.ts", "src/routes/search.ts"],
  affectedPackages: ["knex@2.4.0"],
  regulatoryImplications: ["PCI-DSS Req 6.4", "SOC 2 CC6.1"],
  repositoryFullName: "acme/payments-api",
  findingId: "abc123",
  sentinelUrl: "https://sentinelsec.io",
};

// ── buildGithubIssueTitle ──────────────────────────────────────────────────────

describe("buildGithubIssueTitle", () => {
  test("formats title with SENTINEL prefix and uppercased severity", () => {
    const result = buildGithubIssueTitle("critical", "SQL Injection in query builder");
    expect(result).toBe("[SENTINEL] CRITICAL: SQL Injection in query builder");
  });

  test("uppercases lowercase severity", () => {
    const result = buildGithubIssueTitle("high", "XSS in template renderer");
    expect(result).toContain("[SENTINEL] HIGH:");
  });

  test("truncates title at 200 characters", () => {
    const longTitle = "A".repeat(250);
    const result = buildGithubIssueTitle("medium", longTitle);
    // prefix is "[SENTINEL] MEDIUM: " (19 chars), body should be 200 chars
    expect(result).toBe(`[SENTINEL] MEDIUM: ${"A".repeat(200)}`);
  });
});

// ── buildGithubIssueLabels ─────────────────────────────────────────────────────

describe("buildGithubIssueLabels", () => {
  test("always contains sentinel and security labels", () => {
    const labels = buildGithubIssueLabels("critical");
    expect(labels).toContain("sentinel");
    expect(labels).toContain("security");
  });

  test("includes severity-specific label with lowercase severity", () => {
    const labels = buildGithubIssueLabels("critical");
    expect(labels).toContain("sentinel:critical");
  });

  test("normalises uppercase severity for label", () => {
    const labels = buildGithubIssueLabels("HIGH");
    expect(labels).toContain("sentinel:high");
  });

  test("returns exactly three labels", () => {
    const labels = buildGithubIssueLabels("medium");
    expect(labels).toHaveLength(3);
  });
});

// ── buildGithubIssueBody ───────────────────────────────────────────────────────

describe("buildGithubIssueBody", () => {
  test("contains header, severity, class and repository", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("🛡️ Sentinel Security Finding");
    expect(body).toContain("**Severity:** CRITICAL");
    expect(body).toContain("**Class:** sql injection");
    expect(body).toContain("`acme/payments-api`");
  });

  test("contains summary section", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("## Summary");
    expect(body).toContain("An attacker can inject arbitrary SQL");
  });

  test("contains blast radius section", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("## Blast Radius");
    expect(body).toContain("unauthenticated endpoints");
  });

  test("lists affected files (up to 10) as code backticks", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("## Affected Files");
    expect(body).toContain("`src/db/query.ts`");
    expect(body).toContain("`src/routes/search.ts`");
  });

  test("caps affected files at 10", () => {
    const manyFiles: FindingIssueInput = {
      ...BASE_INPUT,
      affectedFiles: Array.from({ length: 15 }, (_, i) => `src/file${i}.ts`),
    };
    const body = buildGithubIssueBody(manyFiles);
    const matches = body.match(/`src\/file\d+\.ts`/g) ?? [];
    expect(matches).toHaveLength(10);
  });

  test("shows Fix PR section when prUrl is present", () => {
    const withPr: FindingIssueInput = {
      ...BASE_INPUT,
      prUrl: "https://github.com/acme/payments-api/pull/99",
    };
    const body = buildGithubIssueBody(withPr);
    expect(body).toContain("## Fix PR");
    expect(body).toContain("https://github.com/acme/payments-api/pull/99");
  });

  test("omits Fix PR section when prUrl is absent", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).not.toContain("## Fix PR");
  });

  test("shows regulatory implications when non-empty", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("## Regulatory Implications");
    expect(body).toContain("PCI-DSS Req 6.4");
    expect(body).toContain("SOC 2 CC6.1");
  });

  test("omits regulatory implications section when empty", () => {
    const noReg: FindingIssueInput = {
      ...BASE_INPUT,
      regulatoryImplications: [],
    };
    const body = buildGithubIssueBody(noReg);
    expect(body).not.toContain("## Regulatory Implications");
  });

  test("contains links section with Sentinel Dashboard and GitHub repo", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("## Links");
    expect(body).toContain("https://sentinelsec.io/findings/abc123");
    expect(body).toContain("https://github.com/acme/payments-api");
  });

  test("contains auto-created footer", () => {
    const body = buildGithubIssueBody(BASE_INPUT);
    expect(body).toContain("Auto-created by [Sentinel Security Agent]");
  });
});

// ── buildGithubIssueCreateBody ─────────────────────────────────────────────────

describe("buildGithubIssueCreateBody", () => {
  test("assembles title, body and labels correctly", () => {
    const result = buildGithubIssueCreateBody(BASE_INPUT);
    expect(result.title).toBe("[SENTINEL] CRITICAL: SQL Injection in query builder");
    expect(result.body).toContain("## Summary");
    expect(result.labels).toContain("sentinel");
    expect(result.labels).toContain("sentinel:critical");
  });

  test("labels has correct length", () => {
    const result = buildGithubIssueCreateBody(BASE_INPUT);
    expect(result.labels).toHaveLength(3);
  });

  test("shape matches GithubIssueCreateBody interface", () => {
    const result = buildGithubIssueCreateBody(BASE_INPUT);
    expect(typeof result.title).toBe("string");
    expect(typeof result.body).toBe("string");
    expect(Array.isArray(result.labels)).toBe(true);
  });
});

// ── buildGithubIssueCloseBody ──────────────────────────────────────────────────

describe("buildGithubIssueCloseBody", () => {
  test("returns state closed with reason completed", () => {
    const result = buildGithubIssueCloseBody();
    expect(result.state).toBe("closed");
    expect(result.state_reason).toBe("completed");
  });

  test("shape is correct", () => {
    const result = buildGithubIssueCloseBody();
    expect(Object.keys(result)).toEqual(["state", "state_reason"]);
  });
});
